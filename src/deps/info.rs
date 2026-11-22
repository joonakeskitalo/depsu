//! Facts about an installed package, read from disk only: its copy in `node_modules`, the
//! lockfile, and the lockfile of the last commit. Nothing is downloaded.
use semver::Version;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The npm lifecycle scripts that run when a package is installed.
const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// The version found in `node_modules` (or the lockfile when not installed).
    pub version: Option<Version>,
    /// The deprecation message the registry had when the lockfile was written.
    pub deprecated: Option<String>,
    pub install: InstallScripts,
    /// `engines`: e.g. node → `>=18`.
    pub engines: BTreeMap<String, String>,
    /// `os`, `cpu` and `libc` restrictions; empty when it runs anywhere.
    pub platform: Vec<(String, Vec<String>)>,
    /// Bytes and files of the installed copy, its own `node_modules` left out.
    pub size: Option<(u64, u64)>,
    /// `dependencies` and `optionalDependencies` of the installed copy: name → range.
    pub dependencies: BTreeMap<String, String>,
    /// How the dependencies differ from the version in the last commit's lockfile, when the
    /// package changed since.
    pub since_commit: Option<DepChanges>,
    /// The lockfile's checksum of the package file, e.g. `sha512-…`.
    pub integrity: Option<String>,
    /// The lockfile lists the package as downloaded from a registry or a git repository, but
    /// without a checksum, so the package manager can't verify what it installs. Packages
    /// linked from a local folder have none and aren't counted.
    pub missing_integrity: bool,
    /// The lockfile it was read from, or `None` when there is none.
    pub lockfile: Option<&'static str>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum InstallScripts {
    /// Neither the package nor the lockfile says.
    #[default]
    Unknown,
    None,
    /// The scripts that run, with their commands. A lockfile only says there are some.
    Some(Vec<(String, String)>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DepChanges {
    /// The version in the last commit.
    pub from: Option<Version>,
    pub added: Vec<(String, String)>,
    pub removed: Vec<(String, String)>,
    /// Name, old range, new range.
    pub changed: Vec<(String, String, String)>,
}

impl DepChanges {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// The lockfiles of the project, now and in the last commit, parsed once and reused.
#[derive(Default)]
pub struct Reader {
    dir: PathBuf,
    now: Option<Option<Lock>>,
    head: Option<Option<Lock>>,
}

/// A lockfile's entries by package name: the top-level copy, as Node resolves it.
struct Lock {
    file: &'static str,
    entries: BTreeMap<String, Value>,
}

impl Reader {
    pub fn new(dir: PathBuf) -> Reader {
        Reader { dir, now: None, head: None }
    }

    /// Forgets the lockfiles read so far: after an install or a commit.
    pub fn reset(&mut self) {
        self.now = None;
        self.head = None;
    }

    pub fn info(&mut self, name: &str) -> Info {
        let dir = self.dir.clone();
        let installed = package_dir(&dir, name);
        let manifest = installed
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("package.json")).ok())
            .and_then(|t| serde_json::from_str::<Value>(&t).ok());
        let now = self.now.get_or_insert_with(|| Lock::current(&dir));
        let entry = now.as_ref().and_then(|l| l.entries.get(name)).cloned();
        let lockfile = now.as_ref().map(|l| l.file);
        // The installed copy speaks for itself; the lockfile fills in the rest.
        let source = manifest.as_ref().or(entry.as_ref());
        let field = |k: &str| source.and_then(|s| s.get(k));
        let version = field("version")
            .and_then(Value::as_str)
            .and_then(|v| Version::parse(v).ok());
        let install = match (&manifest, &entry) {
            (Some(m), _) => {
                let mut found: Vec<(String, String)> = INSTALL_SCRIPTS
                    .iter()
                    .filter_map(|s| {
                        let cmd = m.get("scripts")?.get(*s)?.as_str()?;
                        Some((s.to_string(), cmd.to_string()))
                    })
                    .collect();
                // npm builds native addons with node-gyp when there is no install script.
                let gyp = installed.as_ref().is_some_and(|d| d.join("binding.gyp").is_file());
                if gyp && !found.iter().any(|(s, _)| s == "install") {
                    found.push(("install".into(), "node-gyp rebuild (binding.gyp)".into()));
                }
                if found.is_empty() { InstallScripts::None } else { InstallScripts::Some(found) }
            }
            (None, Some(e)) => match e.get("hasInstallScript").or(e.get("requiresBuild")) {
                Some(Value::Bool(true)) => InstallScripts::Some(Vec::new()),
                _ => InstallScripts::None,
            },
            (None, None) => InstallScripts::Unknown,
        };
        let platform = ["os", "cpu", "libc"]
            .iter()
            .filter_map(|k| {
                let list = strings(field(k)?);
                (!list.is_empty()).then(|| (k.to_string(), list))
            })
            .collect();
        let dependencies = deps(source);
        let since_commit = self.since_commit(name, version.as_ref(), &dependencies);
        Info {
            deprecated: entry
                .as_ref()
                .and_then(|e| e.get("deprecated"))
                .or(field("deprecated"))
                .and_then(Value::as_str)
                .map(str::to_string),
            install,
            engines: field("engines").map(string_map).unwrap_or_default(),
            platform,
            size: installed.as_deref().map(dir_size),
            dependencies,
            since_commit,
            integrity: entry.as_ref().and_then(integrity),
            missing_integrity: entry.as_ref().is_some_and(|e| integrity(e).is_none() && !is_local(e)),
            lockfile,
            version,
        }
    }

    fn since_commit(
        &mut self,
        name: &str,
        version: Option<&Version>,
        now: &BTreeMap<String, String>,
    ) -> Option<DepChanges> {
        let dir = self.dir.clone();
        let head = self.head.get_or_insert_with(|| Lock::at_head(&dir)).as_ref()?;
        let old = head.entries.get(name)?;
        let from = old.get("version").and_then(Value::as_str).and_then(|v| Version::parse(v).ok());
        if from.as_ref() == version {
            return None;
        }
        let before = deps(Some(old));
        let mut c = DepChanges { from, ..Default::default() };
        for (n, r) in now {
            match before.get(n) {
                None => c.added.push((n.clone(), r.clone())),
                Some(o) if o != r => c.changed.push((n.clone(), o.clone(), r.clone())),
                _ => {}
            }
        }
        for (n, r) in &before {
            if !now.contains_key(n) {
                c.removed.push((n.clone(), r.clone()));
            }
        }
        Some(c)
    }
}

impl Lock {
    fn current(dir: &Path) -> Option<Lock> {
        for file in ["package-lock.json", "pnpm-lock.yaml"] {
            if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
                return Lock::parse(file, &text);
            }
        }
        None
    }

    /// The lockfile as the last commit has it, from git; `None` outside a repository.
    fn at_head(dir: &Path) -> Option<Lock> {
        for file in ["package-lock.json", "pnpm-lock.yaml"] {
            if !dir.join(file).is_file() {
                continue;
            }
            let out = Command::new("git")
                .args(["show", &format!("HEAD:./{file}")])
                .current_dir(dir)
                .output()
                .ok()?;
            return out
                .status
                .success()
                .then(|| Lock::parse(file, &String::from_utf8_lossy(&out.stdout)))
                .flatten();
        }
        None
    }

    fn parse(file: &'static str, text: &str) -> Option<Lock> {
        let entries = if file == "package-lock.json" {
            npm_entries(serde_json::from_str(text).ok()?)
        } else {
            pnpm_entries(serde_yaml_ng::from_str(text).ok()?)
        };
        Some(Lock { file, entries })
    }
}

/// npm lockfile v2/v3: `packages["node_modules/<name>"]`, the top-level copy.
fn npm_entries(lock: Value) -> BTreeMap<String, Value> {
    let Some(Value::Object(packages)) = lock.get("packages").cloned() else {
        return BTreeMap::new();
    };
    packages
        .into_iter()
        .filter_map(|(path, v)| {
            let name = path.strip_prefix("node_modules/")?;
            (!name.contains("/node_modules/")).then(|| (name.to_string(), v))
        })
        .collect()
}

/// pnpm lockfile: `packages` keyed by `/name@1.0.0` (v6), `name@1.0.0` (v9) or `/name/1.0.0`
/// (v5). With several versions of a package, the highest is kept.
fn pnpm_entries(lock: serde_yaml_ng::Value) -> BTreeMap<String, Value> {
    let lock: Value = serde_json::to_value(lock).unwrap_or_default();
    let Some(Value::Object(packages)) = lock.get("packages").cloned() else {
        return BTreeMap::new();
    };
    let mut out: BTreeMap<String, (Version, Value)> = BTreeMap::new();
    for (key, mut v) in packages {
        let key = key.trim_start_matches('/');
        // Peer suffixes: `name@1.0.0(react@18.0.0)`.
        let key = key.split('(').next().unwrap_or(key);
        if key.len() < 2 {
            continue;
        }
        let split = key[1..].rfind(['@', '/']).map(|i| i + 1);
        let Some((name, ver)) = split.map(|i| (&key[..i], &key[i + 1..])) else {
            continue;
        };
        let Ok(ver) = Version::parse(ver) else {
            continue;
        };
        if let Value::Object(m) = &mut v {
            m.entry("version").or_insert(Value::String(ver.to_string()));
        }
        if out.get(name).is_none_or(|(have, _)| ver > *have) {
            out.insert(name.to_string(), (ver, v));
        }
    }
    out.into_iter().map(|(k, (_, v))| (k, v)).collect()
}

/// A lockfile entry for a package linked from a folder: a workspace, `file:` or `link:`.
fn is_local(entry: &Value) -> bool {
    let resolved = entry
        .get("resolved")
        .or_else(|| entry.get("resolution")?.get("directory"))
        .and_then(Value::as_str);
    entry.get("link").and_then(Value::as_bool) == Some(true)
        || entry.get("resolution").is_some_and(|r| r.get("directory").is_some())
        || resolved.is_some_and(|r| r.starts_with("file:") || r.starts_with("link:") || !r.contains(':'))
}
fn integrity(entry: &Value) -> Option<String> {
    entry
        .get("integrity")
        .or_else(|| entry.get("resolution")?.get("integrity"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn deps(source: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for k in ["dependencies", "optionalDependencies"] {
        if let Some(m) = source.and_then(|s| s.get(k)) {
            out.extend(string_map(m));
        }
    }
    out
}

fn string_map(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// The directory Node resolves `name` to from `dir`, symlinks (pnpm) followed.
fn package_dir(dir: &Path, name: &str) -> Option<PathBuf> {
    dir.ancestors()
        .map(|a| a.join("node_modules").join(name))
        .find(|p| p.join("package.json").is_file())
        .map(|p| p.canonicalize().unwrap_or(p))
}

/// Bytes and files under `dir`, leaving out nested `node_modules` and not following links.
fn dir_size(dir: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else {
                continue;
            };
            if t.is_dir() {
                if e.file_name() != "node_modules" {
                    stack.push(e.path());
                }
            } else if t.is_file() {
                files += 1;
                bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    (bytes, files)
}

/// The packages that got an integrity checksum between two versions of a lockfile (`file` is
/// its name): locked at the same version, without one before and with one now.
pub fn integrity_added(file: &str, old: &str, new: &str) -> Vec<(String, Version)> {
    let file: &'static str = match file {
        "package-lock.json" => "package-lock.json",
        "pnpm-lock.yaml" => "pnpm-lock.yaml",
        _ => return Vec::new(),
    };
    let (Some(old), Some(new)) = (Lock::parse(file, old), Lock::parse(file, new)) else {
        return Vec::new();
    };
    let version = |e: &Value| e.get("version").and_then(Value::as_str).and_then(|v| Version::parse(v).ok());
    new.entries
        .iter()
        .filter_map(|(name, now)| {
            let before = old.entries.get(name)?;
            let v = version(now)?;
            (version(before) == Some(v.clone()) && integrity(before).is_none() && integrity(now).is_some())
                .then(|| (name.clone(), v))
        })
        .collect()
}

/// What `package-lock.json` says about a package that lacks a checksum: its version and where
/// it was downloaded from.
pub fn npm_lock_entry(dir: &Path, name: &str) -> Option<(Version, Option<String>)> {
    let text = std::fs::read_to_string(dir.join("package-lock.json")).ok()?;
    let lock = Lock::parse("package-lock.json", &text)?;
    let e = lock.entries.get(name)?;
    let v = Version::parse(e.get("version")?.as_str()?).ok()?;
    Some((v, e.get("resolved").and_then(Value::as_str).map(str::to_string)))
}

/// Writes checksums into `package-lock.json`: `integrity` of the top-level entry of each
/// package, where npm writes it: after `resolved`, or after `version` without one. The file keeps its indentation and line
/// endings. Returns the packages it wrote one for.
pub fn set_npm_integrity(dir: &Path, sums: &[(String, String)]) -> Result<Vec<String>, String> {
    let path = dir.join("package-lock.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("could not read package-lock.json: {e}"))?;
    let mut lock: Value =
        serde_json::from_str(&text).map_err(|e| format!("could not read package-lock.json: {e}"))?;
    let packages = lock
        .get_mut("packages")
        .and_then(Value::as_object_mut)
        .ok_or("package-lock.json has no `packages` (lockfile v1 is not supported)")?;
    let mut done = Vec::new();
    for (name, sum) in sums {
        let Some(Value::Object(entry)) = packages.get_mut(&format!("node_modules/{name}")) else {
            continue;
        };
        if entry.contains_key("integrity") {
            continue;
        }
        // npm writes `version`, `resolved`, `integrity` first, in that order; `resolved` is
        // left out with `omit-lockfile-registry-resolved`.
        let at = ["resolved", "version", "name"]
            .iter()
            .find_map(|k| entry.keys().position(|x| x == k))
            .map_or(0, |i| i + 1);
        entry.shift_insert(at, "integrity".to_string(), Value::String(sum.clone()));
        done.push(name.clone());
    }
    if done.is_empty() {
        return Ok(done);
    }
    // npm writes JSON.stringify(lock, null, indent) and a newline, the indent taken from the
    // file as it was.
    let indent: String = text
        .lines()
        .nth(1)
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect())
        .filter(|i: &String| !i.is_empty())
        .unwrap_or_else(|| "  ".to_string());
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(&lock, &mut ser).map_err(|e| e.to_string())?;
    let mut out = String::from_utf8(out).map_err(|e| e.to_string())?;
    out.push('\n');
    if text.contains("\r\n") {
        out = out.replace('\n', "\r\n");
    }
    std::fs::write(&path, out).map_err(|e| format!("could not write package-lock.json: {e}"))?;
    Ok(done)
}

/// The versions of the tools `engines` can name that this machine runs for the project in `dir`:
/// node, npm and the project's package manager. Run in `dir`, so version managers (asdf, nvm,
/// volta) pick the version the project uses. Tools that don't answer are left out.
pub fn tool_versions(dir: &Path, pm: &str) -> BTreeMap<String, Version> {
    let mut tools = vec!["node", "npm"];
    if !tools.contains(&pm) {
        tools.push(pm);
    }
    tools
        .into_iter()
        .filter_map(|t| {
            let out = Command::new(t).arg("--version").current_dir(dir).output().ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let v = parse_tool_version(&text)?;
            out.status.success().then(|| (t.to_string(), v))
        })
        .collect()
}

/// `v20.11.0`, `10.2.4\n`, `1.1.0-canary` → the version.
fn parse_tool_version(text: &str) -> Option<Version> {
    let t = text.trim().lines().next()?.trim().trim_start_matches('v');
    Version::parse(t).ok()
}

/// An `engines` entry the tool installed here does not satisfy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineProblem {
    pub tool: String,
    pub range: String,
    pub have: Version,
}

/// The `engines` entries that the installed tools don't satisfy. Tools that aren't installed,
/// or ranges that can't be read, are not reported.
pub fn engine_problems(
    engines: &BTreeMap<String, String>,
    tools: &BTreeMap<String, Version>,
) -> Vec<EngineProblem> {
    engines
        .iter()
        .filter_map(|(tool, range)| {
            let have = tools.get(tool)?;
            (crate::deps::overrides::satisfies(range, have) == Some(false)).then(|| EngineProblem {
                tool: tool.clone(),
                range: range.clone(),
                have: have.clone(),
            })
        })
        .collect()
}

/// `1.2 MB`, `340 kB`, `12 B`: decimal units, as npm prints sizes.
pub fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        b if b >= 1_000 => format!("{:.0} kB", b as f64 / 1e3),
        b => format!("{b} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-info-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git").args(args).current_dir(dir).output().unwrap().status.success();
        assert!(ok, "git {args:?}");
    }
    const LOCK_V1: &str = r#"{"lockfileVersion":3,"packages":{
        "":{"name":"app"},
        "node_modules/a":{"version":"1.0.0","integrity":"sha512-old",
            "dependencies":{"x":"^1.0.0","gone":"^1.0.0"}},
        "node_modules/a/node_modules/x":{"version":"0.1.0"}
    }}"#;
    const LOCK_V2: &str = r#"{"lockfileVersion":3,"packages":{
        "":{"name":"app"},
        "node_modules/a":{"version":"2.0.0","integrity":"sha512-abc",
            "deprecated":"use b instead","hasInstallScript":true,
            "dependencies":{"x":"^2.0.0","new":"^1.0.0"}}
    }}"#;

    #[test]
    fn reads_the_installed_copy_and_the_lockfile() {
        let dir = tmp("npm");
        write(&dir.join("package-lock.json"), LOCK_V2);
        write(
            &dir.join("node_modules/a/package.json"),
            r#"{"name":"a","version":"2.0.0",
                "scripts":{"postinstall":"node setup.js","test":"jest"},
                "engines":{"node":">=18"},"os":["darwin","linux"],"cpu":"arm64",
                "dependencies":{"x":"^2.0.0"},"optionalDependencies":{"new":"^1.0.0"}}"#,
        );
        write(&dir.join("node_modules/a/index.js"), "12345");
        write(&dir.join("node_modules/a/node_modules/x/package.json"), "{}");
        let i = Reader::new(dir.clone()).info("a");
        assert_eq!(i.version, Some(Version::new(2, 0, 0)));
        assert_eq!(i.deprecated.as_deref(), Some("use b instead"));
        assert_eq!(
            i.install,
            InstallScripts::Some(vec![("postinstall".into(), "node setup.js".into())])
        );
        assert_eq!(i.engines["node"], ">=18");
        assert_eq!(
            i.platform,
            vec![
                ("os".to_string(), vec!["darwin".to_string(), "linux".to_string()]),
                ("cpu".to_string(), vec!["arm64".to_string()]),
            ]
        );
        assert_eq!(i.dependencies.len(), 2);
        assert_eq!(i.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(i.lockfile, Some("package-lock.json"));
        // Its own package.json and index.js; the nested node_modules is not counted.
        let (bytes, files) = i.size.unwrap();
        assert_eq!(files, 2);
        assert!(bytes > 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn without_node_modules_the_lockfile_says_what_it_can() {
        let dir = tmp("lockonly");
        write(&dir.join("package-lock.json"), LOCK_V2);
        let i = Reader::new(dir.clone()).info("a");
        assert_eq!(i.version, Some(Version::new(2, 0, 0)));
        assert_eq!(i.install, InstallScripts::Some(Vec::new()), "hasInstallScript");
        assert_eq!(i.size, None);
        assert_eq!(Reader::new(dir.clone()).info("missing").install, InstallScripts::Unknown);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn native_addons_count_as_install_scripts() {
        let dir = tmp("gyp");
        write(&dir.join("node_modules/n/package.json"), r#"{"version":"1.0.0"}"#);
        write(&dir.join("node_modules/n/binding.gyp"), "{}");
        let i = Reader::new(dir.clone()).info("n");
        assert!(matches!(&i.install, InstallScripts::Some(s) if s[0].1.contains("node-gyp")));
        write(&dir.join("node_modules/m/package.json"), r#"{"version":"1.0.0"}"#);
        assert_eq!(Reader::new(dir.clone()).info("m").install, InstallScripts::None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dependency_changes_are_against_the_last_commit() {
        let dir = tmp("git");
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@t"]);
        git(&dir, &["config", "user.name", "t"]);
        write(&dir.join("package-lock.json"), LOCK_V1);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "init"]);
        let mut r = Reader::new(dir.clone());
        assert_eq!(r.info("a").since_commit, None, "unchanged since the commit");
        write(&dir.join("package-lock.json"), LOCK_V2);
        r.reset();
        let c = r.info("a").since_commit.unwrap();
        assert_eq!(c.from, Some(Version::new(1, 0, 0)));
        assert_eq!(c.added, vec![("new".to_string(), "^1.0.0".to_string())]);
        assert_eq!(c.removed, vec![("gone".to_string(), "^1.0.0".to_string())]);
        assert_eq!(c.changed, vec![("x".to_string(), "^1.0.0".to_string(), "^2.0.0".to_string())]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_pnpm_lockfiles() {
        let v9 = "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-one}\n  a@2.0.0:\n    resolution: {integrity: sha512-two}\n    deprecated: old\n    requiresBuild: true\n    engines: {node: '>=20'}\n  '@s/b@3.0.0(react@18.0.0)':\n    resolution: {integrity: sha512-b}\n";
        let lock = Lock::parse("pnpm-lock.yaml", v9).unwrap();
        assert_eq!(lock.entries["a"]["version"], "2.0.0", "the highest version");
        assert_eq!(integrity(&lock.entries["a"]).as_deref(), Some("sha512-two"));
        assert_eq!(lock.entries["a"]["deprecated"], "old");
        assert_eq!(integrity(&lock.entries["@s/b"]).as_deref(), Some("sha512-b"));
        let v6 = "lockfileVersion: '6.0'\npackages:\n  /c@1.2.3:\n    resolution: {integrity: sha512-c}\n";
        assert!(Lock::parse("pnpm-lock.yaml", v6).unwrap().entries.contains_key("c"));
        let v5 = "lockfileVersion: 5.4\npackages:\n  /@s/d/4.0.0:\n    resolution: {integrity: sha512-d}\n";
        assert!(Lock::parse("pnpm-lock.yaml", v5).unwrap().entries.contains_key("@s/d"));
    }

    #[test]
    fn engines_are_checked_against_the_installed_tools() {
        let tools: BTreeMap<String, Version> =
            [("node".to_string(), Version::new(18, 19, 0)), ("npm".to_string(), Version::new(10, 2, 4))]
                .into();
        let engines: BTreeMap<String, String> = [
            ("node".to_string(), "^18.18.0 || ^19.8.0 || >= 20.0.0".to_string()),
            ("npm".to_string(), ">=11".to_string()),
            ("pnpm".to_string(), ">=9".to_string()),
            ("vscode".to_string(), "^1.80.0".to_string()),
        ]
        .into();
        let p = engine_problems(&engines, &tools);
        assert_eq!(
            p,
            vec![EngineProblem { tool: "npm".into(), range: ">=11".into(), have: Version::new(10, 2, 4) }],
            "node fits; pnpm and vscode aren't installed"
        );
        let engines: BTreeMap<String, String> = [("node".to_string(), ">=20".to_string())].into();
        assert_eq!(engine_problems(&engines, &tools)[0].have, Version::new(18, 19, 0));
        assert_eq!(parse_tool_version("v20.11.0\n"), Some(Version::new(20, 11, 0)));
        assert_eq!(parse_tool_version("10.2.4"), Some(Version::new(10, 2, 4)));
        assert_eq!(parse_tool_version("not a version"), None);
    }
    #[test]
    fn a_missing_checksum_is_noticed_except_for_local_packages() {
        let lock = r#"{"lockfileVersion":3,"packages":{
            "node_modules/ok":{"version":"1.0.0","resolved":"https://r/ok.tgz","integrity":"sha512-x"},
            "node_modules/bare":{"version":"1.0.0","resolved":"https://r/bare.tgz"},
            "node_modules/gitdep":{"version":"1.0.0","resolved":"git+ssh://git@github.com/a/b.git#abc"},
            "node_modules/ws":{"resolved":"packages/ws","link":true},
            "node_modules/local":{"version":"1.0.0","resolved":"file:../local"}
        }}"#;
        let dir = tmp("integrity");
        write(&dir.join("package-lock.json"), lock);
        let mut r = Reader::new(dir.clone());
        let missing = |r: &mut Reader, n: &str| r.info(n).missing_integrity;
        assert!(!missing(&mut r, "ok"));
        assert!(missing(&mut r, "bare"));
        assert!(missing(&mut r, "gitdep"), "git packages can't be verified either");
        assert!(!missing(&mut r, "ws"), "a workspace");
        assert!(!missing(&mut r, "local"));
        assert!(!missing(&mut r, "absent"), "not in the lockfile at all");
        let pnpm = "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {tarball: https://r/a.tgz}\n";
        write(&dir.join("pnpm-lock.yaml"), pnpm);
        std::fs::remove_file(dir.join("package-lock.json")).unwrap();
        assert!(Reader::new(dir.clone()).info("a").missing_integrity);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn checksums_are_written_after_resolved_keeping_the_format() {
        let dir = tmp("setsum");
        let lock = "{\n    \"name\": \"app\",\n    \"lockfileVersion\": 3,\n    \"packages\": {\n        \"\": {\n            \"name\": \"app\"\n        },\n        \"node_modules/a\": {\n            \"version\": \"1.0.0\",\n            \"resolved\": \"https://r/a/-/a-1.0.0.tgz\",\n            \"license\": \"MIT\"\n        },\n        \"node_modules/b\": {\n            \"version\": \"1.0.0\",\n            \"integrity\": \"sha512-keep\"\n        }\n    }\n}\n";
        write(&dir.join("package-lock.json"), lock);
        let done = set_npm_integrity(
            &dir,
            &[("a".into(), "sha512-new".into()), ("b".into(), "sha512-other".into()), ("x".into(), "sha512-x".into())],
        )
        .unwrap();
        assert_eq!(done, vec!["a".to_string()], "b has one already; x isn't there");
        let text = std::fs::read_to_string(dir.join("package-lock.json")).unwrap();
        let want = lock.replace(
            "\"resolved\": \"https://r/a/-/a-1.0.0.tgz\",\n",
            "\"resolved\": \"https://r/a/-/a-1.0.0.tgz\",\n            \"integrity\": \"sha512-new\",\n",
        );
        assert_eq!(text, want, "only the new line differs");
        // Without `resolved`, it goes right under `version`, not last.
        let lock = "{\n  \"packages\": {\n    \"node_modules/c\": {\n      \"version\": \"1.0.0\",\n      \"license\": \"MIT\",\n      \"engines\": {\n        \"node\": \">=18\"\n      }\n    }\n  }\n}\n";
        write(&dir.join("package-lock.json"), lock);
        set_npm_integrity(&dir, &[("c".into(), "sha512-c".into())]).unwrap();
        let text = std::fs::read_to_string(dir.join("package-lock.json")).unwrap();
        assert_eq!(
            text,
            lock.replace(
                "\"version\": \"1.0.0\",\n",
                "\"version\": \"1.0.0\",\n      \"integrity\": \"sha512-c\",\n"
            )
        );
        write(&dir.join("package-lock.json"), &want);
        assert_eq!(
            npm_lock_entry(&dir, "a"),
            Some((Version::new(1, 0, 0), Some("https://r/a/-/a-1.0.0.tgz".into())))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn added_checksums_are_found_between_two_lockfiles() {
        let old = r#"{"packages":{
            "node_modules/a":{"version":"1.0.0"},
            "node_modules/b":{"version":"1.0.0"},
            "node_modules/c":{"version":"1.0.0","integrity":"sha512-c"},
            "node_modules/d":{"version":"1.0.0"}}}"#;
        let new = r#"{"packages":{
            "node_modules/a":{"version":"1.0.0","integrity":"sha512-a"},
            "node_modules/b":{"version":"1.0.0"},
            "node_modules/c":{"version":"1.0.0","integrity":"sha512-c2"},
            "node_modules/d":{"version":"2.0.0","integrity":"sha512-d"},
            "node_modules/e":{"version":"1.0.0","integrity":"sha512-e"}}}"#;
        assert_eq!(
            integrity_added("package-lock.json", old, new),
            vec![("a".to_string(), Version::new(1, 0, 0))],
            "b still has none, c had one, d was upgraded, e is new"
        );
        let old = "packages:\n  a@1.0.0:\n    resolution: {tarball: https://r/a.tgz}\n";
        let new = "packages:\n  a@1.0.0:\n    resolution: {integrity: sha512-a, tarball: https://r/a.tgz}\n";
        assert_eq!(integrity_added("pnpm-lock.yaml", old, new).len(), 1);
        assert!(integrity_added("yarn.lock", "", "").is_empty());
    }
    #[test]
    fn sizes_read_like_npm_prints_them() {
        assert_eq!(human_size(12), "12 B");
        assert_eq!(human_size(340_123), "340 kB");
        assert_eq!(human_size(1_234_567), "1.2 MB");
    }
}
