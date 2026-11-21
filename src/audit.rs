//! `npm audit` and `bun audit` integration.
//!
//! Neither tool says which of the project's direct dependencies a finding belongs to, nor
//! which installed copy is affected. So the advisories are matched against the installed tree
//! (`node_modules`) afterwards, which gives the same per-dependency view as Snyk: the
//! vulnerable package, its installed version, and the path from the direct dependency.

use crate::pm::Pm;
use crate::tree::{Analyzer, Located};
use crate::vuln::{Report, Severity, Source, Vuln};
use semver::Version;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

/// One security advisory affecting a package, in the tool's own terms.
#[derive(Clone, Debug, PartialEq)]
pub struct Advisory {
    /// `GHSA-…` when the URL has one, otherwise the registry's numeric id.
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub package: String,
    /// Versions of the package that are affected, as an npm range.
    pub range: String,
}

/// What `npm audit` says about fixing a vulnerable package.
#[derive(Clone, Debug, PartialEq)]
pub enum NpmFix {
    None,
    /// Fixable by updating the lockfile within the existing ranges (`npm audit fix`).
    InLockfile,
    /// Fixable by installing `name@version`, usually the direct dependency.
    Upgrade {
        name: String,
        version: String,
        major: bool,
    },
}

/// A fix that can't be applied: the fixed version, and the dependents that block it, each with
/// the range it requires.
type Blocked = (String, Vec<(String, String)>);

/// The plan printed by `bun audit fix --dry-run --json`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BunPlan {
    /// (package, installed version) → (version to install, whether `package.json` changes).
    /// Two installed copies of a package are two entries.
    fixes: HashMap<(String, String), (String, bool)>,
    /// (package, installed version) → (fixed version, the dependents that block it with the
    /// range each requires).
    blocked: HashMap<(String, String), Blocked>,
}

enum FixInfo {
    Npm(HashMap<String, NpmFix>),
    Bun(BunPlan),
}

fn advisory_id(url: Option<&str>, numeric: Option<&Value>) -> String {
    let ghsa = url
        .and_then(|u| u.rsplit('/').next())
        .filter(|s| s.starts_with("GHSA-"));
    match (ghsa, numeric) {
        (Some(g), _) => g.to_string(),
        (None, Some(n)) => n.to_string().trim_matches('"').to_string(),
        (None, None) => url.unwrap_or("unknown").to_string(),
    }
}

/// Parses `npm audit --json` (report version 2).
pub fn parse_npm(text: &str) -> Result<(Vec<Advisory>, HashMap<String, NpmFix>), String> {
    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("could not read npm audit's output: {e}"))?;
    let Some(vulns) = json.get("vulnerabilities").and_then(Value::as_object) else {
        let msg = [
            json.pointer("/error/summary"),
            json.get("message"),
            json.pointer("/error/detail"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find(|s| !s.is_empty());
        return Err(msg.unwrap_or("npm audit failed").to_string());
    };

    let mut advisories = Vec::new();
    let mut fixes = HashMap::new();
    let mut seen = HashSet::new();
    for (name, entry) in vulns {
        fixes.insert(name.clone(), npm_fix(entry.get("fixAvailable")));
        // `via` holds advisories (objects) and the names of vulnerable dependencies the
        // package inherits its vulnerability from (strings, which are not findings).
        for via in entry
            .get("via")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(obj) = via.as_object() else { continue };
            let url = obj.get("url").and_then(Value::as_str);
            let id = advisory_id(url, obj.get("source"));
            let package = obj.get("name").and_then(Value::as_str).unwrap_or(name);
            if !seen.insert((id.clone(), package.to_string())) {
                continue;
            }
            advisories.push(Advisory {
                id,
                title: obj
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                severity: Severity::parse(
                    obj.get("severity").and_then(Value::as_str).unwrap_or(""),
                ),
                package: package.to_string(),
                range: obj
                    .get("range")
                    .and_then(Value::as_str)
                    .unwrap_or("*")
                    .to_string(),
            });
        }
    }
    Ok((advisories, fixes))
}

fn npm_fix(v: Option<&Value>) -> NpmFix {
    match v {
        Some(Value::Bool(true)) => NpmFix::InLockfile,
        Some(Value::Object(o)) => match (
            o.get("name").and_then(Value::as_str),
            o.get("version").and_then(Value::as_str),
        ) {
            (Some(name), Some(version)) => NpmFix::Upgrade {
                name: name.to_string(),
                version: version.to_string(),
                major: o
                    .get("isSemVerMajor")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            _ => NpmFix::None,
        },
        _ => NpmFix::None,
    }
}

/// Parses `bun audit --json`, which is the registry's response: package name to a list of
/// advisories.
pub fn parse_bun(text: &str) -> Result<Vec<Advisory>, String> {
    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("could not read bun audit's output: {e}"))?;
    let Some(packages) = json.as_object() else {
        return Err("bun audit's output is not an advisory report".to_string());
    };
    let mut out = Vec::new();
    for (package, advisories) in packages {
        let Some(list) = advisories.as_array() else {
            return Err("bun audit's output is not an advisory report".to_string());
        };
        for a in list {
            out.push(Advisory {
                id: advisory_id(a.get("url").and_then(Value::as_str), a.get("id")),
                title: a
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                severity: Severity::parse(a.get("severity").and_then(Value::as_str).unwrap_or("")),
                package: package.clone(),
                range: a
                    .get("vulnerable_versions")
                    .and_then(Value::as_str)
                    .unwrap_or("*")
                    .to_string(),
            });
        }
    }
    Ok(out)
}

/// Parses `bun audit fix --dry-run --json`.
pub fn parse_bun_plan(text: &str) -> Result<BunPlan, String> {
    let json: Value =
        serde_json::from_str(text).map_err(|e| format!("could not read bun's fix plan: {e}"))?;
    let name_from_to = |v: &Value| -> Option<(String, String, String)> {
        Some((
            v.get("name")?.as_str()?.to_string(),
            v.get("from")?.as_str()?.to_string(),
            v.get("to")?.as_str()?.to_string(),
        ))
    };
    let mut plan = BunPlan::default();
    for f in json
        .get("fixes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some((name, from, to)) = name_from_to(f) {
            let in_manifest = f
                .get("packageJson")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());
            plan.fixes.insert((name, from), (to, in_manifest));
        }
    }
    for b in json
        .get("blocked")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some((name, from, to)) = name_from_to(b) {
            let blockers = b
                .get("blockers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|x| {
                    let text = |k: &str, default: &str| {
                        x.get(k)
                            .and_then(Value::as_str)
                            .unwrap_or(default)
                            .to_string()
                    };
                    (text("dependent", "a dependent"), text("range", ""))
                })
                .collect();
            plan.blocked.insert((name, from), (to, blockers));
        }
    }
    Ok(plan)
}

/// Turns advisories and where they were found into findings per direct dependency.
fn assemble(
    source: Source,
    advisories: &[Advisory],
    fix: &FixInfo,
    located: &[Located],
    direct_names: &HashSet<String>,
) -> Report {
    let mut report = Report::default();
    for loc in located {
        let adv = &advisories[loc.advisory];
        let version = loc.version.to_string();
        let (upgrade_to, major, note) = fix_for(fix, &loc.package, &version, &loc.direct);
        report.vulns.push(Vuln {
            source,
            id: adv.id.clone(),
            title: adv.title.clone(),
            severity: adv.severity,
            package: loc.package.clone(),
            version,
            direct: loc.direct.clone(),
            direct_version: loc.direct_version.as_ref().map(Version::to_string),
            path: loc.path.clone(),
            fixed_in: Vec::new(),
            upgrade_to,
            upgrade_brings: None,
            upgrade_major: major,
            range: Some(adv.range.clone()),
            fix_note: note,
            cve: Vec::new(),
        });
    }

    // The version to install for a direct dependency is the highest one any of its findings
    // needs, so a single install covers all of them.
    for v in &report.vulns {
        if let Some(to) = v.upgrade_to.as_deref().and_then(|t| Version::parse(t).ok())
            && direct_names.contains(&v.direct)
        {
            let best = report
                .fixes
                .entry(v.direct.clone())
                .or_insert_with(|| to.clone());
            if to > *best {
                *best = to;
            }
        }
    }
    report.vulns.sort_by(|a, b| {
        (std::cmp::Reverse(a.severity), &a.direct, &a.id).cmp(&(
            std::cmp::Reverse(b.severity),
            &b.direct,
            &b.id,
        ))
    });
    report
}

/// For a vulnerable `package` reached through `direct`: the version of `direct` that fixes
/// it (and whether that is a breaking upgrade), or a note about what else is known.
fn fix_for(
    fix: &FixInfo,
    package: &str,
    version: &str,
    direct: &str,
) -> (Option<String>, bool, Option<String>) {
    match fix {
        FixInfo::Npm(fixes) => {
            // npm's entry for the direct dependency is the authority on what upgrading it
            // does: it covers everything the dependency inherits. The entry of the vulnerable
            // package itself only describes the best fix for *all* its dependents, so it says
            // "no fix" as soon as one of them (say, another direct dependency) can't be fixed.
            if let Some(NpmFix::Upgrade {
                name,
                version,
                major,
            }) = fixes.get(direct)
                && name == direct
            {
                return (Some(version.clone()), *major, None);
            }
            match fixes.get(package) {
                Some(NpmFix::Upgrade {
                    name,
                    version,
                    major,
                }) if name == direct => (Some(version.clone()), *major, None),
                // npm names a single package to upgrade for each vulnerable one; a different
                // direct dependency that shares it isn't fixed by upgrading itself.
                Some(NpmFix::Upgrade { name, version, .. }) => (
                    None,
                    false,
                    Some(format!(
                        "npm suggests upgrading {name} to {version}, not {direct}"
                    )),
                ),
                _ if fixes.get(direct) == Some(&NpmFix::InLockfile)
                    || fixes.get(package) == Some(&NpmFix::InLockfile) =>
                {
                    (
                        None,
                        false,
                        Some(
                            "fixable without changing package.json: run npm audit fix".to_string(),
                        ),
                    )
                }
                _ => (None, false, None),
            }
        }
        FixInfo::Bun(plan) => {
            let key = (package.to_string(), version.to_string());
            if let Some((to, in_manifest)) = plan.fixes.get(&key) {
                if package == direct && *in_manifest {
                    return (Some(to.clone()), false, None);
                }
                return (
                    None,
                    false,
                    Some(format!(
                        "bun audit fix updates {package} to {to} in bun.lock without changing package.json"
                    )),
                );
            }
            if let Some((to, blockers)) = plan.blocked.get(&key) {
                // Several dependents can block the same copy: name the one belonging to the
                // direct dependency this finding is shown under, if there is one.
                let of_direct =
                    |dependent: &str| dependent.rsplit_once('@').is_some_and(|(n, _)| n == direct);
                let blocker = blockers
                    .iter()
                    .find(|(dependent, _)| of_direct(dependent))
                    .or(blockers.first());
                let text = match blocker {
                    Some((dependent, range)) if !range.is_empty() => {
                        format!("{package} {to} has the fix, but {dependent} requires {range}")
                    }
                    Some((dependent, _)) => {
                        format!("{package} {to} has the fix, but {dependent} blocks it")
                    }
                    None => format!("{package} {to} has the fix, but a dependent blocks it"),
                };
                return (None, false, Some(text));
            }
            (None, false, None)
        }
    }
}

fn run(program: &str, args: &[&str], dir: &Path) -> Result<(String, String), String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("`{program}` was not found")
            } else {
                format!("could not run {program}: {e}")
            }
        })?;
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// The last meaningful line of a tool's stderr, for error messages.
fn last_line(stderr: &str) -> String {
    stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// Which source (and tool) audits a project of this package manager.
pub fn source_for(pm: Pm) -> Option<Source> {
    match pm {
        Pm::Npm => Some(Source::NpmAudit),
        Pm::Bun => Some(Source::BunAudit),
        Pm::Yarn | Pm::Pnpm => None,
    }
}

/// Audits the project with the package manager's own audit command. The advisory lookup goes
/// to the registry the package manager is configured for (`.npmrc` and friends), not to a
/// third party.
pub fn scan(pm: Pm, dir: &Path, root_deps: &[(String, String)]) -> Result<Report, String> {
    let Some(source) = source_for(pm) else {
        return Err(format!(
            "auditing is supported for npm and bun projects, not {}. Snyk (s) works with any package manager",
            pm.name()
        ));
    };
    let program = pm.program();

    let (advisories, fix) = match pm {
        Pm::Npm => {
            let (stdout, stderr) = run(&program, &["audit", "--json"], dir)?;
            if stdout.trim().is_empty() {
                return Err(last_line(&stderr));
            }
            let (advisories, fixes) = parse_npm(&stdout)?;
            (advisories, FixInfo::Npm(fixes))
        }
        _ => {
            let (stdout, stderr) = run(&program, &["audit", "--json"], dir)?;
            if stdout.trim().is_empty() {
                let line = last_line(&stderr);
                return Err(if line.contains("Script not found") {
                    "this Bun version has no `bun audit` command, update Bun".to_string()
                } else {
                    line
                });
            }
            let advisories = parse_bun(&stdout)?;
            // The fix plan is a bonus: without it the findings are still listed.
            let plan = if advisories.is_empty() {
                BunPlan::default()
            } else {
                run(&program, &["audit", "fix", "--dry-run", "--json"], dir)
                    .and_then(|(out, _)| parse_bun_plan(&out))
                    .unwrap_or_default()
            };
            (advisories, FixInfo::Bun(plan))
        }
    };

    let mut by_package: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    for (i, a) in advisories.iter().enumerate() {
        by_package
            .entry(a.package.clone())
            .or_default()
            .push((i, a.range.clone()));
    }
    let located = if advisories.is_empty() {
        Vec::new()
    } else {
        Analyzer::new(dir.to_path_buf(), Vec::new()).find_vulnerable(root_deps, &by_package)?
    };

    let direct_names: HashSet<String> = root_deps.iter().map(|(n, _)| n.clone()).collect();
    let mut report = assemble(source, &advisories, &fix, &located, &direct_names);

    let matched: HashSet<usize> = located.iter().map(|l| l.advisory).collect();
    let unmatched = (0..advisories.len())
        .filter(|i| !matched.contains(i))
        .count();
    if unmatched > 0 {
        report.warnings.push(format!(
            "{unmatched} advisories match no installed package, node_modules may be out of date with the lockfile"
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const NPM: &str = include_str!("../tests/fixtures/npm_audit.json");
    const NPM_ERROR: &str = include_str!("../tests/fixtures/npm_audit_error.json");
    const NPM_CLEAN: &str = include_str!("../tests/fixtures/npm_audit_clean.json");
    const BUN: &str = include_str!("../tests/fixtures/bun_audit.json");
    const BUN_PLAN: &str = include_str!("../tests/fixtures/bun_plan.json");

    #[test]
    fn parses_npm_audit_advisories_and_fixes() {
        let (advisories, fixes) = parse_npm(NPM).unwrap();
        // inherited vulnerabilities (string `via`) are not findings of their own
        assert!(
            advisories
                .iter()
                .all(|a| !a.id.is_empty() && !a.range.is_empty())
        );
        let bp = advisories
            .iter()
            .find(|a| a.id == "GHSA-qwcr-r2fm-qrc7")
            .unwrap();
        assert_eq!(
            (bp.package.as_str(), bp.severity, bp.range.as_str()),
            ("body-parser", Severity::High, "<1.20.3")
        );
        // npm's "moderate" is our medium
        assert!(advisories.iter().any(|a| a.severity == Severity::Medium));
        assert_eq!(
            fixes["body-parser"],
            NpmFix::Upgrade {
                name: "express".into(),
                version: "4.22.3".into(),
                major: false
            }
        );
        assert_eq!(fixes["serve-static"], NpmFix::InLockfile);
        assert_eq!(fixes["request"], NpmFix::None);
        // one advisory is listed once even though several packages inherit from it
        let unique: HashSet<_> = advisories.iter().map(|a| (&a.id, &a.package)).collect();
        assert_eq!(unique.len(), advisories.len());
    }

    #[test]
    fn reports_npm_audit_errors_and_clean_projects() {
        assert!(parse_npm(NPM_ERROR).unwrap_err().contains("lockfile"));
        let (a, f) = parse_npm(NPM_CLEAN).unwrap();
        assert!(a.is_empty() && f.is_empty());
        // registry failures come as a top-level message with empty error fields
        let net = r#"{"message":"request failed, reason: ECONNREFUSED","error":{"summary":"","detail":""}}"#;
        assert!(parse_npm(net).unwrap_err().contains("ECONNREFUSED"));
        assert!(parse_npm("garbage").is_err());
    }

    #[test]
    fn parses_bun_audit_and_plan() {
        let advisories = parse_bun(BUN).unwrap();
        assert!(advisories.len() > 15);
        let qs = advisories.iter().find(|a| a.package == "qs").unwrap();
        assert!(qs.id.starts_with("GHSA-"), "{}", qs.id);
        assert!(
            parse_bun("{}").unwrap().is_empty(),
            "a clean audit is an empty object"
        );
        assert!(parse_bun("[]").is_err());
        assert!(parse_bun(r#"{"a":"not a list"}"#).is_err());

        let plan = parse_bun_plan(BUN_PLAN).unwrap();
        let key = |n: &str, v: &str| (n.to_string(), v.to_string());
        assert_eq!(
            plan.fixes[&key("express", "4.17.1")],
            ("4.20.0".to_string(), true)
        );
        let (to, blockers) = &plan.blocked[&key("body-parser", "1.19.0")];
        assert_eq!(to, "1.20.9");
        assert_eq!(
            blockers,
            &[("express@4.17.1".to_string(), "1.19.0".to_string())]
        );
        // two installed copies of qs are two entries, with different blockers
        assert_eq!(plan.blocked[&key("qs", "6.5.5")].1.len(), 1);
        assert_eq!(plan.blocked[&key("qs", "6.7.0")].1.len(), 2);
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, pkg: &str, json: &str) {
        let d = dir.join(pkg);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), json).unwrap();
    }

    /// The same shape as the real project the fixtures were taken from, in miniature.
    fn mini_project(name: &str) -> (PathBuf, Vec<(String, String)>) {
        let dir = tmp(name);
        write(
            &dir,
            "node_modules/express",
            r#"{"version":"4.17.1","dependencies":{"body-parser":"1.19.0","qs":"6.7.0"}}"#,
        );
        write(
            &dir,
            "node_modules/body-parser",
            r#"{"version":"1.19.0","dependencies":{"qs":"6.7.0"}}"#,
        );
        write(&dir, "node_modules/qs", r#"{"version":"6.7.0"}"#);
        write(
            &dir,
            "node_modules/request",
            r#"{"version":"2.88.0","dependencies":{"qs":"~6.5.2"}}"#,
        );
        write(
            &dir,
            "node_modules/request/node_modules/qs",
            r#"{"version":"6.5.5"}"#,
        );
        let roots = vec![
            ("express".to_string(), "4.17.1".to_string()),
            ("request".to_string(), "2.88.0".to_string()),
        ];
        (dir, roots)
    }

    fn report_for(
        source: Source,
        advisories: &[Advisory],
        fix: FixInfo,
        dir: &Path,
        roots: &[(String, String)],
    ) -> Report {
        let mut by_package: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        for (i, a) in advisories.iter().enumerate() {
            by_package
                .entry(a.package.clone())
                .or_default()
                .push((i, a.range.clone()));
        }
        let located = Analyzer::new(dir.to_path_buf(), Vec::new())
            .find_vulnerable(roots, &by_package)
            .unwrap();
        let names = roots.iter().map(|(n, _)| n.clone()).collect();
        assemble(source, advisories, &fix, &located, &names)
    }

    fn summary(r: &Report, direct: &str, package: &str, id: &str) -> String {
        r.vulns
            .iter()
            .find(|v| v.direct == direct && v.package == package && v.id == id)
            .unwrap_or_else(|| panic!("{direct} {package} {id}"))
            .fix_summary()
    }

    #[test]
    fn npm_audit_findings_are_listed_per_direct_dependency_with_their_own_fix() {
        let (advisories, fixes) = parse_npm(NPM).unwrap();
        let (dir, roots) = mini_project("npm");
        let r = report_for(
            Source::NpmAudit,
            &advisories,
            FixInfo::Npm(fixes),
            &dir,
            &roots,
        );

        // qs 6.5.5 (request's own copy) isn't hit by the advisory that only covers 6.7.0..6.7.2
        let narrow = advisories
            .iter()
            .find(|a| a.package == "qs" && a.range == ">=6.7.0 <6.7.3")
            .unwrap();
        assert!(
            !r.vulns
                .iter()
                .any(|v| v.direct == "request" && v.id == narrow.id)
        );
        assert!(
            r.vulns
                .iter()
                .any(|v| v.direct == "express" && v.id == narrow.id)
        );

        // a transitive finding is fixed by upgrading the direct dependency npm names
        assert_eq!(
            summary(&r, "express", "body-parser", "GHSA-qwcr-r2fm-qrc7"),
            "fixed by upgrading express to 4.22.3"
        );
        // the direct dependency's own finding
        let own = r
            .vulns
            .iter()
            .find(|v| v.direct == "express" && v.package == "express")
            .unwrap();
        assert_eq!(own.fix_summary(), "fixed in express 4.22.3");
        assert!(own.path.is_empty());
        // npm has no fix for qs: no suggestion, whichever dependency brings it in
        let qs_request = r
            .vulns
            .iter()
            .find(|v| v.direct == "request" && v.package == "qs")
            .unwrap();
        assert_eq!(qs_request.fix_summary(), "no fix available");
        assert_eq!(qs_request.path, ["qs"]);
        assert_eq!(qs_request.version, "6.5.5");
        // one version to install per direct dependency
        assert_eq!(r.fixes["express"], Version::new(4, 22, 3));
        assert!(!r.fixes.contains_key("request"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bun_audit_findings_use_buns_fix_plan() {
        let advisories = parse_bun(BUN).unwrap();
        let plan = parse_bun_plan(BUN_PLAN).unwrap();
        let (dir, roots) = mini_project("bun");
        let r = report_for(
            Source::BunAudit,
            &advisories,
            FixInfo::Bun(plan),
            &dir,
            &roots,
        );

        let express_own = r
            .vulns
            .iter()
            .find(|v| v.direct == "express" && v.package == "express")
            .unwrap();
        assert_eq!(express_own.fix_summary(), "fixed in express 4.20.0");
        // blocked by the dependent's own pin: says who blocks it
        let bp = r
            .vulns
            .iter()
            .find(|v| v.direct == "express" && v.package == "body-parser")
            .unwrap();
        assert_eq!(
            bp.fix_summary(),
            "body-parser 1.20.9 has the fix, but express@4.17.1 requires 1.19.0"
        );
        assert_eq!(r.fixes["express"], Version::new(4, 20, 0));
        assert!(r.vulns.iter().all(|v| v.source == Source::BunAudit));

        // each installed copy of qs gets the blocker of that copy, not of the other one
        let qs_note = |direct: &str| {
            r.vulns
                .iter()
                .find(|v| v.direct == direct && v.package == "qs")
                .unwrap()
                .fix_summary()
        };
        assert_eq!(
            qs_note("request"),
            "qs 6.16.1 has the fix, but request@2.88.0 requires ~6.5.2"
        );
        // 6.7.0 is blocked by body-parser and by express: express is the one to name here
        assert_eq!(
            qs_note("express"),
            "qs 6.16.1 has the fix, but express@4.17.1 requires 6.7.0"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_fix_for_another_package_is_not_claimed_for_this_one() {
        let mut fixes = HashMap::new();
        fixes.insert(
            "shared".to_string(),
            NpmFix::Upgrade {
                name: "a".into(),
                version: "2.0.0".into(),
                major: true,
            },
        );
        let fix = FixInfo::Npm(fixes);
        assert_eq!(
            fix_for(&fix, "shared", "1.0.0", "a"),
            (Some("2.0.0".into()), true, None)
        );
        let (to, _, note) = fix_for(&fix, "shared", "1.0.0", "b");
        assert_eq!(to, None);
        assert!(note.unwrap().contains("upgrading a to 2.0.0, not b"));
    }

    #[test]
    fn only_npm_and_bun_projects_can_be_audited() {
        assert_eq!(source_for(Pm::Npm), Some(Source::NpmAudit));
        assert_eq!(source_for(Pm::Bun), Some(Source::BunAudit));
        let e = scan(Pm::Pnpm, Path::new("."), &[]).unwrap_err();
        assert!(e.contains("npm and bun") && e.contains("Snyk"), "{e}");
    }
}
