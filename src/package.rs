//! Reading dependencies from `package.json` and computing upgrades.

use anyhow::{Context, Result};
use semver::Version;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Prod,
    Dev,
    Optional,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Prod => "dep",
            Kind::Dev => "dev",
            Kind::Optional => "opt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dep {
    pub name: String,
    pub spec: String,
    pub kind: Kind,
}

pub struct Manifest {
    pub deps: Vec<Dep>,
    pub package_manager: Option<String>,
    /// The parsed `package.json`, for fields needing package-manager-specific handling.
    pub raw: serde_json::Value,
}

pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let mut deps = Vec::new();
    for (field, kind) in [
        ("dependencies", Kind::Prod),
        ("devDependencies", Kind::Dev),
        ("optionalDependencies", Kind::Optional),
    ] {
        if let Some(map) = json.get(field).and_then(|v| v.as_object()) {
            for (name, spec) in map {
                if let Some(spec) = spec.as_str() {
                    deps.push(Dep {
                        name: name.clone(),
                        spec: spec.into(),
                        kind,
                    });
                }
            }
        }
    }
    let package_manager = json
        .get("packageManager")
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(Manifest {
        deps,
        package_manager,
        raw: json,
    })
}

/// Names of the dependencies declared by the installed copy of `name`, found in the
/// `node_modules` of `dir` or its ancestors. `None` if it isn't installed there
/// (for example with Yarn Plug'n'Play).
pub fn installed_dependencies(dir: &Path, name: &str) -> Option<Vec<String>> {
    let path = dir
        .ancestors()
        .map(|d| d.join("node_modules").join(name).join("package.json"))
        .find(|p| p.is_file())?;
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let mut deps = Vec::new();
    for field in ["dependencies", "optionalDependencies"] {
        if let Some(map) = json.get(field).and_then(|v| v.as_object()) {
            deps.extend(map.keys().cloned());
        }
    }
    Some(deps)
}

/// Splits a simple range like `^1.2.3`, `~1.2`, `1.0.0` into (prefix, version).
/// Returns `None` for anything else (tags, URLs, workspaces, complex ranges).
pub fn parse_spec(spec: &str) -> Option<(&'static str, Version)> {
    let spec = spec.trim();
    for prefix in ["^", "~", ">=", ""] {
        if let Some(rest) = spec.strip_prefix(prefix)
            && let Some(v) = lenient_version(rest)
        {
            return Some((
                match prefix {
                    "^" => "^",
                    "~" => "~",
                    ">=" => ">=",
                    _ => "",
                },
                v,
            ));
        }
    }
    None
}

fn lenient_version(s: &str) -> Option<Version> {
    if !s.chars().next()?.is_ascii_digit() {
        return None;
    }
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }
    // "1" or "1.2" -> pad with zeros; reject anything with x/*/spaces/etc.
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let mut parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 && parts.iter().all(|p| !p.is_empty()) {
            while parts.len() < 3 {
                parts.push("0");
            }
            return Version::parse(&parts.join(".")).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_installed_dependencies() {
        let dir = std::env::temp_dir().join(format!("depsu-test-{}", std::process::id()));
        let pkg = dir.join("node_modules/@s/pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"dependencies":{"a":"1"},"optionalDependencies":{"b":"1"},"devDependencies":{"c":"1"}}"#,
        )
        .unwrap();
        let sub = dir.join("packages/app");
        std::fs::create_dir_all(&sub).unwrap();
        // found via an ancestor node_modules (monorepo hoisting)
        let mut deps = installed_dependencies(&sub, "@s/pkg").unwrap();
        deps.sort();
        assert_eq!(deps, ["a", "b"]);
        assert_eq!(installed_dependencies(&sub, "missing"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn specs() {
        assert_eq!(parse_spec("^1.2.3"), Some(("^", Version::new(1, 2, 3))));
        assert_eq!(parse_spec("~1.2"), Some(("~", Version::new(1, 2, 0))));
        assert_eq!(parse_spec("2"), Some(("", Version::new(2, 0, 0))));
        assert_eq!(parse_spec(">=1.0.0"), Some((">=", Version::new(1, 0, 0))));
        for bad in [
            "latest",
            "workspace:*",
            "1.x",
            "*",
            "^1 || ^2",
            "npm:foo@1",
            "github:a/b",
            "file:../x",
        ] {
            assert_eq!(parse_spec(bad), None, "{bad}");
        }
    }
}
