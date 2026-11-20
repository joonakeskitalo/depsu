//! Snyk integration: runs `snyk test --json` and turns the result into per-dependency
//! vulnerabilities and the upgrade versions Snyk suggests.

use semver::Version;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn parse(s: &str) -> Self {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Vuln {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// The vulnerable package and its installed version.
    pub package: String,
    pub version: String,
    /// The project's direct dependency that brings it in (equal to `package` for direct ones).
    pub direct: String,
    /// Packages below the direct dependency down to the vulnerable one (empty if it is the
    /// direct dependency itself).
    pub path: Vec<String>,
    /// Versions of the vulnerable package that fix it.
    pub fixed_in: Vec<String>,
    /// Whether upgrading the direct dependency fixes it.
    pub fixable: bool,
    pub cve: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub vulns: Vec<Vuln>,
    /// The version Snyk suggests for each direct dependency to fix what can be fixed.
    pub fixes: HashMap<String, Version>,
    /// Problems with some projects of a multi-project scan that didn't stop the others.
    pub warnings: Vec<String>,
}

/// Splits `name@version`, where the name may itself start with `@scope/`.
fn split_pkg(s: &str) -> Option<(&str, &str)> {
    let i = s.get(1..)?.rfind('@')? + 1;
    Some((&s[..i], &s[i + 1..]))
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Parses the JSON printed by `snyk test --json`: one object, or an array of them when several
/// projects were tested.
pub fn parse(text: &str) -> Result<Report, String> {
    let json: Value =
        serde_json::from_str(text).map_err(|e| format!("could not read Snyk's output: {e}"))?;
    let docs: Vec<&Value> = match &json {
        Value::Array(a) => a.iter().collect(),
        one => vec![one],
    };

    let mut report = Report::default();
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    let mut parsed_any = false;
    for doc in docs {
        let Some(vulns) = doc.get("vulnerabilities").and_then(Value::as_array) else {
            if let Some(e) = doc.get("error").and_then(Value::as_str) {
                errors.push(e.to_string());
            }
            continue;
        };
        parsed_any = true;
        for v in vulns {
            let from = strings(v.get("from"));
            let (Some(first_hop), Some(id)) = (from.get(1), v.get("id").and_then(Value::as_str))
            else {
                continue;
            };
            let Some((direct, _)) = split_pkg(first_hop) else {
                continue;
            };
            let package = v
                .get("packageName")
                .and_then(Value::as_str)
                .unwrap_or(direct);
            let version = v.get("version").and_then(Value::as_str).unwrap_or("");
            if !seen.insert((
                id.to_string(),
                package.to_string(),
                version.to_string(),
                direct.to_string(),
            )) {
                continue;
            }
            let severity = v
                .get("severityWithCritical")
                .or_else(|| v.get("severity"))
                .and_then(Value::as_str)
                .map(Severity::parse)
                .unwrap_or(Severity::Low);
            report.vulns.push(Vuln {
                id: id.to_string(),
                title: v
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                severity,
                package: package.to_string(),
                version: version.to_string(),
                direct: direct.to_string(),
                path: from[2..]
                    .iter()
                    .map(|s| split_pkg(s).map_or(s.as_str(), |(n, _)| n).to_string())
                    .collect(),
                fixed_in: strings(v.get("fixedIn")),
                fixable: v
                    .get("isUpgradable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                cve: strings(v.get("identifiers").and_then(|i| i.get("CVE"))),
            });
        }

        // `remediation.upgrade`: "name@installed" -> { upgradeTo: "name@suggested", .. }
        if let Some(upgrades) = doc
            .get("remediation")
            .and_then(|r| r.get("upgrade"))
            .and_then(Value::as_object)
        {
            for (from, to) in upgrades {
                let (Some((name, _)), Some(target)) = (
                    split_pkg(from),
                    to.get("upgradeTo")
                        .and_then(Value::as_str)
                        .and_then(split_pkg),
                ) else {
                    continue;
                };
                if let Ok(v) = Version::parse(target.1) {
                    let best = report
                        .fixes
                        .entry(name.to_string())
                        .or_insert_with(|| v.clone());
                    if v > *best {
                        *best = v;
                    }
                }
            }
        }
    }

    if !parsed_any {
        return Err(if errors.is_empty() {
            "Snyk's output contained no results".to_string()
        } else {
            errors.join("; ")
        });
    }
    report.warnings = errors;
    // Worst first, then by package, so the most urgent issue of a package is listed first.
    report.vulns.sort_by(|a, b| {
        (std::cmp::Reverse(a.severity), &a.direct, &a.id).cmp(&(
            std::cmp::Reverse(b.severity),
            &b.direct,
            &b.id,
        ))
    });
    Ok(report)
}

/// Runs `snyk test` in `dir`. This sends the project's dependency list to Snyk and counts as
/// a test against the organisation's quota. Development dependencies are included, since they
/// are listed as well.
pub fn scan(dir: &Path) -> Result<Report, String> {
    let program = if cfg!(windows) { "snyk.cmd" } else { "snyk" };
    let out = Command::new(program)
        .args(["test", "--json", "--dev"])
        .current_dir(dir)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "the snyk CLI was not found. Install it with `npm i -g snyk` and run `snyk auth`"
                    .to_string()
            } else {
                format!("could not run snyk: {e}")
            }
        })?;
    // Exit code 1 means "vulnerabilities found" and still prints a normal report.
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "snyk exited with {}: {}",
            out.status,
            stderr.trim().lines().last().unwrap_or("no output")
        ));
    }
    parse(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIRECT: &str = include_str!("../tests/fixtures/snyk_direct.json");
    const TRANSITIVE: &str = include_str!("../tests/fixtures/snyk_transitive.json");
    const ERROR: &str = include_str!("../tests/fixtures/snyk_error.json");
    const CLEAN: &str = include_str!("../tests/fixtures/snyk_clean.json");

    #[test]
    fn splits_scoped_names() {
        assert_eq!(split_pkg("lodash@4.17.15"), Some(("lodash", "4.17.15")));
        assert_eq!(split_pkg("@scope/pkg@1.0.0"), Some(("@scope/pkg", "1.0.0")));
        assert_eq!(split_pkg("@scope/pkg"), None);
    }

    #[test]
    fn parses_real_output_for_direct_dependencies() {
        let r = parse(DIRECT).unwrap();
        assert_eq!(r.vulns.len(), 10);
        assert!(
            r.vulns
                .iter()
                .all(|v| v.path.is_empty() && v.direct == v.package)
        );
        // Snyk's suggestion covers every issue of the package, so it can be newer than the
        // version that fixes the first one (4.17.21).
        assert_eq!(r.fixes["lodash"], Version::new(4, 18, 1));
        assert_eq!(r.fixes["minimist"], Version::new(1, 2, 6));
        // worst first
        assert_eq!(r.vulns[0].severity, Severity::High);
        assert_eq!(r.vulns.last().unwrap().severity, Severity::Low);
        let v = r
            .vulns
            .iter()
            .find(|v| v.id == "SNYK-JS-LODASH-1040724")
            .unwrap();
        assert_eq!(
            (v.package.as_str(), v.version.as_str()),
            ("lodash", "4.17.15")
        );
        assert_eq!(v.cve, ["CVE-2021-23337"]);
        assert!(v.fixable);
    }

    #[test]
    fn maps_transitive_issues_to_the_direct_dependency_that_brings_them_in() {
        let r = parse(TRANSITIVE).unwrap();
        let by_direct = |d: &str| r.vulns.iter().filter(|v| v.direct == d).count();
        // the same issue reached through two direct dependencies is listed for both
        assert_eq!((by_direct("mid"), by_direct("other")), (1, 1));
        let v = r.vulns.iter().find(|v| v.direct == "mid").unwrap();
        assert_eq!(v.package, "tar");
        assert_eq!(v.path, ["tar"]);
        assert_eq!(v.severity, Severity::Critical, "severityWithCritical wins");
        assert_eq!(r.fixes["mid"], Version::new(1, 2, 0));
        assert_eq!(r.fixes["other"], Version::new(2, 1, 0));
        // unfixable issue in a scoped direct dependency: no suggestion
        let old = r.vulns.iter().find(|v| v.direct == "@scope/old").unwrap();
        assert!(!old.fixable);
        assert!(!r.fixes.contains_key("@scope/old"));
    }

    #[test]
    fn reports_snyk_errors_and_clean_projects() {
        assert!(parse(ERROR).unwrap_err().contains("snyk auth"));
        let clean = parse(CLEAN).unwrap();
        assert!(clean.vulns.is_empty() && clean.fixes.is_empty());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn handles_multi_project_output() {
        let both = format!("[{CLEAN},{ERROR},{TRANSITIVE}]");
        let r = parse(&both).unwrap();
        assert_eq!(r.vulns.len(), 3);
        // a failing project doesn't hide the others, but is reported
        assert_eq!(r.warnings.len(), 1);
    }
}
