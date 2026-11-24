//! Snyk integration: runs `snyk test --json` and turns the result into per-dependency
//! vulnerabilities and the upgrade versions Snyk suggests.

use crate::security::vuln::{Report, Severity, Source, Vuln};
use semver::Version;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Splits `name@version`, where the name may itself start with `@scope/`.
fn split_pkg(s: &str) -> Option<(&str, &str)> {
    let i = s.get(1..)?.rfind('@')? + 1;
    Some((&s[..i], &s[i + 1..]))
}

/// Like `strings`, but entries that aren't strings (Snyk puts `false` first) are skipped
/// instead of shifting the positions of the others.
fn strings_or_false(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
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

/// One finding of Snyk's output. Needs the project's first hop in `from` to name the direct
/// dependency.
fn to_vuln(v: &Value) -> Option<Vuln> {
    let from = strings(v.get("from"));
    let (Some(first_hop), Some(id)) = (from.get(1), v.get("id").and_then(Value::as_str))
    else {
        return None;
    };
    let Some((direct, direct_version)) = split_pkg(first_hop) else {
        return None;
    };
    let package = v
        .get("packageName")
        .and_then(Value::as_str)
        .unwrap_or(direct);
    let version = v.get("version").and_then(Value::as_str).unwrap_or("");
    // `upgradePath` is `[false, "direct@fixed", .., "vulnerable@fixed"]` when upgrading
    // the direct dependency fixes it, and empty or `[false]` when nothing does.
    let up = strings_or_false(v.get("upgradePath"));
    let upgrade_to = up
        .get(1)
        .and_then(|s| split_pkg(s))
        .map(|(_, v)| v.to_string());
    let upgrade_brings = (up.len() > 2)
        .then(|| {
            up.last()
                .and_then(|s| split_pkg(s))
                .map(|(_, v)| v.to_string())
        })
        .flatten();
    let severity = v
        .get("severityWithCritical")
        .or_else(|| v.get("severity"))
        .and_then(Value::as_str)
        .map(Severity::parse)
        .unwrap_or(Severity::Low);
    Some(Vuln {
        source: Source::Snyk,
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
        direct_version: (!direct_version.is_empty()).then(|| direct_version.to_string()),
        path: from[2..]
            .iter()
            .map(|s| split_pkg(s).map_or(s.as_str(), |(n, _)| n).to_string())
            .collect(),
        fixed_in: strings(v.get("fixedIn")),
        upgrade_to,
        upgrade_brings,
        upgrade_major: false,
        range: None,
        fix_note: None,
        cve: strings(v.get("identifiers").and_then(|i| i.get("CVE"))),
    })
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
            let Some(vuln) = to_vuln(v) else { continue };
            if seen.insert((
                vuln.id.clone(),
                vuln.package.clone(),
                vuln.version.clone(),
                vuln.direct.clone(),
            )) {
                report.vulns.push(vuln);
            }
        }
        // Findings the `.snyk` file ignores are not in `vulnerabilities`, only here.
        let ignored = doc
            .get("filtered")
            .and_then(|f| f.get("ignore"))
            .and_then(Value::as_array);
        for v in ignored.into_iter().flatten() {
            let Some(vuln) = to_vuln(v) else { continue };
            if !report
                .ignored
                .iter()
                .any(|o| (&o.id, &o.package, &o.version, &o.direct, &o.path) == (&vuln.id, &vuln.package, &vuln.version, &vuln.direct, &vuln.path))
            {
                report.ignored.push(vuln);
            }
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

    const DIRECT: &str = include_str!("../../tests/fixtures/snyk_direct.json");
    const TRANSITIVE: &str = include_str!("../../tests/fixtures/snyk_transitive.json");
    const ERROR: &str = include_str!("../../tests/fixtures/snyk_error.json");
    const CLEAN: &str = include_str!("../../tests/fixtures/snyk_clean.json");

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
        assert_eq!(v.upgrade_to.as_deref(), Some("4.17.21"));
        assert_eq!(v.fix_summary(), "fixed in lodash 4.17.21");
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
        assert_eq!(old.fix_summary(), "no fix available");
        assert!(!r.fixes.contains_key("@scope/old"));
    }

    const TRANSITIVE_REAL: &str = include_str!("../../tests/fixtures/snyk_transitive_real.json");

    fn summary(r: &Report, direct: &str, id: &str) -> String {
        r.vulns
            .iter()
            .find(|v| v.direct == direct && v.id == id)
            .unwrap_or_else(|| panic!("{direct} {id}"))
            .fix_summary()
    }

    #[test]
    fn the_same_issue_gets_a_fix_text_specific_to_each_direct_dependency() {
        let r = parse(TRANSITIVE_REAL).unwrap();
        // qs 6.x is a dependency of both express and request. Upgrading express brings the
        // fixed qs in, upgrading request doesn't. The text must say so, and name the package.
        let via_express = summary(&r, "express", "SNYK-JS-QS-14724253");
        let via_request = summary(&r, "request", "SNYK-JS-QS-14724253");
        assert_ne!(via_express, via_request);
        assert!(
            via_express.starts_with("fixed by upgrading express to "),
            "{via_express}"
        );
        assert!(via_express.contains("(brings qs "), "{via_express}");
        assert_eq!(
            via_request,
            "qs (in request) 6.14.1 has the fix, but upgrading request doesn't bring it in"
        );
    }

    #[test]
    fn different_findings_of_one_package_give_different_upgrade_targets() {
        let r = parse(TRANSITIVE_REAL).unwrap();
        // Each finding needs a different minimum express version.
        let targets: std::collections::HashSet<_> = r
            .vulns
            .iter()
            .filter(|v| v.direct == "express")
            .filter_map(|v| v.upgrade_to.clone())
            .collect();
        assert!(targets.len() > 1, "{targets:?}");
        // the overall suggestion covers all of them
        let best = targets
            .iter()
            .filter_map(|t| Version::parse(t).ok())
            .max()
            .unwrap();
        assert_eq!(r.fixes["express"], best);
    }

    #[test]
    fn only_lists_fixes_newer_than_the_installed_version() {
        let r = parse(TRANSITIVE_REAL).unwrap();
        // qs 6.7.0 is installed: Snyk also lists 6.2.4 ... 6.6.1 for older release lines
        let v = r
            .vulns
            .iter()
            .find(|v| v.id == "SNYK-JS-QS-3153490" && v.direct == "express")
            .unwrap();
        assert!(v.fixed_in.len() > 5);
        let newer = v.newer_fixes();
        assert_eq!(newer.first(), Some(&"6.7.3"));
        assert!(
            !newer.contains(&"6.2.4") && !newer.contains(&"6.6.1"),
            "{newer:?}"
        );
        // and without any fix there is nothing to say
        let none = r
            .vulns
            .iter()
            .find(|v| v.id == "SNYK-JS-REQUEST-3361831")
            .unwrap();
        assert_eq!(none.fix_summary(), "no fix available");
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

    #[test]
    fn findings_ignored_by_the_policy_are_listed_apart() {
        let json = r#"{"vulnerabilities":[],"filtered":{"ignore":[
            {"id":"SNYK-1","title":"T","packageName":"c","version":"3.0.0","from":["proj@1.0.0","a@1.0.0","b@2.0.0","c@3.0.0"]},
            {"id":"SNYK-1","title":"T","packageName":"c","version":"3.0.0","from":["proj@1.0.0","a@1.0.0","b@2.0.0","c@3.0.0"]},
            {"id":"SNYK-2","from":["proj@1.0.0","@s/x@1.0.0"]}],"patch":[]}}"#;
        let r = parse(json).unwrap();
        assert!(r.vulns.is_empty());
        assert_eq!(r.ignored.len(), 2);
        assert_eq!(r.ignored[0].id, "SNYK-1");
        assert_eq!(r.ignored[0].title, "T");
        assert_eq!(crate::security::policy::path_of(&r.ignored[0]), "a > b > c");
        assert_eq!(crate::security::policy::path_of(&r.ignored[1]), "@s/x");
    }
}
