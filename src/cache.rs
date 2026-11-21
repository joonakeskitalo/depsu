//! Latest versions and vulnerability findings, kept in memory and optionally in a JSON file
//! (`--cache`) so the next start doesn't have to ask the registry, Snyk or the audit tool
//! again. Findings are stored per project and per package version: what a package brings in
//! depends on the project's lockfile and overrides, so the same version can be clean in one
//! project and vulnerable in another. Latest versions are shared by all projects.
use crate::vuln::Vuln;
use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

// 4: findings are filed under the version the scanner looked at (lockfile), never the
// `package.json` version. Older files may hold findings under the wrong version.
const FORMAT: u32 = 4;

#[derive(Default, Serialize, Deserialize)]
pub struct Cache {
    #[serde(default)]
    pub format: u32,
    /// Latest version of each package, by name.
    #[serde(default)]
    pub latest: BTreeMap<String, String>,
    /// Scan results of each project, by the project's directory.
    #[serde(default)]
    pub projects: BTreeMap<String, Scans>,
}

/// The scan results of one project: scanner label (`snyk`, `npm audit`, `bun audit`) →
/// package → installed version → findings.
#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scans(BTreeMap<String, BTreeMap<String, BTreeMap<String, Findings>>>);

/// What a scanner found for one version of one of the project's packages. An entry with no
/// vulnerabilities means the version was scanned and found clean.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Findings {
    /// Vulnerabilities in the package or anything it brings in.
    #[serde(default)]
    pub vulns: Vec<Vuln>,
    /// The version the scanner suggests upgrading to.
    #[serde(default)]
    pub fix: Option<Version>,
}

impl Cache {
    /// Reads the cache. A file that doesn't exist yet, or one written by another version of
    /// depsu, is an empty cache.
    pub fn load(path: &Path) -> Result<Cache> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Cache::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let bad = || format!("parsing {} (delete it to start over)", path.display());
        let value: serde_json::Value = serde_json::from_str(&text).with_context(bad)?;
        if value.get("format").and_then(|f| f.as_u64()) != Some(FORMAT as u64) {
            return Ok(Cache::default());
        }
        serde_json::from_value(value).with_context(bad)
    }

    /// Writes the cache through a temporary file, so an interrupted write can't corrupt it.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.format = FORMAT;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, text + "\n").with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// The scan results of the project in `project`.
    pub fn scans(&self, project: &str) -> Option<&Scans> {
        self.projects.get(project)
    }

    pub fn scans_mut(&mut self, project: &str) -> &mut Scans {
        self.projects.entry(project.to_string()).or_default()
    }
}

impl Scans {
    /// The findings of `scanner` for `package` at `version`, if that version was scanned.
    pub fn findings(&self, scanner: &str, package: &str, version: &str) -> Option<&Findings> {
        self.0.get(scanner)?.get(package)?.get(version)
    }

    pub fn set_findings(&mut self, scanner: &str, package: &str, version: &str, f: Findings) {
        self.0
            .entry(scanner.to_string())
            .or_default()
            .entry(package.to_string())
            .or_default()
            .insert(version.to_string(), f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::{Severity, Source};

    fn vuln(id: &str) -> Vuln {
        Vuln {
            source: Source::Snyk,
            id: id.into(),
            title: "Bad".into(),
            severity: Severity::High,
            package: "lodash".into(),
            version: "4.17.15".into(),
            direct: "lodash".into(),
            direct_version: Some("4.17.15".into()),
            path: Vec::new(),
            fixed_in: vec!["4.17.21".into()],
            upgrade_to: Some("4.17.21".into()),
            upgrade_brings: None,
            upgrade_major: false,
            range: None,
            fix_note: None,
            cve: vec!["CVE-1".into()],
        }
    }

    #[test]
    fn round_trips_through_a_file_keeping_versions_apart() {
        let dir = std::env::temp_dir().join(format!("depsu-cache-{}", std::process::id()));
        let path = dir.join("nested").join("cache.json");
        let mut cache = Cache::default();
        cache.latest.insert("lodash".into(), "4.17.21".into());
        cache.scans_mut("/p/a").set_findings(
            "snyk",
            "lodash",
            "4.17.15",
            Findings {
                vulns: vec![vuln("SNYK-1")],
                fix: Some(Version::new(4, 17, 21)),
            },
        );
        cache.scans_mut("/p/a").set_findings("snyk", "lodash", "4.17.21", Findings::default());
        // Another project with the same version of the package, where it isn't clean.
        cache.scans_mut("/p/b").set_findings(
            "snyk",
            "lodash",
            "4.17.21",
            Findings {
                vulns: vec![vuln("SNYK-B")],
                fix: None,
            },
        );
        cache.save(&path).unwrap();
        let back = Cache::load(&path).unwrap();
        assert_eq!(back.latest["lodash"], "4.17.21");
        let a = back.scans("/p/a").unwrap();
        let old = a.findings("snyk", "lodash", "4.17.15").unwrap();
        assert_eq!(old.vulns[0].id, "SNYK-1");
        assert_eq!(old.vulns[0].severity, Severity::High);
        assert_eq!(old.fix, Some(Version::new(4, 17, 21)));
        let new = a.findings("snyk", "lodash", "4.17.21").unwrap();
        assert!(new.vulns.is_empty(), "scanned and clean in project a");
        assert!(a.findings("snyk", "lodash", "4.17.20").is_none(), "never scanned");
        assert!(a.findings("npm audit", "lodash", "4.17.15").is_none());
        let b = back.scans("/p/b").unwrap();
        assert_eq!(b.findings("snyk", "lodash", "4.17.21").unwrap().vulns[0].id, "SNYK-B");
        assert!(back.scans("/p/c").is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_file_is_an_empty_cache() {
        let path = std::env::temp_dir().join("depsu-no-such-cache.json");
        assert!(Cache::load(&path).unwrap().latest.is_empty());
    }

    #[test]
    fn a_file_of_an_older_format_is_ignored() {
        let path = std::env::temp_dir().join(format!("depsu-old-cache-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"format":2,"latest":{"a":"1.0.0"},"scans":{"snyk":{}}}"#).unwrap();
        let c = Cache::load(&path).unwrap();
        assert!(c.latest.is_empty() && c.projects.is_empty());
        std::fs::remove_file(path).unwrap();
    }
}
