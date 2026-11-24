//! Types shared by the vulnerability scanners (Snyk, `npm audit`, `bun audit`).
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parses the severity names of Snyk and of npm (`moderate`); unknown ones count as low.
    pub fn parse(s: &str) -> Self {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
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

/// Where a finding comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    Snyk,
    NpmAudit,
    BunAudit,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Snyk => "snyk",
            Source::NpmAudit => "npm audit",
            Source::BunAudit => "bun audit",
        }
    }

    pub fn is_audit(self) -> bool {
        self != Source::Snyk
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vuln {
    pub source: Source,
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// The vulnerable package and its installed version.
    pub package: String,
    pub version: String,
    /// The project's direct dependency that brings it in (equal to `package` for direct ones).
    pub direct: String,
    /// The version of `direct` the scanner looked at, when it says so. Snyk reads it from the
    /// lockfile, which can differ from `package.json` and from `node_modules`.
    #[serde(default)]
    pub direct_version: Option<String>,
    /// Packages below the direct dependency down to the vulnerable one (empty if it is the
    /// direct dependency itself).
    pub path: Vec<String>,
    /// Versions of the vulnerable package that fix it, across all its release lines.
    pub fixed_in: Vec<String>,
    /// The version of the direct dependency that fixes this finding, if upgrading it does.
    pub upgrade_to: Option<String>,
    /// For a transitive finding: the version of the vulnerable package that upgrade brings in.
    pub upgrade_brings: Option<String>,
    /// The upgrade is a breaking (semver-major) one.
    pub upgrade_major: bool,
    /// Versions of the vulnerable package that are affected, as a range (audit tools).
    pub range: Option<String>,
    /// What the tool says about fixing it when that isn't an upgrade of the direct dependency.
    pub fix_note: Option<String>,
    pub cve: Vec<String>,
}

impl Vuln {
    /// Releases of the vulnerable package that fix this finding and are newer than the
    /// installed one. Snyk lists the fixed version of every older release line too, which is
    /// of no use here.
    pub fn newer_fixes(&self) -> Vec<&str> {
        let installed = Version::parse(&self.version).ok();
        let mut fixes: Vec<(Option<Version>, &str)> = self
            .fixed_in
            .iter()
            .map(|f| (Version::parse(f).ok(), f.as_str()))
            .filter(|(v, _)| match (v, &installed) {
                (Some(v), Some(i)) => v > i,
                _ => true, // can't compare: keep it rather than hide a fix
            })
            .collect();
        fixes.sort_by(|a, b| a.0.cmp(&b.0));
        fixes.into_iter().map(|(_, s)| s).collect()
    }

    /// What to do about this finding, from the point of view of the direct dependency.
    pub fn fix_summary(&self) -> String {
        if let Some(to) = &self.upgrade_to {
            let major = if self.upgrade_major {
                " (breaking)"
            } else {
                ""
            };
            return if self.path.is_empty() {
                format!("fixed in {} {to}{major}", self.direct)
            } else {
                let brings = self
                    .upgrade_brings
                    .as_ref()
                    .map(|n| format!(" (brings {} {n})", self.package))
                    .unwrap_or_default();
                format!("fixed by upgrading {} to {to}{major}{brings}", self.direct)
            };
        }
        if let Some(note) = &self.fix_note {
            return note.clone();
        }
        let fixes = self.newer_fixes();
        if fixes.is_empty() {
            return "no fix available".to_string();
        }
        let shown: Vec<&str> = fixes.iter().take(3).copied().collect();
        let more = if fixes.len() > 3 { " …" } else { "" };
        let who = if self.path.is_empty() {
            self.package.clone()
        } else {
            format!("{} (in {})", self.package, self.direct)
        };
        format!(
            "{} {}{more} has the fix, but upgrading {} doesn't bring it in",
            who,
            shown.join(" / "),
            self.direct
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub vulns: Vec<Vuln>,
    /// The version Snyk suggests for each direct dependency to fix what can be fixed.
    pub fixes: HashMap<String, Version>,
    /// Problems with some projects of a multi-project scan that didn't stop the others.
    pub warnings: Vec<String>,
    /// Findings Snyk left out because the project's `.snyk` ignores them.
    #[serde(default)]
    pub ignored: Vec<Vuln>,
}
