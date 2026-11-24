//! The `.snyk` policy file: reads and edits its `ignore` entries.
//!
//! ```yaml
//! version: v1.25.0
//! ignore:
//!   SNYK-JS-LODASH-1040724:
//!     - '*':
//!         reason: not reachable
//!         expires: 2025-08-01T00:00:00.000Z
//!         created: 2025-07-02T12:00:00.000Z
//! ```
//!
//! Everything else in the file (`patch`, `exclude`, ..) is kept as it is. Comments are not:
//! the YAML is read into a value and written back, so [`add`] and [`remove`] report when the
//! file had any.
use crate::security::vuln::Vuln;
use serde_yaml_ng::{Mapping, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Policy version written to a new file.
const VERSION: &str = "v1.25.0";

/// One ignore rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ignore {
    pub id: String,
    /// `*` for every path, or `a > b > c`, the chain from the direct dependency down to the
    /// vulnerable package.
    pub path: String,
    pub reason: String,
    /// ISO timestamp, e.g. `2025-08-01T00:00:00.000Z`. Without one the rule never expires.
    pub expires: Option<String>,
    pub created: Option<String>,
}

impl Ignore {
    /// Whether the rule has run out on `today` (`YYYY-MM-DD`).
    pub fn expired(&self, today: &str) -> bool {
        self.expires
            .as_deref()
            .is_some_and(|e| e.get(..10).is_some_and(|d| d <= today))
    }

    /// Whether the rule covers `v`.
    pub fn covers(&self, v: &Vuln) -> bool {
        self.id == v.id && (self.path == "*" || self.path == path_of(v))
    }
}

/// The path of a finding in a policy: the direct dependency, then the packages below it.
pub fn path_of(v: &Vuln) -> String {
    let mut parts = vec![v.direct.as_str()];
    parts.extend(v.path.iter().map(String::as_str));
    parts.join(" > ")
}

pub fn file(dir: &Path) -> PathBuf {
    dir.join(".snyk")
}

fn read_doc(dir: &Path) -> Result<(Mapping, bool), String> {
    let path = file(dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Mapping::new(), false)),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let comments = text.lines().any(|l| l.trim_start().starts_with('#'));
    if text.trim().is_empty() {
        return Ok((Mapping::new(), comments));
    }
    match serde_yaml_ng::from_str::<Value>(&text) {
        Ok(Value::Mapping(m)) => Ok((m, comments)),
        Ok(Value::Null) => Ok((Mapping::new(), comments)),
        Ok(_) => Err(format!("{} is not a YAML mapping", path.display())),
        Err(e) => Err(format!("could not parse {}: {e}", path.display())),
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn rules(map: &Mapping) -> Vec<Ignore> {
    let mut out = Vec::new();
    let Some(Value::Mapping(ignore)) = map.get("ignore") else {
        return out;
    };
    for (id, entries) in ignore {
        let (Some(id), Value::Sequence(entries)) = (text(id), entries) else {
            continue;
        };
        for entry in entries {
            let Value::Mapping(entry) = entry else {
                continue;
            };
            for (path, body) in entry {
                let Some(path) = text(path) else { continue };
                let field = |k: &str| body.get(k).and_then(text);
                out.push(Ignore {
                    id: id.clone(),
                    path,
                    reason: field("reason").unwrap_or_default(),
                    expires: field("expires"),
                    created: field("created"),
                });
            }
        }
    }
    out
}

/// The ignore rules in `dir/.snyk`. A missing file has none.
pub fn load(dir: &Path) -> Result<Vec<Ignore>, String> {
    read_doc(dir).map(|(m, _)| rules(&m))
}

fn build(rules: &[Ignore]) -> Value {
    let mut ignore = Mapping::new();
    for r in rules {
        let mut body = Mapping::new();
        body.insert("reason".into(), r.reason.clone().into());
        if let Some(e) = &r.expires {
            body.insert("expires".into(), e.clone().into());
        }
        if let Some(c) = &r.created {
            body.insert("created".into(), c.clone().into());
        }
        let mut entry = Mapping::new();
        entry.insert(r.path.clone().into(), Value::Mapping(body));
        match ignore.get_mut(r.id.as_str()) {
            Some(Value::Sequence(s)) => s.push(Value::Mapping(entry)),
            _ => {
                ignore.insert(r.id.clone().into(), Value::Sequence(vec![Value::Mapping(entry)]));
            }
        }
    }
    Value::Mapping(ignore)
}

/// Writes `rules` as the `ignore` section, keeping the other keys. Returns whether the file
/// had comments, which the rewrite drops.
fn save(dir: &Path, mut map: Mapping, rules: &[Ignore], comments: bool) -> Result<bool, String> {
    if !map.contains_key("version") {
        map.insert("version".into(), VERSION.into());
    }
    if rules.is_empty() {
        map.remove("ignore");
    } else {
        map.insert("ignore".into(), build(rules));
    }
    let out = serde_yaml_ng::to_string(&Value::Mapping(map)).map_err(|e| e.to_string())?;
    let path = file(dir);
    std::fs::write(&path, out).map_err(|e| format!("could not write {}: {e}", path.display()))?;
    Ok(comments)
}

/// Adds an ignore for `id` on `path`, replacing the one already there. `expires` is a date
/// `YYYY-MM-DD` and the rule ends at the start of that day. Returns whether comments in the
/// file were lost.
pub fn add(
    dir: &Path,
    id: &str,
    path: &str,
    reason: &str,
    expires: Option<&str>,
) -> Result<bool, String> {
    let (map, comments) = read_doc(dir)?;
    let mut all = rules(&map);
    all.retain(|r| !(r.id == id && r.path == path));
    all.push(Ignore {
        id: id.to_string(),
        path: path.to_string(),
        reason: reason.trim().to_string(),
        expires: expires.map(|d| format!("{d}T00:00:00.000Z")),
        created: Some(now_iso()),
    });
    save(dir, map, &all, comments)
}

/// Removes the ignore for `id` on `path`. Returns whether comments in the file were lost.
pub fn remove(dir: &Path, id: &str, path: &str) -> Result<bool, String> {
    let (map, comments) = read_doc(dir)?;
    let mut all = rules(&map);
    let before = all.len();
    all.retain(|r| !(r.id == id && r.path == path));
    if all.len() == before {
        return Err(format!("{id} is not ignored on {path}"));
    }
    save(dir, map, &all, comments)
}

// ---- dates (no time crate: days since 1970 <-> civil date) --------------------------------

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_from(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn date(days: i64) -> String {
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Today's date (UTC) as `YYYY-MM-DD`.
pub fn today() -> String {
    date(secs().div_euclid(86_400))
}

/// The date `n` days from today.
pub fn in_days(n: i64) -> String {
    date(secs().div_euclid(86_400) + n)
}

fn now_iso() -> String {
    let s = secs();
    let r = s.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}.000Z",
        date(s.div_euclid(86_400)),
        r / 3600,
        r % 3600 / 60,
        r % 60
    )
}

/// Checks a typed expiry: empty means none, otherwise a real date after `today`.
pub fn parse_expiry(input: &str, today: &str) -> Result<Option<String>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let bad = || format!("`{s}` is not a date like 2025-08-01");
    let parts: Vec<&str> = s.split('-').collect();
    let [y, m, d] = parts[..] else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (Ok(y), Ok(m), Ok(d)) = (y.parse::<i64>(), m.parse::<u32>(), d.parse::<u32>()) else {
        return Err(bad());
    };
    // A date that doesn't exist (02-30) doesn't survive the round trip.
    let norm = date(days_from(y, m, d));
    if !(1..=12).contains(&m) || norm != s {
        return Err(bad());
    }
    if norm.as_str() <= today {
        return Err("the expiry must be after today".to_string());
    }
    Ok(Some(norm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::vuln::{Severity, Source};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn vuln(id: &str, direct: &str, path: &[&str]) -> Vuln {
        Vuln {
            source: Source::Snyk,
            id: id.into(),
            title: String::new(),
            severity: Severity::High,
            package: path.last().copied().unwrap_or(direct).into(),
            version: "1.0.0".into(),
            direct: direct.into(),
            direct_version: None,
            path: path.iter().map(|s| s.to_string()).collect(),
            fixed_in: vec![],
            upgrade_to: None,
            upgrade_brings: None,
            upgrade_major: false,
            range: None,
            fix_note: None,
            cve: vec![],
        }
    }

    #[test]
    fn a_missing_file_has_no_rules() {
        let d = tmp("missing");
        assert_eq!(load(&d).unwrap(), vec![]);
    }

    #[test]
    fn add_creates_the_file_and_load_reads_it_back() {
        let d = tmp("add");
        let lost = add(&d, "SNYK-1", "*", " not reachable ", Some("2999-01-02")).unwrap();
        assert!(!lost);
        let text = std::fs::read_to_string(file(&d)).unwrap();
        assert!(text.contains("version: v1.25.0"), "{text}");
        let r = load(&d).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].id.as_str(), r[0].path.as_str()), ("SNYK-1", "*"));
        assert_eq!(r[0].reason, "not reachable");
        assert_eq!(r[0].expires.as_deref(), Some("2999-01-02T00:00:00.000Z"));
        assert!(r[0].created.is_some());
    }

    #[test]
    fn add_replaces_the_same_id_and_path_and_keeps_others() {
        let d = tmp("replace");
        add(&d, "SNYK-1", "*", "a", None).unwrap();
        add(&d, "SNYK-1", "x > y", "b", None).unwrap();
        add(&d, "SNYK-1", "*", "c", None).unwrap();
        let r = load(&d).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.iter().find(|r| r.path == "*").unwrap().reason, "c");
        assert!(r.iter().any(|r| r.path == "x > y"));
    }

    #[test]
    fn other_keys_survive_and_comments_are_reported() {
        let d = tmp("keep");
        std::fs::write(
            file(&d),
            "# policy\nversion: v1.19.0\nexclude:\n  global:\n    - test/**\nignore: {}\n",
        )
        .unwrap();
        let lost = add(&d, "SNYK-2", "*", "r", None).unwrap();
        assert!(lost);
        let text = std::fs::read_to_string(file(&d)).unwrap();
        assert!(text.contains("v1.19.0") && text.contains("test/**"), "{text}");
        assert_eq!(load(&d).unwrap().len(), 1);
    }

    #[test]
    fn remove_deletes_one_rule_and_the_empty_section() {
        let d = tmp("remove");
        add(&d, "SNYK-1", "*", "a", None).unwrap();
        add(&d, "SNYK-2", "*", "b", None).unwrap();
        remove(&d, "SNYK-1", "*").unwrap();
        assert_eq!(load(&d).unwrap().len(), 1);
        remove(&d, "SNYK-2", "*").unwrap();
        assert!(!std::fs::read_to_string(file(&d)).unwrap().contains("ignore"));
        assert!(remove(&d, "SNYK-2", "*").is_err());
    }

    #[test]
    fn reads_snyks_own_format() {
        let d = tmp("real");
        std::fs::write(
            file(&d),
            "version: v1.25.0\nignore:\n  SNYK-JS-A-1:\n    - '*':\n        reason: none\n        expires: 2020-01-01T00:00:00.000Z\n        created: 2019-01-01T00:00:00.000Z\n  SNYK-JS-B-2:\n    - 'a > b':\n        reason: x\npatch: {}\n",
        )
        .unwrap();
        let r = load(&d).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].expired("2025-01-01"));
        assert!(!r[1].expired("2025-01-01"));
    }

    #[test]
    fn a_broken_file_is_an_error_and_is_left_alone() {
        let d = tmp("broken");
        std::fs::write(file(&d), "ignore: [unclosed").unwrap();
        assert!(add(&d, "SNYK-1", "*", "a", None).is_err());
        assert_eq!(std::fs::read_to_string(file(&d)).unwrap(), "ignore: [unclosed");
    }

    #[test]
    fn covers_matches_the_id_and_the_path() {
        let v = vuln("SNYK-1", "a", &["b", "c"]);
        let rule = |path: &str| Ignore {
            id: "SNYK-1".into(),
            path: path.into(),
            reason: String::new(),
            expires: None,
            created: None,
        };
        assert_eq!(path_of(&v), "a > b > c");
        assert!(rule("*").covers(&v));
        assert!(rule("a > b > c").covers(&v));
        assert!(!rule("a > b").covers(&v));
        assert!(!Ignore { id: "SNYK-2".into(), ..rule("*") }.covers(&v));
        assert_eq!(path_of(&vuln("SNYK-1", "a", &[])), "a");
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(days_from(2024, 2, 29)), "2024-02-29");
        assert_eq!(date(19_723), "2024-01-01");
        assert_eq!(today().len(), 10);
        assert!(in_days(30).as_str() > today().as_str());
    }

    #[test]
    fn expiry_input_is_checked() {
        let today = "2025-06-01";
        assert_eq!(parse_expiry("", today), Ok(None));
        assert_eq!(parse_expiry(" 2025-08-01 ", today), Ok(Some("2025-08-01".into())));
        assert!(parse_expiry("2025-02-30", today).is_err());
        assert!(parse_expiry("2025-13-01", today).is_err());
        assert!(parse_expiry("soon", today).is_err());
        assert!(parse_expiry("2025-6-1", today).is_err());
        assert!(parse_expiry("2025-06-01", today).is_err());
        assert!(parse_expiry("2024-01-01", today).is_err());
    }
}
