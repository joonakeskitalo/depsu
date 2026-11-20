//! Editing override values in `package.json` in place.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::path::Path;

/// A change to an override entry in `package.json`.
pub enum Change {
    Set {
        /// Path of keys to the string value, e.g. `["overrides", "foo", "."]`.
        loc: Vec<String>,
        /// Expected current value, so a concurrently edited file is never clobbered.
        old: String,
        new: String,
    },
    Remove {
        loc: Vec<String>,
        old: String,
    },
}

/// Applies the changes and rewrites the file, keeping key order, indentation and the trailing
/// newline (the same normalisation npm applies when it writes `package.json`). Nothing is
/// written unless every change applies.
pub fn apply(path: &Path, changes: &[Change]) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut root: Value = serde_json::from_str(&text).context("parsing package.json")?;
    for c in changes {
        match c {
            Change::Set { loc, old, new } => {
                match value_at(&mut root, loc, old)? {
                    Value::String(s) => *s = new.clone(),
                    _ => unreachable!("value_at only returns matching strings"),
                };
            }
            Change::Remove { loc, old } => {
                value_at(&mut root, loc, old)?;
                let (key, parent) = loc.split_last().context("empty location")?;
                if let Some(Value::Object(m)) = navigate(&mut root, parent) {
                    m.shift_remove(key.as_str());
                }
                prune(&mut root, parent);
            }
        }
    }

    let indent = detect_indent(&text);
    let mut buf = Vec::new();
    let mut ser =
        Serializer::with_formatter(&mut buf, PrettyFormatter::with_indent(indent.as_bytes()));
    root.serialize(&mut ser)?;
    let mut out = String::from_utf8(buf)?;
    if text.ends_with('\n') {
        out.push('\n');
    }

    // Write to a temp file first so a failure can't leave a truncated package.json.
    let tmp = path.with_extension("json.depsu-tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn navigate<'a>(root: &'a mut Value, loc: &[String]) -> Option<&'a mut Value> {
    let mut cur = root;
    for k in loc {
        cur = cur.get_mut(k.as_str())?;
    }
    Some(cur)
}

/// The string at `loc`, checked to equal `old`.
fn value_at<'a>(root: &'a mut Value, loc: &[String], old: &str) -> Result<&'a mut Value> {
    let shown = loc.join(" › ");
    let v = navigate(root, loc).with_context(|| format!("`{shown}` not found in package.json"))?;
    match v {
        Value::String(s) if s == old => Ok(v),
        _ => bail!("package.json changed: `{shown}` is no longer `{old}`"),
    }
}

/// Removes objects left empty along `loc` (the path of the object a key was just removed
/// from), innermost first, so `"overrides": {}` doesn't linger.
fn prune(root: &mut Value, loc: &[String]) {
    for depth in (1..=loc.len()).rev() {
        let empty = navigate(root, &loc[..depth])
            .and_then(|v| v.as_object())
            .is_some_and(|m| m.is_empty());
        if !empty {
            break;
        }
        if let Some(Value::Object(parent)) = navigate(root, &loc[..depth - 1]) {
            parent.shift_remove(loc[depth - 1].as_str());
        }
    }
}

fn detect_indent(text: &str) -> String {
    text.lines()
        .find_map(|l| {
            let t = l.trim_start();
            (t.starts_with('"') && t.len() < l.len()).then(|| l[..l.len() - t.len()].to_string())
        })
        .unwrap_or_else(|| "  ".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, content: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-edit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("package.json");
        std::fs::write(&p, content).unwrap();
        p
    }

    fn loc(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    fn set(l: &[&str], old: &str, new: &str) -> Change {
        Change::Set {
            loc: loc(l),
            old: old.into(),
            new: new.into(),
        }
    }

    fn remove(l: &[&str], old: &str) -> Change {
        Change::Remove {
            loc: loc(l),
            old: old.into(),
        }
    }

    fn cleanup(p: &Path) {
        std::fs::remove_dir_all(p.parent().unwrap()).unwrap();
    }

    #[test]
    fn edits_nested_value_keeping_order_and_indent() {
        let src = "{\n    \"name\": \"x\",\n    \"overrides\": {\n        \"zeta\": \"1.0.0\",\n        \"bar\": {\n            \".\": \"2.0.0\",\n            \"foo\": \"3.0.0\"\n        }\n    },\n    \"version\": \"1.0.0\"\n}\n";
        let p = file("nested", src);
        apply(
            &p,
            &[
                set(&["overrides", "bar", "foo"], "3.0.0", "3.5.0"),
                set(&["overrides", "bar", "."], "2.0.0", "2.1.0"),
            ],
        )
        .unwrap();
        let out = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            out,
            src.replace("3.0.0", "3.5.0").replace("2.0.0", "2.1.0"),
            "only the values may change"
        );
        cleanup(&p);
    }

    #[test]
    fn refuses_stale_or_missing_entries() {
        let p = file("stale", "{\"overrides\":{\"a\":\"1.0.0\"}}");
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(apply(&p, &[set(&["overrides", "a"], "9.9.9", "2.0.0")]).is_err());
        assert!(apply(&p, &[set(&["overrides", "nope"], "1.0.0", "2.0.0")]).is_err());
        assert!(apply(&p, &[remove(&["overrides", "a"], "9.9.9")]).is_err());
        // all-or-nothing: a valid change followed by a bad one writes nothing
        assert!(
            apply(
                &p,
                &[
                    remove(&["overrides", "a"], "1.0.0"),
                    remove(&["overrides", "b"], "1.0.0")
                ]
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        cleanup(&p);
    }

    #[test]
    fn removes_entries_and_prunes_empty_containers() {
        let src = "{\n  \"name\": \"x\",\n  \"overrides\": {\n    \"keep\": \"1.0.0\",\n    \"bar\": {\n      \"foo\": \"3.0.0\"\n    },\n    \"gone\": \"2.0.0\"\n  },\n  \"version\": \"1.0.0\"\n}\n";
        let p = file("remove", src);
        apply(
            &p,
            &[
                remove(&["overrides", "bar", "foo"], "3.0.0"),
                remove(&["overrides", "gone"], "2.0.0"),
            ],
        )
        .unwrap();
        // `bar` became empty and is removed with its entry; siblings and order are kept
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "{\n  \"name\": \"x\",\n  \"overrides\": {\n    \"keep\": \"1.0.0\"\n  },\n  \"version\": \"1.0.0\"\n}\n"
        );

        // removing the last override drops the `overrides` key itself
        apply(&p, &[remove(&["overrides", "keep"], "1.0.0")]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\"\n}\n"
        );
        cleanup(&p);
    }

    #[test]
    fn removing_the_dot_entry_keeps_nested_overrides() {
        let p = file(
            "dot",
            "{\"overrides\":{\"bar\":{\".\":\"2.0.0\",\"foo\":\"3.0.0\"}}}",
        );
        apply(&p, &[remove(&["overrides", "bar", "."], "2.0.0")]).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["overrides"]["bar"]["foo"], "3.0.0");
        assert!(v["overrides"]["bar"].get(".").is_none());
        cleanup(&p);
    }
}
