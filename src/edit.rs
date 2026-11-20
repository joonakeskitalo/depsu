//! Editing override values in `package.json` in place.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::path::Path;

pub struct OverrideEdit {
    /// Path of keys to the string value, e.g. `["overrides", "foo", "."]`.
    pub loc: Vec<String>,
    /// Expected current value, so a concurrently edited file is never clobbered.
    pub old: String,
    pub new: String,
}

/// Applies the edits and rewrites the file, keeping key order, indentation and the trailing
/// newline (the same normalisation npm applies when it writes `package.json`).
pub fn apply(path: &Path, edits: &[OverrideEdit]) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut root: Value = serde_json::from_str(&text).context("parsing package.json")?;
    for e in edits {
        let mut cur = &mut root;
        for k in &e.loc {
            cur = cur
                .get_mut(k.as_str())
                .with_context(|| format!("`{}` not found in package.json", e.loc.join(" › ")))?;
        }
        match cur {
            Value::String(s) if *s == e.old => *s = e.new.clone(),
            _ => bail!(
                "package.json changed: `{}` is no longer `{}`",
                e.loc.join(" › "),
                e.old
            ),
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

    fn edit(loc: &[&str], old: &str, new: &str) -> OverrideEdit {
        OverrideEdit {
            loc: loc.iter().map(|s| s.to_string()).collect(),
            old: old.into(),
            new: new.into(),
        }
    }

    #[test]
    fn edits_nested_value_keeping_order_and_indent() {
        let src = "{\n    \"name\": \"x\",\n    \"overrides\": {\n        \"zeta\": \"1.0.0\",\n        \"bar\": {\n            \".\": \"2.0.0\",\n            \"foo\": \"3.0.0\"\n        }\n    },\n    \"version\": \"1.0.0\"\n}\n";
        let p = file("nested", src);
        apply(
            &p,
            &[
                edit(&["overrides", "bar", "foo"], "3.0.0", "3.5.0"),
                edit(&["overrides", "bar", "."], "2.0.0", "2.1.0"),
            ],
        )
        .unwrap();
        let out = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            out,
            src.replace("3.0.0", "3.5.0").replace("2.0.0", "2.1.0"),
            "only the values may change"
        );
        std::fs::remove_dir_all(p.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_stale_or_missing_entries() {
        let p = file("stale", "{\"overrides\":{\"a\":\"1.0.0\"}}");
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(apply(&p, &[edit(&["overrides", "a"], "9.9.9", "2.0.0")]).is_err());
        assert!(apply(&p, &[edit(&["overrides", "nope"], "1.0.0", "2.0.0")]).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        std::fs::remove_dir_all(p.parent().unwrap()).unwrap();
    }
}
