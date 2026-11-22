//! `bunfig.toml` registry support, translated into `.npmrc`-style settings.
//!
//! Supported forms:
//! ```toml
//! [install]
//! registry = "https://r.example/"                       # string
//! registry = { url = "https://r.example/", token = "$T" } # inline table
//!
//! [install.registry]                                     # table
//! url = "https://r.example/"
//! token = "$T"            # or username + password
//!
//! [install.scopes]
//! "@acme" = "https://r.example/"
//! "@acme" = { url = "https://r.example/", token = "$T" }
//! ```

use crate::config::npmrc::Npmrc;
use std::path::Path;
use toml::Value;

/// Expands `$VAR` and `${VAR}` (also `${VAR:-default}`). Unknown variables become empty,
/// as in Bun.
fn expand(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let rest = &s[i + 1..];
        let (expr, consumed) = if let Some(inner) = rest.strip_prefix('{') {
            match inner.find('}') {
                Some(end) => (&inner[..end], end + 2),
                None => {
                    out.push('$');
                    continue;
                }
            }
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], end)
        };
        if expr.is_empty() {
            out.push('$');
            continue;
        }
        let (name, default) = match expr.split_once(":-") {
            Some((n, d)) => (n, d),
            None => (expr, ""),
        };
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => out.push_str(&v),
            _ => out.push_str(default),
        }
        for _ in 0..consumed {
            chars.next();
        }
    }
    out
}

/// Loads global (`~/.bunfig.toml`, `$XDG_CONFIG_HOME/.bunfig.toml`) then project
/// `bunfig.toml` into `rc`; later files win.
pub fn merge_into(rc: &mut Npmrc, dir: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut paths = Vec::new();
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        paths.push(Path::new(&xdg).join(".bunfig.toml"));
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        paths.push(Path::new(&home).join(".bunfig.toml"));
    }
    paths.push(dir.join("bunfig.toml"));
    for p in paths {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        if let Err(e) = merge_str(rc, &text) {
            warnings.push(format!("! {}: {e}", p.display()));
        }
    }
    warnings
}

pub fn merge_str(rc: &mut Npmrc, text: &str) -> Result<(), toml::de::Error> {
    let doc: Value = toml::from_str(text)?;
    let Some(install) = doc.get("install") else {
        return Ok(());
    };
    if let Some(reg) = install.get("registry") {
        apply(rc, None, reg);
    }
    if let Some(scopes) = install.get("scopes").and_then(Value::as_table) {
        for (scope, v) in scopes {
            apply(rc, Some(scope.trim_start_matches('@')), v);
        }
    }
    Ok(())
}

fn apply(rc: &mut Npmrc, scope: Option<&str>, v: &Value) {
    let (url, token, user, pass) = match v {
        Value::String(s) => (expand(s), None, None, None),
        Value::Table(t) => {
            let get = |k: &str| t.get(k).and_then(Value::as_str).map(expand);
            let Some(url) = get("url") else { return };
            (url, get("token"), get("username"), get("password"))
        }
        _ => return,
    };
    if url.is_empty() {
        return;
    }
    let key = match scope {
        Some(s) => format!("@{s}:registry"),
        None => "registry".to_string(),
    };
    rc.set(&key, &url);

    let Some((_, rest)) = url.split_once("://") else {
        return;
    };
    let prefix = format!("//{}/:", rest.trim_end_matches('/'));
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        rc.set(&format!("{prefix}_authToken"), &t);
    } else if let (Some(u), Some(p)) = (user, pass) {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD.encode(p);
        rc.set(&format!("{prefix}username"), &u);
        rc.set(&format!("{prefix}_password"), &enc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_form_with_env_token() {
        unsafe { std::env::set_var("DEPSU_BUN_TOK", "tok") };
        let mut rc = Npmrc::default();
        merge_str(
            &mut rc,
            "[install.registry]\nurl = \"https://npm.example.fi/sok-npm/\"\ntoken = \"$DEPSU_BUN_TOK\"\n",
        )
        .unwrap();
        assert_eq!(
            rc.registry_for("left-pad"),
            "https://npm.example.fi/sok-npm/"
        );
        assert_eq!(
            rc.auth_header("https://npm.example.fi/sok-npm/").as_deref(),
            Some("Bearer tok")
        );
    }

    #[test]
    fn string_and_scopes() {
        let mut rc = Npmrc::default();
        merge_str(
            &mut rc,
            "[install]\nregistry = \"https://a.example/\"\n[install.scopes]\n\"@acme\" = { url = \"https://b.example/\", token = \"x\" }\n",
        )
        .unwrap();
        assert_eq!(rc.registry_for("foo"), "https://a.example/");
        assert_eq!(rc.registry_for("@acme/foo"), "https://b.example/");
        assert_eq!(
            rc.auth_header("https://b.example/").as_deref(),
            Some("Bearer x")
        );
    }

    #[test]
    fn expand_forms() {
        unsafe { std::env::set_var("DEPSU_X", "v") };
        assert_eq!(expand("a$DEPSU_X/b${DEPSU_X}c${DEPSU_NOPE:-d}"), "av/bvcd");
    }
}
