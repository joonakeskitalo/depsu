//! Minimal `.npmrc` support: registries (default and per-scope) and auth.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;
use std::path::Path;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

#[derive(Debug, Default)]
pub struct Npmrc {
    values: HashMap<String, String>,
}

impl Npmrc {
    /// Loads user (`~/.npmrc`) then project (`<dir>/.npmrc`) config; project wins.
    /// `NPM_CONFIG_REGISTRY` overrides both for the default registry.
    pub fn load(dir: &Path) -> Self {
        let mut rc = Npmrc::default();
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            rc.merge_file(&Path::new(&home).join(".npmrc"));
        }
        rc.merge_file(&dir.join(".npmrc"));
        for var in ["NPM_CONFIG_REGISTRY", "npm_config_registry"] {
            if let Ok(v) = std::env::var(var)
                && !v.is_empty()
            {
                rc.values.insert("registry".into(), v);
            }
        }
        rc
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.values.insert(key.to_string(), value.to_string());
    }

    fn merge_file(&mut self, path: &Path) {
        if let Ok(text) = std::fs::read_to_string(path) {
            self.merge_str(&text);
        }
    }

    pub fn merge_str(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            self.values.insert(k.trim().to_string(), expand_env(v));
        }
    }

    /// Registry base URL (always ending in `/`) for a package name.
    pub fn registry_for(&self, package: &str) -> String {
        let scoped = package
            .strip_prefix('@')
            .and_then(|r| r.split_once('/'))
            .and_then(|(scope, _)| self.values.get(&format!("@{scope}:registry")));
        let url = scoped
            .or_else(|| self.values.get("registry"))
            .map(String::as_str)
            .unwrap_or(DEFAULT_REGISTRY);
        if url.ends_with('/') {
            url.to_string()
        } else {
            format!("{url}/")
        }
    }

    /// Value for the `Authorization` header for a registry URL, if configured.
    /// Looks up `//host/path/:_authToken` (and `_auth`, `username`/`_password`),
    /// trying progressively shorter path prefixes like npm does.
    pub fn auth_header(&self, registry_url: &str) -> Option<String> {
        let rest = registry_url.split_once("://")?.1;
        let mut path = format!("//{}", rest.trim_end_matches('/'));
        loop {
            let prefix = format!("{path}/:");
            if let Some(t) = self.values.get(&format!("{prefix}_authToken")) {
                return Some(format!("Bearer {t}"));
            }
            if let Some(a) = self.values.get(&format!("{prefix}_auth")) {
                return Some(format!("Basic {a}"));
            }
            if let (Some(u), Some(p)) = (
                self.values.get(&format!("{prefix}username")),
                self.values.get(&format!("{prefix}_password")),
            ) {
                let pw = STANDARD
                    .decode(p)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())?;
                return Some(format!("Basic {}", STANDARD.encode(format!("{u}:{pw}"))));
            }
            match path.rfind('/') {
                Some(i) if i > 2 => path.truncate(i),
                _ => return None,
            }
        }
    }
}

/// Expands `${VAR}` and `${VAR:-default}`; unknown variables are left as-is.
fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let expr = &after[..end];
        let (name, default) = match expr.split_once(":-") {
            Some((n, d)) => (n, Some(d)),
            None => (expr, None),
        };
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => out.push_str(&v),
            _ => match default {
                Some(d) => out.push_str(d),
                None => out.push_str(&rest[start..start + 3 + end]),
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc(text: &str) -> Npmrc {
        let mut r = Npmrc::default();
        r.merge_str(text);
        r
    }

    #[test]
    fn default_and_scoped_registry() {
        let r = rc("registry=https://a.example/npm\n@acme:registry=https://b.example/\n# c\n");
        assert_eq!(r.registry_for("left-pad"), "https://a.example/npm/");
        assert_eq!(r.registry_for("@acme/x"), "https://b.example/");
        assert_eq!(r.registry_for("@other/x"), "https://a.example/npm/");
        assert_eq!(Npmrc::default().registry_for("x"), DEFAULT_REGISTRY);
    }

    #[test]
    fn auth_token_prefix_match() {
        let r = rc("//a.example/:_authToken=tok\n");
        assert_eq!(
            r.auth_header("https://a.example/npm/deep/").as_deref(),
            Some("Bearer tok")
        );
        assert_eq!(r.auth_header("https://other.example/"), None);
    }

    #[test]
    fn env_expansion() {
        unsafe { std::env::set_var("DEPSU_TEST_TOK", "abc") };
        let r = rc(
            "//a.example/:_authToken=${DEPSU_TEST_TOK}\nregistry=${DEPSU_NOPE:-https://d.example/}",
        );
        assert_eq!(
            r.auth_header("https://a.example/").as_deref(),
            Some("Bearer abc")
        );
        assert_eq!(r.registry_for("x"), "https://d.example/");
    }
}
