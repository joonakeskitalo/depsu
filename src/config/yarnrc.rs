//! `.yarnrc.yml` support (Yarn 2+), translated into `.npmrc`-style settings.
//!
//! Yarn Modern ignores `.npmrc` completely, so for such projects this replaces it instead of
//! adding to it. Supported settings:
//!
//! ```yaml
//! npmRegistryServer: "https://registry.example.com"
//! npmAuthToken: "${TOKEN}"          # or npmAuthIdent: "user:password"
//! npmScopes:
//!   my-company:
//!     npmRegistryServer: "https://npm.example.com"
//!     npmAuthToken: "${COMPANY_TOKEN}"
//! npmRegistries:
//!   "//npm.other.com":
//!     npmAuthToken: "${OTHER_TOKEN}"
//! ```
//!
//! Credentials are chosen like Yarn does: the package's scope first, then the registry's own
//! entry in `npmRegistries`, then the top-level ones. Yarn only sends credentials on reads when
//! `npmAlwaysAuth` is set. `depsu` sends them whenever they are configured, which is what a
//! private registry needs anyway.

use crate::config::npmrc::Npmrc;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_yaml_ng::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FILE: &str = ".yarnrc.yml";

/// The `.yarnrc.yml` files that apply to `dir`, lowest precedence first: the home directory,
/// then every directory from the filesystem root down to `dir`.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        out.push(Path::new(&home).join(FILE));
    }
    let mut ancestors: Vec<PathBuf> = dir.ancestors().map(|d| d.join(FILE)).collect();
    ancestors.reverse();
    for f in ancestors {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out.into_iter().filter(|f| f.is_file()).collect()
}

/// True if the project is configured through `.yarnrc.yml`, in `dir` or a parent directory
/// (the home directory alone doesn't make a project a Yarn Modern one).
pub fn is_yarn_modern(dir: &Path) -> bool {
    dir.ancestors().any(|d| d.join(FILE).is_file())
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Auth {
    token: Option<String>,
    ident: Option<String>,
}

impl Auth {
    fn overlay(&mut self, other: Auth) {
        self.token = other.token.or(self.token.take());
        self.ident = other.ident.or(self.ident.take());
    }

    /// `Authorization` header value. A token wins over an identity, as in Yarn.
    fn header(&self) -> Option<String> {
        if let Some(t) = &self.token {
            return Some(format!("Bearer {t}"));
        }
        let ident = self.ident.as_deref()?;
        // `user:password`, or the same already base64 encoded.
        let encoded = if ident.contains(':') {
            STANDARD.encode(ident)
        } else {
            ident.to_string()
        };
        Some(format!("Basic {encoded}"))
    }
}

#[derive(Default, Debug)]
struct Scope {
    registry: Option<String>,
    auth: Auth,
}

#[derive(Default, Debug)]
struct Config {
    registry: Option<String>,
    auth: Auth,
    /// Scope name without `@`.
    scopes: BTreeMap<String, Scope>,
    /// Normalised registry (`host/path`) to its credentials.
    registries: BTreeMap<String, Auth>,
}

/// Loads the Yarn configuration for `dir`. Returns the settings and any problems found.
pub fn load(dir: &Path) -> (Npmrc, Vec<String>) {
    let mut cfg = Config::default();
    let mut warnings = Vec::new();
    for path in files(dir) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match parse(&text) {
            Ok((file_cfg, w)) => {
                warnings.extend(w.into_iter().map(|m| format!("! {}: {m}", path.display())));
                cfg.overlay(file_cfg);
            }
            Err(e) => warnings.push(format!("! {}: {e}", path.display())),
        }
    }
    // Settings can also come from the environment, and win over the files.
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    if let Some(r) = env("YARN_NPM_REGISTRY_SERVER") {
        cfg.registry = Some(r);
    }
    cfg.auth.overlay(Auth {
        token: env("YARN_NPM_AUTH_TOKEN"),
        ident: env("YARN_NPM_AUTH_IDENT"),
    });

    let mut rc = Npmrc::default();
    cfg.apply(&mut rc);
    (rc, warnings)
}

impl Config {
    /// Merges `other` into `self`; values in `other` win.
    fn overlay(&mut self, other: Config) {
        self.registry = other.registry.or(self.registry.take());
        self.auth.overlay(other.auth);
        for (name, s) in other.scopes {
            let mine = self.scopes.entry(name).or_default();
            mine.registry = s.registry.or(mine.registry.take());
            mine.auth.overlay(s.auth);
        }
        for (reg, a) in other.registries {
            self.registries.entry(reg).or_default().overlay(a);
        }
    }

    fn apply(&self, rc: &mut Npmrc) {
        if let Some(r) = &self.registry {
            rc.set("registry", r);
        }
        for (reg, auth) in &self.registries {
            set_registry_auth(rc, reg, auth);
        }
        for (name, scope) in &self.scopes {
            if let Some(r) = &scope.registry {
                rc.set(&format!("@{name}:registry"), r);
            }
            // Credentials on a scope apply to its packages, whichever registry serves them.
            if let Some(h) = scope.auth.header() {
                rc.set_scope_auth(&format!("@{name}"), h);
            }
        }
        if let Some(h) = self.auth.header() {
            rc.set_fallback_auth(h);
        }
    }
}

fn set_registry_auth(rc: &mut Npmrc, registry: &str, auth: &Auth) {
    let prefix = format!("//{}/:", registry);
    if let Some(t) = &auth.token {
        rc.set(&format!("{prefix}_authToken"), t);
    } else if let Some(i) = &auth.ident {
        let encoded = if i.contains(':') {
            STANDARD.encode(i)
        } else {
            i.clone()
        };
        rc.set(&format!("{prefix}_auth"), &encoded);
    }
}

/// `https://npm.example.com/path/`, `//npm.example.com/path` and `npm.example.com/path` all
/// become `npm.example.com/path`.
fn normalize_registry(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn parse(text: &str) -> Result<(Config, Vec<String>), String> {
    let doc: Value = serde_yaml_ng::from_str(text).map_err(|e| format!("invalid YAML: {e}"))?;
    let mut cfg = Config::default();
    let mut warnings = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return Ok((cfg, warnings));
    };

    // A string setting with environment variables expanded. A variable that isn't set drops
    // the setting with a warning, since Yarn itself would refuse to run.
    let mut text_of = |v: Option<&Value>, what: &str| -> Option<String> {
        let raw = v?.as_str()?;
        match expand(raw) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => Some(s),
            Err(e) => {
                warnings.push(format!("{what}: {e}"));
                None
            }
        }
    };
    let get = |m: &serde_yaml_ng::Mapping, k: &str| m.get(Value::String(k.to_string())).cloned();

    cfg.registry = text_of(get(root, "npmRegistryServer").as_ref(), "npmRegistryServer");
    cfg.auth = Auth {
        token: text_of(get(root, "npmAuthToken").as_ref(), "npmAuthToken"),
        ident: text_of(get(root, "npmAuthIdent").as_ref(), "npmAuthIdent"),
    };

    if let Some(scopes) = get(root, "npmScopes").as_ref().and_then(Value::as_mapping) {
        for (name, v) in scopes {
            let (Some(name), Some(m)) = (name.as_str(), v.as_mapping()) else {
                continue;
            };
            let name = name.trim_start_matches('@');
            cfg.scopes.insert(
                name.to_string(),
                Scope {
                    registry: text_of(
                        get(m, "npmRegistryServer").as_ref(),
                        &format!("npmScopes.{name}.npmRegistryServer"),
                    ),
                    auth: Auth {
                        token: text_of(
                            get(m, "npmAuthToken").as_ref(),
                            &format!("npmScopes.{name}.npmAuthToken"),
                        ),
                        ident: text_of(
                            get(m, "npmAuthIdent").as_ref(),
                            &format!("npmScopes.{name}.npmAuthIdent"),
                        ),
                    },
                },
            );
        }
    }

    if let Some(regs) = get(root, "npmRegistries")
        .as_ref()
        .and_then(Value::as_mapping)
    {
        for (url, v) in regs {
            let (Some(url), Some(m)) = (url.as_str(), v.as_mapping()) else {
                continue;
            };
            let auth = Auth {
                token: text_of(
                    get(m, "npmAuthToken").as_ref(),
                    &format!("npmRegistries.{url}.npmAuthToken"),
                ),
                ident: text_of(
                    get(m, "npmAuthIdent").as_ref(),
                    &format!("npmRegistries.{url}.npmAuthIdent"),
                ),
            };
            cfg.registries.insert(normalize_registry(url), auth);
        }
    }
    Ok((cfg, warnings))
}

/// Expands environment variables the way Yarn does: `${NAME}` (an error if unset),
/// `${NAME:-fallback}` (unset or empty), `${NAME-fallback}` (unset), with `\$`, `\\` and `\}`
/// as escapes.
fn expand(s: &str) -> Result<String, String> {
    let chars: Vec<char> = s.chars().collect();
    expand_from(&chars, 0, false, true).map(|(out, _)| out)
}

/// Expands from `i`, up to the `}` closing a fallback when `nested`. With `eval` false the
/// text is only scanned, so a fallback that isn't used can't fail. Returns the text and the
/// index it stopped at.
fn expand_from(
    c: &[char],
    mut i: usize,
    nested: bool,
    eval: bool,
) -> Result<(String, usize), String> {
    let mut out = String::new();
    while i < c.len() {
        match c[i] {
            '\\' if matches!(c.get(i + 1), Some('$' | '\\' | '}')) => {
                out.push(c[i + 1]);
                i += 2;
            }
            '}' if nested => return Ok((out, i)),
            '$' if c.get(i + 1) == Some(&'{') => {
                i += 2;
                let start = i;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                let name: String = c[start..i].iter().collect();
                if name.is_empty() {
                    return Err("invalid environment variable expansion".to_string());
                }
                let value = if eval {
                    std::env::var(&name).ok()
                } else {
                    None
                };
                let (when_empty_too, has_fallback) = match (c.get(i), c.get(i + 1)) {
                    (Some('}'), _) => (false, false),
                    (Some(':'), Some('-')) => {
                        i += 2;
                        (true, true)
                    }
                    (Some('-'), _) => {
                        i += 1;
                        (false, true)
                    }
                    _ => return Err(format!("invalid expansion of ${{{name}}}")),
                };
                if !has_fallback {
                    i += 1; // the closing brace
                    if eval {
                        out.push_str(
                            &value
                                .ok_or_else(|| format!("environment variable {name} is not set"))?,
                        );
                    }
                    continue;
                }
                let use_value = value
                    .as_ref()
                    .is_some_and(|v| !(when_empty_too && v.is_empty()));
                let (fallback, end) = expand_from(c, i, true, eval && !use_value)?;
                if c.get(end) != Some(&'}') {
                    return Err(format!("unclosed expansion of ${{{name}}}"));
                }
                i = end + 1;
                if eval {
                    out.push_str(&if use_value {
                        value.unwrap_or_default()
                    } else {
                        fallback
                    });
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    if nested {
        return Err("unclosed environment variable expansion".to_string());
    }
    Ok((out, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_text(text: &str) -> (Npmrc, Vec<String>) {
        let (cfg, warnings) = parse(text).unwrap();
        let mut rc = Npmrc::default();
        cfg.apply(&mut rc);
        (rc, warnings)
    }

    #[test]
    fn expands_variables_like_yarn() {
        unsafe {
            std::env::set_var("DEPSU_Y_SET", "v");
            std::env::set_var("DEPSU_Y_EMPTY", "");
            std::env::remove_var("DEPSU_Y_UNSET");
        }
        let ok = |s: &str| expand(s).unwrap();
        assert_eq!(ok("a${DEPSU_Y_SET}b"), "avb");
        assert_eq!(ok("${DEPSU_Y_UNSET:-fb}"), "fb");
        assert_eq!(ok("${DEPSU_Y_EMPTY:-fb}"), "fb"); // `:-` also replaces empty
        assert_eq!(ok("${DEPSU_Y_EMPTY-fb}"), ""); // `-` only replaces unset
        assert_eq!(ok("${DEPSU_Y_UNSET-fb}"), "fb");
        assert_eq!(ok("${DEPSU_Y_UNSET:-${DEPSU_Y_SET}}"), "v"); // nested fallback
        assert_eq!(ok(r"\${DEPSU_Y_SET} \\ \}"), r"${DEPSU_Y_SET} \ }");
        // an unused fallback is never evaluated, so it can't fail
        assert_eq!(ok("${DEPSU_Y_SET:-${DEPSU_Y_UNSET}}"), "v");
        assert!(
            expand("${DEPSU_Y_UNSET}")
                .unwrap_err()
                .contains("DEPSU_Y_UNSET")
        );
        assert!(expand("${DEPSU_Y_SET").is_err());
        assert!(expand("${DEPSU_Y_UNSET:-x").is_err());
        assert!(expand("${}").is_err());
        assert_eq!(ok("plain } text"), "plain } text");
    }

    #[test]
    fn default_and_scoped_registries_with_credentials() {
        unsafe { std::env::set_var("DEPSU_Y_TOKEN", "tok") };
        let (rc, w) = load_text(
            r#"
npmRegistryServer: "https://npm.artifacts.example.fi/sok-npm/"
npmAuthToken: "${DEPSU_Y_TOKEN}"
npmScopes:
  acme:
    npmRegistryServer: "https://scoped.example.com/"
    npmAuthToken: scoped-token
"#,
        );
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            rc.registry_for("left-pad"),
            "https://npm.artifacts.example.fi/sok-npm/"
        );
        assert_eq!(rc.registry_for("@acme/x"), "https://scoped.example.com/");
        assert_eq!(
            rc.registry_for("@other/x"),
            "https://npm.artifacts.example.fi/sok-npm/"
        );
        // top-level token: used for registries without credentials of their own
        let reg = rc.registry_for("left-pad");
        assert_eq!(rc.auth_for("left-pad", &reg).as_deref(), Some("Bearer tok"));
        assert_eq!(rc.auth_for("@other/x", &reg).as_deref(), Some("Bearer tok"));
        // scope token: only for that scope's packages
        assert_eq!(
            rc.auth_for("@acme/x", "https://scoped.example.com/")
                .as_deref(),
            Some("Bearer scoped-token")
        );
    }

    #[test]
    fn per_registry_credentials_beat_the_top_level_ones() {
        let (rc, _) = load_text(
            r#"
npmAuthToken: top
npmRegistries:
  "//npm.a.example.com":
    npmAuthToken: for-a
  "https://npm.b.example.com/path/":
    npmAuthIdent: "user:pass"
"#,
        );
        assert_eq!(
            rc.auth_for("x", "https://npm.a.example.com/").as_deref(),
            Some("Bearer for-a")
        );
        assert_eq!(
            rc.auth_for("x", "https://npm.b.example.com/path/")
                .as_deref(),
            Some(format!("Basic {}", STANDARD.encode("user:pass")).as_str())
        );
        assert_eq!(
            rc.auth_for("x", "https://npm.c.example.com/").as_deref(),
            Some("Bearer top")
        );
    }

    #[test]
    fn top_level_credentials_never_go_to_the_public_registries() {
        let (rc, _) = load_text("npmAuthToken: private\n");
        assert_eq!(rc.auth_for("x", "https://registry.npmjs.org/"), None);
        assert_eq!(rc.auth_for("x", "https://registry.yarnpkg.com/"), None);
        assert_eq!(
            rc.auth_for("x", "https://npm.internal.example/").as_deref(),
            Some("Bearer private")
        );
    }

    #[test]
    fn auth_ident_accepts_plain_and_base64_forms() {
        let plain = Auth {
            ident: Some("user:pass".into()),
            ..Auth::default()
        };
        let encoded = STANDARD.encode("user:pass");
        let b64 = Auth {
            ident: Some(encoded.clone()),
            ..Auth::default()
        };
        assert_eq!(plain.header(), b64.header());
        assert_eq!(plain.header().unwrap(), format!("Basic {encoded}"));
        let both = Auth {
            token: Some("t".into()),
            ident: Some("u:p".into()),
        };
        assert_eq!(both.header().as_deref(), Some("Bearer t"));
    }

    #[test]
    fn missing_environment_variable_drops_the_setting_with_a_warning() {
        unsafe { std::env::remove_var("DEPSU_Y_MISSING") };
        let (rc, w) = load_text(
            "npmRegistryServer: https://r.example/\nnpmAuthToken: \"${DEPSU_Y_MISSING}\"\n",
        );
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("npmAuthToken") && w[0].contains("DEPSU_Y_MISSING"),
            "{w:?}"
        );
        assert_eq!(rc.registry_for("x"), "https://r.example/");
        assert_eq!(
            rc.auth_for("x", "https://r.example/"),
            None,
            "no literal ${{...}} token is sent"
        );
    }

    #[test]
    fn unrelated_settings_and_odd_files_are_harmless() {
        let (rc, w) = load_text("nodeLinker: node-modules\nenableTelemetry: false\n");
        assert!(w.is_empty());
        assert_eq!(rc.registry_for("x"), "https://registry.npmjs.org/");
        assert!(parse("").is_ok());
        assert!(parse("- just\n- a list\n").is_ok());
        assert!(parse("a: [unclosed").is_err());
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-yarnrc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn files_cascade_and_the_nearest_one_wins() {
        let root = tmp("cascade");
        let sub = root.join("packages/app");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            root.join(FILE),
            "npmRegistryServer: https://root.example/\nnpmScopes:\n  acme:\n    npmRegistryServer: https://acme-root.example/\n",
        )
        .unwrap();
        std::fs::write(sub.join(FILE), "npmRegistryServer: https://app.example/\n").unwrap();
        // an `.npmrc` must be ignored for Yarn Modern
        std::fs::write(sub.join(".npmrc"), "registry=https://npmrc.example/\n").unwrap();

        assert!(is_yarn_modern(&sub));
        let (rc, w) = load(&sub);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            rc.registry_for("x"),
            "https://app.example/",
            "nearest file wins"
        );
        // settings only the parent file has still apply
        assert_eq!(rc.registry_for("@acme/x"), "https://acme-root.example/");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_projects_without_yarnrc() {
        let d = tmp("none");
        assert!(!is_yarn_modern(&d));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn broken_file_is_reported_not_fatal() {
        let d = tmp("broken");
        std::fs::write(d.join(FILE), "a: [unclosed").unwrap();
        let (rc, w) = load(&d);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("invalid YAML"), "{w:?}");
        assert_eq!(rc.registry_for("x"), "https://registry.npmjs.org/");
        std::fs::remove_dir_all(d).unwrap();
    }
}
