//! Package manager overrides (`overrides`, `resolutions`, `pnpm.overrides`) and whether a
//! planned dependency update is compatible with them.
//!
//! Rules, per package manager:
//! - npm: a direct dependency may only have an override with the exact same spec, or a
//!   `$name` reference. Anything else fails with `EOVERRIDE`.
//! - yarn, pnpm, bun: the override silently wins, so the update is only effective when the
//!   new version satisfies the override.

use crate::pm::Pm;
use semver::{Version, VersionReq};
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Override {
    /// Overridden package name.
    pub name: String,
    /// Version selector from the key (`foo@^1`), limiting which versions are overridden.
    pub range: Option<String>,
    /// Override target, e.g. `1.2.3`, `^2`, `$foo`.
    pub value: String,
    /// `overrides`, `resolutions` or `pnpm.overrides`.
    pub source: &'static str,
    /// Parent packages the override is limited to. Empty means it applies everywhere.
    pub path: Vec<String>,
}

impl Override {
    pub fn describe(&self) -> String {
        let mut key = self.path.join(" > ");
        if !key.is_empty() {
            key.push_str(" > ");
        }
        key.push_str(&self.name);
        if let Some(r) = &self.range {
            key.push('@');
            key.push_str(r);
        }
        format!("{}: {key} → {}", self.source, self.value)
    }

    fn global(&self) -> bool {
        self.path.is_empty()
    }
}

/// Ordered by severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Compat {
    Ok,
    /// The override value could not be interpreted (URL, alias, `-`, odd range).
    Unknown,
    Conflict,
}

/// Collects the overrides the given package manager honours from a parsed `package.json`.
pub fn collect(manifest: &Value, pm: Pm) -> Vec<Override> {
    let mut out = Vec::new();
    let top = |key: &str| manifest.get(key).and_then(Value::as_object);
    match pm {
        Pm::Npm => npm_style(top("overrides"), "overrides", &mut out),
        Pm::Bun => {
            npm_style(top("overrides"), "overrides", &mut out);
            flat(top("resolutions"), "resolutions", '/', &mut out);
        }
        Pm::Yarn => flat(top("resolutions"), "resolutions", '/', &mut out),
        Pm::Pnpm => flat(
            manifest
                .get("pnpm")
                .and_then(|p| p.get("overrides"))
                .and_then(Value::as_object),
            "pnpm.overrides",
            '>',
            &mut out,
        ),
    }
    out
}

/// Splits `name@range` (the name may start with `@scope/`).
fn split_name(key: &str) -> (String, Option<String>) {
    match key.get(1..).and_then(|r| r.find('@')) {
        Some(i) => (key[..=i].to_string(), Some(key[i + 2..].to_string())),
        None => (key.to_string(), None),
    }
}

/// npm: nested objects, `"."` holds the override for the package itself.
fn npm_style(obj: Option<&Map<String, Value>>, source: &'static str, out: &mut Vec<Override>) {
    fn walk(
        obj: &Map<String, Value>,
        path: &mut Vec<String>,
        source: &'static str,
        out: &mut Vec<Override>,
    ) {
        for (key, val) in obj {
            if key == "." {
                continue;
            }
            let (name, range) = split_name(key);
            let mut push = |value: &str| {
                out.push(Override {
                    name: name.clone(),
                    range: range.clone(),
                    value: value.to_string(),
                    source,
                    path: path.clone(),
                })
            };
            match val {
                Value::String(s) => push(s),
                Value::Object(o) => {
                    if let Some(Value::String(s)) = o.get(".") {
                        push(s);
                    }
                    path.push(key.clone());
                    walk(o, path, source, out);
                    path.pop();
                }
                _ => {}
            }
        }
    }
    if let Some(o) = obj {
        walk(o, &mut Vec::new(), source, out);
    }
}

/// yarn/pnpm/bun-resolutions: flat keys such as `foo`, `**/foo`, `a/foo` (yarn, `/`) or
/// `a>foo@^1` (pnpm, `>`).
fn flat(
    obj: Option<&Map<String, Value>>,
    source: &'static str,
    sep: char,
    out: &mut Vec<Override>,
) {
    let Some(obj) = obj else { return };
    for (key, val) in obj {
        let Some(value) = val.as_str() else { continue };
        let mut parts: Vec<String> = Vec::new();
        let mut tokens = key.split(sep).map(str::trim);
        while let Some(t) = tokens.next() {
            // Re-join "@scope" "name" pairs split by '/'.
            if sep == '/' && t.starts_with('@') && !t.contains('/') {
                match tokens.next() {
                    Some(n) => parts.push(format!("{t}/{n}")),
                    None => parts.push(t.to_string()),
                }
            } else {
                parts.push(t.to_string());
            }
        }
        let Some(last) = parts.pop() else { continue };
        let (name, range) = split_name(&last);
        parts.retain(|p| p != "**");
        out.push(Override {
            name,
            range,
            value: value.to_string(),
            source,
            path: parts,
        });
    }
}

/// Checks whether updating direct dependency `name` to `new_spec` (resolving to `latest`)
/// is compatible with the overrides targeting it.
pub fn check(overrides: &[Override], pm: Pm, new_spec: &str, latest: &Version) -> Compat {
    overrides
        .iter()
        .filter(|o| o.global())
        .map(|o| check_one(o, pm, new_spec, latest))
        .max()
        .unwrap_or(Compat::Ok)
}

fn check_one(o: &Override, pm: Pm, new_spec: &str, latest: &Version) -> Compat {
    if o.value.starts_with('$') {
        return Compat::Ok; // follows the direct dependency
    }
    // A selector like `foo@^1` only overrides matching versions.
    if let Some(sel) = &o.range {
        match satisfies(sel, latest) {
            Some(false) => return Compat::Ok,
            None => return Compat::Unknown,
            Some(true) => {}
        }
    }
    if pm == Pm::Npm {
        return if o.value == new_spec {
            Compat::Ok
        } else {
            Compat::Conflict
        };
    }
    match satisfies(&o.value, latest) {
        Some(true) => Compat::Ok,
        Some(false) => Compat::Conflict,
        None => Compat::Unknown,
    }
}

/// npm-style range matching. Returns `None` for anything not understood.
pub fn satisfies(range: &str, v: &Version) -> Option<bool> {
    let mut unknown = false;
    for alt in range.split("||") {
        match alt_satisfies(alt.trim(), v) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown { None } else { Some(false) }
}

fn alt_satisfies(alt: &str, v: &Version) -> Option<bool> {
    if alt.is_empty() || alt == "*" || alt.eq_ignore_ascii_case("x") {
        return Some(true);
    }
    // In npm a bare version is exact, unlike Rust's semver where it means `^`.
    if let Ok(exact) = Version::parse(alt) {
        return Some(*v == exact);
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut pending_op = String::new();
    let mut it = alt.split_whitespace().peekable();
    while let Some(t) = it.next() {
        if t == "-" {
            // Hyphen range: "1.2.3 - 2.3.4"
            let lo = tokens.pop()?;
            let hi = it.next()?;
            tokens.push(format!(">={lo}"));
            tokens.push(format!("<={hi}"));
            continue;
        }
        if t.chars().all(|c| "<>=~^".contains(c)) {
            pending_op.push_str(t);
            continue;
        }
        let full = format!("{pending_op}{t}");
        pending_op.clear();
        // "1.2" means ~1.2 in npm but ^1.2 in Rust's semver.
        let is_minor_partial = {
            let parts: Vec<_> = full.split('.').collect();
            parts.len() == 2 && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
        };
        tokens.push(if is_minor_partial {
            format!("~{full}")
        } else {
            full
        });
    }
    if !pending_op.is_empty() || tokens.is_empty() {
        return None;
    }
    VersionReq::parse(&tokens.join(", "))
        .ok()
        .map(|r| r.matches(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn npm_range_semantics() {
        assert_eq!(satisfies("1.2.3", &v("1.2.4")), Some(false)); // exact in npm
        assert_eq!(satisfies("1.2.3", &v("1.2.3")), Some(true));
        assert_eq!(satisfies("1.2", &v("1.3.0")), Some(false)); // ~1.2
        assert_eq!(satisfies("^1.2.0", &v("1.9.0")), Some(true));
        assert_eq!(satisfies(">= 1.0.0 < 2.0.0", &v("1.5.0")), Some(true));
        assert_eq!(satisfies("^1 || ^3", &v("3.1.0")), Some(true));
        assert_eq!(satisfies("1.0.0 - 2.0.0", &v("1.5.0")), Some(true));
        assert_eq!(satisfies("github:a/b", &v("1.0.0")), None);
        assert_eq!(satisfies("npm:foo@1", &v("1.0.0")), None);
    }

    #[test]
    fn collects_npm_nested() {
        let m = json!({"overrides": {
            "foo": "1.0.0",
            "bar": {".": "2.0.0", "baz": "3.0.0"},
            "qux@^1": {"foo": "4.0.0"},
            "@s/pkg@2": "5.0.0"
        }});
        let o = collect(&m, Pm::Npm);
        let find = |n: &str, val: &str| o.iter().find(|x| x.name == n && x.value == val).unwrap();
        assert!(find("foo", "1.0.0").path.is_empty());
        assert!(find("bar", "2.0.0").path.is_empty());
        assert_eq!(find("baz", "3.0.0").path, ["bar"]);
        assert_eq!(find("foo", "4.0.0").path, ["qux@^1"]);
        assert_eq!(find("@s/pkg", "5.0.0").range.as_deref(), Some("2"));
    }

    #[test]
    fn collects_per_package_manager() {
        let m = json!({
            "overrides": {"a": "1.0.0"},
            "resolutions": {"**/b": "1.0.0", "@s/x/@s/c": "2.0.0", "d@^1": "3.0.0"},
            "pnpm": {"overrides": {"p>e": "1.0.0", "f": "-"}}
        });
        let names = |pm| {
            let mut n: Vec<_> = collect(&m, pm).into_iter().map(|o| o.name).collect();
            n.sort();
            n
        };
        assert_eq!(names(Pm::Npm), ["a"]);
        assert_eq!(names(Pm::Yarn), ["@s/c", "b", "d"]);
        assert_eq!(names(Pm::Pnpm), ["e", "f"]);
        assert_eq!(names(Pm::Bun), ["@s/c", "a", "b", "d"]);
        let y = collect(&m, Pm::Yarn);
        assert_eq!(y.iter().find(|o| o.name == "@s/c").unwrap().path, ["@s/x"]);
        assert!(y.iter().find(|o| o.name == "b").unwrap().path.is_empty());
    }

    fn ovr(value: &str) -> Vec<Override> {
        vec![Override {
            name: "foo".into(),
            range: None,
            value: value.into(),
            source: "overrides",
            path: vec![],
        }]
    }

    #[test]
    fn npm_requires_same_spec_or_reference() {
        let l = v("2.0.0");
        assert_eq!(check(&ovr("$foo"), Pm::Npm, "^2.0.0", &l), Compat::Ok);
        assert_eq!(check(&ovr("^2.0.0"), Pm::Npm, "^2.0.0", &l), Compat::Ok);
        assert_eq!(
            check(&ovr("^1.0.0"), Pm::Npm, "^2.0.0", &l),
            Compat::Conflict
        );
        // satisfied but not the same spec: npm still throws EOVERRIDE
        assert_eq!(
            check(&ovr("2.0.0"), Pm::Npm, "^2.0.0", &l),
            Compat::Conflict
        );
    }

    #[test]
    fn others_check_resolved_version() {
        let l = v("2.0.0");
        assert_eq!(
            check(&ovr("1.2.3"), Pm::Yarn, "^2.0.0", &l),
            Compat::Conflict
        );
        assert_eq!(check(&ovr("^2.0.0"), Pm::Pnpm, "^2.0.0", &l), Compat::Ok);
        assert_eq!(check(&ovr("-"), Pm::Pnpm, "^2.0.0", &l), Compat::Unknown);
    }

    #[test]
    fn selector_and_scoped_overrides() {
        let l = v("2.0.0");
        let mut o = ovr("1.2.3");
        o[0].range = Some("^1".into()); // only overrides foo@^1, not 2.x
        assert_eq!(check(&o, Pm::Yarn, "^2.0.0", &l), Compat::Ok);
        let mut o = ovr("1.2.3");
        o[0].path = vec!["bar".into()]; // only under bar: the direct dependency is unaffected
        assert_eq!(check(&o, Pm::Yarn, "^2.0.0", &l), Compat::Ok);
    }
}
