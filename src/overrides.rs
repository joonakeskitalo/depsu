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
    /// Location of the value in `package.json`, as a path of keys.
    pub loc: Vec<String>,
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

    /// Stable identity of the entry in `package.json`.
    pub fn key(&self) -> String {
        self.loc.join("\u{1f}")
    }

    pub fn global(&self) -> bool {
        self.path.is_empty()
    }

    /// True if the override applies below the dependency chain `chain` (outermost first):
    /// it applies everywhere, or every parent it is limited to appears in the chain in order.
    pub fn path_applies(&self, chain: &[String]) -> bool {
        let mut rest = chain.iter();
        self.path
            .iter()
            .all(|p| rest.any(|c| *c == split_name(p).0))
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
            flat(
                top("resolutions"),
                &["resolutions"],
                "resolutions",
                '/',
                &mut out,
            );
        }
        Pm::Yarn => flat(
            top("resolutions"),
            &["resolutions"],
            "resolutions",
            '/',
            &mut out,
        ),
        Pm::Pnpm => flat(
            manifest
                .get("pnpm")
                .and_then(|p| p.get("overrides"))
                .and_then(Value::as_object),
            &["pnpm", "overrides"],
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
    struct Ctx<'a> {
        source: &'static str,
        /// Parent package names the current object is nested under.
        path: Vec<String>,
        /// Raw keys from the document root to the current object.
        loc: Vec<String>,
        out: &'a mut Vec<Override>,
    }

    fn walk(obj: &Map<String, Value>, cx: &mut Ctx) {
        for (key, val) in obj {
            if key == "." {
                continue;
            }
            let (name, range) = split_name(key);
            let mut push = |value: &str, extra: Option<&str>| {
                let mut loc = cx.loc.clone();
                loc.push(key.clone());
                loc.extend(extra.map(String::from));
                cx.out.push(Override {
                    name: name.clone(),
                    range: range.clone(),
                    value: value.to_string(),
                    source: cx.source,
                    path: cx.path.clone(),
                    loc,
                })
            };
            match val {
                Value::String(s) => push(s, None),
                Value::Object(o) => {
                    if let Some(Value::String(s)) = o.get(".") {
                        push(s, Some("."));
                    }
                    cx.path.push(key.clone());
                    cx.loc.push(key.clone());
                    walk(o, cx);
                    cx.loc.pop();
                    cx.path.pop();
                }
                _ => {}
            }
        }
    }

    if let Some(o) = obj {
        let mut cx = Ctx {
            source,
            path: Vec::new(),
            loc: vec![source.to_string()],
            out,
        };
        walk(o, &mut cx);
    }
}

/// yarn/pnpm/bun-resolutions: flat keys such as `foo`, `**/foo`, `a/foo` (yarn, `/`) or
/// `a>foo@^1` (pnpm, `>`). `root` is the path of keys to the object in `package.json`.
fn flat(
    obj: Option<&Map<String, Value>>,
    root: &[&str],
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
        let mut loc: Vec<String> = root.iter().map(|s| s.to_string()).collect();
        loc.push(key.clone());
        out.push(Override {
            name,
            range,
            value: value.to_string(),
            source,
            path: parts,
            loc,
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

/// Why an override is probably no longer needed.
#[derive(Clone, Debug, PartialEq)]
pub enum Unneeded {
    /// No installed package depends on the overridden package.
    Unused,
    /// Every dependent already asks for exactly the override's value.
    SameSpec,
    /// Every dependent already requires at least this version, which is what the override
    /// guarantees as a floor.
    FloorMet(Version),
}

impl Unneeded {
    pub fn reason(&self, o: &Override) -> String {
        match self {
            Unneeded::Unused => format!("nothing installed depends on {}", o.name),
            Unneeded::SameSpec => format!("every dependent already asks for {}", o.value),
            Unneeded::FloorMet(v) => format!("every dependent already requires ≥ {v}"),
        }
    }
}

/// Decides whether `o` still changes anything, given the ranges that every installed
/// package (and the project itself) declares for the overridden package. Conservative:
/// returns `None` unless the evidence is clear.
pub fn assess(o: &Override, requested: &[String]) -> Option<Unneeded> {
    if o.value.starts_with('$') {
        return None; // a reference to a direct dependency's spec
    }
    if requested.is_empty() {
        return Some(Unneeded::Unused);
    }
    if requested.iter().all(|r| *r == o.value) {
        return Some(Unneeded::SameSpec);
    }
    let floor = min_version(&o.value)?;
    requested
        .iter()
        .all(|r| min_version(r).is_some_and(|m| m >= floor))
        .then_some(Unneeded::FloorMet(floor))
}

/// Lowest version an npm-style range can select. For `||` the lowest alternative counts, so
/// the answer is a guaranteed lower bound. `None` for anything not understood.
pub fn min_version(range: &str) -> Option<Version> {
    range
        .split("||")
        .map(|alt| alt_min(alt.trim()))
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .min()
}

fn alt_min(alt: &str) -> Option<Version> {
    let mut lower = Version::new(0, 0, 0);
    let mut pending_op = String::new();
    let mut it = alt.split_whitespace();
    while let Some(t) = it.next() {
        if t == "-" {
            // Hyphen range "a - b": `a` was the lower bound, the next token is the upper one.
            it.next();
            continue;
        }
        if t.chars().all(|c| "<>=~^".contains(c)) {
            pending_op.push_str(t);
            continue;
        }
        let full = format!("{pending_op}{t}");
        pending_op.clear();
        let split = full.find(|c: char| c.is_ascii_digit() || c == 'x' || c == 'X' || c == '*')?;
        let (op, ver) = full.split_at(split);
        if op.starts_with('<') {
            continue; // upper bound only
        }
        if !matches!(op, "" | "=" | "^" | "~" | ">" | ">=") {
            return None;
        }
        let v = partial_version(ver)?;
        if v > lower {
            lower = v;
        }
    }
    if !pending_op.is_empty() {
        return None;
    }
    Some(lower)
}

/// `1`, `1.2`, `1.x`, `1.2.3`, `1.2.3-beta.1` (missing or wildcard parts become 0).
fn partial_version(s: &str) -> Option<Version> {
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }
    let mut nums = [0u64; 3];
    let mut wildcard = false;
    for (i, part) in s.split('.').enumerate() {
        if i >= 3 {
            return None;
        }
        if matches!(part, "x" | "X" | "*") {
            wildcard = true;
        } else if wildcard {
            return None;
        } else {
            nums[i] = part.parse().ok()?;
        }
    }
    Some(Version::new(nums[0], nums[1], nums[2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn lowest_selectable_version() {
        let m = |r: &str| min_version(r).map(|v| v.to_string());
        assert_eq!(m("5.0.5").as_deref(), Some("5.0.5"));
        assert_eq!(m("^5.0.5").as_deref(), Some("5.0.5"));
        assert_eq!(m("~1.2").as_deref(), Some("1.2.0"));
        assert_eq!(m("1.x").as_deref(), Some("1.0.0"));
        assert_eq!(m(">=1.2.3 <2").as_deref(), Some("1.2.3"));
        assert_eq!(m("< 2").as_deref(), Some("0.0.0"));
        assert_eq!(m("1.2.3 - 2.0.0").as_deref(), Some("1.2.3"));
        assert_eq!(m("^4 || ^5.1.0").as_deref(), Some("4.0.0")); // lowest alternative
        assert_eq!(m("*").as_deref(), Some("0.0.0"));
        assert_eq!(m("github:a/b"), None);
        assert_eq!(m("workspace:*"), None);
        assert_eq!(m("npm:foo@1"), None);
    }

    fn named(value: &str) -> Override {
        ovr(value).remove(0)
    }

    fn reqs(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_unneeded_overrides() {
        let o = named("5.0.5");
        assert_eq!(assess(&o, &[]), Some(Unneeded::Unused));
        assert_eq!(
            assess(&o, &reqs(&["5.0.5", "5.0.5"])),
            Some(Unneeded::SameSpec)
        );
        // every dependent already requires at least the pinned version
        assert_eq!(
            assess(&o, &reqs(&["^5.0.5", "^5.1.0"])),
            Some(Unneeded::FloorMet(Version::new(5, 0, 5)))
        );
        // one dependent still allows a lower (vulnerable) version: still needed
        assert_eq!(assess(&o, &reqs(&["^5.0.5", "^5.0.0"])), None);
        // unparseable declared range: no verdict
        assert_eq!(assess(&o, &reqs(&["^5.0.5", "github:a/b"])), None);
        // references are never judged
        assert_eq!(assess(&named("$foo"), &[]), None);
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
    fn records_where_each_value_lives() {
        let m = json!({
            "overrides": {"foo": "1.0.0", "bar": {".": "2.0.0", "baz@^1": "3.0.0"}},
            "resolutions": {"a/b": "4.0.0"},
            "pnpm": {"overrides": {"p>q": "5.0.0"}}
        });
        let loc = |pm, value: &str| {
            collect(&m, pm)
                .into_iter()
                .find(|o| o.value == value)
                .unwrap()
                .loc
        };
        assert_eq!(loc(Pm::Npm, "1.0.0"), ["overrides", "foo"]);
        assert_eq!(loc(Pm::Npm, "2.0.0"), ["overrides", "bar", "."]);
        assert_eq!(loc(Pm::Npm, "3.0.0"), ["overrides", "bar", "baz@^1"]);
        assert_eq!(loc(Pm::Yarn, "4.0.0"), ["resolutions", "a/b"]);
        assert_eq!(loc(Pm::Pnpm, "5.0.0"), ["pnpm", "overrides", "p>q"]);
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

    #[test]
    fn path_applies_in_order() {
        let chain = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut o = ovr("1.0.0").remove(0);
        assert!(o.path_applies(&chain(&["x"])));
        o.path = vec!["a".into(), "b@^1".into()];
        assert!(o.path_applies(&chain(&["x", "a", "m", "b"])));
        assert!(!o.path_applies(&chain(&["x", "b", "a"])));
        assert!(!o.path_applies(&chain(&["x", "a"])));
    }

    fn ovr(value: &str) -> Vec<Override> {
        vec![Override {
            name: "foo".into(),
            range: None,
            value: value.into(),
            source: "overrides",
            path: vec![],
            loc: vec!["overrides".into(), "foo".into()],
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
