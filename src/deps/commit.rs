//! Committing the dependency changes with git. The commit gets a conventional-commit title
//! that says what changed, e.g. `chore: upgrade eslint 8.57.0 to 9.0.0`, and a body listing
//! every change. Only `package.json` and the lockfile are committed: anything else the user
//! has staged stays staged and out of the commit.
//!
//! The changes come from comparing `package.json` (and npm's lockfile, for the versions
//! actually installed) at `HEAD` with the working tree, so the title describes what the
//! commit contains, also changes made outside depsu.
use crate::deps::overrides;
use crate::deps::package::parse_spec;
use crate::config::pm::Pm;
use semver::Version;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Longest title git tools show without cutting it.
const TITLE_MAX: usize = 72;

/// One change to the project's dependencies.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    Upgrade { name: String, from: String, to: String },
    Downgrade { name: String, from: String, to: String },
    Add { name: String, version: String },
    Remove { name: String },
    /// Another spec at the same version, e.g. `^1.2.0` → `~1.2.0`, or a spec that isn't a
    /// version (a URL, a tag).
    Spec { name: String, from: String, to: String },
    OverrideAdd { name: String, value: String },
    OverrideRemove { name: String },
    OverrideChange { name: String, from: String, to: String },
    /// The lockfile got the checksum of a package it had none for, at the same version.
    Integrity { name: String, version: String },
    /// A vulnerability ignored in the `.snyk` policy. `path` is `*` or `a > b`.
    IgnoreAdd { id: String, path: String },
    /// The reason or the expiry of an ignore in `.snyk` changed.
    IgnoreChange { id: String, path: String },
    IgnoreRemove { id: String, path: String },
}
fn on_path(id: &str, path: &str) -> String {
    if path == "*" { id.to_string() } else { format!("{id} on {path}") }
}

impl Change {
    /// (verb, what with versions, just the name). The verb is shared by changes of one kind
    /// in a title: `upgrade a 1.0.0 to 2.0.0 and b 3.0.0 to 4.0.0`.
    fn parts(&self) -> (&'static str, String, String) {
        match self {
            Change::Upgrade { name, from, to } => ("upgrade", format!("{name} {from} to {to}"), name.clone()),
            Change::Downgrade { name, from, to } => ("downgrade", format!("{name} {from} to {to}"), name.clone()),
            Change::Add { name, version } => ("add", format!("{name} {version}"), name.clone()),
            Change::Remove { name } => ("remove", name.clone(), name.clone()),
            Change::Spec { name, from, to } => ("change", format!("{name} {from} to {to}"), name.clone()),
            Change::OverrideAdd { name, value } => ("override", format!("{name} to {value}"), name.clone()),
            Change::OverrideChange { name, from, to } => {
                ("change the override of", format!("{name} {from} to {to}"), name.clone())
            }
            Change::OverrideRemove { name } => ("remove the override of", name.clone(), name.clone()),
            Change::Integrity { name, version } => {
                ("add the checksum of", format!("{name} {version}"), name.clone())
            }
            Change::IgnoreAdd { id, path } => ("ignore", on_path(id, path), id.clone()),
            Change::IgnoreChange { id, path } => ("update the ignore of", on_path(id, path), id.clone()),
            Change::IgnoreRemove { id, path } => ("remove the ignore of", on_path(id, path), id.clone()),
        }
    }
}

/// The order kinds of change appear in a title.
const VERBS: [&str; 12] = [
    "upgrade",
    "downgrade",
    "add",
    "remove",
    "change",
    "override",
    "change the override of",
    "remove the override of",
    "add the checksum of",
    "ignore",
    "update the ignore of",
    "remove the ignore of",
];

/// `a`, `a and b`, `a, b and c`.
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The changes grouped by verb, in title order.
fn groups(changes: &[Change]) -> Vec<(&'static str, Vec<(String, String)>)> {
    let mut out: Vec<(&'static str, Vec<(String, String)>)> = Vec::new();
    for verb in VERBS {
        let items: Vec<(String, String)> = changes
            .iter()
            .map(Change::parts)
            .filter(|(v, ..)| *v == verb)
            .map(|(_, full, name)| (full, name))
            .collect();
        if !items.is_empty() {
            out.push((verb, items));
        }
    }
    out
}

/// A conventional-commit title for `changes`, as specific as fits in 72 characters:
/// with versions, else with names, else with counts.
pub fn title(changes: &[Change]) -> String {
    let groups = groups(changes);
    let fits = |t: String| (t.chars().count() <= TITLE_MAX).then_some(t);
    let phrase = |with_versions: bool| {
        let parts: Vec<String> = groups
            .iter()
            .map(|(verb, items)| {
                let items: Vec<String> = items
                    .iter()
                    .map(|(full, name)| if with_versions { full.clone() } else { name.clone() })
                    .collect();
                format!("{verb} {}", join_and(&items))
            })
            .collect();
        format!("chore: {}", parts.join(", "))
    };
    if let Some(t) = fits(phrase(true)).or_else(|| fits(phrase(false))) {
        return t;
    }
    let is_ignore = |c: &Change| {
        matches!(
            c,
            Change::IgnoreAdd { .. } | Change::IgnoreChange { .. } | Change::IgnoreRemove { .. }
        )
    };
    if changes.iter().all(is_ignore) {
        return "chore: update the Snyk policy".to_string();
    }
    let overrides_only = changes.iter().all(|c| {
        matches!(
            c,
            Change::OverrideAdd { .. } | Change::OverrideRemove { .. } | Change::OverrideChange { .. }
        )
    });
    let noun = if overrides_only { "overrides" } else { "dependencies" };
    match groups.as_slice() {
        [("add the checksum of", items)] => {
            format!("chore: add the integrity checksums of {} packages", items.len())
        }
        [(verb, items)] if !verb.contains("override") || overrides_only => {
            let verb = verb.trim_end_matches(" the override of");
            format!("chore: {verb} {} {noun}", items.len())
        }
        _ => format!("chore: update {noun}"),
    }
}

/// The commit body: every change on a line of its own.
pub fn body(changes: &[Change]) -> String {
    groups(changes)
        .into_iter()
        .flat_map(|(verb, items)| items.into_iter().map(move |(full, _)| format!("- {verb} {full}")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The project's dependencies in a `package.json`: name → spec.
fn deps(manifest: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(map) = manifest.get(field).and_then(Value::as_object) {
            for (name, spec) in map {
                out.entry(name.clone())
                    .or_insert_with(|| spec.as_str().unwrap_or("").to_string());
            }
        }
    }
    out
}

/// What changed from `old` to `new` (`package.json` contents), with the locked versions of
/// the project's packages when known on both sides.
pub fn changes(
    old: &Value,
    new: &Value,
    old_lock: &HashMap<String, Version>,
    new_lock: &HashMap<String, Version>,
    pm: Pm,
) -> Vec<Change> {
    let (before, after) = (deps(old), deps(new));
    let mut out = Vec::new();
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    let spec_version = |spec: &str| parse_spec(spec).map(|(_, v)| v);
    for name in names {
        match (before.get(name), after.get(name)) {
            (None, Some(spec)) => out.push(Change::Add {
                name: name.clone(),
                version: new_lock
                    .get(name)
                    .cloned()
                    .or_else(|| spec_version(spec))
                    .map_or_else(|| spec.clone(), |v| v.to_string()),
            }),
            (Some(_), None) => out.push(Change::Remove { name: name.clone() }),
            (Some(o), Some(n)) => {
                // The installed versions say more than the specs, when both lockfiles have them.
                let (from, to) = match (old_lock.get(name), new_lock.get(name)) {
                    (Some(a), Some(b)) => (Some(a.clone()), Some(b.clone())),
                    _ => (spec_version(o), spec_version(n)),
                };
                match (from, to) {
                    (Some(f), Some(t)) if t > f => out.push(Change::Upgrade {
                        name: name.clone(),
                        from: f.to_string(),
                        to: t.to_string(),
                    }),
                    (Some(f), Some(t)) if t < f => out.push(Change::Downgrade {
                        name: name.clone(),
                        from: f.to_string(),
                        to: t.to_string(),
                    }),
                    _ if o != n => out.push(Change::Spec {
                        name: name.clone(),
                        from: o.clone(),
                        to: n.clone(),
                    }),
                    _ => {}
                }
            }
            (None, None) => {}
        }
    }

    // Overrides, by where they are in package.json.
    let label = |o: &overrides::Override| {
        let mut parts = o.path.clone();
        parts.push(match &o.range {
            Some(r) => format!("{}@{r}", o.name),
            None => o.name.clone(),
        });
        parts.join(" > ")
    };
    let before: BTreeMap<String, overrides::Override> =
        overrides::collect(old, pm).into_iter().map(|o| (o.key(), o)).collect();
    let after: BTreeMap<String, overrides::Override> =
        overrides::collect(new, pm).into_iter().map(|o| (o.key(), o)).collect();
    for (key, o) in &after {
        match before.get(key) {
            None => out.push(Change::OverrideAdd {
                name: label(o),
                value: o.value.clone(),
            }),
            Some(b) if b.value != o.value => out.push(Change::OverrideChange {
                name: label(o),
                from: b.value.clone(),
                to: o.value.clone(),
            }),
            Some(_) => {}
        }
    }
    for (key, o) in &before {
        if !after.contains_key(key) {
            out.push(Change::OverrideRemove { name: label(o) });
        }
    }
    out
}

// ---- git -------------------------------------------------------------------------------

/// A vulnerability an install or override in this session fixed.
#[derive(Clone, Debug, PartialEq)]
pub struct Fixed {
    /// The package whose change fixed it: the dependency that was upgraded, or the package
    /// that was overridden.
    pub package: String,
    pub id: String,
    pub title: String,
    /// `snyk`, `npm audit` or `bun audit`.
    pub source: String,
    pub severity: String,
}

impl Fixed {
    fn line(&self) -> String {
        format!("- {}: {} ({})", self.id, self.title, self.severity)
    }
}

/// What would be committed.
#[derive(Clone, Debug)]
pub struct Plan {
    pub title: String,
    /// The body: the changes, then the vulnerabilities they fix.
    pub body: String,
    /// The list of changes alone.
    pub changes_body: String,
    /// The names of the changed packages and overrides.
    pub names: Vec<String>,
    /// Vulnerabilities fixed by the changes in this commit.
    pub fixes: Vec<Fixed>,
    /// Each change as the title words it with versions (`eslint 8.57.0 to 9.0.0`), to tell
    /// whether a title already says everything the body does.
    pub items: Vec<String>,
    /// The files to commit, relative to the project directory.
    pub files: Vec<String>,
    pub branch: String,
    /// Files staged for something else, which stay out of this commit.
    pub other_staged: Vec<String>,
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    match Command::new("git").args(args).current_dir(dir).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stderr).trim().to_string();
            let out = String::from_utf8_lossy(&o.stdout);
            if !out.trim().is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(out.trim());
            }
            Err(if text.is_empty() {
                format!("`git {}` failed", args.join(" "))
            } else {
                text
            })
        }
        Err(e) => Err(format!("could not run git: {e}")),
    }
}

/// The lockfile names of `pm`, most usual first.
fn lockfiles(pm: Pm) -> &'static [&'static str] {
    match pm {
        Pm::Npm => &["package-lock.json", "npm-shrinkwrap.json"],
        Pm::Pnpm => &["pnpm-lock.yaml"],
        Pm::Yarn => &["yarn.lock"],
        Pm::Bun => &["bun.lock", "bun.lockb"],
    }
}

/// `path` relative to `base` (both absolute), with `..` where needed.
fn relative(path: &Path, base: &Path) -> String {
    let (p, b): (Vec<_>, Vec<_>) = (path.components().collect(), base.components().collect());
    let common = p.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut out = PathBuf::new();
    for _ in common..b.len() {
        out.push("..");
    }
    for c in &p[common..] {
        out.push(c);
    }
    out.to_string_lossy().into_owned()
}

/// What changed between two versions of a `.snyk` file.
pub fn policy_changes(old: &str, new: &str) -> Vec<Change> {
    use crate::security::policy::rules_from_text;
    let (old, new) = (rules_from_text(old), rules_from_text(new));
    let same = |a: &crate::security::policy::Ignore, b: &crate::security::policy::Ignore| {
        a.id == b.id && a.path == b.path
    };
    let mut out = Vec::new();
    for n in &new {
        match old.iter().find(|o| same(o, n)) {
            None => out.push(Change::IgnoreAdd { id: n.id.clone(), path: n.path.clone() }),
            Some(o) if o.reason != n.reason || o.expires != n.expires => {
                out.push(Change::IgnoreChange { id: n.id.clone(), path: n.path.clone() })
            }
            Some(_) => {}
        }
    }
    for o in &old {
        if !new.iter().any(|n| same(o, n)) {
            out.push(Change::IgnoreRemove { id: o.id.clone(), path: o.path.clone() });
        }
    }
    out
}
/// Looks at what changed since the last commit, and proposes the commit.
pub fn prepare(dir: &Path, pm: Pm) -> Result<Plan, String> {
    let top = git(dir, &["rev-parse", "--show-toplevel"])
        .map_err(|_| format!("{} is not in a git repository", dir.display()))?;
    let top = PathBuf::from(top.trim());
    let top = top.canonicalize().unwrap_or(top);
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());

    // A workspace member's lockfile lives in the workspace root, somewhere up to the repo root.
    let lock = dir
        .ancestors()
        .take_while(|a| a.starts_with(&top))
        .flat_map(|a| lockfiles(pm).iter().map(move |n| a.join(n)))
        .find(|p| p.is_file());
    let mut files = vec!["package.json".to_string()];
    if let Some(l) = &lock {
        files.push(relative(l, &dir));
    }
    // The Snyk policy, when there is one now or at the last commit.
    if dir.join(".snyk").exists() || git(&dir, &["cat-file", "-e", "HEAD:./.snyk"]).is_ok() {
        files.push(".snyk".to_string());
    }
    let mut args = vec!["status", "--porcelain", "--"];
    args.extend(files.iter().map(String::as_str));
    let status = git(&dir, &args)?;
    // Only the files that changed are committed.
    let changed: Vec<String> = files
        .iter()
        .filter(|f| {
            let full = relative(&dir.join(f), &top);
            status.lines().any(|l| l.get(3..).is_some_and(|p| p.trim_matches('"') == full))
        })
        .cloned()
        .collect();

    let at_head = |file: &str| git(&dir, &["show", &format!("HEAD:./{file}")]).ok();
    let parse = |text: Option<String>| -> Value {
        text.and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Object(Default::default()))
    };
    let old = parse(at_head("package.json"));
    let new = parse(std::fs::read_to_string(dir.join("package.json")).ok());
    let lock_versions = |text: Option<String>| {
        text.and_then(|t| crate::deps::tree::npm_lock_versions_from(&t))
            .unwrap_or_default()
    };
    let (old_lock, new_lock) = match &lock {
        Some(l) if pm == Pm::Npm => {
            let rel = relative(l, &dir);
            (lock_versions(at_head(&rel)), lock_versions(std::fs::read_to_string(l).ok()))
        }
        _ => (HashMap::new(), HashMap::new()),
    };
    let mut changes = if changed.is_empty() {
        Vec::new()
    } else {
        changes(&old, &new, &old_lock, &new_lock, pm)
    };
    if changed.iter().any(|f| f == ".snyk") {
        let now = std::fs::read_to_string(dir.join(".snyk")).unwrap_or_default();
        changes.extend(policy_changes(&at_head(".snyk").unwrap_or_default(), &now));
    }
    // Checksums the lockfile got since the last commit (e.g. depsu's `I`).
    if let Some(l) = &lock {
        let rel = relative(l, &dir);
        if changed.contains(&rel) {
            let file = l.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let (before, now) = (at_head(&rel).unwrap_or_default(), std::fs::read_to_string(l).unwrap_or_default());
            for (name, version) in crate::deps::info::integrity_added(&file, &before, &now) {
                changes.push(Change::Integrity { name, version: version.to_string() });
            }
        }
    }

    let branch = git(&dir, &["symbolic-ref", "--short", "HEAD"])
        .map(|b| b.trim().to_string())
        .unwrap_or_else(|_| "a detached HEAD".to_string());
    let ours: Vec<String> = changed.iter().map(|f| relative(&dir.join(f), &top)).collect();
    let other_staged = git(&dir, &["diff", "--cached", "--name-only"])
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty() && !ours.iter().any(|o| o == l))
        .map(String::from)
        .collect();
    Ok(Plan {
        title: title(&changes),
        body: body(&changes),
        changes_body: body(&changes),
        names: changes.iter().map(|c| c.parts().2).collect(),
        fixes: Vec::new(),
        items: changes.iter().map(|c| c.parts().1).collect(),
        files: changed,
        branch,
        other_staged,
    })
}

/// `item` appears in `title` as a whole: not as the end of a longer package name.
fn mentions(title: &str, item: &str) -> bool {
    title.match_indices(item).any(|(i, _)| {
        let before = title[..i].chars().next_back();
        let after = title[i + item.len()..].chars().next();
        before.is_none_or(|c| c == ' ' || c == ',')
            && after.is_none_or(|c| c == ' ' || c == ',' || c == ')')
    })
}

impl Plan {
    /// Adds the vulnerabilities fixed by the changes in this commit to the body: those of the
    /// changed packages, once each.
    pub fn with_fixes(mut self, fixed: &[Fixed]) -> Plan {
        self.fixes = Vec::new();
        for f in fixed {
            if self.names.contains(&f.package)
                && !self.fixes.iter().any(|x| x.id == f.id && x.package == f.package)
            {
                self.fixes.push(f.clone());
            }
        }
        self.body = self.changes_body.clone();
        if !self.fixes.is_empty() {
            let lines = fix_lines(self.fixes.iter());
            if !self.body.is_empty() {
                self.body.push_str("\n\n");
            }
            self.body.push_str(&format!("Fixes:\n{}", lines.join("\n")));
        }
        self.body = wrap(&self.body);
        self
    }
}

/// The body to commit with `title`, without what the title already says: the list of changes
/// goes when the title names every change with its versions, and a fixed vulnerability goes
/// when the title mentions its ID. `None` when nothing is left.
pub fn body_for(plan: &Plan, title: &str) -> Option<String> {
    let mut parts = Vec::new();
    if !plan.changes_body.is_empty() && !title_has_changes(plan, title) {
        parts.push(plan.changes_body.clone());
    }
    let fixes = fixes_for(plan, title);
    if !fixes.is_empty() {
        let lines = fix_lines(fixes.into_iter());
        parts.push(format!("Fixes:\n{}", lines.join("\n")));
    }
    (!parts.is_empty()).then(|| wrap(&parts.join("\n\n")))
}
/// Longest line of a commit body.
const BODY_MAX: usize = 100;
/// The lines of `fixes`, each distinct line once: the same vulnerability can be fixed through
/// several packages.
fn fix_lines<'a>(fixes: impl Iterator<Item = &'a Fixed>) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for l in fixes.map(Fixed::line) {
        if !lines.contains(&l) {
            lines.push(l);
        }
    }
    lines
}
/// Breaks lines longer than `BODY_MAX` characters at spaces. A list item's continuation lines
/// are indented under its text.
fn wrap(body: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        if line.chars().count() <= BODY_MAX {
            out.push(line.to_string());
            continue;
        }
        let indent = if line.starts_with("- ") { "  " } else { "" };
        let mut cur = String::new();
        for word in line.split(' ') {
            let used = cur.chars().count();
            if !cur.is_empty() && used + 1 + word.chars().count() > BODY_MAX {
                out.push(std::mem::take(&mut cur));
                cur.push_str(indent);
            } else if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
            // A word longer than a line is cut.
            while cur.chars().count() > BODY_MAX {
                let head: String = cur.chars().take(BODY_MAX).collect();
                cur = format!("{indent}{}", cur.chars().skip(BODY_MAX).collect::<String>());
                out.push(head);
            }
        }
        out.push(cur);
    }
    out.join("\n")
}

/// The title names every change with its versions.
pub fn title_has_changes(plan: &Plan, title: &str) -> bool {
    !plan.items.is_empty() && plan.items.iter().all(|i| mentions(title, i))
}

/// The fixed vulnerabilities the body lists: those the title doesn't mention.
pub fn fixes_for<'a>(plan: &'a Plan, title: &str) -> Vec<&'a Fixed> {
    plan.fixes.iter().filter(|f| !title.contains(&f.id)).collect()
}

/// Commits the plan's files with `title` and `body` (none when `None`). Returns the new
/// commit's short hash.
pub fn run(dir: &Path, plan: &Plan, title: &str, body: Option<&str>) -> Result<String, String> {
    let mut add = vec!["add", "-A", "--"];
    add.extend(plan.files.iter().map(String::as_str));
    git(dir, &add)?;
    let mut commit = vec!["commit", "-m", title];
    if let Some(body) = body {
        commit.extend(["-m", body]);
    }
    // With paths, git commits only those files, whatever else is staged.
    commit.push("--");
    commit.extend(plan.files.iter().map(String::as_str));
    git(dir, &commit)?;
    Ok(git(dir, &["rev-parse", "--short", "HEAD"])?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn policy_edits_become_changes() {
        let a = "version: v1.25.0\nignore:\n  A:\n    - '*':\n        reason: r\n  B:\n    - '*':\n        reason: r\n";
        let b = "version: v1.25.0\nignore:\n  A:\n    - '*':\n        reason: new\n  C:\n    - x > y:\n        reason: r\n";
        let c = policy_changes(a, b);
        assert_eq!(
            c,
            vec![
                Change::IgnoreChange { id: "A".into(), path: "*".into() },
                Change::IgnoreAdd { id: "C".into(), path: "x > y".into() },
                Change::IgnoreRemove { id: "B".into(), path: "*".into() },
            ]
        );
        assert_eq!(title(&c[..1]), "chore: update the ignore of A");
        assert_eq!(title(&c[1..2]), "chore: ignore C on x > y");
    }

    fn up(name: &str, from: &str, to: &str) -> Change {
        Change::Upgrade {
            name: name.into(),
            from: from.into(),
            to: to.into(),
        }
    }

    #[test]
    fn one_upgrade_names_the_package_and_both_versions() {
        assert_eq!(title(&[up("eslint", "8.9.0", "9.0.0")]), "chore: upgrade eslint 8.9.0 to 9.0.0");
    }

    #[test]
    fn several_changes_of_a_kind_share_the_verb() {
        let t = title(&[up("eslint", "8.57.0", "9.0.0"), up("prettier", "3.2.0", "3.3.3")]);
        assert_eq!(t, "chore: upgrade eslint 8.57.0 to 9.0.0 and prettier 3.2.0 to 3.3.3");
    }

    #[test]
    fn titles_get_less_specific_to_fit_72_characters() {
        let many: Vec<Change> = ["eslint", "prettier", "typescript", "vite"]
            .iter()
            .map(|n| up(n, "1.0.0", "2.0.0"))
            .collect();
        assert_eq!(title(&many), "chore: upgrade eslint, prettier, typescript and vite");
        let lots: Vec<Change> = (0..12).map(|i| up(&format!("package-{i}"), "1.0.0", "2.0.0")).collect();
        assert_eq!(title(&lots), "chore: upgrade 12 dependencies");
        for t in [title(&many), title(&lots)] {
            assert!(t.chars().count() <= 72, "{t}");
        }
    }

    #[test]
    fn mixed_changes_list_each_kind() {
        let changes = [
            up("eslint", "8.57.0", "9.0.0"),
            Change::Add {
                name: "lodash".into(),
                version: "4.17.21".into(),
            },
            Change::Remove { name: "left-pad".into() },
        ];
        // With versions it would be 74 characters: names only.
        assert_eq!(title(&changes), "chore: upgrade eslint, add lodash, remove left-pad");
        let short = [
            up("vite", "5.0.0", "5.1.0"),
            Change::Add {
                name: "zod".into(),
                version: "3.23.8".into(),
            },
        ];
        assert_eq!(title(&short), "chore: upgrade vite 5.0.0 to 5.1.0, add zod 3.23.8");
        assert_eq!(
            body(&changes),
            "- upgrade eslint 8.57.0 to 9.0.0\n- add lodash 4.17.21\n- remove left-pad"
        );
        let lots: Vec<Change> = (0..8)
            .map(|i| up(&format!("package-{i}"), "1.0.0", "2.0.0"))
            .chain([Change::Remove { name: "left-pad".into() }])
            .collect();
        assert_eq!(title(&lots), "chore: update dependencies");
    }

    #[test]
    fn overrides_have_their_own_wording() {
        let t = title(&[Change::OverrideAdd {
            name: "qs".into(),
            value: "6.14.1".into(),
        }]);
        assert_eq!(t, "chore: override qs to 6.14.1");
        let t = title(&[Change::OverrideRemove { name: "qs".into() }]);
        assert_eq!(t, "chore: remove the override of qs");
    }

    #[test]
    fn package_json_and_lockfile_differences_become_changes() {
        let old = json!({
            "dependencies": {"react": "^18.2.0", "left-pad": "^1.3.0", "zod": "^3.22.0"},
            "devDependencies": {"eslint": "^8.57.0", "typescript": "5.4.5"},
            "overrides": {"qs": "6.11.0", "gone": "1.0.0"}
        });
        let new = json!({
            "dependencies": {"react": "^18.2.0", "lodash": "^4.17.21", "zod": "~3.22.0"},
            "devDependencies": {"eslint": "^9.0.0", "typescript": "5.3.3"},
            "overrides": {"qs": "6.14.1", "minimist": "1.2.8"}
        });
        let v = |s: &str| Version::parse(s).unwrap();
        // react's range didn't change, but the lockfile moved it.
        let old_lock = HashMap::from([("react".to_string(), v("18.2.0")), ("eslint".to_string(), v("8.57.1"))]);
        let new_lock = HashMap::from([
            ("react".to_string(), v("18.3.1")),
            ("eslint".to_string(), v("9.0.0")),
            ("lodash".to_string(), v("4.17.21")),
        ]);
        let c = changes(&old, &new, &old_lock, &new_lock, Pm::Npm);
        assert_eq!(
            c,
            [
                up("eslint", "8.57.1", "9.0.0"),
                Change::Remove { name: "left-pad".into() },
                Change::Add {
                    name: "lodash".into(),
                    version: "4.17.21".into()
                },
                up("react", "18.2.0", "18.3.1"),
                Change::Downgrade {
                    name: "typescript".into(),
                    from: "5.4.5".into(),
                    to: "5.3.3".into()
                },
                Change::Spec {
                    name: "zod".into(),
                    from: "^3.22.0".into(),
                    to: "~3.22.0".into()
                },
                Change::OverrideAdd {
                    name: "minimist".into(),
                    value: "1.2.8".into()
                },
                Change::OverrideChange {
                    name: "qs".into(),
                    from: "6.11.0".into(),
                    to: "6.14.1".into()
                },
                Change::OverrideRemove { name: "gone".into() },
            ]
        );
    }

    fn plan_for(changes: &[Change]) -> Plan {
        Plan {
            title: title(changes),
            body: body(changes),
            changes_body: body(changes),
            names: changes.iter().map(|c| c.parts().2).collect(),
            fixes: Vec::new(),
            items: changes.iter().map(|c| c.parts().1).collect(),
            files: vec!["package.json".into()],
            branch: "main".into(),
            other_staged: Vec::new(),
        }
    }

    #[test]
    fn added_checksums_have_their_own_wording() {
        let sum = |n: &str| Change::Integrity { name: n.into(), version: "1.0.0".into() };
        assert_eq!(title(&[sum("a")]), "chore: add the checksum of a 1.0.0");
        assert_eq!(
            title(&[up("eslint", "9.0.0", "9.0.1"), sum("a")]),
            "chore: upgrade eslint 9.0.0 to 9.0.1, add the checksum of a 1.0.0"
        );
        // Over 72 characters with the versions: the names say it.
        assert_eq!(
            title(&[up("@typescript-eslint/parser", "8.57.0", "9.0.0"), sum("a")]),
            "chore: upgrade @typescript-eslint/parser, add the checksum of a"
        );
        let many: Vec<Change> = (0..9).map(|i| sum(&format!("some-long-package-{i}"))).collect();
        assert_eq!(title(&many), "chore: add the integrity checksums of 9 packages");
        assert_eq!(
            body(&[sum("a"), sum("b")]),
            "- add the checksum of a 1.0.0\n- add the checksum of b 1.0.0"
        );
    }
    #[test]
    fn the_body_is_left_out_when_the_title_already_says_it_all() {
        // One change.
        let p = plan_for(&[up("eslint", "8.57.0", "9.0.0")]);
        assert_eq!(body_for(&p, &p.title), None);
        // Two, both with versions in the title.
        let p = plan_for(&[up("eslint", "8.57.0", "9.0.0"), up("prettier", "3.2.0", "3.3.3")]);
        assert_eq!(p.title, "chore: upgrade eslint 8.57.0 to 9.0.0 and prettier 3.2.0 to 3.3.3");
        assert_eq!(body_for(&p, &p.title), None);
        // Another type or a scope doesn't matter, only the changes do.
        assert_eq!(body_for(&p, "fix(deps): upgrade eslint 8.57.0 to 9.0.0 and prettier 3.2.0 to 3.3.3"), None);
    }

    fn fixed(package: &str, id: &str) -> Fixed {
        Fixed {
            package: package.into(),
            id: id.into(),
            title: "Prototype Pollution".into(),
            source: "snyk".into(),
            severity: "high".into(),
        }
    }

    #[test]
    fn a_vulnerability_fixed_through_two_packages_is_listed_once() {
        let p = plan_for(&[up("a", "1.0.0", "2.0.0"), up("b", "1.0.0", "2.0.0")])
            .with_fixes(&[fixed("a", "SNYK-1"), fixed("b", "SNYK-1")]);
        assert_eq!(p.body.matches("SNYK-1").count(), 1, "{}", p.body);
        assert_eq!(body_for(&p, "x").unwrap().matches("SNYK-1").count(), 1);
    }
    #[test]
    fn long_body_lines_are_wrapped_at_100_characters() {
        let mut f = fixed("lodash", "SNYK-1");
        f.title = "very long title ".repeat(12);
        let p = plan_for(&[up("lodash", "4.17.15", "4.17.21")]).with_fixes(&[f]);
        let body = body_for(&p, "x").unwrap();
        assert!(body.lines().all(|l| l.chars().count() <= 100), "{body}");
        assert!(body.lines().count() > 3, "{body}");
        assert!(p.body.lines().all(|l| l.chars().count() <= 100));
    }
    #[test]
    fn fixed_vulnerabilities_are_listed_in_the_body() {
        let p = plan_for(&[up("lodash", "4.17.15", "4.17.21")]).with_fixes(&[
            fixed("lodash", "SNYK-JS-LODASH-1040724"),
            fixed("lodash", "SNYK-JS-LODASH-1040724"),
            // Another package's fix isn't part of this commit.
            fixed("express", "SNYK-JS-QS-3153490"),
        ]);
        assert_eq!(
            p.body,
            "- upgrade lodash 4.17.15 to 4.17.21\n\nFixes:\n- SNYK-JS-LODASH-1040724: Prototype Pollution (high)"
        );
        // The title names the change, so the body has only what the title can't say.
        assert_eq!(p.title, "chore: upgrade lodash 4.17.15 to 4.17.21");
        assert_eq!(
            body_for(&p, &p.title).as_deref(),
            Some("Fixes:\n- SNYK-JS-LODASH-1040724: Prototype Pollution (high)")
        );
        // A title without the versions gets both.
        assert_eq!(body_for(&p, "fix: upgrade lodash").as_deref(), Some(p.body.as_str()));
        // A title naming the vulnerability doesn't get it repeated either.
        assert_eq!(
            body_for(&p, "fix: upgrade lodash 4.17.15 to 4.17.21 (SNYK-JS-LODASH-1040724)"),
            None
        );
        assert_eq!(
            body_for(&p, "fix: SNYK-JS-LODASH-1040724").as_deref(),
            Some("- upgrade lodash 4.17.15 to 4.17.21")
        );
        // Without fixes it's left out again.
        let p = p.with_fixes(&[]);
        assert_eq!(body_for(&p, &p.title), None);
    }

    #[test]
    fn the_body_stays_when_it_says_more_than_the_title() {
        // A title with names only.
        let many: Vec<Change> = ["eslint", "prettier", "typescript", "vite"]
            .iter()
            .map(|n| up(n, "1.0.0", "2.0.0"))
            .collect();
        let p = plan_for(&many);
        assert_eq!(p.title, "chore: upgrade eslint, prettier, typescript and vite");
        assert_eq!(body_for(&p, &p.title), Some(p.body.clone()));
        // A title the user edited the versions out of.
        let p = plan_for(&[up("eslint", "8.57.0", "9.0.0")]);
        assert_eq!(
            body_for(&p, "chore: upgrade eslint to v9").as_deref(),
            Some("- upgrade eslint 8.57.0 to 9.0.0")
        );
        // A longer package name containing the change's text doesn't count.
        let p = plan_for(&[up("lint", "1.0.0", "2.0.0")]);
        assert!(body_for(&p, "chore: upgrade eslint 1.0.0 to 2.0.0").is_some());
    }

    #[test]
    fn nothing_changed_gives_no_changes() {
        let m = json!({"dependencies": {"a": "^1.0.0"}});
        assert!(changes(&m, &m, &HashMap::new(), &HashMap::new(), Pm::Npm).is_empty());
    }

    // ---- with a real git repository ---------------------------------------------------

    fn sh(dir: &Path, args: &[&str]) -> String {
        let o = Command::new("git").args(args).current_dir(dir).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }
    /// A repository with a committed project in `app/`, as in a monorepo.
    fn repo(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("depsu-git-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("app");
        std::fs::create_dir_all(&dir).unwrap();
        sh(&root, &["init", "-q", "-b", "main"]);
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")] {
            sh(&root, &["config", k, v]);
        }
        std::fs::write(dir.join("package.json"), r#"{"devDependencies":{"eslint":"^8.57.0"}}"#).unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/eslint":{"version":"8.57.1"}}}"#,
        )
        .unwrap();
        std::fs::write(root.join("README.md"), "hi\n").unwrap();
        sh(&root, &["add", "-A"]);
        sh(&root, &["commit", "-q", "-m", "init"]);
        (root, dir)
    }

    #[test]
    fn commits_package_json_and_the_lockfile_only() {
        let (root, dir) = repo("commit");
        std::fs::write(dir.join("package.json"), r#"{"devDependencies":{"eslint":"^9.0.0"}}"#).unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/eslint":{"version":"9.0.0"}}}"#,
        )
        .unwrap();
        // Unrelated work: one file staged, one not.
        std::fs::write(root.join("README.md"), "changed\n").unwrap();
        std::fs::write(root.join("notes.txt"), "wip\n").unwrap();
        sh(&root, &["add", "notes.txt"]);

        let plan = prepare(&dir, Pm::Npm).unwrap();
        assert_eq!(plan.title, "chore: upgrade eslint 8.57.1 to 9.0.0");
        assert_eq!(plan.files, ["package.json", "package-lock.json"]);
        assert_eq!(plan.branch, "main");
        assert_eq!(plan.other_staged, ["notes.txt"]);

        let hash = run(&dir, &plan, &plan.title, body_for(&plan, &plan.title).as_deref()).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(sh(&root, &["log", "-1", "--format=%s"]), "chore: upgrade eslint 8.57.1 to 9.0.0");
        // The title says it all: no body repeating it.
        assert_eq!(sh(&root, &["log", "-1", "--format=%b"]), "");
        let files = sh(&root, &["show", "--name-only", "--format=", "HEAD"]);
        assert_eq!(files, "app/package-lock.json\napp/package.json");
        // The rest is where it was: notes.txt still staged, README.md still modified.
        let status = sh(&root, &["status", "--porcelain"]);
        assert!(status.contains("A  notes.txt"), "{status}");
        assert!(status.lines().any(|l| l.trim_start() == "M README.md"), "{status}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_checksum_added_to_the_lockfile_is_committed_with_its_own_title() {
        // The committed lockfile has no checksum for eslint; now it has one.
        let (root, dir) = repo("integrity");
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/eslint":{"version":"8.57.1","integrity":"sha512-e"}}}"#,
        )
        .unwrap();
        let plan = prepare(&dir, Pm::Npm).unwrap();
        assert_eq!(plan.title, "chore: add the checksum of eslint 8.57.1");
        assert_eq!(plan.files, ["package-lock.json"], "package.json didn't change");
        assert!(title_has_changes(&plan, &plan.title));
        run(&dir, &plan, &plan.title, body_for(&plan, &plan.title).as_deref()).unwrap();
        assert_eq!(sh(&root, &["log", "-1", "--format=%s"]), "chore: add the checksum of eslint 8.57.1");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn nothing_to_commit_when_the_files_are_unchanged() {
        let (root, dir) = repo("clean");
        let plan = prepare(&dir, Pm::Npm).unwrap();
        assert!(plan.files.is_empty() && plan.body.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn outside_a_repository_says_so() {
        let dir = std::env::temp_dir().join(format!("depsu-no-git-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The temp dir itself might be inside a repo on some machines; only check the message
        // when it isn't.
        if git(&dir, &["rev-parse", "--show-toplevel"]).is_err() {
            assert!(prepare(&dir, Pm::Npm).unwrap_err().contains("is not in a git repository"));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
