//! Grouping and filtering of the outdated-package list into display items.

use crate::app::Row;
use crate::package::Kind;
use crate::vuln::Source;
use semver::Version;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupBy {
    None,
    Release,
    Prefix,
    /// Dependencies, dev dependencies and optional dependencies.
    Kind,
}

impl GroupBy {
    pub fn next(self) -> Self {
        match self {
            GroupBy::None => GroupBy::Release,
            GroupBy::Release => GroupBy::Prefix,
            GroupBy::Prefix => GroupBy::Kind,
            GroupBy::Kind => GroupBy::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            GroupBy::None => "none",
            GroupBy::Release => "release type",
            GroupBy::Prefix => "name prefix",
            GroupBy::Kind => "dependency type",
        }
    }
}

/// How much of the override information is listed under each package.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Overrides {
    Off,
    /// Own overrides plus the first few overrides found in the dependency tree.
    Compact,
    Full,
}

impl Overrides {
    pub fn next(self) -> Self {
        match self {
            Overrides::Compact => Overrides::Full,
            Overrides::Full => Overrides::Off,
            Overrides::Off => Overrides::Compact,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Overrides::Off => "hidden",
            Overrides::Compact => "compact",
            Overrides::Full => "full",
        }
    }
}

/// Tree hits listed per package in compact mode.
const COMPACT_TREE_HITS: usize = 5;

/// A nested entry under a package.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Child {
    /// `Row::overrides[i]`: an override on the package itself.
    Own(usize),
    /// `Row::tree_hits[i]`: an override somewhere in its dependency tree.
    Tree(usize),
    /// Number of tree hits not listed.
    More(usize),
    /// `Row::vulns[i]`: a Snyk finding.
    Vuln(usize),
    /// Number of Snyk findings not listed.
    MoreVulns(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Release {
    Patch,
    Minor,
    Major,
}

impl Release {
    pub fn of(current: &Version, latest: &Version) -> Self {
        if latest.major > current.major {
            Release::Major
        } else if latest.minor > current.minor {
            Release::Minor
        } else {
            Release::Patch
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Release::Patch => "Patch",
            Release::Minor => "Minor",
            Release::Major => "Major",
        }
    }
}

/// One line in the list. `idx` and `members` index into `App::rows`.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Header {
        label: String,
        members: Vec<usize>,
    },
    Row {
        idx: usize,
        name: String,
    },
    /// A package uninstalled in this session, in the removed section; `r` restores it.
    Removed {
        name: String,
    },
    /// An override listed on its own, in the section of overrides that look unnecessary.
    Override {
        key: String,
    },
    /// Override line nested under the package `rows[idx]`. It can hold the cursor only when
    /// the override can be updated (decided by the app).
    Detail {
        idx: usize,
        child: Child,
        last: bool,
        /// Package name and override key: identity that survives list rebuilds.
        row: String,
        key: String,
    },
}

/// Which vulnerability findings are listed under the packages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VulnView {
    All,
    SnykOnly,
    AuditOnly,
    Hidden,
}
impl VulnView {
    pub fn next(self) -> Self {
        match self {
            VulnView::All => VulnView::SnykOnly,
            VulnView::SnykOnly => VulnView::AuditOnly,
            VulnView::AuditOnly => VulnView::Hidden,
            VulnView::Hidden => VulnView::All,
        }
    }
    pub fn allows(self, source: Source) -> bool {
        match self {
            VulnView::All => true,
            VulnView::SnykOnly => source == Source::Snyk,
            VulnView::AuditOnly => source.is_audit(),
            VulnView::Hidden => false,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            VulnView::All => "all",
            VulnView::SnykOnly => "snyk only",
            VulnView::AuditOnly => "audit only",
            VulnView::Hidden => "hidden",
        }
    }
}
impl From<bool> for VulnView {
    fn from(shown: bool) -> Self {
        if shown { VulnView::All } else { VulnView::Hidden }
    }
}
fn children(r: &Row, idx: usize, mode: Overrides, vulns: VulnView) -> Vec<Item> {
    let cap = if mode == Overrides::Full {
        usize::MAX
    } else {
        COMPACT_TREE_HITS
    };
    let mut kids: Vec<Child> = Vec::new();
    // Security findings first: they matter more than where overrides apply.
    let shown: Vec<usize> = (0..r.vulns.len())
        .filter(|&i| vulns.allows(r.vulns[i].source))
        .collect();
    kids.extend(shown.iter().take(cap).copied().map(Child::Vuln));
    if shown.len() > cap {
        kids.push(Child::MoreVulns(shown.len() - cap));
    }
    if mode != Overrides::Off {
        if r.lists_own_overrides() {
            kids.extend((0..r.overrides.len()).map(Child::Own));
        }
        kids.extend((0..r.tree_hits.len().min(cap)).map(Child::Tree));
        if r.tree_hits.len() > cap {
            kids.push(Child::More(r.tree_hits.len() - cap));
        }
    }
    let n = kids.len();
    kids.into_iter()
        .enumerate()
        .map(|(i, child)| Item::Detail {
            idx,
            child,
            last: i + 1 == n,
            row: r.name.clone(),
            key: match child {
                Child::Own(i) => r.overrides[i].key(),
                Child::Tree(i) => r.tree_hits[i].over.key(),
                Child::Vuln(i) => format!("vuln:{}", r.vulns[i].id),
                Child::More(_) | Child::MoreVulns(_) => String::new(),
            },
        })
        .collect()
}

const OTHER: &str = "(other)";
pub const UP_TO_DATE: &str = "Up to date";
/// Label of the section listing overridden packages that aren't dependencies.
pub const OVERRIDDEN: &str = "Overridden packages";
/// Label of the section listing overrides that look unnecessary.
pub const UNNEEDED: &str = "Unneeded overrides";
pub const REMOVED: &str = "Removed this session";

/// Group label for a package name. Scoped packages group by scope; unscoped ones by the
/// text before the first `-`, but only when at least two outdated packages share it.
fn prefix_label(name: &str, counts: &HashMap<&str, usize>) -> String {
    if name.starts_with('@')
        && let Some((scope, _)) = name.split_once('/')
    {
        return scope.to_string();
    }
    let seg = name.split('-').next().unwrap_or(name);
    if counts.get(seg).copied().unwrap_or(0) >= 2 {
        format!("{seg}-*")
    } else {
        OTHER.to_string()
    }
}

/// Builds the list. Up-to-date packages (shown only because they have overrides) are
/// hidden unless `uptodate` is set; they sort after outdated ones.
pub fn build(
    rows: &[Row],
    mode: GroupBy,
    filter: &str,
    ov: Overrides,
    uptodate: bool,
    vulns: impl Into<VulnView>,
) -> Vec<Item> {
    let vulns = vulns.into();
    let needle = filter.trim().to_lowercase();
    let mut visible: Vec<usize> = (0..rows.len())
        .filter(|&i| uptodate || rows[i].outdated)
        .filter(|&i| needle.is_empty() || rows[i].name.to_lowercase().contains(&needle))
        .collect();
    visible.sort_by_key(|&i| !rows[i].outdated); // stable: outdated first
    // Overridden packages that aren't dependencies go in a section of their own at the end.
    let (over, visible): (Vec<usize>, Vec<usize>) = visible
        .into_iter()
        .partition(|&i| rows[i].kind == Kind::Override);
    // A package row followed by its nested override lines.
    let item = |i: usize| {
        let mut v = vec![Item::Row {
            idx: i,
            name: rows[i].name.clone(),
        }];
        v.extend(children(&rows[i], i, ov, vulns));
        v
    };

    let mut out = if mode == GroupBy::None {
        visible.into_iter().flat_map(item).collect()
    } else {
        grouped(rows, mode, visible, &item)
    };
    if !over.is_empty() {
        out.push(Item::Header {
            label: OVERRIDDEN.to_string(),
            members: over.clone(),
        });
        out.extend(over.into_iter().flat_map(item));
    }
    out
}
fn grouped(
    rows: &[Row],
    mode: GroupBy,
    visible: Vec<usize>,
    item: &dyn Fn(usize) -> Vec<Item>,
) -> Vec<Item> {

    // (sort key, label) -> members
    let mut groups: Vec<((u8, String), Vec<usize>)> = Vec::new();
    // Prefix counts cover all rows, so groups don't change shape while filtering.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    if mode == GroupBy::Prefix {
        for r in rows.iter().filter(|r| !r.name.starts_with('@')) {
            *counts
                .entry(r.name.split('-').next().unwrap_or(&r.name))
                .or_default() += 1;
        }
    }
    for i in visible {
        let key = match mode {
            GroupBy::Release if !rows[i].outdated => (3, UP_TO_DATE.to_string()),
            GroupBy::Release => {
                let rel = rows[i].release();
                (rel as u8, rel.label().to_string())
            }
            GroupBy::Kind => match rows[i].kind {
                Kind::Prod => (0, "Dependencies".to_string()),
                Kind::Dev => (1, "Dev dependencies".to_string()),
                Kind::Optional => (2, "Optional dependencies".to_string()),
                Kind::Override => (3, OVERRIDDEN.to_string()),
            },
            _ => {
                let label = prefix_label(&rows[i].name, &counts);
                (u8::from(label == OTHER), label)
            }
        };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, m)) => m.push(i),
            None => groups.push((key, vec![i])),
        }
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for ((_, label), mut members) in groups {
        members.sort_by(|&a, &b| rows[a].name.cmp(&rows[b].name));
        out.push(Item::Header {
            label,
            members: members.clone(),
        });
        out.extend(members.into_iter().flat_map(|i| item(i)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Status;
    use crate::overrides::Compat;
    use crate::package::Kind;

    fn row(name: &str, cur: &str, latest: &str) -> Row {
        Row {
            name: name.into(),
            kind: Kind::Prod,
            prefix: "^",
            current: Version::parse(cur).unwrap(),
            latest: Version::parse(latest).unwrap(),
            selected: false,
            status: Status::Idle,
            overrides: Vec::new(),
            compat: Compat::Ok,
            tree_hits: Vec::new(),
            outdated: true,
            vulns: Vec::new(),
            snyk_fix: None,
            audit_fix: None,
            changed_from: None,
        }
    }

    fn labels(items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                Item::Header { label, .. } => format!("# {label}"),
                Item::Row { name, .. } => name.clone(),
                Item::Detail { child, .. } => format!("  - {child:?}"),
                Item::Override { key } => format!("  ✂ {key}"),
                Item::Removed { name } => format!("  ↩ {name}"),
            })
            .collect()
    }

    fn sample() -> Vec<Row> {
        vec![
            row("@babel/core", "7.0.0", "7.1.0"),
            row("@babel/cli", "7.0.0", "7.0.1"),
            row("eslint-plugin-a", "1.0.0", "2.0.0"),
            row("eslint", "8.0.0", "8.0.5"),
            row("lodash", "4.0.0", "4.1.0"),
        ]
    }

    #[test]
    fn release_types() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert_eq!(Release::of(&v("1.2.3"), &v("2.0.0")), Release::Major);
        assert_eq!(Release::of(&v("1.2.3"), &v("1.3.0")), Release::Minor);
        assert_eq!(Release::of(&v("1.2.3"), &v("1.2.4")), Release::Patch);
    }

    #[test]
    fn overridden_packages_form_a_last_section() {
        let mut rows = sample();
        let mut o = row("zlib-x", "1.0.0", "1.1.0");
        o.kind = Kind::Override;
        rows.insert(0, o);
        for mode in [GroupBy::None, GroupBy::Release] {
            let items = build(&rows, mode, "", Overrides::Off, true, true);
            let l = labels(&items);
            let at = l.iter().position(|x| x == &format!("# {OVERRIDDEN}")).unwrap();
            assert_eq!(l[at + 1..], ["zlib-x"], "{mode:?}");
            assert!(l[..at].iter().all(|x| x != "zlib-x"));
        }
    }

    #[test]
    fn groups_by_dependency_type_with_overrides_last() {
        let mut rows = sample();
        rows[1].kind = Kind::Dev;
        rows[2].kind = Kind::Optional;
        let mut o = row("zlib-x", "1.0.0", "1.1.0");
        o.kind = Kind::Override;
        rows.push(o);
        let items = build(&rows, GroupBy::Kind, "", Overrides::Off, true, true);
        let l: Vec<String> = labels(&items)
            .into_iter()
            .filter(|x| x.starts_with('#'))
            .collect();
        assert_eq!(
            l,
            [
                "# Dependencies",
                "# Dev dependencies",
                "# Optional dependencies",
                "# Overridden packages"
            ]
        );
    }

    #[test]
    fn groups_by_release_patch_first() {
        let items = build(
            &sample(),
            GroupBy::Release,
            "",
            Overrides::Compact,
            true,
            true,
        );
        assert_eq!(
            labels(&items),
            [
                "# Patch",
                "@babel/cli",
                "eslint",
                "# Minor",
                "@babel/core",
                "lodash",
                "# Major",
                "eslint-plugin-a"
            ]
        );
    }

    #[test]
    fn groups_by_prefix() {
        let items = build(
            &sample(),
            GroupBy::Prefix,
            "",
            Overrides::Compact,
            true,
            true,
        );
        assert_eq!(
            labels(&items),
            [
                "# @babel",
                "@babel/cli",
                "@babel/core",
                "# eslint-*",
                "eslint",
                "eslint-plugin-a",
                "# (other)",
                "lodash"
            ]
        );
    }

    #[test]
    fn filter_is_case_insensitive_and_drops_empty_groups() {
        let items = build(
            &sample(),
            GroupBy::Prefix,
            "ESLINT",
            Overrides::Compact,
            true,
            true,
        );
        assert_eq!(labels(&items), ["# eslint-*", "eslint", "eslint-plugin-a"]);
        assert!(
            build(
                &sample(),
                GroupBy::None,
                "zzz",
                Overrides::Compact,
                true,
                true
            )
            .is_empty()
        );
    }

    fn hit(name: &str, risk: crate::overrides::Compat) -> crate::tree::Hit {
        crate::tree::Hit {
            over: crate::overrides::Override {
                name: name.into(),
                range: None,
                value: "1.0.0".into(),
                source: "overrides",
                path: vec![],
                loc: vec!["overrides".into(), name.into()],
            },
            via: vec![name.into()],
            installed: None,
            requested: "^1".into(),
            risk,
        }
    }

    #[test]
    fn nests_overrides_under_their_package() {
        use crate::overrides::Compat;
        let mut rows = vec![row("a", "1.0.0", "2.0.0"), row("b", "1.0.0", "2.0.0")];
        rows[0].overrides = vec![hit("a", Compat::Ok).over];
        rows[0].tree_hits = (0..7).map(|i| hit(&format!("t{i}"), Compat::Ok)).collect();

        let kinds = |mode| -> Vec<String> {
            build(&rows, GroupBy::None, "", mode, true, true)
                .iter()
                .map(|i| match i {
                    Item::Row { name, .. } => name.clone(),
                    Item::Detail { child, last, .. } => {
                        format!("{child:?}{}", if *last { "$" } else { "" })
                    }
                    Item::Header { .. } | Item::Override { .. } | Item::Removed { .. } => "H".into(),
                })
                .collect()
        };
        assert_eq!(kinds(Overrides::Off), ["a", "b"]);
        let compact = kinds(Overrides::Compact);
        // own override + 5 tree hits + "+2 more", all nested under `a`, none under `b`
        assert_eq!(compact.len(), 1 + 1 + 5 + 1 + 1);
        assert_eq!(compact[1], "Own(0)");
        assert_eq!(compact[7], "More(2)$");
        assert_eq!(compact[8], "b");
        let full = kinds(Overrides::Full);
        assert_eq!(full.len(), 1 + 1 + 7 + 1);
        assert_eq!(full[8], "Tree(6)$");
    }

    #[test]
    fn up_to_date_rows_sort_last_group_separately_and_can_be_hidden() {
        let mut rows = sample();
        rows[0].outdated = false; // @babel/core
        let names = |items: &[Item]| -> Vec<String> {
            items
                .iter()
                .map(|i| match i {
                    Item::Row { name, .. } => name.clone(),
                    Item::Header { label, .. } => format!("# {label}"),
                    Item::Detail { .. } | Item::Override { .. } | Item::Removed { .. } => "-".into(),
                })
                .collect()
        };
        let flat = names(&build(&rows, GroupBy::None, "", Overrides::Off, true, true));
        assert_eq!(flat.last().unwrap(), "@babel/core");
        assert_eq!(flat.len(), 5);
        let grouped = names(&build(
            &rows,
            GroupBy::Release,
            "",
            Overrides::Off,
            true,
            true,
        ));
        assert_eq!(
            &grouped[grouped.len() - 2..],
            ["# Up to date", "@babel/core"]
        );
        let hidden = names(&build(
            &rows,
            GroupBy::None,
            "",
            Overrides::Off,
            false,
            true,
        ));
        assert!(!hidden.contains(&"@babel/core".to_string()));
        assert_eq!(hidden.len(), 4);
    }
}
