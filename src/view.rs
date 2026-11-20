//! Grouping and filtering of the outdated-package list into display items.

use crate::app::Row;
use semver::Version;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupBy {
    None,
    Release,
    Prefix,
}

impl GroupBy {
    pub fn next(self) -> Self {
        match self {
            GroupBy::None => GroupBy::Release,
            GroupBy::Release => GroupBy::Prefix,
            GroupBy::Prefix => GroupBy::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            GroupBy::None => "none",
            GroupBy::Release => "release type",
            GroupBy::Prefix => "name prefix",
        }
    }
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
    Header { label: String, members: Vec<usize> },
    Row { idx: usize, name: String },
}

const OTHER: &str = "(other)";

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

pub fn build(rows: &[Row], mode: GroupBy, filter: &str) -> Vec<Item> {
    let needle = filter.trim().to_lowercase();
    let visible: Vec<usize> = (0..rows.len())
        .filter(|&i| needle.is_empty() || rows[i].name.to_lowercase().contains(&needle))
        .collect();
    let item = |i: usize| Item::Row {
        idx: i,
        name: rows[i].name.clone(),
    };

    if mode == GroupBy::None {
        return visible.into_iter().map(item).collect();
    }

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
            GroupBy::Release => {
                let rel = rows[i].release();
                (rel as u8, rel.label().to_string())
            }
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
        out.extend(members.into_iter().map(item));
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
            dep_overrides: Vec::new(),
        }
    }

    fn labels(items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                Item::Header { label, .. } => format!("# {label}"),
                Item::Row { name, .. } => name.clone(),
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
    fn groups_by_release_patch_first() {
        let items = build(&sample(), GroupBy::Release, "");
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
        let items = build(&sample(), GroupBy::Prefix, "");
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
        let items = build(&sample(), GroupBy::Prefix, "ESLINT");
        assert_eq!(labels(&items), ["# eslint-*", "eslint", "eslint-plugin-a"]);
        assert!(build(&sample(), GroupBy::None, "zzz").is_empty());
    }
}
