//! Peer dependency check before an install. Updating a package can require other installed
//! packages to change too, through peer dependencies (regular dependencies don't, since the
//! package manager installs a nested copy instead):
//!
//! - the new version declares a peer that the installed version of it doesn't satisfy
//!   (`react-dom@19` needs `react ^19`), or
//! - an installed package declares the updated package as a peer, and the new version is
//!   outside its range (`eslint-plugin-react-hooks@4` needs `react ^16 || ^17 || ^18`).
//!
//! For each such package the check suggests a version that fits, when it is one of the
//! project's own dependencies and the registry has one.
use crate::overrides::satisfies;
use crate::registry::Packument;
use semver::Version;
use std::collections::HashMap;

/// Another package that has to change for the install to work.
#[derive(Clone, Debug, PartialEq)]
pub struct Need {
    pub name: String,
    /// Its version now.
    pub from: Version,
    /// A version that fits, if the package is one of the project's own dependencies and the
    /// registry has one. `None` means depsu can't fix it.
    pub to: Option<Version>,
    /// Why it has to change, e.g. `react-dom@19.0.0 needs react ^19.0.0`.
    pub why: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub needs: Vec<Need>,
    /// Problems that kept a package from being checked, e.g. the registry couldn't be reached.
    pub warnings: Vec<String>,
}

/// What the check needs to know about the project.
pub struct Project<'a> {
    /// The project's own dependencies, which depsu can update.
    pub direct: &'a [String],
    /// The version a package is at now (lockfile or `node_modules`), `None` if not installed.
    pub installed: &'a dyn Fn(&str) -> Option<Version>,
    /// The peer dependencies an installed package declares (name → range).
    pub installed_peers: &'a dyn Fn(&str) -> Option<HashMap<String, String>>,
    /// The registry document of a package.
    pub fetch: &'a dyn Fn(&str) -> Result<Packument, String>,
}

/// Finds the packages that have to change when `plan` (name, target version) is installed.
pub fn check(plan: &[(String, Version)], p: &Project) -> Report {
    let mut report = Report::default();
    let mut cache: HashMap<String, Result<Packument, String>> = HashMap::new();
    let mut fetch = |name: &str| -> Option<Packument> {
        cache
            .entry(name.to_string())
            .or_insert_with(|| (p.fetch)(name))
            .as_ref()
            .ok()
            .cloned()
    };
    let target = |name: &str| plan.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    let add = |report: &mut Report, need: Need| {
        match report.needs.iter_mut().find(|n| n.name == need.name) {
            Some(n) => {
                n.why.push_str("; ");
                n.why.push_str(&need.why);
                // Keep the suggestion that fits more requirements: re-checked below.
                if n.to.is_none() {
                    n.to = need.to;
                }
            }
            None => report.needs.push(need),
        }
    };

    // 1. Peers the new versions declare.
    for (name, to) in plan {
        let Some(doc) = fetch(name) else {
            report
                .warnings
                .push(format!("could not check the peer dependencies of {name}@{to}"));
            continue;
        };
        let Some(info) = doc.versions.get(to) else {
            continue;
        };
        let mut peers: Vec<(&String, &String)> = info.peers.iter().collect();
        peers.sort();
        for (peer, range) in peers {
            // Not installed: the package manager installs it (or it is optional).
            let Some(have) = target(peer).or_else(|| (p.installed)(peer)) else {
                continue;
            };
            // A range depsu can't read doesn't block the install.
            if satisfies(range, &have) != Some(false) {
                continue;
            }
            let why = format!("{name}@{to} needs {peer} {range}");
            let to = if target(peer).is_some() || !p.direct.contains(peer) {
                None
            } else {
                fetch(peer).and_then(|d| {
                    d.best(|v, _| satisfies(range, v) == Some(true))
                })
            };
            add(
                &mut report,
                Need {
                    name: peer.clone(),
                    from: have,
                    to,
                    why: if p.direct.contains(peer) || target(peer).is_some() {
                        why
                    } else {
                        format!("{why} (installed by another package, update that one)")
                    },
                },
            );
        }
    }

    // 2. Installed packages that declare an updated package as a peer.
    for dep in p.direct {
        if target(dep).is_some() {
            continue;
        }
        let Some(peers) = (p.installed_peers)(dep) else {
            continue;
        };
        let Some(have) = (p.installed)(dep) else {
            continue;
        };
        for (name, to) in plan {
            let Some(range) = peers.get(name) else {
                continue;
            };
            if satisfies(range, to) != Some(false) {
                continue;
            }
            // A version of `dep` that accepts every updated package it peers on.
            let fits = |info: &crate::registry::VersionInfo| {
                plan.iter().all(|(n, v)| {
                    info.peers
                        .get(n)
                        .is_none_or(|r| satisfies(r, v) != Some(false))
                })
            };
            let suggestion = fetch(dep).and_then(|d| d.best(|_, info| fits(info)));
            add(
                &mut report,
                Need {
                    name: dep.clone(),
                    from: have.clone(),
                    to: suggestion,
                    why: format!("{dep}@{have} needs {name} {range}, not {to}"),
                },
            );
        }
    }
    report.needs.retain(|n| n.to.as_ref() != Some(&n.from));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::VersionInfo;
    use std::collections::BTreeMap;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }
    /// A registry document with versions `(version, [(peer, range)])`.
    fn doc(latest: &str, versions: &[(&str, &[(&str, &str)])]) -> Packument {
        Packument {
            latest: Some(v(latest)),
            versions: versions
                .iter()
                .map(|(ver, peers)| {
                    (
                        v(ver),
                        VersionInfo {
                            peers: peers
                                .iter()
                                .map(|(n, r)| (n.to_string(), r.to_string()))
                                .collect(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }
    fn registry() -> HashMap<&'static str, Packument> {
        HashMap::from([
            (
                "react-dom",
                doc(
                    "19.0.0",
                    &[("18.2.0", &[("react", "^18.2.0")]), ("19.0.0", &[("react", "^19.0.0")])],
                ),
            ),
            ("react", doc("19.0.0", &[("18.2.0", &[]), ("19.0.0", &[]), ("19.1.0-rc.1", &[])])),
            (
                "hooks-plugin",
                doc(
                    "5.0.0",
                    &[
                        ("4.6.0", &[("react", "^16 || ^17 || ^18")]),
                        ("5.0.0", &[("react", "^18 || ^19")]),
                    ],
                ),
            ),
            ("old-plugin", doc("1.0.0", &[("1.0.0", &[("react", "^17")])])),
        ])
    }
    fn run(plan: &[(&str, &str)], direct: &[&str], installed: &[(&str, &str)]) -> Report {
        let reg = registry();
        let installed: HashMap<String, Version> =
            installed.iter().map(|(n, ver)| (n.to_string(), v(ver))).collect();
        let installed_peers = |name: &str| -> Option<HashMap<String, String>> {
            let have = installed.get(name)?;
            Some(reg.get(name)?.versions.get(have)?.peers.clone())
        };
        let direct: Vec<String> = direct.iter().map(|s| s.to_string()).collect();
        let plan: Vec<(String, Version)> =
            plan.iter().map(|(n, ver)| (n.to_string(), v(ver))).collect();
        let project = Project {
            direct: &direct,
            installed: &|n| installed.get(n).cloned(),
            installed_peers: &installed_peers,
            fetch: &|n| reg.get(n).cloned().ok_or_else(|| format!("{n} not found")),
        };
        check(&plan, &project)
    }

    #[test]
    fn nothing_to_do_when_peers_are_satisfied() {
        let r = run(&[("react-dom", "18.2.0")], &["react", "react-dom"], &[("react", "18.2.0"), ("react-dom", "18.2.0")]);
        assert!(r.needs.is_empty(), "{:?}", r.needs);
    }

    #[test]
    fn a_new_version_that_needs_a_newer_peer_suggests_it() {
        let r = run(&[("react-dom", "19.0.0")], &["react", "react-dom"], &[("react", "18.2.0"), ("react-dom", "18.2.0")]);
        assert_eq!(r.needs.len(), 1);
        let n = &r.needs[0];
        assert_eq!(n.name, "react");
        assert_eq!(n.from, v("18.2.0"));
        assert_eq!(n.to, Some(v("19.0.0")), "the release, not the release candidate");
        assert!(n.why.contains("react-dom@19.0.0 needs react ^19.0.0"));
    }

    #[test]
    fn updating_both_together_needs_nothing_else() {
        let r = run(
            &[("react-dom", "19.0.0"), ("react", "19.0.0")],
            &["react", "react-dom"],
            &[("react", "18.2.0"), ("react-dom", "18.2.0")],
        );
        assert!(r.needs.is_empty(), "{:?}", r.needs);
    }

    #[test]
    fn an_installed_package_that_peers_on_the_updated_one_is_updated_too() {
        let r = run(
            &[("react", "19.0.0")],
            &["react", "react-dom", "hooks-plugin"],
            &[("react", "18.2.0"), ("react-dom", "18.2.0"), ("hooks-plugin", "4.6.0")],
        );
        let names: Vec<&str> = r.needs.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["react-dom", "hooks-plugin"]);
        assert_eq!(r.needs[0].to, Some(v("19.0.0")));
        assert_eq!(r.needs[1].to, Some(v("5.0.0")));
        assert!(r.needs[1].why.contains("hooks-plugin@4.6.0 needs react ^16 || ^17 || ^18, not 19.0.0"));
    }

    #[test]
    fn a_package_without_a_fitting_version_is_reported_without_a_suggestion() {
        let r = run(
            &[("react", "19.0.0")],
            &["react", "old-plugin"],
            &[("react", "18.2.0"), ("old-plugin", "1.0.0")],
        );
        assert_eq!(r.needs.len(), 1);
        assert_eq!(r.needs[0].name, "old-plugin");
        assert_eq!(r.needs[0].to, None);
    }

    #[test]
    fn a_peer_that_is_not_a_project_dependency_is_reported_without_a_suggestion() {
        // `react` is only installed because something else depends on it.
        let r = run(&[("react-dom", "19.0.0")], &["react-dom"], &[("react", "18.2.0"), ("react-dom", "18.2.0")]);
        assert_eq!(r.needs.len(), 1);
        assert_eq!(r.needs[0].to, None);
        assert!(r.needs[0].why.contains("installed by another package"));
    }

    #[test]
    fn a_peer_that_is_not_installed_is_left_to_the_package_manager() {
        let r = run(&[("react-dom", "19.0.0")], &["react-dom"], &[("react-dom", "18.2.0")]);
        assert!(r.needs.is_empty());
    }

    #[test]
    fn registry_failures_are_warnings() {
        let r = run(&[("unknown", "1.0.0")], &["unknown"], &[]);
        assert!(r.needs.is_empty());
        assert_eq!(r.warnings.len(), 1);
    }
}
