//! Walks the installed dependency tree of a package to find overrides that apply anywhere
//! below it, since an override can change the behaviour of the package even when the
//! overridden dependency is several levels deep.

use crate::overrides::{Compat, Override, Unneeded, assess, satisfies};
use semver::Version;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MAX_DEPTH: usize = 64;
/// Upper bound on dependency edges visited per analysed package.
const MAX_EDGES: usize = 20_000;
/// Same, for the walk over the whole project.
const MAX_PROJECT_EDGES: usize = 500_000;

#[derive(Clone, Debug)]
pub struct Hit {
    pub over: Override,
    /// Packages from the analysed one down to the overridden one (the last element).
    pub via: Vec<String>,
    /// Version of the overridden package found in `node_modules`.
    pub installed: Option<Version>,
    /// Range the parent package declares for the overridden dependency.
    pub requested: String,
    /// `Conflict` when the override forces a version outside what the parent asked for.
    pub risk: Compat,
}

#[derive(Default)]
struct Pkg {
    version: Option<Version>,
    /// (name, declared range) from `dependencies` and `optionalDependencies`.
    deps: Vec<(String, String)>,
}

pub struct Analyzer {
    dir: PathBuf,
    overrides: Vec<Override>,
    pkgs: HashMap<PathBuf, Rc<Pkg>>,
    resolved: HashMap<(PathBuf, String), Option<PathBuf>>,
}

impl Analyzer {
    /// Replaces the overrides, e.g. after `package.json` was edited.
    pub fn set_overrides(&mut self, overrides: Vec<Override>) {
        self.overrides = overrides;
    }

    pub fn new(dir: PathBuf, overrides: Vec<Override>) -> Self {
        Analyzer {
            dir,
            overrides,
            pkgs: HashMap::new(),
            resolved: HashMap::new(),
        }
    }

    fn pkg(&mut self, dir: &Path) -> Rc<Pkg> {
        if let Some(p) = self.pkgs.get(dir) {
            return p.clone();
        }
        let pkg = std::fs::read_to_string(dir.join("package.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .map(|json| {
                let mut deps = Vec::new();
                for field in ["dependencies", "optionalDependencies"] {
                    if let Some(map) = json.get(field).and_then(|v| v.as_object()) {
                        for (k, v) in map {
                            deps.push((k.clone(), v.as_str().unwrap_or("").to_string()));
                        }
                    }
                }
                Pkg {
                    version: json
                        .get("version")
                        .and_then(|v| v.as_str())
                        .and_then(|v| Version::parse(v).ok()),
                    deps,
                }
            })
            .unwrap_or_default();
        let pkg = Rc::new(pkg);
        self.pkgs.insert(dir.to_path_buf(), pkg.clone());
        pkg
    }

    /// Node-style resolution of `dep` from `from`: look in each ancestor's `node_modules`.
    /// Returns the real path, so pnpm's symlinked layout resolves siblings correctly.
    fn resolve(&mut self, from: &Path, dep: &str) -> Option<PathBuf> {
        let key = (from.to_path_buf(), dep.to_string());
        if let Some(r) = self.resolved.get(&key) {
            return r.clone();
        }
        let found = from
            .ancestors()
            .map(|a| {
                if a.file_name().is_some_and(|n| n == "node_modules") {
                    a.join(dep)
                } else {
                    a.join("node_modules").join(dep)
                }
            })
            .find(|c| c.join("package.json").is_file())
            .and_then(|c| c.canonicalize().ok());
        self.resolved.insert(key, found.clone());
        found
    }

    /// Overrides applying to anything in the installed dependency tree of `name`.
    pub fn analyze(&mut self, name: &str) -> Vec<Hit> {
        let dir = self.dir.clone();
        let Some(root) = self.resolve(&dir, name) else {
            return Vec::new();
        };
        let mut state = Walk {
            visited: HashSet::from([root.clone()]),
            seen: HashSet::new(),
            hits: Vec::new(),
            budget: MAX_EDGES,
        };
        self.walk(&root, &mut vec![name.to_string()], &mut state);
        state.hits
    }

    fn walk(&mut self, dir: &Path, chain: &mut Vec<String>, st: &mut Walk) {
        if chain.len() > MAX_DEPTH {
            return;
        }
        let pkg = self.pkg(dir);
        for (dep, requested) in &pkg.deps {
            if st.budget == 0 {
                return;
            }
            st.budget -= 1;
            let child = self.resolve(dir, dep);
            let installed = child.as_ref().and_then(|c| self.pkg(c).version.clone());

            for (i, o) in self.overrides.iter().enumerate() {
                if o.name != *dep || !o.path_applies(chain) {
                    continue;
                }
                // `foo@^1` selectors only override matching installed versions.
                if let (Some(sel), Some(v)) = (&o.range, &installed)
                    && satisfies(sel, v) == Some(false)
                {
                    continue;
                }
                if !st.seen.insert((i, dep.clone(), installed.clone())) {
                    continue;
                }
                let mut via: Vec<String> = chain[1..].to_vec();
                via.push(dep.clone());
                st.hits.push(Hit {
                    over: o.clone(),
                    via,
                    installed: installed.clone(),
                    requested: requested.clone(),
                    risk: risk(o, requested),
                });
            }

            if let Some(c) = child
                && st.visited.insert(c.clone())
            {
                chain.push(dep.clone());
                self.walk(&c, chain, st);
                chain.pop();
            }
        }
    }
}

impl Analyzer {
    /// Finds overrides that probably no longer change anything. Walks the whole installed tree
    /// starting from the project's own dependencies (`root_deps`: name and declared range),
    /// collecting for every override the ranges that all dependents declare for it.
    ///
    /// Returns nothing when none of the project's dependencies are installed, because then the
    /// absence of dependents proves nothing.
    pub fn unneeded(&mut self, root_deps: &[(String, String)]) -> Vec<(String, Unneeded)> {
        let overrides = self.overrides.clone();
        if overrides.is_empty() {
            return Vec::new();
        }
        let dir = self.dir.clone();
        let mut st = UsageWalk {
            visited: HashSet::new(),
            requested: vec![Vec::new(); overrides.len()],
            budget: MAX_PROJECT_EDGES,
        };
        let mut installed_any = false;
        for (dep, spec) in root_deps {
            let child = self.resolve(&dir, dep);
            installed_any |= child.is_some();
            let version = child.as_ref().and_then(|c| self.pkg(c).version.clone());
            record(
                &overrides,
                &[],
                dep,
                spec,
                version.as_ref(),
                &mut st.requested,
            );
            if let Some(c) = child
                && st.visited.insert(c.clone())
            {
                self.usage_walk(&overrides, &c, &mut vec![dep.clone()], &mut st);
            }
        }
        if !installed_any {
            return Vec::new();
        }
        overrides
            .iter()
            .zip(&st.requested)
            .filter_map(|(o, req)| Some((o.key(), assess(o, req)?)))
            .collect()
    }

    fn usage_walk(
        &mut self,
        overrides: &[Override],
        dir: &Path,
        chain: &mut Vec<String>,
        st: &mut UsageWalk,
    ) {
        if chain.len() > MAX_DEPTH {
            return;
        }
        let pkg = self.pkg(dir);
        for (dep, requested) in &pkg.deps {
            if st.budget == 0 {
                return;
            }
            st.budget -= 1;
            let child = self.resolve(dir, dep);
            let version = child.as_ref().and_then(|c| self.pkg(c).version.clone());
            record(
                overrides,
                chain,
                dep,
                requested,
                version.as_ref(),
                &mut st.requested,
            );
            if let Some(c) = child
                && st.visited.insert(c.clone())
            {
                chain.push(dep.clone());
                self.usage_walk(overrides, &c, chain, st);
                chain.pop();
            }
        }
    }
}

struct UsageWalk {
    visited: HashSet<PathBuf>,
    /// Per override: the range declared by each dependent edge the override applies to.
    requested: Vec<Vec<String>>,
    budget: usize,
}

/// Notes the declared range of an edge `parent chain -> dep` for every override applying to it.
fn record(
    overrides: &[Override],
    chain: &[String],
    dep: &str,
    requested: &str,
    installed: Option<&Version>,
    out: &mut [Vec<String>],
) {
    for (i, o) in overrides.iter().enumerate() {
        if o.name != dep || !o.path_applies(chain) {
            continue;
        }
        if let (Some(sel), Some(v)) = (&o.range, installed)
            && satisfies(sel, v) == Some(false)
        {
            continue;
        }
        out[i].push(requested.to_string());
    }
}

struct Walk {
    visited: HashSet<PathBuf>,
    seen: HashSet<(usize, String, Option<Version>)>,
    hits: Vec<Hit>,
    budget: usize,
}

/// Does the override force a version the parent didn't ask for?
pub fn risk(o: &Override, requested: &str) -> Compat {
    if o.value.starts_with('$') || o.value == requested {
        return Compat::Ok;
    }
    match Version::parse(&o.value) {
        Ok(v) => match satisfies(requested, &v) {
            Some(true) => Compat::Ok,
            Some(false) => Compat::Conflict,
            None => Compat::Unknown,
        },
        Err(_) => Compat::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overrides::collect;
    use crate::pm::Pm;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, pkg_path: &str, json: &str) {
        let d = dir.join(pkg_path);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), json).unwrap();
    }

    #[test]
    fn finds_transitive_overrides_with_scoping() {
        let dir = tmp("flat");
        write(
            &dir,
            "node_modules/x",
            r#"{"version":"1.0.0","dependencies":{"y":"^1"}}"#,
        );
        write(
            &dir,
            "node_modules/y",
            r#"{"version":"1.2.0","dependencies":{"z":"^5"}}"#,
        );
        write(&dir, "node_modules/z", r#"{"version":"5.0.0"}"#);
        let m = json!({"overrides": {
            "z": "6.0.0",
            "other": {"y": "9.0.0"},
            "y@^2": "2.0.0",
            "x": {"z": "5.0.0"}
        }});
        let mut a = Analyzer::new(dir.clone(), collect(&m, Pm::Npm));
        let hits = a.analyze("x");
        // global z (forces 6.0.0 vs ^5: risky) and x > z (5.0.0 satisfies ^5);
        // `other > y` doesn't apply under x, `y@^2` doesn't match installed 1.2.0.
        assert_eq!(hits.len(), 2, "{hits:#?}");
        let global = hits.iter().find(|h| h.over.value == "6.0.0").unwrap();
        assert_eq!(global.via, ["y", "z"]);
        assert_eq!(global.risk, Compat::Conflict);
        assert_eq!(global.installed, Some(Version::new(5, 0, 0)));
        let scoped = hits.iter().find(|h| h.over.value == "5.0.0").unwrap();
        assert_eq!(scoped.risk, Compat::Ok);
        assert!(a.analyze("not-installed").is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn finds_overrides_that_no_longer_matter() {
        let dir = tmp("unneeded");
        write(
            &dir,
            "node_modules/a",
            r#"{"version":"1.0.0","dependencies":{"floor":"^5.1.0","same":"2.0.0","needed":"^1.0.0"}}"#,
        );
        write(
            &dir,
            "node_modules/b",
            r#"{"version":"1.0.0","dependencies":{"floor":"^5.0.5","needed":"^1.0.0"}}"#,
        );
        for (n, v) in [("floor", "5.1.0"), ("same", "2.0.0"), ("needed", "1.2.0")] {
            write(
                &dir,
                &format!("node_modules/{n}"),
                &format!(r#"{{"version":"{v}"}}"#),
            );
        }
        let m = json!({"overrides": {
            "floor": "5.0.5",     // every dependent already requires >= 5.0.5
            "same": "2.0.0",      // dependents already ask for exactly this
            "needed": "1.1.0",    // b still allows ^1.0.0, below the floor
            "ghost": "1.0.0"      // nothing depends on it
        }});
        let mut a = Analyzer::new(dir.clone(), collect(&m, Pm::Npm));
        let roots = vec![
            ("a".to_string(), "^1.0.0".to_string()),
            ("b".to_string(), "^1.0.0".to_string()),
        ];
        let got: HashMap<String, Unneeded> = a.unneeded(&roots).into_iter().collect();
        let key = |n: &str| format!("overrides\u{1f}{n}");
        assert_eq!(
            got[&key("floor")],
            Unneeded::FloorMet(Version::new(5, 0, 5))
        );
        assert_eq!(got[&key("same")], Unneeded::SameSpec);
        assert_eq!(got[&key("ghost")], Unneeded::Unused);
        assert!(!got.contains_key(&key("needed")), "{got:?}");

        // Nothing installed: no evidence, so no verdicts (not "everything is unused").
        let mut empty = Analyzer::new(tmp("empty"), collect(&m, Pm::Npm));
        assert!(empty.unneeded(&roots).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn survives_cycles() {
        let dir = tmp("cycle");
        write(&dir, "node_modules/a", r#"{"dependencies":{"b":"1"}}"#);
        write(
            &dir,
            "node_modules/b",
            r#"{"dependencies":{"a":"1","c":"1"}}"#,
        );
        write(&dir, "node_modules/c", r#"{"version":"1.0.0"}"#);
        let m = json!({"overrides": {"c": "1.0.0"}});
        let mut a = Analyzer::new(dir.clone(), collect(&m, Pm::Npm));
        assert_eq!(a.analyze("a").len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn resolves_pnpm_symlinked_layout() {
        use std::os::unix::fs::symlink;
        let dir = tmp("pnpm");
        let store = dir.join("node_modules/.pnpm");
        write(
            &store,
            "x@1.0.0/node_modules/x",
            r#"{"dependencies":{"y":"^1"}}"#,
        );
        write(&store, "y@1.0.0/node_modules/y", r#"{"version":"1.0.0"}"#);
        symlink(
            "../../y@1.0.0/node_modules/y",
            store.join("x@1.0.0/node_modules/y"),
        )
        .unwrap();
        symlink(".pnpm/x@1.0.0/node_modules/x", dir.join("node_modules/x")).unwrap();
        let m = json!({"pnpm": {"overrides": {"y": "1.0.0"}}});
        let mut a = Analyzer::new(dir.clone(), collect(&m, Pm::Pnpm));
        let hits = a.analyze("x");
        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(hits[0].installed, Some(Version::new(1, 0, 0)));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
