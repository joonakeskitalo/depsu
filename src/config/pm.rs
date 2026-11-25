//! Package manager detection and install command construction.

use crate::deps::package::Kind;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pm {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

impl Pm {
    pub fn name(self) -> &'static str {
        match self {
            Pm::Npm => "npm",
            Pm::Yarn => "yarn",
            Pm::Pnpm => "pnpm",
            Pm::Bun => "bun",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "npm" => Some(Pm::Npm),
            "yarn" => Some(Pm::Yarn),
            "pnpm" => Some(Pm::Pnpm),
            "bun" => Some(Pm::Bun),
            _ => None,
        }
    }

    /// Detects from the `packageManager` field, then lockfiles in `dir` and its
    /// ancestors (monorepo roots). Falls back to npm.
    pub fn detect(dir: &Path, package_manager_field: Option<&str>) -> Self {
        if let Some(pm) = package_manager_field
            .and_then(|f| f.split('@').next())
            .and_then(Pm::parse)
        {
            return pm;
        }
        for d in dir.ancestors() {
            let has = |f: &str| d.join(f).exists();
            if has("bun.lock") || has("bun.lockb") {
                return Pm::Bun;
            }
            if has("pnpm-lock.yaml") {
                return Pm::Pnpm;
            }
            if has("yarn.lock") {
                return Pm::Yarn;
            }
            if has("package-lock.json") || has("npm-shrinkwrap.json") {
                return Pm::Npm;
            }
        }
        Pm::Npm
    }

    /// Arguments for installing `specs` (e.g. `foo@^1.2.3`) into `kind`.
    pub fn install_args(self, specs: &[String], kind: Kind, exact: bool) -> Vec<String> {
        let mut a: Vec<String> = vec![if self == Pm::Npm { "install" } else { "add" }.into()];
        a.extend(specs.iter().cloned());
        match kind {
            Kind::Prod | Kind::Override => {}
            Kind::Dev => a.push("-D".into()),
            Kind::Optional => a.push(if self == Pm::Bun { "--optional" } else { "-O" }.into()),
        }
        if exact {
            a.push(
                if matches!(self, Pm::Npm | Pm::Pnpm) {
                    "--save-exact"
                } else {
                    "--exact"
                }
                .into(),
            );
        }
        a
    }

    /// Flags and environment variables that make the package manager keep its download cache in
    /// `dir`. `modern_yarn` is Yarn 2+, which has no such flag and reads the environment instead.
    pub fn cache_setup(self, dir: &str, modern_yarn: bool) -> (Vec<String>, Vec<(String, String)>) {
        let env = |k: &str| vec![(k.to_string(), dir.to_string())];
        match self {
            Pm::Npm => (vec![format!("--cache={dir}")], Vec::new()),
            Pm::Pnpm => (vec![format!("--store-dir={dir}")], Vec::new()),
            Pm::Yarn if modern_yarn => (Vec::new(), env("YARN_CACHE_FOLDER")),
            Pm::Yarn => (vec![format!("--cache-folder={dir}")], Vec::new()),
            Pm::Bun => (Vec::new(), env("BUN_INSTALL_CACHE_DIR")),
        }
    }
    /// Flags that make the package manager use cached packages without asking the registry
    /// whether they are stale. Yarn 2+ and bun have no such flag.
    pub fn offline_args(self, modern_yarn: bool) -> Vec<String> {
        match self {
            Pm::Npm | Pm::Pnpm => vec!["--prefer-offline".into()],
            Pm::Yarn if !modern_yarn => vec!["--prefer-offline".into()],
            _ => Vec::new(),
        }
    }
    pub fn uninstall_args(self, names: &[String]) -> Vec<String> {
        let mut a: Vec<String> = vec![if self == Pm::Npm { "uninstall" } else { "remove" }.into()];
        a.extend(names.iter().cloned());
        a
    }

    /// Executable name (Windows uses `.cmd` shims).
    pub fn program(self) -> String {
        if cfg!(windows) {
            format!("{}.cmd", self.name())
        } else {
            self.name().into()
        }
    }
}

static CACHE_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
/// Sets the directory for the package manager's download cache (once, at startup).
pub fn set_cache_dir(dir: String) {
    let _ = CACHE_DIR.set(dir);
}
pub fn cache_dir() -> Option<&'static str> {
    CACHE_DIR.get().map(String::as_str)
}
static PREFER_OFFLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_prefer_offline() {
    PREFER_OFFLINE.store(true, std::sync::atomic::Ordering::Relaxed);
}
pub fn prefer_offline() -> bool {
    PREFER_OFFLINE.load(std::sync::atomic::Ordering::Relaxed)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_wins() {
        assert_eq!(
            Pm::detect(Path::new("/nonexistent"), Some("pnpm@9.1.0")),
            Pm::Pnpm
        );
    }

    #[test]
    fn args() {
        let s = vec!["a@^1.0.0".to_string()];
        assert_eq!(
            Pm::Npm.install_args(&s, Kind::Dev, false),
            ["install", "a@^1.0.0", "-D"]
        );
        assert_eq!(
            Pm::Yarn.install_args(&s, Kind::Prod, true),
            ["add", "a@^1.0.0", "--exact"]
        );
    }
    #[test]
    fn cache_dir_is_passed_the_way_each_manager_takes_it() {
        assert_eq!(Pm::Npm.cache_setup("/c", false), (vec!["--cache=/c".to_string()], vec![]));
        assert_eq!(Pm::Pnpm.cache_setup("/c", false).0, ["--store-dir=/c"]);
        assert_eq!(Pm::Yarn.cache_setup("/c", false).0, ["--cache-folder=/c"]);
        let (flags, env) = Pm::Yarn.cache_setup("/c", true);
        assert!(flags.is_empty());
        assert_eq!(env, [("YARN_CACHE_FOLDER".to_string(), "/c".to_string())]);
        assert_eq!(Pm::Bun.cache_setup("/c", false).1[0].0, "BUN_INSTALL_CACHE_DIR");
    }
    #[test]
    fn prefer_offline_is_passed_where_supported() {
        assert_eq!(Pm::Npm.offline_args(false), ["--prefer-offline"]);
        assert_eq!(Pm::Pnpm.offline_args(false), ["--prefer-offline"]);
        assert_eq!(Pm::Yarn.offline_args(false), ["--prefer-offline"]);
        assert!(Pm::Yarn.offline_args(true).is_empty());
        assert!(Pm::Bun.offline_args(false).is_empty());
    }
}
