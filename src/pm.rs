//! Package manager detection and install command construction.

use crate::package::Kind;
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
            Kind::Prod => {}
            Kind::Dev => a.push("-D".into()),
            Kind::Optional => a.push(
                if self == Pm::Bun { "--optional" } else { "-O" }.into(),
            ),
        }
        if exact {
            a.push(if matches!(self, Pm::Npm | Pm::Pnpm) { "--save-exact" } else { "--exact" }.into());
        }
        a
    }

    /// Executable name (Windows uses `.cmd` shims).
    pub fn program(self) -> String {
        if cfg!(windows) { format!("{}.cmd", self.name()) } else { self.name().into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_wins() {
        assert_eq!(Pm::detect(Path::new("/nonexistent"), Some("pnpm@9.1.0")), Pm::Pnpm);
    }

    #[test]
    fn args() {
        let s = vec!["a@^1.0.0".to_string()];
        assert_eq!(Pm::Npm.install_args(&s, Kind::Dev, false), ["install", "a@^1.0.0", "-D"]);
        assert_eq!(Pm::Yarn.install_args(&s, Kind::Prod, true), ["add", "a@^1.0.0", "--exact"]);
    }
}
