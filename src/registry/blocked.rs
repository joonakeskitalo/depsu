//! Versions a registry refuses to hand out. Registries with a security policy (JFrog Curation,
//! Nexus Firewall and the like) list every version in the package document but answer 403
//! when the file of a blocked one is downloaded, so an install of it fails. This finds the
//! newest version that can be downloaded instead.
use crate::registry::registry::Packument;
use semver::Version;

/// How many older versions are tried before giving up.
const MAX_PROBES: usize = 15;

/// A version the registry won't hand out.
#[derive(Clone, Debug, PartialEq)]
pub struct Blocked {
    pub name: String,
    pub version: Version,
    /// The newest older release that can be downloaded, if one was found.
    pub alternative: Option<Version>,
    /// One of the project's own dependencies (else something they bring in).
    pub direct: bool,
}

/// The newest release below `blocked` (and not above `latest`) whose file can be downloaded.
/// `downloadable` gets the file's URL; versions it can't decide on are skipped.
pub fn latest_available(
    doc: &Packument,
    blocked: &Version,
    downloadable: &dyn Fn(&str) -> Result<bool, String>,
) -> Option<Version> {
    doc.versions
        .iter()
        .rev()
        .filter(|(v, _)| *v < blocked && v.pre.is_empty())
        .filter(|(v, _)| doc.latest.as_ref().is_none_or(|l| *v <= l))
        .filter_map(|(v, info)| Some((v, info.tarball.as_deref()?)))
        .take(MAX_PROBES)
        .find(|(_, url)| downloadable(url) == Ok(true))
        .map(|(v, _)| v.clone())
}

/// The versions in `plan` whose files the registry refuses, each with the newest older
/// version it hands out. `downloadable` gets the package name and the file's URL.
pub fn find_blocked(
    plan: &[(String, Version)],
    fetch: &dyn Fn(&str) -> Result<Packument, String>,
    downloadable: &dyn Fn(&str, &str) -> Result<bool, String>,
    direct: &[String],
) -> Vec<Blocked> {
    let mut out = Vec::new();
    for (name, version) in plan {
        let Ok(doc) = fetch(name) else {
            continue;
        };
        let Some(url) = doc.versions.get(version).and_then(|i| i.tarball.clone()) else {
            continue;
        };
        // Only a clear refusal counts: an unreachable registry shouldn't stop the install.
        if downloadable(name, &url) != Ok(false) {
            continue;
        }
        out.push(Blocked {
            name: name.clone(),
            version: version.clone(),
            alternative: latest_available(&doc, version, &|u| downloadable(name, u)),
            direct: direct.contains(name),
        });
    }
    out
}

/// The package and version whose file download was refused with 403, from a package
/// manager's error output: npm (`403 Forbidden - GET <url>`), pnpm (`ERR_PNPM_FETCH_403`),
/// yarn and bun all name the file's URL.
pub fn parse_forbidden(output: &str) -> Option<(String, Version)> {
    output
        .lines()
        .filter(|l| l.contains("403"))
        .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == '"' || c == '\''))
        .filter(|w| w.starts_with("http") && w.contains(".tgz"))
        .find_map(|url| from_tarball_url(url.trim_end_matches([':', ',', ')'])))
}

/// `https://r/@scope/name/-/name-1.2.3.tgz` (the scope may be encoded) → `@scope/name`, 1.2.3.
fn from_tarball_url(url: &str) -> Option<(String, Version)> {
    let path = url.split("://").nth(1)?.split_once('/')?.1;
    let path = path.split(['?', '#']).next()?;
    let (pkg, file) = path.rsplit_once("/-/")?;
    let pkg = pkg.replace("%2f", "/").replace("%2F", "/").replace("%40", "@");
    // Registries mounted under a path (`/artifactory/api/npm/npm/lodash`): the package is the
    // last segment, or the last two for a scoped one.
    let segments: Vec<&str> = pkg.split('/').collect();
    let name = match segments.as_slice() {
        [.., scope, n] if scope.starts_with('@') => format!("{scope}/{n}"),
        [.., n] => n.to_string(),
        [] => return None,
    };
    let base = name.rsplit('/').next()?;
    let version = file.strip_suffix(".tgz")?.strip_prefix(base)?.strip_prefix('-')?;
    Some((name, Version::parse(version).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::registry::VersionInfo;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn reads_npm_pnpm_yarn_and_bun_errors() {
        let npm = "npm error code E403\nnpm error 403 403 Forbidden - GET https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\nnpm error 403 In most cases, you or one of your dependencies are requesting\n";
        assert_eq!(parse_forbidden(npm), Some(("lodash".into(), v("4.17.21"))));
        let pnpm = " ERR_PNPM_FETCH_403  GET https://repo.example.com/artifactory/api/npm/npm/@types/node/-/node-20.11.5.tgz: Forbidden - 403";
        assert_eq!(parse_forbidden(pnpm), Some(("@types/node".into(), v("20.11.5"))));
        let yarn = "error An unexpected error occurred: \"https://registry.yarnpkg.com/@babel%2fcore/-/core-7.24.0.tgz: Request failed \\\"403 Forbidden\\\"\".";
        assert_eq!(parse_forbidden(yarn), Some(("@babel/core".into(), v("7.24.0"))));
        let bun = "error: GET https://registry.npmjs.org/qs/-/qs-6.11.0.tgz - 403";
        assert_eq!(parse_forbidden(bun), Some(("qs".into(), v("6.11.0"))));
    }

    #[test]
    fn other_errors_are_not_mistaken_for_a_block() {
        assert_eq!(parse_forbidden("npm error code ERESOLVE\nnpm error peer react@^19"), None);
        // A 404 for a file is a missing version, not a blocked one.
        assert_eq!(
            parse_forbidden("npm error 404 Not Found - GET https://registry.npmjs.org/x/-/x-1.0.0.tgz"),
            None
        );
    }

    #[test]
    fn finds_the_newest_older_release_that_downloads() {
        let url = |ver: &str| Some(format!("https://r/x/-/x-{ver}.tgz"));
        let doc = Packument {
            latest: Some(v("2.1.0")),
            versions: ["1.9.0", "2.0.0", "2.0.1", "2.1.0", "2.2.0-rc.1"]
                .iter()
                .map(|s| (v(s), VersionInfo { tarball: url(s), ..Default::default() }))
                .collect(),
        };
        // 2.1.0 and 2.0.1 are blocked too.
        let ok = |u: &str| Ok(!u.contains("2.1.0") && !u.contains("2.0.1"));
        assert_eq!(latest_available(&doc, &v("2.1.0"), &ok), Some(v("2.0.0")));
        // Everything blocked.
        assert_eq!(latest_available(&doc, &v("2.1.0"), &|_| Ok(false)), None);
        // Probe errors don't count as downloadable.
        assert_eq!(latest_available(&doc, &v("2.1.0"), &|_| Err("timeout".into())), None);
    }
}
