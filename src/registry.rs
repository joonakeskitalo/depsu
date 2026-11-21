//! Fetching the latest published version from the configured registry.
//!
//! Mirrors `npm-check-updates`: request the package document (preferring the abbreviated
//! "corgi" form), stream-parse it and stop reading once `dist-tags` has been seen, so the
//! (potentially huge) `versions` section is never downloaded. On a 404 the request is
//! retried once asking for the full `application/json` document.

use crate::npmrc::Npmrc;
use semver::Version;
use serde::Deserializer as _;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufReader, Read};
use std::time::Duration;

/// Number of parallel requests.
pub const CONCURRENCY: usize = 16;

const CORGI: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const FULL: &str = "application/json";

enum Failure {
    NotFound,
    Other(String),
}

pub fn latest_version(rc: &Npmrc, agent: &ureq::Agent, name: &str) -> Result<Version, String> {
    let registry = rc.registry_for(name);
    // Scoped names need the slash encoded, keeping the leading @: @scope%2fname
    let url = format!("{registry}{}", name.replacen('/', "%2f", 1));
    let auth = rc.auth_for(name, &registry);

    let tags = match dist_tags(agent, &url, auth.as_deref(), CORGI) {
        // Some registries don't serve the abbreviated document.
        Err(Failure::NotFound) => dist_tags(agent, &url, auth.as_deref(), FULL),
        other => other,
    };
    let tags = tags.map_err(|f| match f {
        Failure::NotFound => format!("not found in {registry}"),
        Failure::Other(e) => e,
    })?;
    let latest = tags.get("latest").ok_or("no `latest` dist-tag")?;
    Version::parse(latest).map_err(|e| format!("bad version {latest}: {e}"))
}

fn dist_tags(
    agent: &ureq::Agent,
    url: &str,
    auth: Option<&str>,
    accept: &str,
) -> Result<HashMap<String, String>, Failure> {
    let mut req = agent
        .get(url)
        .set("Accept", accept)
        .set("User-Agent", concat!("depsu/", env!("CARGO_PKG_VERSION")));
    if let Some(auth) = auth {
        req = req.set("Authorization", auth);
    }
    match req.call() {
        Ok(resp) => parse_dist_tags(resp.into_reader()).map_err(Failure::Other),
        Err(ureq::Error::Status(404, _)) => Err(Failure::NotFound),
        Err(ureq::Error::Status(401 | 403, _)) => Err(Failure::Other("unauthorized".into())),
        Err(ureq::Error::Status(code, _)) => Err(Failure::Other(format!("HTTP {code}"))),
        Err(e) => Err(Failure::Other(e.to_string())),
    }
}

/// Reads top-level keys of the package document until `dist-tags`, then stops without
/// consuming the rest of the stream.
fn parse_dist_tags(reader: impl Read) -> Result<HashMap<String, String>, String> {
    struct Find<'a>(&'a mut Option<HashMap<String, String>>);

    impl<'de> Visitor<'de> for Find<'_> {
        type Value = ();

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a package document object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<String>()? {
                if key == "dist-tags" {
                    *self.0 = Some(map.next_value()?);
                    // Abort parsing: the remaining (large) content is not needed.
                    return Err(de::Error::custom("done"));
                }
                map.next_value::<IgnoredAny>()?;
            }
            Ok(())
        }
    }

    let mut found = None;
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(reader));
    let result = (&mut de).deserialize_map(Find(&mut found));
    match (found, result) {
        (Some(tags), _) => Ok(tags),
        (None, Err(e)) => Err(format!("invalid response: {e}")),
        (None, Ok(())) => Err("no `dist-tags` in response".into()),
    }
}

/// What depsu needs to know about one published version.
#[derive(Clone, Debug, Default)]
pub struct VersionInfo {
    /// `peerDependencies`: name → range.
    pub peers: HashMap<String, String>,
    /// Where the package file is downloaded from (`dist.tarball`).
    pub tarball: Option<String>,
}

/// The versions of a package, from its registry document.
#[derive(Clone, Debug, Default)]
pub struct Packument {
    /// The `latest` dist-tag.
    pub latest: Option<Version>,
    pub versions: BTreeMap<Version, VersionInfo>,
}

impl Packument {
    /// The highest release (no pre-releases, nothing above `latest`) that `ok` accepts.
    pub fn best(&self, ok: impl Fn(&Version, &VersionInfo) -> bool) -> Option<Version> {
        self.versions
            .iter()
            .rev()
            .filter(|(v, _)| v.pre.is_empty())
            .filter(|(v, _)| self.latest.as_ref().is_none_or(|l| *v <= l))
            .find(|(v, info)| ok(v, info))
            .map(|(v, _)| v.clone())
    }
}

/// Fetches the whole (abbreviated) registry document of `name`.
pub fn packument(rc: &Npmrc, agent: &ureq::Agent, name: &str) -> Result<Packument, String> {
    let registry = rc.registry_for(name);
    let url = format!("{registry}{}", name.replacen('/', "%2f", 1));
    let auth = rc.auth_for(name, &registry);
    let get = |accept: &str| {
        let mut req = agent
            .get(&url)
            .set("Accept", accept)
            .set("User-Agent", concat!("depsu/", env!("CARGO_PKG_VERSION")));
        if let Some(auth) = &auth {
            req = req.set("Authorization", auth);
        }
        req.call()
    };
    let resp = match get(CORGI) {
        Err(ureq::Error::Status(404, _)) => get(FULL),
        other => other,
    };
    match resp {
        Ok(r) => parse_packument(r.into_reader()),
        Err(ureq::Error::Status(404, _)) => Err(format!("{name} not found in {registry}")),
        Err(ureq::Error::Status(401 | 403, _)) => Err(format!("{name}: unauthorized")),
        Err(ureq::Error::Status(code, _)) => Err(format!("{name}: HTTP {code}")),
        Err(e) => Err(format!("{name}: {e}")),
    }
}

fn parse_packument(reader: impl Read) -> Result<Packument, String> {
    #[derive(serde::Deserialize)]
    struct Doc {
        #[serde(rename = "dist-tags", default)]
        tags: HashMap<String, String>,
        #[serde(default)]
        versions: HashMap<String, Ver>,
    }
    #[derive(serde::Deserialize)]
    struct Ver {
        #[serde(rename = "peerDependencies", default)]
        peers: HashMap<String, String>,
        #[serde(default)]
        dist: Option<Dist>,
    }
    #[derive(serde::Deserialize)]
    struct Dist {
        tarball: Option<String>,
    }
    let doc: Doc = serde_json::from_reader(BufReader::new(reader))
        .map_err(|e| format!("invalid response: {e}"))?;
    Ok(Packument {
        latest: doc.tags.get("latest").and_then(|v| Version::parse(v).ok()),
        versions: doc
            .versions
            .into_iter()
            .filter_map(|(v, info)| {
                let tarball = info.dist.and_then(|d| d.tarball);
                Some((Version::parse(&v).ok()?, VersionInfo { peers: info.peers, tarball }))
            })
            .collect(),
    })
}

/// Whether the registry hands out the package file at `url`. `false` when it refuses (403, or
/// 451 for legal reasons) or doesn't have it (404); errors for anything else.
pub fn downloadable(rc: &Npmrc, agent: &ureq::Agent, name: &str, url: &str) -> Result<bool, String> {
    let registry = rc.registry_for(name);
    let mut req = agent
        .get(url)
        .set("User-Agent", concat!("depsu/", env!("CARGO_PKG_VERSION")));
    if let Some(auth) = rc.auth_for(name, &registry) {
        req = req.set("Authorization", &auth);
    }
    // Only the status is needed: the response is dropped without reading the file.
    match req.call() {
        Ok(_) => Ok(true),
        Err(ureq::Error::Status(403 | 404 | 451, _)) => Ok(false),
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(e.to_string()),
    }
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .max_idle_connections(CONCURRENCY * 4)
        .max_idle_connections_per_host(CONCURRENCY)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_after_dist_tags_even_if_truncated() {
        let doc = br#"{"name":"x","modified":"t","dist-tags":{"latest":"1.2.3","next":"2.0.0-rc.1"},"versions":{"1.2.3":{"name":"x","depen"#;
        let tags = parse_dist_tags(&doc[..]).unwrap();
        assert_eq!(tags["latest"], "1.2.3");
    }

    #[test]
    fn reads_versions_and_their_peers() {
        let doc = br#"{"name":"react-dom","dist-tags":{"latest":"19.0.0"},"versions":{
            "18.2.0":{"version":"18.2.0","peerDependencies":{"react":"^18.2.0"},"dist":{"tarball":"https://r/react-dom/-/react-dom-18.2.0.tgz"}},
            "19.0.0":{"version":"19.0.0","peerDependencies":{"react":"^19.0.0"}},
            "19.1.0-rc.0":{"version":"19.1.0-rc.0"},
            "20.0.0":{"version":"20.0.0"},
            "garbage":{}
        }}"#;
        let p = parse_packument(&doc[..]).unwrap();
        assert_eq!(p.latest, Some(Version::new(19, 0, 0)));
        assert_eq!(p.versions.len(), 4);
        assert_eq!(p.versions[&Version::new(19, 0, 0)].peers["react"], "^19.0.0");
        assert_eq!(
            p.versions[&Version::new(18, 2, 0)].tarball.as_deref(),
            Some("https://r/react-dom/-/react-dom-18.2.0.tgz")
        );
        // `best` skips pre-releases and anything above `latest`.
        assert_eq!(p.best(|_, _| true), Some(Version::new(19, 0, 0)));
        assert_eq!(
            p.best(|_, i| i.peers.get("react").is_some_and(|r| r.starts_with("^18"))),
            Some(Version::new(18, 2, 0))
        );
    }
    #[test]
    fn missing_dist_tags_is_an_error() {
        assert!(parse_dist_tags(&br#"{"name":"x"}"#[..]).is_err());
        assert!(parse_dist_tags(&b"not json"[..]).is_err());
    }
}
