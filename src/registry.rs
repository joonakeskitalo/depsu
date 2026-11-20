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
use std::collections::HashMap;
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
    let auth = rc.auth_header(&registry);

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
    fn missing_dist_tags_is_an_error() {
        assert!(parse_dist_tags(&br#"{"name":"x"}"#[..]).is_err());
        assert!(parse_dist_tags(&b"not json"[..]).is_err());
    }
}
