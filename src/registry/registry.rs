//! Fetching the latest published version from the configured registry.
//!
//! Mirrors `npm-check-updates`: request the package document (preferring the abbreviated
//! "corgi" form), stream-parse it and stop reading once `dist-tags` has been seen, so the
//! (potentially huge) `versions` section is never downloaded. On a 404 the request is
//! retried once asking for the full `application/json` document.

use crate::config::npmrc::Npmrc;
use semver::Version;
use serde::Deserializer as _;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use std::collections::{BTreeMap, HashMap};
use std::collections::HashSet;
use std::io::{BufReader, Read};
use std::sync::Mutex;
use std::time::Duration;

/// Number of parallel requests.
pub const CONCURRENCY: usize = 16;

const CORGI: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const FULL: &str = "application/json";

enum Failure {
    NotFound,
    Other(String),
}

/// Registries that didn't serve `/-/package/<name>/dist-tags`, so it isn't asked again.
static NO_TAGS_ENDPOINT: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn tags_endpoint_unsupported(registry: &str) -> bool {
    NO_TAGS_ENDPOINT
        .lock()
        .is_ok_and(|g| g.as_ref().is_some_and(|s| s.contains(registry)))
}

/// The dist-tags from `/-/package/<name>/dist-tags`: a few hundred bytes, read to the end, so
/// the connection goes back to the agent's pool and the next request skips the TCP and TLS
/// setup. Reading the package document only as far as `dist-tags` leaves the rest of the
/// response unread, and ureq closes a connection in that state.
///
/// `None` when the registry doesn't have the endpoint (or the package: the document request
/// tells the two apart).
fn small_dist_tags(
    agent: &ureq::Agent,
    registry: &str,
    encoded: &str,
    auth: Option<&str>,
) -> Option<HashMap<String, String>> {
    let url = format!("{registry}-/package/{encoded}/dist-tags");
    let mut req = agent
        .get(&url)
        .set("Accept", FULL)
        .set("User-Agent", concat!("depsu/", env!("CARGO_PKG_VERSION")));
    if let Some(auth) = auth {
        req = req.set("Authorization", auth);
    }
    let body = req.call().ok()?.into_string().ok()?;
    let tags: HashMap<String, String> = serde_json::from_str(&body).ok()?;
    tags.contains_key("latest").then_some(tags)
}

pub fn latest_version(rc: &Npmrc, agent: &ureq::Agent, name: &str) -> Result<Version, String> {
    let registry = rc.registry_for(name);
    // Scoped names need the slash encoded, keeping the leading @: @scope%2fname
    let encoded = name.replacen('/', "%2f", 1);
    let url = format!("{registry}{encoded}");
    let auth = rc.auth_for(name, &registry);
    if !tags_endpoint_unsupported(&registry)
        && let Some(tags) = small_dist_tags(agent, &registry, &encoded, auth.as_deref())
        && let Some(v) = tags.get("latest").and_then(|l| Version::parse(l).ok())
    {
        return Ok(v);
    }
    let tags = match dist_tags(agent, &url, auth.as_deref(), CORGI) {
        // Some registries don't serve the abbreviated document.
        Err(Failure::NotFound) => dist_tags(agent, &url, auth.as_deref(), FULL),
        other => other,
    };
    let tags = tags.map_err(|f| match f {
        Failure::NotFound => format!("not found in {registry}"),
        Failure::Other(e) => e,
    })?;
    // The document exists, so the smaller endpoint failing means the registry lacks it.
    if let Ok(mut g) = NO_TAGS_ENDPOINT.lock() {
        g.get_or_insert_with(HashSet::new).insert(registry.clone());
    }
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
    /// The checksum the registry publishes for the package file (`dist.integrity`).
    pub integrity: Option<String>,
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
        integrity: Option<String>,
    }
    let doc: Doc = serde_json::from_reader(BufReader::new(reader))
        .map_err(|e| format!("invalid response: {e}"))?;
    Ok(Packument {
        latest: doc.tags.get("latest").and_then(|v| Version::parse(v).ok()),
        versions: doc
            .versions
            .into_iter()
            .filter_map(|(v, info)| {
                let (tarball, integrity) = match info.dist {
                    Some(d) => (d.tarball, d.integrity),
                    None => (None, None),
                };
                Some((Version::parse(&v).ok()?, VersionInfo { peers: info.peers, tarball, integrity }))
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
            "18.2.0":{"version":"18.2.0","peerDependencies":{"react":"^18.2.0"},"dist":{"tarball":"https://r/react-dom/-/react-dom-18.2.0.tgz","integrity":"sha512-rd"}},
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
        assert_eq!(p.versions[&Version::new(18, 2, 0)].integrity.as_deref(), Some("sha512-rd"));
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

    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A keep-alive HTTP server on localhost. `reply` maps a request path to a status and a
    /// body. Returns the registry URL, how many connections were accepted and the paths asked.
    fn server(
        reply: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (conns, paths) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(Vec::new())));
        let (c, p, reply) = (conns.clone(), paths.clone(), Arc::new(reply));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                c.fetch_add(1, Ordering::SeqCst);
                let (p, reply) = (p.clone(), reply.clone());
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    // One request at a time, until the client closes.
                    while stream.read(&mut byte).is_ok_and(|n| n == 1) {
                        buf.push(byte[0]);
                        if !buf.ends_with(b"\r\n\r\n") {
                            continue;
                        }
                        let head = String::from_utf8_lossy(&buf).into_owned();
                        let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                        buf.clear();
                        p.lock().unwrap().push(path.clone());
                        let (status, body) = reply(&path);
                        let msg = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if stream.write_all(msg.as_bytes()).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (url, conns, paths)
    }

    fn rc_for(url: &str) -> Npmrc {
        let mut rc = Npmrc::default();
        rc.set("registry", url);
        rc
    }

    #[test]
    fn the_small_endpoint_is_asked_and_the_connection_is_reused() {
        let (url, conns, paths) = server(|path| match path {
            "/-/package/a/dist-tags" => (200, r#"{"latest":"1.2.3"}"#.into()),
            "/-/package/@s%2fb/dist-tags" => (200, r#"{"latest":"2.0.0","next":"3.0.0-rc.1"}"#.into()),
            _ => (404, "{}".into()),
        });
        let (rc, agent) = (rc_for(&url), agent());
        assert_eq!(latest_version(&rc, &agent, "a").unwrap(), Version::new(1, 2, 3));
        assert_eq!(latest_version(&rc, &agent, "@s/b").unwrap(), Version::new(2, 0, 0));
        assert_eq!(latest_version(&rc, &agent, "a").unwrap(), Version::new(1, 2, 3));
        assert_eq!(conns.load(Ordering::SeqCst), 1, "{:?}", paths.lock().unwrap());
        assert_eq!(paths.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_registry_without_the_endpoint_falls_back_once_and_is_remembered() {
        let (url, _conns, paths) = server(|path| {
            if path.starts_with("/-/") {
                (404, "{}".into())
            } else {
                (200, format!(r#"{{"name":"x","dist-tags":{{"latest":"4.5.6"}},"versions":{{}},"path":"{path}"}}"#))
            }
        });
        let (rc, agent) = (rc_for(&url), agent());
        assert_eq!(latest_version(&rc, &agent, "x").unwrap(), Version::new(4, 5, 6));
        assert_eq!(latest_version(&rc, &agent, "y").unwrap(), Version::new(4, 5, 6));
        let asked = paths.lock().unwrap().clone();
        assert_eq!(asked, ["/-/package/x/dist-tags", "/x", "/y"], "{asked:?}");
    }

    #[test]
    fn a_missing_package_is_still_not_found() {
        let (url, _c, _p) = server(|_| (404, "{}".into()));
        let err = latest_version(&rc_for(&url), &agent(), "nope").unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    /// Times the lookups against the real registry: `cargo test --release bench_ -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_latest_versions() {
        let names: Vec<String> = "react react-dom lodash express typescript eslint prettier jest vitest webpack vite rollup esbuild @babel/core @babel/preset-env @types/node @types/react axios chalk commander debug dotenv semver uuid yargs zod next vue svelte tailwindcss postcss autoprefixer sass less moment dayjs date-fns rxjs redux @reduxjs/toolkit mobx immer classnames clsx styled-components @emotion/react @mui/material antd bootstrap jquery underscore ramda bluebird async glob minimatch rimraf mkdirp fs-extra chokidar nodemon ts-node tsx concurrently cross-env husky lint-staged @commitlint/cli eslint-plugin-react eslint-config-prettier @typescript-eslint/parser @typescript-eslint/eslint-plugin mocha chai sinon supertest nock cypress playwright @playwright/test puppeteer jsdom @testing-library/react @testing-library/jest-dom msw graphql apollo-server @apollo/client prisma @prisma/client mongoose sequelize pg mysql2 redis ioredis socket.io ws koa fastify hapi body-parser cors helmet morgan winston pino".split(' ').map(String::from).collect();
        let rc = Npmrc::default();
        for threads in [16, 32, 64] {
            NO_TAGS_ENDPOINT.lock().unwrap().take();
            let agent = agent();
            let queue = Arc::new(Mutex::new(names.clone()));
            let t = std::time::Instant::now();
            let times = Arc::new(Mutex::new(Vec::new()));
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let (q, rc, agent, times) = (queue.clone(), Npmrc::default(), agent.clone(), times.clone());
                    let _ = &rc;
                    std::thread::spawn(move || {
                        loop {
                            let Some(n) = q.lock().unwrap().pop() else { break };
                            let t = std::time::Instant::now();
                            let r = latest_version(&rc, &agent, &n);
                            times.lock().unwrap().push((t.elapsed().as_millis(), n, r.is_ok()));
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            let mut times = times.lock().unwrap().clone();
            times.sort();
            let ok = times.iter().filter(|t| t.2).count();
            let median = times[times.len() / 2].0;
            let slow: Vec<String> = times.iter().rev().take(3).map(|(ms, n, _)| format!("{n} {ms}ms")).collect();
            println!(
                "{threads} threads: {} packages in {:?}, {ok} ok, median {median}ms, slowest {slow:?}",
                names.len(),
                t.elapsed()
            );
        }
        let _ = rc;
    }
}
