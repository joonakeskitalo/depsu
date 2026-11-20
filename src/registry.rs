//! Fetching the latest published version from the configured registry.

use crate::npmrc::Npmrc;
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// Number of parallel requests. The agent keeps this many connections alive per host.
pub const CONCURRENCY: usize = 16;

#[derive(Deserialize)]
struct Packument {
    #[serde(rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
}

pub fn latest_version(rc: &Npmrc, agent: &ureq::Agent, name: &str) -> Result<Version, String> {
    let registry = rc.registry_for(name);
    // Scoped names need the slash encoded: @scope%2fname
    let base = format!("{registry}{}", name.replacen('/', "%2f", 1));
    let auth = rc.auth_header(&registry);

    // Fast path: `/<pkg>/latest` returns a single small manifest instead of every version.
    // Not every registry implements it, so any non-auth failure falls back to the full document.
    match get(agent, &format!("{base}/latest"), auth.as_deref()) {
        Ok(resp) => {
            if let Ok(m) = resp.into_json::<Manifest>()
                && let Ok(v) = Version::parse(&m.version)
            {
                return Ok(v);
            }
        }
        Err(ureq::Error::Status(401 | 403, _)) => {
            return Err(format!("unauthorized for {registry}"));
        }
        Err(ureq::Error::Status(..)) => {}
        Err(e) => return Err(e.to_string()),
    }

    let packument: Packument = match get(agent, &base, auth.as_deref()) {
        Ok(resp) => resp
            .into_json()
            .map_err(|e| format!("invalid response: {e}"))?,
        Err(ureq::Error::Status(code, _)) => return Err(format!("HTTP {code} from {registry}")),
        Err(e) => return Err(e.to_string()),
    };
    let latest = packument
        .dist_tags
        .get("latest")
        .ok_or("no `latest` dist-tag")?;
    Version::parse(latest).map_err(|e| format!("bad version {latest}: {e}"))
}

#[allow(clippy::result_large_err)] // ureq::Error is large; used only locally
fn get(agent: &ureq::Agent, url: &str, auth: Option<&str>) -> Result<ureq::Response, ureq::Error> {
    let mut req = agent.get(url).set(
        "Accept",
        "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8",
    );
    if let Some(auth) = auth {
        req = req.set("Authorization", auth);
    }
    req.call()
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        // ureq keeps only one idle connection per host by default, which forces new
        // TLS handshakes for most parallel requests.
        .max_idle_connections(CONCURRENCY * 4)
        .max_idle_connections_per_host(CONCURRENCY)
        .build()
}
