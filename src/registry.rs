//! Fetching the latest published version from the configured registry.

use crate::npmrc::Npmrc;
use semver::Version;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct Packument {
    #[serde(rename = "dist-tags")]
    dist_tags: std::collections::HashMap<String, String>,
}

pub fn latest_version(rc: &Npmrc, agent: &ureq::Agent, name: &str) -> Result<Version, String> {
    let registry = rc.registry_for(name);
    // Scoped names need the slash encoded: @scope%2fname
    let url = format!("{registry}{}", name.replacen('/', "%2f", 1));
    let mut req = agent.get(&url).set(
        "Accept",
        "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8",
    );
    if let Some(auth) = rc.auth_header(&registry) {
        req = req.set("Authorization", &auth);
    }
    let packument: Packument = match req.call() {
        Ok(resp) => resp
            .into_json()
            .map_err(|e| format!("invalid response: {e}"))?,
        Err(ureq::Error::Status(code, _)) => return Err(format!("HTTP {code} from {registry}")),
        Err(e) => return Err(format!("{e}")),
    };
    let latest = packument
        .dist_tags
        .get("latest")
        .ok_or("no `latest` dist-tag")?;
    Version::parse(latest).map_err(|e| format!("bad version {latest}: {e}"))
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
}
