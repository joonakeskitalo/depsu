//! A caching registry proxy for npm.
//!
//! depsu starts it on `127.0.0.1` and runs npm with `--registry` pointing at it. The proxy
//! forwards every request to the real registry (adding the credentials from `.npmrc`, which npm
//! doesn't know for the local address, and following redirects such as Cloudsmith's 307 to a
//! CDN), and keeps what it gets in a directory:
//!
//! - tarballs (`…/-/name-1.0.0.tgz`) never change, so a stored one is served without asking;
//! - package metadata is asked for again with `If-None-Match`, so a changed package is seen
//!   at once and an unchanged one costs a `304`. When the registry can't be reached, the stored
//!   copy is served;
//! - everything else (audit, search, `POST`s) is passed through unchanged.
//!
//! It is a registry mirror rather than a forward proxy on purpose: npm talks plain HTTP to
//! localhost, so no TLS interception or certificate is needed.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// Where npm is sent while the proxy runs.
#[derive(Debug, Clone)]
pub struct Active {
    /// `http://127.0.0.1:PORT/<path of the real registry>/`, for `--registry`.
    pub registry_url: String,
    /// `http://127.0.0.1:PORT`.
    pub local_origin: String,
    /// `https://registry.example` (no path), what `local_origin` stands for.
    pub upstream_origin: String,
    /// Host (and port) of the real registry, for `--replace-registry-host`: tarball URLs of
    /// that host are fetched through the proxy as well.
    pub upstream_host: String,
    /// What the proxy did, one line per request, until `take_log` collects it.
    log: Log,
}

type Log = Arc<Mutex<Vec<String>>>;

/// The lines the proxy has logged since the last call: where each request was served from.
pub fn take_log() -> Vec<String> {
    active()
        .and_then(|a| a.log.lock().ok().map(|mut l| std::mem::take(&mut *l)))
        .unwrap_or_default()
}

static ACTIVE: OnceLock<Active> = OnceLock::new();

pub fn active() -> Option<&'static Active> {
    ACTIVE.get()
}

struct Ctx {
    /// `http://host[:port]`, no trailing slash.
    origin: String,
    auth: Option<String>,
    dir: PathBuf,
    agent: ureq::Agent,
    log: Log,
}

impl Ctx {
    /// Records where a request was served from.
    fn note(&self, from: &str, req: &Request, what: &str) {
        let path = req.target.trim_start_matches('/');
        let line = format!("proxy {from:<6} {path}{}", if what.is_empty() { String::new() } else { format!(" ({what})") });
        if let Ok(mut l) = self.log.lock() {
            // Nobody reads it when depsu is not showing it; don't let it grow without bound.
            if l.len() < 10_000 {
                l.push(line);
            }
        }
    }
}

/// Starts the proxy for `registry` (the default registry URL), storing files in `dir`.
/// `auth` is the `Authorization` header value the registry needs, if any. Runs until the
/// process ends.
pub fn start(dir: &Path, registry: &str, auth: Option<String>) -> Result<Active, String> {
    let (scheme, rest) = registry
        .split_once("://")
        .ok_or_else(|| format!("registry `{registry}` is not a URL"))?;
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let path = if path.ends_with('/') { path } else { format!("{path}/") };
    let upstream_origin = format!("{scheme}://{host}");
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("could not start the proxy: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let log: Log = Arc::default();
    let ctx = Arc::new(Ctx {
        origin: upstream_origin.clone(),
        auth,
        log: log.clone(),
        dir: dir.join(sanitize(host)),
        agent: ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .redirects(5)
            // Same-host redirects keep the credentials; a signed CDN URL must not get them.
            .redirect_auth_headers(ureq::RedirectAuthHeaders::SameHost)
            .build(),
    });
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let ctx = ctx.clone();
            thread::spawn(move || {
                let _ = handle(stream, &ctx);
            });
        }
    });
    let active = Active {
        registry_url: format!("http://127.0.0.1:{port}{path}"),
        local_origin: format!("http://127.0.0.1:{port}"),
        upstream_origin,
        upstream_host: host.to_string(),
        log,
    };
    let _ = ACTIVE.set(active.clone());
    Ok(active)
}

/// npm may write the proxy's address into the lockfile as the place a package came from.
/// That address means nothing outside this run, so it is turned back into the real registry.
pub fn restore_lockfiles(dir: &Path) {
    if let Some(a) = active() {
        restore_in(dir, &a.local_origin, &a.upstream_origin);
    }
}

fn restore_in(dir: &Path, local: &str, upstream: &str) {
    for name in ["package-lock.json", "npm-shrinkwrap.json"] {
        let path = dir.join(name);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        if text.contains(local) {
            let _ = std::fs::write(&path, text.replace(local, upstream));
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 32 * 1024 * 1024;

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".into());
        }
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut req = Request { method, target, headers, body: buf[end..].to_vec() };
    if req.header("transfer-encoding").is_some() {
        return Err("chunked request bodies are not supported".into());
    }
    let len: usize = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Err("request body too large".into());
    }
    while req.body.len() < len {
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed".into());
        }
        req.body.extend_from_slice(&chunk[..n]);
    }
    req.body.truncate(len);
    Ok(req)
}

struct Reply {
    status: u16,
    content_type: String,
    etag: Option<String>,
    body: Vec<u8>,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn send(stream: &mut TcpStream, r: &Reply, head_only: bool) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    if let Some(e) = &r.etag {
        head.push_str(&format!("ETag: {e}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if !head_only {
        stream.write_all(&r.body)?;
    }
    stream.flush()
}

fn error(status: u16, msg: &str) -> Reply {
    Reply {
        status,
        content_type: "text/plain".into(),
        etag: None,
        body: msg.as_bytes().to_vec(),
    }
}

fn handle(mut stream: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let reply = match read_request(&mut stream) {
        Ok(req) => respond(&req, ctx),
        Err(e) => error(400, &e),
    };
    send(&mut stream, &reply, false)
}

#[derive(PartialEq)]
enum Kind {
    Tarball,
    Packument,
    Other,
}

fn classify(req: &Request) -> Kind {
    let path = req.target.as_str();
    if req.method != "GET" || path.contains('?') || path.contains("/-/npm/") || path.contains("/-/v1/") {
        Kind::Other
    } else if path.contains("/-/") && path.ends_with(".tgz") {
        Kind::Tarball
    } else if !path.contains("/-/") {
        Kind::Packument
    } else {
        Kind::Other
    }
}

/// A file name for any string: letters, digits and `._@-` stay, the rest becomes `%XX`.
fn sanitize(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct Stored {
    body: Vec<u8>,
    content_type: String,
    etag: Option<String>,
}

fn cache_file(ctx: &Ctx, req: &Request, kind: &Kind) -> Option<PathBuf> {
    let mut name = sanitize(&req.target);
    if *kind == Kind::Packument {
        // The short form (`install-v1`) and the full document are different files.
        let short = req.header("accept").is_some_and(|a| a.contains("application/vnd.npm.install-v1+json"));
        name.push_str(if short { ".short" } else { ".full" });
    }
    (name.len() <= 200).then(|| ctx.dir.join(name))
}

fn read_stored(file: &Path) -> Option<Stored> {
    let body = std::fs::read(file).ok()?;
    let meta = std::fs::read_to_string(meta_path(file)).unwrap_or_default();
    let mut lines = meta.lines();
    let content_type = lines.next().filter(|l| !l.is_empty()).unwrap_or("application/octet-stream").to_string();
    let etag = lines.next().filter(|l| !l.is_empty()).map(String::from);
    Some(Stored { body, content_type, etag })
}

fn meta_path(file: &Path) -> PathBuf {
    let mut p = file.as_os_str().to_owned();
    p.push(".meta");
    PathBuf::from(p)
}

static TMP: AtomicU64 = AtomicU64::new(0);

/// Writes through a temporary name, so a request that reads at the same time never sees half a file.
fn store(file: &Path, r: &Reply) {
    let Some(parent) = file.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let tmp = |p: &Path| {
        let mut t = p.as_os_str().to_owned();
        t.push(format!(".tmp{}", TMP.fetch_add(1, Ordering::Relaxed)));
        PathBuf::from(t)
    };
    let meta = format!("{}\n{}\n", r.content_type, r.etag.as_deref().unwrap_or(""));
    let (tb, tm) = (tmp(file), tmp(&meta_path(file)));
    let ok = std::fs::write(&tb, &r.body).is_ok() && std::fs::write(&tm, meta).is_ok();
    if ok {
        let _ = std::fs::rename(&tm, meta_path(file));
        let _ = std::fs::rename(&tb, file);
    } else {
        let _ = std::fs::remove_file(&tb);
        let _ = std::fs::remove_file(&tm);
    }
}

fn respond(req: &Request, ctx: &Ctx) -> Reply {
    if !req.target.starts_with('/') {
        return error(400, "expected a path");
    }
    let kind = classify(req);
    let file = if kind == Kind::Other { None } else { cache_file(ctx, req, &kind) };
    let stored = file.as_deref().and_then(read_stored);
    if kind == Kind::Tarball
        && let Some(s) = stored
    {
        ctx.note("cache", req, "");
        return Reply { status: 200, content_type: s.content_type, etag: s.etag, body: s.body };
    }
    let etag = stored.as_ref().and_then(|s| s.etag.clone());
    match fetch(req, ctx, etag.as_deref().filter(|_| kind == Kind::Packument)) {
        Ok(r) if r.status == 304 => match stored {
            Some(s) => {
                ctx.note("cache", req, "unchanged at the registry");
                Reply { status: 200, content_type: s.content_type, etag: s.etag, body: s.body }
            }
            None => error(502, "registry answered 304 for a file the proxy has not stored"),
        },
        Ok(r) => {
            if r.status == 200
                && let Some(f) = &file
            {
                store(f, &r);
            }
            if r.status == 200 {
                ctx.note("remote", req, if file.is_some() { "stored" } else { "" });
            } else {
                ctx.note("remote", req, &format!("status {}", r.status));
            }
            r
        }
        // The registry can't be reached: an old copy of the metadata beats no answer.
        Err(e) => match stored {
            Some(s) => {
                ctx.note("cache", req, "registry unreachable");
                Reply { status: 200, content_type: s.content_type, etag: s.etag, body: s.body }
            }
            None => {
                ctx.note("failed", req, &e);
                error(502, &format!("could not reach the registry: {e}"))
            }
        },
    }
}

/// Sends the request on to the registry. Statuses of 400 and above come back as replies, only
/// a failed connection is an error.
fn fetch(req: &Request, ctx: &Ctx, etag: Option<&str>) -> Result<Reply, String> {
    let url = format!("{}{}", ctx.origin, req.target);
    let mut r = ctx.agent.request(&req.method, &url);
    for name in ["accept", "content-type", "user-agent", "npm-command"] {
        if let Some(v) = req.header(name) {
            r = r.set(name, v);
        }
    }
    if let Some(a) = &ctx.auth {
        r = r.set("Authorization", a);
    }
    if let Some(e) = etag {
        r = r.set("If-None-Match", e);
    }
    let resp = match if req.body.is_empty() && req.method != "POST" && req.method != "PUT" {
        r.call()
    } else {
        r.send_bytes(&req.body)
    } {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    let content_type = resp.header("content-type").unwrap_or("application/octet-stream").to_string();
    let etag = resp.header("etag").map(String::from);
    let mut body = Vec::new();
    resp.into_reader().take(1 << 31).read_to_end(&mut body).map_err(|e| e.to_string())?;
    Ok(Reply { status, content_type, etag, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    /// A registry that counts requests, remembers their headers and can be switched off.
    struct Fake {
        origin: String,
        seen: Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>,
        down: Arc<AtomicBool>,
    }

    fn fake(handler: impl Fn(&str, &[(String, String)]) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + 'static) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let down = Arc::new(AtomicBool::new(false));
        let (s, d) = (seen.clone(), down.clone());
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                if d.load(Ordering::Relaxed) {
                    continue; // closes the connection without an answer
                }
                let Ok(req) = read_request(&mut stream) else { continue };
                s.lock().unwrap().push((req.target.clone(), req.headers.clone()));
                let (status, headers, body) = handler(&req.target, &req.headers);
                let mut head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                for (k, v) in headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Fake { origin, seen, down }
    }

    fn proxy_for(f: &Fake, auth: Option<&str>) -> (String, tempdir::Dir) {
        let (url, dir, _) = proxy_with_log(f, auth);
        (url, dir)
    }

    fn proxy_with_log(f: &Fake, auth: Option<&str>) -> (String, tempdir::Dir, Log) {
        let log = Log::default();
        let dir = tempdir::Dir::new();
        let ctx = Arc::new(Ctx {
            origin: f.origin.clone(),
            auth: auth.map(String::from),
            dir: dir.0.clone(),
            agent: ureq::AgentBuilder::new().build(),
            log: log.clone(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let ctx = ctx.clone();
                thread::spawn(move || {
                    let _ = handle(s, &ctx);
                });
            }
        });
        (url, dir, log)
    }

    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicUsize, Ordering};
        pub struct Dir(pub PathBuf);
        impl Dir {
            pub fn new() -> Self {
                static N: AtomicUsize = AtomicUsize::new(0);
                let p = std::env::temp_dir().join(format!("depsu-proxy-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn get(url: &str) -> (u16, String) {
        match ureq::get(url).call() {
            Ok(r) => (r.status(), r.into_string().unwrap()),
            Err(ureq::Error::Status(c, r)) => (c, r.into_string().unwrap_or_default()),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn a_tarball_is_fetched_once_and_gets_the_credentials() {
        let f = fake(|_, _| (200, vec![("Content-Type", "application/octet-stream".into())], b"TGZ".to_vec()));
        let (url, _dir) = proxy_for(&f, Some("Bearer tok"));
        for _ in 0..3 {
            assert_eq!(get(&format!("{url}/sok-npm/a/-/a-1.0.0.tgz")), (200, "TGZ".into()));
        }
        let seen = f.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "later requests come from the directory");
        assert_eq!(seen[0].0, "/sok-npm/a/-/a-1.0.0.tgz");
        assert!(seen[0].1.contains(&("authorization".into(), "Bearer tok".into())));
    }

    #[test]
    fn metadata_is_checked_again_and_a_304_serves_the_stored_copy() {
        let f = fake(|_, h| {
            if h.iter().any(|(k, v)| k == "if-none-match" && v == "\"v1\"") {
                (304, vec![], vec![])
            } else {
                (200, vec![("ETag", "\"v1\"".into()), ("Content-Type", "application/json".into())], b"{\"name\":\"a\"}".to_vec())
            }
        });
        let (url, _dir) = proxy_for(&f, None);
        assert_eq!(get(&format!("{url}/a")).1, "{\"name\":\"a\"}");
        assert_eq!(get(&format!("{url}/a")), (200, "{\"name\":\"a\"}".into()));
        assert_eq!(f.seen.lock().unwrap().len(), 2, "metadata is revalidated every time");
    }

    #[test]
    fn stored_metadata_is_served_when_the_registry_is_down() {
        let f = fake(|_, _| (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec()));
        let (url, _dir) = proxy_for(&f, None);
        assert_eq!(get(&format!("{url}/a")).0, 200);
        f.down.store(true, Ordering::Relaxed);
        assert_eq!(get(&format!("{url}/a")), (200, "{}".into()));
        assert_eq!(get(&format!("{url}/never-seen")).0, 502);
    }

    #[test]
    fn errors_pass_through_and_are_not_stored() {
        let f = fake(|_, _| (403, vec![], b"blocked".to_vec()));
        let (url, _dir) = proxy_for(&f, None);
        assert_eq!(get(&format!("{url}/a/-/a-1.0.0.tgz")), (403, "blocked".into()));
        assert_eq!(get(&format!("{url}/a/-/a-1.0.0.tgz")), (403, "blocked".into()));
        assert_eq!(f.seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_log_says_where_each_request_was_served_from() {
        let f = fake(|t, _| {
            if t.ends_with(".tgz") {
                (200, vec![], b"TGZ".to_vec())
            } else {
                (200, vec![("ETag", "\"v1\"".into())], b"{}".to_vec())
            }
        });
        let (url, _dir, log) = proxy_with_log(&f, None);
        get(&format!("{url}/a/-/a-1.0.0.tgz"));
        get(&format!("{url}/a/-/a-1.0.0.tgz"));
        get(&format!("{url}/a"));
        f.down.store(true, Ordering::Relaxed);
        get(&format!("{url}/a"));
        get(&format!("{url}/b"));
        let lines = log.lock().unwrap().clone();
        assert_eq!(lines[0], "proxy remote a/-/a-1.0.0.tgz (stored)");
        assert_eq!(lines[1], "proxy cache  a/-/a-1.0.0.tgz");
        assert_eq!(lines[2], "proxy remote a (stored)");
        assert_eq!(lines[3], "proxy cache  a (registry unreachable)");
        assert!(lines[4].starts_with("proxy failed b ("), "{}", lines[4]);
    }

    #[test]
    fn short_and_full_metadata_are_stored_apart() {
        let f = fake(|_, h| {
            let short = h.iter().any(|(k, v)| k == "accept" && v.contains("install-v1"));
            (200, vec![], if short { b"short".to_vec() } else { b"full".to_vec() })
        });
        let (url, _dir) = proxy_for(&f, None);
        let short = ureq::get(&format!("{url}/a")).set("Accept", "application/vnd.npm.install-v1+json").call().unwrap().into_string().unwrap();
        assert_eq!(short, "short");
        assert_eq!(get(&format!("{url}/a")).1, "full");
    }

    #[test]
    fn posts_are_forwarded_with_their_body() {
        let f = fake(|_, _| (200, vec![], b"{}".to_vec()));
        let (url, _dir) = proxy_for(&f, None);
        let r = ureq::post(&format!("{url}/-/npm/v1/security/advisories/bulk")).send_string("{\"a\":[\"1.0.0\"]}").unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(f.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_local_registry_keeps_the_path_of_the_real_one() {
        let dir = tempdir::Dir::new();
        let a = start(&dir.0, "https://npm.artifacts.example/sok-npm", None).unwrap();
        assert!(a.registry_url.starts_with("http://127.0.0.1:"));
        assert!(a.registry_url.ends_with("/sok-npm/"));
        assert_eq!(a.upstream_origin, "https://npm.artifacts.example");
        assert_eq!(a.upstream_host, "npm.artifacts.example");
    }

    #[test]
    fn the_proxy_address_is_taken_out_of_the_lockfile() {
        let dir = tempdir::Dir::new();
        let lock = dir.0.join("package-lock.json");
        std::fs::write(&lock, "{\"resolved\":\"http://127.0.0.1:5555/sok-npm/a/-/a-1.0.0.tgz\"}").unwrap();
        restore_in(&dir.0, "http://127.0.0.1:5555", "https://npm.example");
        assert_eq!(
            std::fs::read_to_string(&lock).unwrap(),
            "{\"resolved\":\"https://npm.example/sok-npm/a/-/a-1.0.0.tgz\"}"
        );
    }

    /// Needs npm and network access: `cargo test real_npm -- --ignored`.
    #[test]
    #[ignore]
    fn real_npm_installs_through_the_proxy() {
        let cache = tempdir::Dir::new();
        let project = tempdir::Dir::new();
        std::fs::write(project.0.join("package.json"), "{\"name\":\"t\",\"version\":\"1.0.0\"}").unwrap();
        let a = start(&cache.0, "https://registry.npmjs.org/", None).unwrap();
        let run = |extra: &[&str]| {
            let o = std::process::Command::new("npm")
                .args(["install", "is-odd@3.0.1", "--cache", project.0.join("npmcache").to_str().unwrap()])
                .arg(format!("--registry={}", a.registry_url))
                .arg(format!("--replace-registry-host={}", a.upstream_host))
                .args(extra)
                .current_dir(&project.0)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        };
        run(&[]);
        let lock = std::fs::read_to_string(project.0.join("package-lock.json")).unwrap();
        println!("lockfile mentions the proxy: {}", lock.contains(&a.local_origin));
        restore_in(&project.0, &a.local_origin, &a.upstream_origin);
        let lock = std::fs::read_to_string(project.0.join("package-lock.json")).unwrap();
        assert!(!lock.contains("127.0.0.1"));
        assert!(lock.contains("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"));
        let stored: Vec<_> = std::fs::read_dir(cache.0.join("registry.npmjs.org")).unwrap().flatten().map(|e| e.file_name()).collect();
        println!("{stored:?}");
        assert!(stored.iter().any(|n| n.to_string_lossy().ends_with(".tgz")));
    }

    #[test]
    fn file_names_are_safe() {
        assert_eq!(sanitize("/@s%2fn/-/n-1.tgz"), "%2F@s%252fn%2F-%2Fn-1.tgz");
        assert!(!sanitize("/../../etc/passwd").contains('/'));
    }
}
