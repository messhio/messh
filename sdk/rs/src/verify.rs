//! Verify Web Bot Auth signatures with keys from messh.
//!
//! ```no_run
//! use messh::verify::{Request, VerifyConfig, Verifier};
//! let verifier = Verifier::new(VerifyConfig::trust(["mukul"]));
//! # let headers: Vec<(String, String)> = vec![];
//! let agent = verifier.verify(&Request { method: "GET", url: "https://api.example.com/hello", headers: &headers, body: b"" })?;
//! # Ok::<(), messh::verify::VerifyError>(())
//! ```

use crate::wba::{self, Directory, Jwk};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Directory cache policy, the same in every messh SDK.
/// An unknown keyid refetches its signer's directory at most this often (s).
const MIN_REFRESH: i64 = 30;
/// While messh is unreachable, retry a directory at most this often (s).
const RETRY_AFTER: i64 = 5;
/// Directories kept at most.
const MAX_ENTRIES: usize = 10_000;
/// Fetch locks: one fetch per directory at a time.
const FETCH_STRIPES: usize = 64;

pub const ACCEPT_SIGNATURE: &str = r#"sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth""#;

/// Verification failure; `code()` and `status()` follow the messh spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    code: &'static str,
    status: u16,
    message: String,
}

impl VerifyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        let status = if code == "untrusted" { 403 } else { 401 };
        VerifyError {
            code,
            status,
            message: message.into(),
        }
    }
    /// missing_signature, bad_signature, digest_mismatch, clock_skew, nonce_replayed, unknown_key, untrusted.
    pub fn code(&self) -> &'static str {
        self.code
    }
    /// 401, or 403 for untrusted.
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    /// JSON error body: `{"error": code, "message": …}`.
    pub fn to_json(&self) -> String {
        serde_json::json!({ "error": self.code, "message": self.message }).to_string()
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for VerifyError {}

/// A verified caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// messh username, e.g. "mukul".
    pub identity: String,
    /// Key name on messh, e.g. "laptop".
    pub key_name: String,
    /// RFC 7638 thumbprint.
    pub key_id: String,
    /// SHA256:… of the SSH key.
    pub fingerprint: String,
    /// Signature-Agent.
    pub agent_url: String,
    /// Signature creation time, seconds since epoch.
    pub created: i64,
}

/// Replay store. `add` returns false if `key` was seen within `ttl`.
pub trait NonceStore: Send + Sync {
    fn add(&self, key: &str, ttl: Duration) -> bool;
}

/// In-process replay store. Use a shared store when running several instances.
#[derive(Default)]
pub struct MemoryNonceStore(Mutex<HashMap<String, Instant>>);

impl NonceStore for MemoryNonceStore {
    fn add(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut seen = self.0.lock().expect("nonce lock");
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(key) {
            return false;
        }
        seen.insert(key.to_string(), now + ttl);
        true
    }
}

type Resolver = Arc<dyn Fn(&str, &str) -> Result<Directory, VerifyError> + Send + Sync>;

/// Verifier settings. Start with [`VerifyConfig::trust`].
#[derive(Clone)]
pub struct VerifyConfig {
    trust: Vec<String>,
    registries: Vec<(String, String)>,
    max_skew: i64,
    cache_ttl: Duration,
    stale_if_error: Duration,
    timeout: Duration,
    nonces: Arc<dyn NonceStore>,
    clock: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    resolver: Option<Resolver>,
}

impl VerifyConfig {
    /// Who may call: messh usernames, or "*". Required (non-empty).
    pub fn trust<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        VerifyConfig {
            trust: patterns.into_iter().map(Into::into).collect(),
            registries: Vec::new(),
            max_skew: 60,
            cache_ttl: Duration::from_secs(300),
            stale_if_error: Duration::from_secs(3600),
            timeout: Duration::from_secs(5),
            nonces: Arc::new(MemoryNonceStore::default()),
            clock: None,
            resolver: None,
        }
    }
    /// Accept Signature-Agent URLs under `origin`; fetch directories from
    /// `fetch_base` (or `origin` if empty). Default: https://messh.io.
    pub fn registry(mut self, origin: &str, fetch_base: &str) -> Self {
        let o = origin.trim_end_matches('/').to_string();
        let b = if fetch_base.is_empty() {
            o.clone()
        } else {
            fetch_base.trim_end_matches('/').to_string()
        };
        self.registries.push((o, b));
        self
    }
    /// Max |now − created|. Default 60 s.
    pub fn max_skew(mut self, d: Duration) -> Self {
        self.max_skew = d.as_secs() as i64;
        self
    }
    /// Directory cache. Default 5 min.
    pub fn cache_ttl(mut self, d: Duration) -> Self {
        self.cache_ttl = d;
        self
    }
    /// Keep cached keys this long if messh is unreachable. Default 1 h.
    pub fn stale_if_error(mut self, d: Duration) -> Self {
        self.stale_if_error = d;
        self
    }
    /// Directory fetch timeout. Default 5 s.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
    pub fn nonce_store(mut self, s: Arc<dyn NonceStore>) -> Self {
        self.nonces = s;
        self
    }
    /// Seconds since epoch (tests).
    pub fn clock(mut self, f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Arc::new(f));
        self
    }
    /// Resolve directories yourself (tests, air-gapped setups).
    pub fn directory(
        mut self,
        f: impl Fn(&str, &str) -> Result<Directory, VerifyError> + Send + Sync + 'static,
    ) -> Self {
        self.resolver = Some(Arc::new(f));
        self
    }
}

/// The parts of a request the verifier needs. `url` is the full URL; the
/// authority is the Host header if present, else the URL's host.
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

/// Verifies requests. Create once and share (it caches directories).
pub struct Verifier {
    cfg: VerifyConfig,
    cache: Mutex<Cache>,
    fetching: Vec<Mutex<()>>,
}

#[derive(Default)]
struct Cache {
    map: HashMap<String, Entry>,
    seq: u64,
}

/// A key directory: `dir` is the last good answer (`None`: no such identity),
/// fetched at `at`; `failed_at` is the last failed fetch.
#[derive(Clone, Default)]
struct Entry {
    dir: Option<Directory>,
    at: Option<i64>,
    failed_at: Option<i64>,
    seq: u64,
}

impl Verifier {
    /// Panics if `trust` is empty.
    pub fn new(mut cfg: VerifyConfig) -> Self {
        assert!(
            !cfg.trust.is_empty(),
            "VerifyConfig::trust must not be empty"
        );
        if cfg.registries.is_empty() {
            cfg.registries
                .push(("https://messh.io".into(), "https://messh.io".into()));
        }
        Verifier {
            cfg,
            cache: Mutex::new(Cache::default()),
            fetching: (0..FETCH_STRIPES).map(|_| Mutex::new(())).collect(),
        }
    }

    fn now(&self) -> i64 {
        match &self.cfg.clock {
            Some(c) => c(),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }

    /// Verify one request. Blocking: the first request per identity fetches
    /// its directory (use `spawn_blocking` on async runtimes).
    pub fn verify(&self, req: &Request<'_>) -> Result<Agent, VerifyError> {
        let bad = |m: String| VerifyError::new("bad_signature", m);
        let mut h: HashMap<String, String> = HashMap::new();
        for (k, v) in req.headers {
            let k = k.to_ascii_lowercase();
            let v = v.trim().to_string();
            h.entry(k)
                .and_modify(|e| *e = format!("{e}, {v}"))
                .or_insert(v);
        }
        let now = self.now();
        let (input, sig_header) = match (h.get("signature-input"), h.get("signature")) {
            (Some(i), Some(s)) if !i.is_empty() && !s.is_empty() => (i, s),
            _ => {
                return Err(VerifyError::new(
                    "missing_signature",
                    "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)",
                ))
            }
        };
        let sp = wba::pick_web_bot_auth(input).map_err(bad)?;
        let sig = wba::signature_bytes(sig_header, &sp.label).map_err(bad)?;
        for c in ["@method", "@authority", "@path", "signature-agent"] {
            if !sp.covers(c) {
                return Err(bad(format!("{c} must be covered")));
            }
        }
        let (_, url_authority, path, query) =
            wba::split_url(req.url).ok_or_else(|| bad("request url must be absolute".into()))?;
        if !query.is_empty() && !sp.covers("@query") {
            return Err(bad("@query must be covered when the URL has a query".into()));
        }
        let agent_header = h
            .get("signature-agent")
            .ok_or_else(|| bad("Signature-Agent header is missing".into()))?;
        let agent_url = wba::parse_agent(agent_header, &sp.label).map_err(bad)?;
        if sp
            .params
            .get("alg")
            .map(|a| a != "ed25519")
            .unwrap_or(false)
        {
            return Err(bad("alg is not supported".into()));
        }

        if sp.covers("content-digest") {
            if h.get("content-digest").map(String::as_str)
                != Some(wba::content_digest(req.body).as_str())
            {
                return Err(VerifyError::new(
                    "digest_mismatch",
                    "the body doesn't match Content-Digest",
                ));
            }
        } else if !req.body.is_empty() {
            return Err(bad(
                "a request body must be covered by content-digest".into()
            ));
        }

        let created: i64 = sp
            .params
            .get("created")
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| bad("created is required".into()))?;
        if (now - created).abs() > self.cfg.max_skew {
            return Err(VerifyError::new(
                "clock_skew",
                format!("created is {}s from the server clock", now - created),
            ));
        }
        if let Some(e) = sp.params.get("expires") {
            match e.parse::<i64>() {
                Ok(exp) if now <= exp && exp - created <= wba::MAX_LIFETIME => {}
                _ => return Err(VerifyError::new("clock_skew", "signature expired")),
            }
        }
        let nonce = sp
            .params
            .get("nonce")
            .filter(|n| !n.is_empty())
            .ok_or_else(|| bad("nonce is required".into()))?;

        let identity = self.identity(&agent_url)?;
        // Before any fetch: callers outside the trust list can't make this API fetch directories.
        if !self.cfg.trust.iter().any(|t| t == "*" || *t == identity) {
            return Err(VerifyError::new(
                "untrusted",
                format!("{identity} is not in this API's trust list"),
            ));
        }
        let kid = sp.params.get("keyid").cloned().unwrap_or_default();
        let (key, pub_) = self.lookup(&agent_url, &identity, &kid)?;

        let mut comps = Vec::with_capacity(sp.components.len());
        for c in &sp.components {
            let v = match c.as_str() {
                "@method" => req.method.to_ascii_uppercase(),
                "@authority" => h
                    .get("host")
                    .cloned()
                    .unwrap_or_else(|| url_authority.clone())
                    .to_ascii_lowercase(),
                "@path" => path.clone(),
                "@query" => format!("?{query}"),
                other if other.starts_with('@') => {
                    return Err(bad(format!("unsupported component {other}")))
                }
                other => h
                    .get(other)
                    .cloned()
                    .ok_or_else(|| bad(format!("covered header {other} is missing")))?,
            };
            comps.push((c.clone(), v));
        }
        let vk = VerifyingKey::from_bytes(&pub_)
            .map_err(|_| VerifyError::new("unknown_key", "invalid Ed25519 key"))?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| bad("signature must be 64 bytes".into()))?;
        vk.verify_strict(&wba::base(&comps, &sp.raw), &Signature::from_bytes(&sig))
            .map_err(|_| bad("the signature doesn't match the request".into()))?;
        if !self.cfg.nonces.add(
            &format!("{agent_url} {nonce}"),
            Duration::from_secs(2 * self.cfg.max_skew as u64),
        ) {
            return Err(VerifyError::new(
                "nonce_replayed",
                "this signature was already accepted once",
            ));
        }
        Ok(Agent {
            identity,
            key_name: key.name.clone(),
            key_id: kid,
            fingerprint: key.fingerprint.clone(),
            agent_url,
            created,
        })
    }

    /// Verify an `http::Request` (feature `http`); `body` is the raw body bytes.
    #[cfg(feature = "http")]
    pub fn verify_http<B>(
        &self,
        req: &http::Request<B>,
        body: &[u8],
    ) -> Result<Agent, VerifyError> {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .or(req.uri().authority().map(|a| a.as_str()))
            .unwrap_or("localhost");
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let scheme = req.uri().scheme_str().unwrap_or("http");
        let url = format!("{scheme}://{host}{pq}");
        self.verify(&Request {
            method: req.method().as_str(),
            url: &url,
            headers: &headers,
            body,
        })
    }

    fn origin_base(&self, agent_url: &str) -> Option<(String, &str)> {
        let (scheme, authority, _, _) = wba::split_url(agent_url)?;
        let origin = format!("{scheme}://{authority}");
        self.cfg
            .registries
            .iter()
            .find(|(o, _)| *o == origin)
            .map(|(o, b)| (o.clone(), b.as_str()))
    }

    fn identity(&self, agent_url: &str) -> Result<String, VerifyError> {
        let (_, _, path, _) = wba::split_url(agent_url)
            .ok_or_else(|| VerifyError::new("bad_signature", "Signature-Agent is not a URL"))?;
        if self.origin_base(agent_url).is_none() {
            return Err(VerifyError::new(
                "untrusted",
                format!("Signature-Agent {agent_url} is not a messh registry this API accepts"),
            ));
        }
        let id = path.trim_matches('/').to_string();
        if !crate::valid_identity(&id) {
            return Err(VerifyError::new(
                "unknown_key",
                "Signature-Agent must be <registry>/<user>",
            ));
        }
        Ok(id)
    }

    /// The signer's key for `kid`. Directories are cached for `cache_ttl`; an
    /// unknown kid refetches at most every 30 s (so a key published a moment
    /// ago works), unknown identities are remembered the same way, one fetch
    /// per directory runs at a time, and while messh is unreachable cached
    /// keys keep working for `stale_if_error`.
    fn lookup(
        &self,
        agent_url: &str,
        identity: &str,
        kid: &str,
    ) -> Result<(Jwk, [u8; 32]), VerifyError> {
        let find = |dir: Option<&Directory>| {
            dir?.keys
                .iter()
                .filter(|k| k.kid == kid)
                .find_map(|k| wba::jwk_public_key(k).map(|p| (k.clone(), p)))
        };
        let found = |dir: Option<&Directory>| {
            find(dir).ok_or_else(|| match dir {
                None => VerifyError::new("unknown_key", format!("there's no messh identity at {agent_url}")),
                Some(_) => VerifyError::new(
                    "unknown_key",
                    format!("keyid {kid} is not an active key of {agent_url}; publish it with messh publish"),
                ),
            })
        };
        if let Some(r) = &self.cfg.resolver {
            return found(Some(&r(agent_url, identity)?));
        }
        let now = self.now();
        let ttl = self.cfg.cache_ttl.as_secs() as i64;
        let mut e = self.entry(agent_url);
        if let Some(at) = e.at.filter(|at| now - at < ttl) {
            if let Some(hit) = find(e.dir.as_ref()) {
                return Ok(hit);
            }
            if now - at < MIN_REFRESH {
                return found(e.dir.as_ref());
            }
        }
        let _fetching = self.fetching[stripe(agent_url)].lock().expect("fetch lock");
        e = self.entry(agent_url);
        if e.at.is_some_and(|at| now - at < ttl.min(MIN_REFRESH)) {
            return found(e.dir.as_ref()); // fetched by another thread while this one waited
        }
        if e.failed_at.is_none_or(|f| now - f >= RETRY_AFTER) {
            let (_, base) = self.origin_base(agent_url).expect("checked in identity()");
            match self.fetch(&format!("{base}/{identity}{}", wba::DIRECTORY_PATH)) {
                Ok(dir) => {
                    self.store(
                        agent_url,
                        Entry {
                            dir: dir.clone(),
                            at: Some(now),
                            ..Entry::default()
                        },
                    );
                    return found(dir.as_ref());
                }
                Err(()) => {
                    e.failed_at = Some(now);
                    self.store(agent_url, e.clone());
                }
            }
        }
        // messh is unreachable: keep verifying with the cached directory for a while.
        match e.at {
            Some(at) if now - at < self.cfg.stale_if_error.as_secs() as i64 => {
                found(e.dir.as_ref())
            }
            _ => Err(VerifyError::new(
                "unknown_key",
                format!("key directory for {agent_url} is unavailable"),
            )),
        }
    }

    fn entry(&self, agent_url: &str) -> Entry {
        let cache = self.cache.lock().expect("cache lock");
        cache.map.get(agent_url).cloned().unwrap_or_default()
    }

    fn store(&self, agent_url: &str, mut e: Entry) {
        let mut cache = self.cache.lock().expect("cache lock");
        cache.seq += 1;
        e.seq = cache.seq;
        cache.map.insert(agent_url.to_string(), e);
        if cache.map.len() > MAX_ENTRIES {
            let oldest = cache
                .map
                .iter()
                .min_by_key(|(_, v)| v.seq)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                cache.map.remove(&k);
            }
        }
    }

    #[cfg(feature = "fetch")]
    fn fetch(&self, url: &str) -> Result<Option<Directory>, ()> {
        let agent = ureq::AgentBuilder::new().timeout(self.cfg.timeout).build();
        match agent
            .get(url)
            .set(
                "Accept",
                "application/http-message-signatures-directory+json, application/json",
            )
            .set("User-Agent", &format!("messh-rust/{}", crate::VERSION))
            .call()
        {
            Ok(r) => r
                .into_string()
                .ok()
                .and_then(|s| serde_json::from_str::<Directory>(&s).ok())
                .map(Some)
                .ok_or(()),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(_) => Err(()),
        }
    }

    #[cfg(not(feature = "fetch"))]
    fn fetch(&self, _url: &str) -> Result<Option<Directory>, ()> {
        Err(())
    }
}

fn stripe(key: &str) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() % FETCH_STRIPES as u64) as usize
}
