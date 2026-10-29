//! Verify Web Bot Auth signatures with keys from messh, or from the key
//! directories of other agents you trust.
//!
//! ```no_run
//! use messh::verify::{Request, VerifyConfig, Verifier};
//! let verifier = Verifier::new(VerifyConfig::trust(["mukul"]));
//! # let headers: Vec<(String, String)> = vec![];
//! let agent = verifier.verify(&Request { method: "GET", url: "https://api.example.com/hello", headers: &headers, body: b"" })?;
//! # Ok::<(), messh::verify::VerifyError>(())
//! ```

use crate::httpsig::{self, Signature};
use crate::sf::{self, Bare, Item, Member};
use crate::wba::{self, Directory, Jwk};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use std::collections::{HashMap, HashSet};
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
    /// An error with a messh code (e.g. from your own key resolver: `unknown_key`); `untrusted` is 403, the rest 401.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
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
    /// messh username, e.g. "mukul"; for other agents, their origin or `jwk:<thumbprint>`.
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
    /// Not a messh identity: an agent origin you trust, or inline keys.
    pub external: bool,
    /// The key's directory response carried a valid signature by that key.
    pub signed_directory: bool,
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
    required: Option<Vec<String>>,
    require_signed: bool,
}

impl VerifyConfig {
    /// Who may call. Required (non-empty): messh usernames, "*" for any messh
    /// identity, the origin of another Web Bot Auth agent
    /// (`https://agent.example`, whose key directory is at
    /// `<origin>/.well-known/http-message-signatures-directory`), or
    /// `jwk:<thumbprint>` for a key sent inline in Signature-Agent.
    pub fn trust<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        VerifyConfig {
            trust: patterns
                .into_iter()
                .map(|p| {
                    let p: String = p.into();
                    if p.starts_with("https://") || p.starts_with("http://") {
                        p.to_ascii_lowercase().trim_end_matches('/').to_string()
                    } else {
                        p
                    }
                })
                .collect(),
            registries: Vec::new(),
            max_skew: 60,
            cache_ttl: Duration::from_secs(300),
            stale_if_error: Duration::from_secs(3600),
            timeout: Duration::from_secs(5),
            nonces: Arc::new(MemoryNonceStore::default()),
            clock: None,
            resolver: None,
            required: None,
            require_signed: false,
        }
    }
    /// Replace the components every signature must cover (default `@method`,
    /// `@authority`, `@path`, `signature-agent`), for agents that sign less.
    /// `@target-uri` counts for `@authority`, `@path` and `@query`,
    /// `@request-target` for `@path` and `@query`. Signature-Agent, a query
    /// and a body (through content-digest) must be covered regardless.
    pub fn require_components<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required = Some(names.into_iter().map(Into::into).collect());
        self
    }
    /// Ignore keys a fetched key directory doesn't sign (draft §5). messh.io
    /// doesn't sign its directories yet, so this rejects messh identities for now.
    pub fn require_signed_directory(mut self, on: bool) -> Self {
        self.require_signed = on;
        self
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
    signed: HashSet<String>,
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
        if !matches!((h.get("signature-input"), h.get("signature")), (Some(i), Some(s)) if !i.is_empty() && !s.is_empty())
        {
            return Err(VerifyError::new(
                "missing_signature",
                "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)",
            ));
        }
        let (_, _, _, query) =
            wba::split_url(req.url).ok_or_else(|| bad("request url must be absolute".into()))?;
        let msg = httpsig::Message {
            method: req.method.to_string(),
            url: req.url.to_string(),
            headers: req.headers.to_vec(),
            body: Some(req.body.to_vec()),
            ..Default::default()
        };
        let sigs = httpsig::signatures(&msg)?;
        let sig = sigs
            .iter()
            .find(|s| s.tag.as_deref() == Some(wba::TAG))
            .ok_or_else(|| bad(r#"no signature with tag="web-bot-auth""#.into()))?;
        self.coverage(sig, !query.is_empty())?;
        let agent_url = agent_of(h.get("signature-agent").map(String::as_str), sig)?;
        if sig.alg.as_deref().is_some_and(|a| a != "ed25519") {
            return Err(bad("alg is not supported".into()));
        }

        if sig.covers("content-digest") {
            httpsig::check_digest(
                h.get("content-digest").map(String::as_str).unwrap_or(""),
                req.body,
            )?;
        } else if !req.body.is_empty() {
            return Err(bad(
                "a request body must be covered by content-digest".into()
            ));
        }

        let created = sig
            .created
            .ok_or_else(|| bad("created is required".into()))?;
        if (now - created).abs() > self.cfg.max_skew {
            return Err(VerifyError::new(
                "clock_skew",
                format!("created is {}s from the server clock", now - created),
            ));
        }
        if sig
            .expires
            .is_some_and(|exp| now > exp || exp - created > wba::MAX_LIFETIME)
        {
            return Err(VerifyError::new("clock_skew", "signature expired"));
        }
        let nonce = sig
            .nonce
            .clone()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| bad("nonce is required".into()))?;

        let kid = sig.keyid.clone().unwrap_or_default();
        let who = self.classify(&agent_url, &kid)?;
        // Before any fetch: callers outside the trust list can't make this API fetch directories.
        if !self
            .cfg
            .trust
            .iter()
            .any(|t| *t == who.identity || (t == "*" && !who.external))
        {
            return Err(VerifyError::new(
                "untrusted",
                format!("{} is not in this API's trust list", who.identity),
            ));
        }
        let (key, pub_, signed) = self.lookup(&agent_url, &who, &kid)?;
        let keys = |_: &str| Ok(pub_);
        let mut opts = httpsig::VerifyOptions::new(&keys);
        opts.now = Some(now);
        opts.max_skew = self.cfg.max_skew;
        opts.max_age = Some(self.cfg.max_skew);
        httpsig::verify_signature(&msg, sig, &opts)?;
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
            identity: who.identity,
            key_name: key.name.clone(),
            key_id: kid,
            fingerprint: if key.fingerprint.is_empty() {
                wba::fingerprint(&pub_)
            } else {
                key.fingerprint.clone()
            },
            agent_url,
            created,
            external: who.external,
            signed_directory: signed,
        })
    }

    /// The components the signature must cover.
    fn coverage(&self, s: &Signature, has_query: bool) -> Result<(), VerifyError> {
        let has = |name: &str| {
            s.covers(name)
                || (name == "@authority" && s.covers("@target-uri"))
                || ((name == "@path" || name == "@query")
                    && (s.covers("@target-uri") || s.covers("@request-target")))
        };
        let mut required: Vec<String> = match &self.cfg.required {
            Some(r) => r.clone(),
            None => ["@method", "@authority", "@path", "signature-agent"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        required.push("signature-agent".into());
        for c in &required {
            if !has(c) {
                return Err(VerifyError::new(
                    "bad_signature",
                    format!("{c} must be covered"),
                ));
            }
        }
        if has_query && !has("@query") {
            return Err(VerifyError::new(
                "bad_signature",
                "@query must be covered when the URL has a query",
            ));
        }
        Ok(())
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

    /// Map Signature-Agent to a messh identity (`<registry>/<user>`), an agent
    /// origin, or inline keys, refusing anything else.
    fn classify(&self, agent_url: &str, kid: &str) -> Result<Who, VerifyError> {
        if agent_url.starts_with("data:") {
            return Ok(Who {
                identity: format!("jwk:{kid}"),
                external: true,
                fetch_url: String::new(),
                inline: Some(parse_data_uri(agent_url)?),
            });
        }
        let (scheme, authority, path, query) = wba::split_url(agent_url)
            .filter(|(s, _, _, _)| s == "https" || s == "http")
            .ok_or_else(|| VerifyError::new("bad_signature", "Signature-Agent is not a URL"))?;
        let origin = format!("{scheme}://{authority}");
        if let Some((_, base)) = self.cfg.registries.iter().find(|(o, _)| *o == origin) {
            let id = path.trim_matches('/').to_string();
            if !crate::valid_identity(&id) {
                return Err(VerifyError::new(
                    "unknown_key",
                    "Signature-Agent must be <registry>/<user>",
                ));
            }
            return Ok(Who {
                fetch_url: format!("{base}/{id}{}", wba::DIRECTORY_PATH),
                identity: id,
                external: false,
                inline: None,
            });
        }
        let origin = origin.to_ascii_lowercase();
        if self.cfg.trust.contains(&origin) {
            if path != "/" || !query.is_empty() {
                return Err(VerifyError::new(
                    "untrusted",
                    format!(
                        "Signature-Agent {agent_url}: an agent outside messh is an origin, like {origin}"
                    ),
                ));
            }
            return Ok(Who {
                fetch_url: format!("{origin}{}", wba::DIRECTORY_PATH),
                identity: origin,
                external: true,
                inline: None,
            });
        }
        Err(VerifyError::new(
            "untrusted",
            format!(
                "Signature-Agent {agent_url} is not a messh registry or an agent this API trusts"
            ),
        ))
    }

    /// The signer's key for `kid`, and whether its directory response signed
    /// it. Directories are cached for `cache_ttl`; an unknown kid refetches at
    /// most every 30 s (so a key published a moment ago works), unknown
    /// identities are remembered the same way, one fetch per directory runs at
    /// a time, and while the directory is unreachable cached keys keep working
    /// for `stale_if_error`.
    fn lookup(
        &self,
        agent_url: &str,
        who: &Who,
        kid: &str,
    ) -> Result<(Jwk, [u8; 32], bool), VerifyError> {
        let found = |dir: Option<&Directory>, signed: Option<&HashSet<String>>| {
            find(dir, kid)
                .map(|(k, p)| (k, p, signed.is_some_and(|s| s.contains(kid))))
                .ok_or_else(|| match dir {
                    None => VerifyError::new(
                        "unknown_key",
                        format!("there's no messh identity at {agent_url}"),
                    ),
                    Some(_) => VerifyError::new(
                        "unknown_key",
                        format!("keyid {kid} is not an active key of {agent_url}; publish it with messh publish"),
                    ),
                })
        };
        if let Some(dir) = &who.inline {
            return found(Some(dir), None);
        }
        if let Some(r) = &self.cfg.resolver {
            return found(Some(&r(agent_url, &who.identity)?), None);
        }
        let now = self.now();
        let ttl = self.cfg.cache_ttl.as_secs() as i64;
        let mut e = self.entry(agent_url);
        if let Some(at) = e.at.filter(|at| now - at < ttl) {
            if find(e.dir.as_ref(), kid).is_some() {
                return found(e.dir.as_ref(), Some(&e.signed));
            }
            if now - at < MIN_REFRESH {
                return found(e.dir.as_ref(), None);
            }
        }
        let _fetching = self.fetching[stripe(agent_url)].lock().expect("fetch lock");
        e = self.entry(agent_url);
        if e.at.is_some_and(|at| now - at < ttl.min(MIN_REFRESH)) {
            return found(e.dir.as_ref(), Some(&e.signed)); // fetched by another thread while this one waited
        }
        if e.failed_at.is_none_or(|f| now - f >= RETRY_AFTER) {
            match self.fetch(&who.fetch_url) {
                Ok((dir, signed)) => {
                    let r = found(dir.as_ref(), Some(&signed));
                    self.store(
                        agent_url,
                        Entry {
                            dir,
                            signed,
                            at: Some(now),
                            ..Entry::default()
                        },
                    );
                    return r;
                }
                Err(()) => {
                    e.failed_at = Some(now);
                    self.store(agent_url, e.clone());
                }
            }
        }
        // The directory is unreachable: keep verifying with the cached one for a while.
        match e.at {
            Some(at) if now - at < self.cfg.stale_if_error.as_secs() as i64 => {
                found(e.dir.as_ref(), Some(&e.signed))
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
    fn fetch(&self, url: &str) -> Result<(Option<Directory>, HashSet<String>), ()> {
        let agent = ureq::AgentBuilder::new().timeout(self.cfg.timeout).build();
        let resp = match agent
            .get(url)
            .set(
                "Accept",
                "application/http-message-signatures-directory+json, application/json",
            )
            .set("User-Agent", &format!("messh-rust/{}", crate::VERSION))
            .call()
        {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => return Ok((None, HashSet::new())),
            Err(_) => return Err(()),
        };
        let headers: Vec<(String, String)> = resp
            .headers_names()
            .iter()
            .flat_map(|n| {
                resp.all(n)
                    .into_iter()
                    .map(move |v| (n.clone(), v.to_string()))
            })
            .collect();
        let body = resp.into_string().map_err(|_| ())?;
        let (mut dir, signed) =
            verify_directory(url, &headers, body.as_bytes(), self.now()).map_err(|_| ())?;
        if self.cfg.require_signed {
            dir.keys.retain(|k| signed.contains(&k.kid));
        }
        Ok((Some(dir), signed))
    }

    #[cfg(not(feature = "fetch"))]
    fn fetch(&self, _url: &str) -> Result<(Option<Directory>, HashSet<String>), ()> {
        Err(())
    }
}

/// Who a Signature-Agent names.
struct Who {
    identity: String,
    external: bool,
    fetch_url: String,
    inline: Option<Directory>,
}

fn find(dir: Option<&Directory>, kid: &str) -> Option<(Jwk, [u8; 32])> {
    dir?.keys.iter().find_map(|k| {
        let p = wba::jwk_public_key(k)?;
        (k.kid == kid || (k.kid.is_empty() && wba::thumbprint(&p) == kid)).then(|| (k.clone(), p))
    })
}

/// Signature-Agent: the member named by the covered component's key
/// parameter, else a string, else the member named like the label.
fn agent_of(header: Option<&str>, s: &Signature) -> Result<String, VerifyError> {
    let bad = |m: String| VerifyError::new("bad_signature", m);
    let header = header
        .filter(|h| !h.is_empty())
        .ok_or_else(|| bad("Signature-Agent header is missing".into()))?;
    let str_member = |key: &str| match sf::parse_dictionary(header) {
        Ok((d, _)) => match sf::member(&d, key) {
            Some(Member::Item(Item {
                bare: Bare::Str(v), ..
            })) => Some(v.clone()),
            _ => None,
        },
        Err(_) => None,
    };
    let keyed = s
        .covered
        .iter()
        .find(|c| c.name == "signature-agent")
        .and_then(|c| c.key.clone());
    if let Some(key) = keyed {
        return str_member(&key).ok_or_else(|| bad(format!("Signature-Agent has no member {key}")));
    }
    if let Ok(Item {
        bare: Bare::Str(v), ..
    }) = sf::parse_item(header)
    {
        return Ok(v);
    }
    str_member(&s.label).ok_or_else(|| bad(format!("Signature-Agent has no value for {}", s.label)))
}

/// An inline key directory: `data:application/http-message-signatures-directory[+json][;base64],…`
fn parse_data_uri(s: &str) -> Result<Directory, VerifyError> {
    let bad = || {
        VerifyError::new(
            "bad_signature",
            "Signature-Agent: the data URI isn't a key directory",
        )
    };
    let (meta, data) = s["data:".len()..].split_once(',').ok_or_else(bad)?;
    let (media, is_b64) = match meta.strip_suffix(";base64") {
        Some(m) => (m, true),
        None => (meta, false),
    };
    let media = media
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let known = [
        "application/http-message-signatures-directory",
        "application/http-message-signatures-directory+json",
        "application/json",
    ];
    if !known.contains(&media.as_str()) {
        return Err(bad());
    }
    let raw = if is_b64 {
        STANDARD_NO_PAD
            .decode(data.trim_end_matches('='))
            .map_err(|_| bad())?
    } else {
        percent_decode(data)
    };
    serde_json::from_slice(&raw).map_err(|_| bad())
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((hi << 4 | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// A key directory response fetched from `url`: its keys, and the key IDs a
/// valid directory signature covers (tag `http-message-signatures-directory`,
/// signed by that key, binding the response to the authority it came from;
/// draft-meunier-http-message-signatures-directory §5).
pub fn verify_directory(
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    now: i64,
) -> Result<(Directory, HashSet<String>), String> {
    let dir: Directory =
        serde_json::from_slice(body).map_err(|e| format!("not a key directory: {e}"))?;
    // The response carries the request's URL too, for directories signed over a plain "@authority".
    let msg = httpsig::Message {
        url: url.to_string(),
        headers: headers.to_vec(),
        body: Some(body.to_vec()),
        status: 200,
        request: Some(Box::new(httpsig::Message {
            method: "GET".into(),
            url: url.to_string(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut signed = HashSet::new();
    let Ok(sigs) = httpsig::signatures(&msg) else {
        return Ok((dir, signed));
    };
    for s in sigs
        .iter()
        .filter(|s| s.tag.as_deref() == Some(crate::DIRECTORY_TAG))
    {
        let kid = s.keyid.clone().unwrap_or_default();
        let Some((_, pub_)) = find(Some(&dir), &kid) else {
            continue;
        };
        let keys = |_: &str| Ok(pub_);
        let mut opts = httpsig::VerifyOptions::new(&keys);
        opts.now = Some(now);
        if httpsig::verify_signature(&msg, s, &opts).is_ok() {
            signed.insert(kid);
        }
    }
    Ok((dir, signed))
}

fn stripe(key: &str) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() % FETCH_STRIPES as u64) as usize
}
