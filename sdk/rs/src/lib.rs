//! Sign and verify HTTP requests as a messh identity with Web Bot Auth
//! (RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`).
//!
//! ```no_run
//! use messh::{Client, KeySource};
//! let client = Client::builder("mukul")
//!     .key(KeySource::File("~/.ssh/id_ed25519".into()))
//!     .build()?;
//! let headers = client.sign("GET", "https://api.example.com/hello", None)?;
//! # Ok::<(), messh::Error>(())
//! ```
//!
//! Verify incoming requests with [`verify::Verifier`]. Sign or verify any HTTP
//! message signature (RFC 9421) with [`httpsig`].

pub mod httpsig;
mod keys;
mod sf;
pub mod verify;
pub mod wba;

pub use keys::{KeySource, Signer};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_REGISTRY: &str = "https://messh.io";
/// Tags the signatures on a key directory response.
pub const DIRECTORY_TAG: &str = "http-message-signatures-directory";

/// Client-side error. `code()`: invalid_identity, invalid_key, invalid_option, sign_failed,
/// send_failed; from `whoami()`: not_published, registry_unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: &'static str,
    message: String,
}

impl Error {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
        }
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "messh: {}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) fn valid_identity(s: &str) -> bool {
    let b = s.as_bytes();
    (3..=30).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
type NonceFn = Arc<dyn Fn() -> String + Send + Sync>;

/// Builds a [`Client`].
pub struct ClientBuilder {
    identity: String,
    key: Option<KeySource>,
    registry: String,
    expires_in: Duration,
    clock: Option<Clock>,
    nonce: Option<NonceFn>,
    profile: Profile,
}

/// What a client signs beyond the defaults (all optional).
#[derive(Clone, Debug)]
struct Profile {
    label: String,
    tag: String,
    components: Vec<String>,
    agent_dictionary: bool,
}

impl ClientBuilder {
    /// Cover more components than the defaults, after them: `content-type`,
    /// `@target-uri`, `"@query-param";name="id"`. Header values come from
    /// [`Client::sign_with_headers`].
    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.profile
            .components
            .extend(components.into_iter().map(Into::into));
        self
    }
    /// Signature label. Default "sig1".
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.profile.label = label.into();
        self
    }
    /// Signature tag. Default "web-bot-auth"; with any other tag it isn't a Web Bot Auth signature.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.profile.tag = tag.into();
        self
    }
    /// Send Signature-Agent in the dictionary form of newer drafts, keyed by the
    /// label (`sig1="https://messh.io/mukul"`), covered as
    /// `"signature-agent";key="sig1"`. The default string form is what messh
    /// verifiers before 0.2.0 require.
    pub fn agent_dictionary(mut self, on: bool) -> Self {
        self.profile.agent_dictionary = on;
        self
    }
    /// Signing key. Default: `KeySource::File("~/.ssh/id_ed25519")`.
    pub fn key(mut self, key: KeySource) -> Self {
        self.key = Some(key);
        self
    }
    /// messh registry base URL. Default: https://messh.io.
    pub fn registry(mut self, url: impl Into<String>) -> Self {
        self.registry = url.into();
        self
    }
    /// Signature lifetime. Default 60 s, max 300 s.
    pub fn expires_in(mut self, d: Duration) -> Self {
        self.expires_in = d;
        self
    }
    /// Seconds since epoch (tests).
    pub fn clock(mut self, f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Arc::new(f));
        self
    }
    /// Nonce generator (tests).
    pub fn nonce(mut self, f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.nonce = Some(Arc::new(f));
        self
    }

    pub fn build(self) -> Result<Client, Error> {
        if !valid_identity(&self.identity) {
            return Err(Error::new(
                "invalid_identity",
                format!("{:?} is not a messh username", self.identity),
            ));
        }
        if !(self.registry.starts_with("https://") || self.registry.starts_with("http://")) {
            return Err(Error::new(
                "invalid_option",
                "registry must be an http(s) URL",
            ));
        }
        let secs = self.expires_in.as_secs() as i64;
        if !(1..=wba::MAX_LIFETIME).contains(&secs) {
            return Err(Error::new(
                "invalid_option",
                "expires_in must be 1..300 seconds",
            ));
        }
        if !sf::valid_key(&self.profile.label) {
            return Err(Error::new(
                "invalid_option",
                "a label is lowercase letters, digits and _-.*, starting with a letter",
            ));
        }
        if self.profile.tag.is_empty() || !sf::valid_string(&self.profile.tag) {
            return Err(Error::new("invalid_option", "a tag is printable ASCII"));
        }
        let key = self
            .key
            .unwrap_or_else(|| KeySource::File("~/.ssh/id_ed25519".into()));
        let signer = key.load()?;
        let key_id = wba::thumbprint(&signer.public_key());
        Ok(Client {
            identity: self.identity,
            registry: self.registry.trim_end_matches('/').to_string(),
            key_id,
            signer,
            expires_in: secs,
            clock: self.clock.unwrap_or_else(|| {
                Arc::new(|| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0)
                })
            }),
            nonce: self.nonce.unwrap_or_else(|| Arc::new(random_nonce)),
            profile: self.profile,
        })
    }
}

fn random_nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS randomness");
    URL_SAFE_NO_PAD.encode(b)
}

/// This client's key as messh lists it: what an API will see. See [`Client::whoami`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedKey {
    /// messh username, e.g. "mukul".
    pub identity: String,
    /// The key's name on messh, e.g. "build-bot".
    pub key_name: String,
    /// RFC 7638 thumbprint, sent as keyid.
    pub key_id: String,
    /// `SHA256:…` of the SSH key.
    pub fingerprint: String,
    /// Signature-Agent: `<registry>/<identity>`.
    pub agent_url: String,
}

/// Signs requests as one identity. Cheap to clone; safe to share across threads.
#[derive(Clone)]
pub struct Client {
    identity: String,
    registry: String,
    key_id: String,
    signer: Arc<dyn Signer>,
    expires_in: i64,
    clock: Clock,
    nonce: NonceFn,
    profile: Profile,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("identity", &self.identity)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Start building a client for `identity`, a messh username such as `"mukul"`.
    pub fn builder(identity: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            identity: identity.into(),
            key: None,
            registry: DEFAULT_REGISTRY.to_string(),
            expires_in: Duration::from_secs(60),
            clock: None,
            nonce: None,
            profile: Profile {
                label: wba::LABEL.into(),
                tag: wba::TAG.into(),
                components: Vec::new(),
                agent_dictionary: false,
            },
        }
    }

    /// A client from the environment, for agents and CI: `MESSH_IDENTITY`
    /// (required), `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or
    /// `MESSH_KEY_FILE` (default ~/.ssh/id_ed25519), and `MESSH_REGISTRY`.
    pub fn from_env() -> Result<Client, Error> {
        Self::builder_from_env()?.build()
    }

    /// Like [`from_env`](Self::from_env), as a builder you can adjust before `build()`.
    pub fn builder_from_env() -> Result<ClientBuilder, Error> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let identity = var("MESSH_IDENTITY").ok_or_else(|| {
            Error::new(
                "invalid_identity",
                "set MESSH_IDENTITY to your messh username",
            )
        })?;
        let mut b = Client::builder(identity);
        if var("MESSH_KEY").is_some() {
            b = b.key(KeySource::Env("MESSH_KEY".into()));
        } else if let Some(f) = var("MESSH_KEY_FILE") {
            b = b.key(KeySource::File(f.into()));
        }
        if let Some(r) = var("MESSH_REGISTRY") {
            b = b.registry(r);
        }
        Ok(b)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// keyid sent in Signature-Input (RFC 7638 JWK thumbprint).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Signature-Agent URL: `<registry>/<identity>`.
    pub fn agent(&self) -> String {
        format!("{}/{}", self.registry, self.identity)
    }

    /// SSH fingerprint of the signing key (`SHA256:…`), as `messh keys` and ssh-keygen -l print it.
    pub fn fingerprint(&self) -> String {
        wba::fingerprint(&self.signer.public_key())
    }

    /// Check that this client's key is published and active on messh, and
    /// how APIs will see it (feature `fetch`). Run it once at startup: it
    /// turns the most common setup mistake (an unpublished key, so every API
    /// answers 401 unknown_key) into a clear error: not_published or
    /// registry_unreachable.
    #[cfg(feature = "fetch")]
    pub fn whoami(&self) -> Result<PublishedKey, Error> {
        let url = format!("{}{}", self.agent(), wba::DIRECTORY_PATH);
        let resp = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .get(&url)
            .set(
                "Accept",
                "application/http-message-signatures-directory+json, application/json",
            )
            .set("User-Agent", &format!("messh-rust/{VERSION}"))
            .call();
        let dir: wba::Directory = match resp {
            Ok(r) => r
                .into_string()
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .ok_or_else(|| {
                    Error::new(
                        "registry_unreachable",
                        format!("{url} didn't answer with a key directory"),
                    )
                })?,
            Err(ureq::Error::Status(404, _)) => {
                return Err(Error::new(
                    "not_published",
                    format!(
                        "{} has no user {}; sign up, then publish this key ({}) with messh publish",
                        self.registry,
                        self.identity,
                        self.fingerprint()
                    ),
                ))
            }
            Err(ureq::Error::Status(code, _)) => {
                return Err(Error::new(
                    "registry_unreachable",
                    format!("{url} answered HTTP {code}"),
                ))
            }
            Err(e) => {
                return Err(Error::new(
                    "registry_unreachable",
                    format!("can't reach {}: {e}", self.registry),
                ))
            }
        };
        let key = dir.keys.iter().find(|k| k.kid == self.key_id).ok_or_else(|| {
            Error::new(
                "not_published",
                format!(
                    "this key ({}) isn't an active key of {}; publish it with messh publish --key <key>.pub --name <name>",
                    self.fingerprint(),
                    self.agent()
                ),
            )
        })?;
        Ok(PublishedKey {
            identity: self.identity.clone(),
            key_name: key.name.clone(),
            key_id: self.key_id.clone(),
            fingerprint: if key.fingerprint.is_empty() {
                self.fingerprint()
            } else {
                key.fingerprint.clone()
            },
            agent_url: self.agent(),
        })
    }

    /// Headers to add: Signature-Agent, Signature-Input, Signature and, with a
    /// body, Content-Digest. Sign last; don't change the request afterwards.
    pub fn sign(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<Vec<(String, String)>, Error> {
        self.sign_with_host(method, url, body, None)
    }

    /// Like [`sign`](Self::sign), with an explicit Host if it differs from the URL's.
    pub fn sign_with_host(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        host: Option<&str>,
    ) -> Result<Vec<(String, String)>, Error> {
        self.sign_with_headers(method, url, body, host, &[])
    }

    /// Like [`sign_with_host`](Self::sign_with_host), with the request's
    /// headers, for covered components beyond the defaults.
    pub fn sign_with_headers(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        host: Option<&str>,
        request_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, Error> {
        let (_, _, _, query) =
            wba::split_url(url).ok_or_else(|| Error::new("sign_failed", "url must be absolute"))?;
        let p = &self.profile;
        let agent = sf::Bare::Str(self.agent()).ser();
        let mut headers = vec![(
            "Signature-Agent".to_string(),
            if p.agent_dictionary {
                format!("{}={agent}", p.label)
            } else {
                agent
            },
        )];
        let mut comps: Vec<String> = vec!["@method".into(), "@authority".into(), "@path".into()];
        if !query.is_empty() {
            comps.push("@query".into());
        }
        if let Some(b) = body.filter(|b| !b.is_empty()) {
            headers.push(("Content-Digest".to_string(), wba::content_digest(b)));
            comps.push("content-digest".into());
        }
        comps.extend(p.components.iter().cloned());
        comps.push(if p.agent_dictionary {
            format!("\"signature-agent\";key=\"{}\"", p.label)
        } else {
            "signature-agent".into()
        });
        let own = [
            "signature-agent",
            "content-digest",
            "signature-input",
            "signature",
        ];
        let mut fields: Vec<(String, String)> = request_headers
            .iter()
            .filter(|(k, _)| {
                let k = k.to_ascii_lowercase();
                !own.contains(&k.as_str()) && !(host.is_some() && k == "host")
            })
            .cloned()
            .collect();
        fields.extend(headers.iter().cloned());
        if let Some(h) = host {
            fields.push(("Host".into(), h.to_string()));
        }
        let created = (self.clock)();
        let msg = httpsig::Message {
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            headers: fields,
            ..Default::default()
        };
        let signed = httpsig::sign_message(
            &msg,
            self.signer.as_ref(),
            &httpsig::SignOptions {
                label: p.label.clone(),
                components: comps,
                created: Some(created),
                expires: Some(created + self.expires_in),
                keyid: Some(self.key_id.clone()),
                alg: Some("ed25519".into()),
                nonce: Some((self.nonce)()),
                tag: Some(p.tag.clone()),
                ..Default::default()
            },
        )
        .map_err(|e| Error::new("sign_failed", e))?;
        headers.extend(signed.headers());
        Ok(headers)
    }

    /// Sign an `http::Request` in place (feature `http`).
    #[cfg(feature = "http")]
    pub fn sign_request<B: AsRef<[u8]>>(&self, req: &mut http::Request<B>) -> Result<(), Error> {
        let url = req.uri().to_string();
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let body = req.body().as_ref().to_vec();
        for (k, v) in
            self.sign_with_host(req.method().as_str(), &url, Some(&body), host.as_deref())?
        {
            let name = http::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| Error::new("sign_failed", e.to_string()))?;
            let value = http::HeaderValue::from_str(&v)
                .map_err(|e| Error::new("sign_failed", e.to_string()))?;
            req.headers_mut().insert(name, value);
        }
        Ok(())
    }

    /// Sign and send with ureq (feature `fetch`, default). Returns (status, body); HTTP errors aren't Err.
    #[cfg(feature = "fetch")]
    pub fn send(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), Error> {
        let mut req =
            ureq::request(method, url).set("User-Agent", &format!("messh-rust/{VERSION}"));
        for (k, v) in self.sign(method, url, body)? {
            req = req.set(&k, &v);
        }
        let resp = match body {
            Some(b) => req.set("Content-Type", "application/json").send_bytes(b),
            None => req.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Error::new("send_failed", e.to_string())),
        };
        let status = resp.status();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut out)
            .map_err(|e| Error::new("send_failed", e.to_string()))?;
        Ok((status, out))
    }
}

/// A key directory to serve, and the headers that sign it. See [`directory_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryResponse {
    /// The JWKS to serve.
    pub body: Vec<u8>,
    /// Content-Type, Content-Digest, Signature-Input and Signature.
    pub headers: Vec<(String, String)>,
}

/// A key directory for `keys`, to serve yourself at
/// `https://<authority>/.well-known/http-message-signatures-directory`, and the
/// headers that sign it: Content-Digest, and one signature per key binding the
/// directory to `authority` (draft-meunier-http-message-signatures-directory
/// §5), the form Cloudflare's tools check. Build it again before it expires.
pub fn directory_response(
    authority: &str,
    keys: &[KeySource],
    created: i64,
    ttl: Duration,
) -> Result<DirectoryResponse, Error> {
    let signers = keys
        .iter()
        .map(KeySource::load)
        .collect::<Result<Vec<_>, _>>()?;
    let jwks: Vec<String> = signers
        .iter()
        .map(|s| {
            let p = s.public_key();
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(p),
                wba::thumbprint(&p)
            )
        })
        .collect();
    let body = format!(r#"{{"keys":[{}]}}"#, jwks.join(",")).into_bytes();
    let digest = wba::content_digest(&body);
    let resp = httpsig::Message {
        status: 200,
        headers: vec![("Content-Digest".into(), digest.clone())],
        request: Some(Box::new(httpsig::Message {
            method: "GET".into(),
            url: format!("https://{authority}{}", wba::DIRECTORY_PATH),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (mut inputs, mut sigs) = (Vec::new(), Vec::new());
    for (i, s) in signers.iter().enumerate() {
        let signed = httpsig::sign_message(
            &resp,
            s.as_ref(),
            &httpsig::SignOptions {
                label: format!("binding{i}"),
                components: vec![r#""@authority";req"#.into(), "content-digest".into()],
                created: Some(created),
                expires: Some(created + ttl.as_secs() as i64),
                keyid: Some(wba::thumbprint(&s.public_key())),
                alg: Some("ed25519".into()),
                tag: Some(DIRECTORY_TAG.into()),
                ..Default::default()
            },
        )
        .map_err(|e| Error::new("sign_failed", e))?;
        inputs.push(format!("{}={}", signed.label, signed.input));
        sigs.push(format!("{}={}", signed.label, signed.signature));
    }
    let headers = vec![
        (
            "Content-Type".into(),
            "application/http-message-signatures-directory+json".into(),
        ),
        ("Content-Digest".into(), digest),
        ("Signature-Input".into(), inputs.join(", ")),
        ("Signature".into(), sigs.join(", ")),
    ];
    Ok(DirectoryResponse { body, headers })
}
