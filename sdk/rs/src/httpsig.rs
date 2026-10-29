//! HTTP message signatures (RFC 9421) with Ed25519 for any request or
//! response: any label, tag and key ID, every derived component, and every
//! field parameter (sf, key, bs, req, tr).
//!
//! ```no_run
//! use messh::httpsig::{sign_message, verify_message, Message, SignOptions, VerifyOptions};
//! # let signer: std::sync::Arc<dyn messh::Signer> = unimplemented!();
//! let m = Message { method: "POST".into(), url: "https://example.com/foo".into(), ..Default::default() };
//! let signed = sign_message(&m, signer.as_ref(), &SignOptions {
//!     components: vec!["@method".into(), "@authority".into()], keyid: Some("k1".into()), ..Default::default() })?;
//! # Ok::<(), String>(())
//! ```
//!
//! Web Bot Auth, built on this, is [`crate::Client`] and [`crate::verify`].

use crate::keys::Signer;
use crate::sf::{self, Bare, Item, Member, Params};
use crate::verify::{NonceStore, VerifyError};
use crate::wba;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What a signature covers: a request, or a response (`status`) with the request it answers.
#[derive(Clone, Debug, Default)]
pub struct Message {
    /// Request method, exactly as sent.
    pub method: String,
    /// Absolute target URI of a request. A Host header, if any, is the authority.
    pub url: String,
    /// Header field lines, in order.
    pub headers: Vec<(String, String)>,
    /// Checked against a covered Content-Digest; `None` skips the check.
    pub body: Option<Vec<u8>>,
    /// Response status code; 0 for a request.
    pub status: u16,
    /// For a response: the request it answers, for components with `req`.
    pub request: Option<Box<Message>>,
    /// Trailer field lines, for components with `tr`.
    pub trailers: Vec<(String, String)>,
    /// The request line's target, if known; else path and query.
    pub request_target: String,
}

struct Msg {
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: String,
    request_target: String,
    status: u16,
    headers: Vec<(String, String)>,
    trailers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    request: Option<Box<Msg>>,
}

fn values<'a>(h: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    h.iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

impl Msg {
    fn from(m: &Message) -> Msg {
        let lower = |h: &[(String, String)]| -> Vec<(String, String)> {
            h.iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
                .collect()
        };
        let mut out = Msg {
            method: m.method.clone(),
            scheme: String::new(),
            authority: String::new(),
            path: String::new(),
            query: String::new(),
            request_target: m.request_target.clone(),
            status: m.status,
            headers: lower(&m.headers),
            trailers: lower(&m.trailers),
            body: m.body.clone(),
            request: m.request.as_ref().map(|r| Box::new(Msg::from(r))),
        };
        if let Some((scheme, authority, path, query)) = wba::split_url(&m.url) {
            out.scheme = scheme;
            out.authority = authority;
            out.path = path;
            out.query = query;
        }
        let host = values(&out.headers, "host")
            .first()
            .map(|h| h.trim().to_string());
        if let Some(h) = host {
            out.authority = h;
        }
        out
    }
}

/// Structured-field types ("dictionary", "list" or "item") of fields covered with sf.
pub type FieldTypes = HashMap<String, String>;

fn known_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "accept-signature"
        | "content-digest"
        | "priority"
        | "repr-digest"
        | "signature"
        | "signature-input"
        | "want-content-digest"
        | "want-repr-digest" => "dictionary",
        "cache-status" | "proxy-status" => "list",
        "signature-agent" => "dictionary-or-item",
        _ => return None,
    })
}

fn fail(code: &'static str, msg: impl Into<String>) -> VerifyError {
    VerifyError::new(code, msg)
}

// --- component identifiers ---

#[derive(Clone, Debug)]
struct Comp {
    name: String,
    params: Params,
}

impl Comp {
    fn id(&self) -> String {
        Bare::Str(self.name.clone()).ser() + &sf::ser_params(&self.params)
    }
}

fn checked(c: Comp) -> Result<Comp, String> {
    let b = c.name.as_bytes();
    let derived = b.len() > 1
        && b[0] == b'@'
        && b[1].is_ascii_lowercase()
        && b[1..].iter().all(|&x| x.is_ascii_lowercase() || x == b'-');
    let field = !b.is_empty()
        && b.iter().all(|&x| {
            x.is_ascii_lowercase() || x.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&x)
        });
    if derived || field {
        Ok(c)
    } else {
        Err(format!(
            "bad component name {:?} (lowercase field names, or @derived)",
            c.name
        ))
    }
}

fn parse_component(s: &str) -> Result<Comp, String> {
    if !s.starts_with('"') {
        return checked(Comp {
            name: s.to_ascii_lowercase(),
            params: Vec::new(),
        });
    }
    match sf::parse_item(s) {
        Ok(Item {
            bare: Bare::Str(name),
            params,
        }) => checked(Comp { name, params }),
        _ => Err(format!("bad component identifier {s}")),
    }
}

// --- component values (RFC 9421 §2) ---

/// The identifier and signature-base value of one component of a message.
pub fn component_value(
    m: &Message,
    component: &str,
    field_types: &FieldTypes,
) -> Result<(String, String), String> {
    let c = parse_component(component)?;
    Ok((c.id(), value(&Msg::from(m), &c, field_types)?))
}

fn value(m: &Msg, c: &Comp, types: &FieldTypes) -> Result<String, String> {
    let id = c.id();
    let (mut req, mut strict, mut bs, mut tr) = (false, false, false, false);
    let (mut key, mut name): (Option<String>, Option<String>) = (None, None);
    for (k, v) in &c.params {
        match (k.as_str(), v) {
            ("req" | "sf" | "bs" | "tr", Bare::Bool(true)) => match k.as_str() {
                "req" => req = true,
                "sf" => strict = true,
                "bs" => bs = true,
                _ => tr = true,
            },
            ("req" | "sf" | "bs" | "tr", _) => {
                return Err(format!("{id}: parameter {k} must be true"))
            }
            ("key", Bare::Str(s)) => key = Some(s.clone()),
            ("name", Bare::Str(s)) => name = Some(s.clone()),
            ("key" | "name", _) => return Err(format!("{id}: parameter {k} must be a string")),
            _ => return Err(format!("{id}: unknown parameter {k}")),
        }
    }
    let derived = c.name.starts_with('@');
    if derived && (strict || bs || tr || key.is_some()) {
        return Err(format!("{id}: sf, bs, tr and key apply to fields only"));
    }
    if name.is_some() && c.name != "@query-param" {
        return Err(format!("{id}: name applies to @query-param only"));
    }
    if bs && (strict || key.is_some()) {
        return Err(format!("{id}: bs can't be combined with sf or key"));
    }
    let ctx = if req {
        match (&m.request, m.status) {
            (Some(r), s) if s != 0 => r.as_ref(),
            _ => {
                return Err(format!(
                    "{id}: req needs a response and the request it answers"
                ))
            }
        }
    } else {
        m
    };
    if derived {
        if c.name == "@query-param" && name.is_none() {
            return Err("@query-param needs a name parameter".into());
        }
        return derived_value(ctx, &c.name, name.as_deref().unwrap_or(""));
    }
    field_value(
        if tr { &ctx.trailers } else { &ctx.headers },
        &c.name,
        strict,
        bs,
        key.as_deref(),
        types,
    )
}

fn path_of(m: &Msg) -> &str {
    if m.path.is_empty() {
        "/"
    } else {
        &m.path
    }
}

fn path_query(m: &Msg) -> String {
    if m.query.is_empty() {
        path_of(m).to_string()
    } else {
        format!("{}?{}", path_of(m), m.query)
    }
}

fn derived_value(m: &Msg, name: &str, param: &str) -> Result<String, String> {
    if name == "@status" {
        return if m.status == 0 {
            Err("@status applies to responses only".into())
        } else {
            Ok(m.status.to_string())
        };
    }
    if m.authority.is_empty() && m.method.is_empty() {
        return Err(format!(
            "{name} needs the request (use req in a response signature)"
        ));
    }
    match name {
        "@method" if m.method.is_empty() => Err("@method needs a request method".into()),
        "@method" => Ok(m.method.clone()),
        "@target-uri" if m.scheme.is_empty() || m.authority.is_empty() => {
            Err("@target-uri needs a scheme and an authority".into())
        }
        "@target-uri" => Ok(format!(
            "{}://{}{}",
            m.scheme.to_ascii_lowercase(),
            m.authority.to_ascii_lowercase(),
            path_query(m)
        )),
        "@authority" if m.authority.is_empty() => Err("@authority needs an authority".into()),
        "@authority" => Ok(m.authority.to_ascii_lowercase()),
        "@scheme" if m.scheme.is_empty() => Err("@scheme needs a scheme".into()),
        "@scheme" => Ok(m.scheme.to_ascii_lowercase()),
        "@request-target" if !m.request_target.is_empty() => Ok(m.request_target.clone()),
        "@request-target" => Ok(path_query(m)),
        "@path" => Ok(path_of(m).to_string()),
        "@query" => Ok(format!("?{}", m.query)),
        "@query-param" => query_param(&m.query, param),
        _ => Err(format!("unknown derived component {name}")),
    }
}

/// Strip surrounding whitespace and replace obsolete line folding with one space.
fn clean(v: &str) -> String {
    let t: Vec<char> = v.trim_matches(|c| c == ' ' || c == '\t').chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < t.len() {
        let mut j = i;
        while j < t.len() && (t[j] == ' ' || t[j] == '\t') {
            j += 1;
        }
        let mut k = j;
        if k < t.len() && t[k] == '\r' {
            k += 1;
        }
        if k < t.len() && t[k] == '\n' {
            let mut e = k + 1;
            while e < t.len() && (t[e] == ' ' || t[e] == '\t') {
                e += 1;
            }
            if e > k + 1 {
                out.push(' ');
                i = e;
                continue;
            }
        }
        out.push(t[i]);
        i += 1;
    }
    out
}

fn field_value(
    h: &[(String, String)],
    name: &str,
    strict: bool,
    bs: bool,
    key: Option<&str>,
    types: &FieldTypes,
) -> Result<String, String> {
    let vals = values(h, name);
    if vals.is_empty() {
        return Err(format!("covered field {name} is missing"));
    }
    let parts: Vec<String> = vals
        .iter()
        .map(|v| {
            let c = clean(v);
            if bs {
                Bare::Bin(c.chars().map(|ch| ch as u32 as u8).collect()).ser()
            } else {
                c
            }
        })
        .collect();
    let v = parts.join(", ");
    if let Some(key) = key {
        let (d, _) =
            sf::parse_dictionary(&v).map_err(|e| format!("{name} is not a dictionary: {e}"))?;
        return sf::member(&d, key)
            .map(Member::ser)
            .ok_or_else(|| format!("{name} has no member {key:?}"));
    }
    if strict {
        return strict_value(name, &v, types);
    }
    Ok(v)
}

fn strict_value(name: &str, v: &str, types: &FieldTypes) -> Result<String, String> {
    let t = types
        .get(name)
        .map(String::as_str)
        .or_else(|| known_type(name));
    if matches!(t, Some("dictionary") | Some("dictionary-or-item")) {
        match sf::parse_dictionary(v) {
            Ok((d, _)) => return Ok(sf::ser_dictionary(&d)),
            Err(e) if t == Some("dictionary") => return Err(format!("{name}: {e}")),
            Err(_) => {}
        }
    }
    match t {
        Some("item") | Some("dictionary-or-item") => sf::parse_item(v)
            .map(|it| it.ser())
            .map_err(|e| format!("{name}: {e}")),
        Some("list") => sf::parse_list(v)
            .map(|l| sf::ser_list(&l))
            .map_err(|e| format!("{name}: {e}")),
        _ => Err(format!(
            "can't serialize {name} strictly: its structured-field type is unknown"
        )),
    }
}

fn form_decode(s: &str) -> Vec<u8> {
    let b = s.replace('+', " ").into_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn form_encode(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c.is_ascii_alphanumeric() || b"*-._".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}

/// The encoded value of one query parameter (RFC 9421 §2.2.8).
fn query_param(raw: &str, name: &str) -> Result<String, String> {
    let vals: Vec<String> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_encode(&form_decode(k)) == name).then(|| form_encode(&form_decode(v)))
        })
        .collect();
    match vals.len() {
        0 => Err(format!("query parameter {name:?} is missing")),
        1 => Ok(vals[0].clone()),
        _ => Err(format!("query parameter {name:?} occurs more than once")),
    }
}

// --- signature base (RFC 9421 §2.5) ---

fn base(m: &Msg, comps: &[Comp], params: &str, types: &FieldTypes) -> Result<String, String> {
    let mut seen = HashSet::new();
    let mut lines = Vec::with_capacity(comps.len() + 1);
    for c in comps {
        let id = c.id();
        if !seen.insert(id.clone()) {
            return Err(format!("component {id} is covered twice"));
        }
        lines.push(format!("{id}: {}", value(m, c, types)?));
    }
    lines.push(format!("\"@signature-params\": {params}"));
    let b = lines.join("\n");
    if b.bytes()
        .any(|c| !(c == b'\n' || (0x20..=0x7e).contains(&c)))
    {
        return Err("signature base must be printable ASCII (wrap such fields with bs)".into());
    }
    Ok(b)
}

// --- signing ---

/// One signature to make. `None` parameters are left out.
#[derive(Clone, Debug)]
pub struct SignOptions {
    /// Default "sig1".
    pub label: String,
    /// Covered components, in order: plain names (`@method`, `content-type`) or
    /// identifiers with parameters (`"example-dict";key="a"`).
    pub components: Vec<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub keyid: Option<String>,
    /// "ed25519", or `None` to leave it out.
    pub alg: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
    pub field_types: FieldTypes,
}

impl Default for SignOptions {
    fn default() -> Self {
        SignOptions {
            label: "sig1".into(),
            components: Vec::new(),
            created: None,
            expires: None,
            keyid: None,
            alg: None,
            nonce: None,
            tag: None,
            field_types: FieldTypes::new(),
        }
    }
}

/// A signature ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub label: String,
    /// The Signature-Input member value: covered components and parameters.
    pub input: String,
    /// The Signature member value: `:base64:`.
    pub signature: String,
    /// The signature base that was signed.
    pub base: String,
}

impl Signed {
    /// Signature-Input and Signature with only this signature.
    pub fn headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Signature-Input".into(),
                format!("{}={}", self.label, self.input),
            ),
            (
                "Signature".into(),
                format!("{}={}", self.label, self.signature),
            ),
        ]
    }
}

/// Sign a message.
pub fn sign_message(m: &Message, signer: &dyn Signer, o: &SignOptions) -> Result<Signed, String> {
    if !sf::valid_key(&o.label) {
        return Err(format!("bad label {:?}", o.label));
    }
    let comps = o
        .components
        .iter()
        .map(|s| parse_component(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut params = Params::new();
    if let Some(c) = o.created {
        params.push(("created".into(), Bare::Int(c)));
    }
    if let Some(e) = o.expires {
        params.push(("expires".into(), Bare::Int(e)));
    }
    for (k, v) in [
        ("keyid", &o.keyid),
        ("alg", &o.alg),
        ("nonce", &o.nonce),
        ("tag", &o.tag),
    ] {
        if let Some(v) = v {
            if !sf::valid_string(v) {
                return Err(format!("{k} must be printable ASCII"));
            }
            params.push((k.into(), Bare::Str(v.clone())));
        }
    }
    let items = comps
        .iter()
        .map(|c| Item {
            bare: Bare::Str(c.name.clone()),
            params: c.params.clone(),
        })
        .collect();
    let input = Member::Inner(items, params).ser();
    let b = base(&Msg::from(m), &comps, &input, &o.field_types)?;
    let sig = signer.sign(b.as_bytes())?;
    Ok(Signed {
        label: o.label.clone(),
        input,
        signature: format!(":{}:", STANDARD.encode(sig)),
        base: b,
    })
}

// --- parsing signatures ---

/// One covered component of a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Covered {
    /// Serialized identifier, e.g. `"signature-agent";key="sig1"`.
    pub id: String,
    pub name: String,
    /// Its key parameter, if any.
    pub key: Option<String>,
}

/// One signature of a message, parsed but not verified.
#[derive(Clone, Debug)]
pub struct Signature {
    pub label: String,
    pub covered: Vec<Covered>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
    pub value: Vec<u8>,
    comps: Vec<Comp>,
    params: String,
}

impl Signature {
    /// Whether a component with this name is covered, with any parameters.
    pub fn covers(&self, name: &str) -> bool {
        self.covered.iter().any(|c| c.name == name)
    }
}

fn dictionary(h: &[(String, String)], name: &str) -> Result<sf::Dictionary, VerifyError> {
    let (d, dups) = sf::parse_dictionary(&values(h, &name.to_ascii_lowercase()).join(", "))
        .map_err(|e| fail("bad_signature", format!("{name}: {e}")))?;
    match dups.first() {
        Some(l) => Err(fail(
            "bad_signature",
            format!("{name} repeats the label {l}"),
        )),
        None => Ok(d),
    }
}

fn parse_signatures(m: &Msg) -> Result<Vec<Signature>, VerifyError> {
    if values(&m.headers, "signature-input").is_empty()
        || values(&m.headers, "signature").is_empty()
    {
        return Err(fail(
            "missing_signature",
            "send Signature-Input and Signature (RFC 9421)",
        ));
    }
    let inputs = dictionary(&m.headers, "Signature-Input")?;
    let sigs = dictionary(&m.headers, "Signature")?;
    let mut out = Vec::new();
    for (label, mem) in &inputs {
        let Member::Inner(items, ps) = mem else {
            return Err(fail(
                "bad_signature",
                format!("Signature-Input {label} is not an inner list"),
            ));
        };
        let mut s = Signature {
            label: label.clone(),
            covered: Vec::new(),
            created: None,
            expires: None,
            keyid: None,
            alg: None,
            nonce: None,
            tag: None,
            value: Vec::new(),
            comps: Vec::new(),
            params: mem.ser(),
        };
        let mut seen = HashSet::new();
        for it in items {
            let Bare::Str(name) = &it.bare else {
                return Err(fail(
                    "bad_signature",
                    format!("Signature-Input {label}: a component is not a string"),
                ));
            };
            let c = checked(Comp {
                name: name.clone(),
                params: it.params.clone(),
            })
            .map_err(|e| fail("bad_signature", format!("Signature-Input {label}: {e}")))?;
            let id = c.id();
            if !seen.insert(id.clone()) {
                return Err(fail(
                    "bad_signature",
                    format!("Signature-Input {label} covers {id} twice"),
                ));
            }
            let key = match sf::param(&c.params, "key") {
                Some(Bare::Str(k)) => Some(k.clone()),
                _ => None,
            };
            s.covered.push(Covered {
                id,
                name: c.name.clone(),
                key,
            });
            s.comps.push(c);
        }
        for (k, v) in ps {
            match (k.as_str(), v) {
                ("created", Bare::Int(n)) => s.created = Some(*n),
                ("expires", Bare::Int(n)) => s.expires = Some(*n),
                ("created" | "expires", _) => {
                    return Err(fail("bad_signature", format!("{k} must be an integer")))
                }
                ("keyid", Bare::Str(x)) => s.keyid = Some(x.clone()),
                ("alg", Bare::Str(x)) => s.alg = Some(x.clone()),
                ("nonce", Bare::Str(x)) => s.nonce = Some(x.clone()),
                ("tag", Bare::Str(x)) => s.tag = Some(x.clone()),
                ("keyid" | "alg" | "nonce" | "tag", _) => {
                    return Err(fail("bad_signature", format!("{k} must be a string")))
                }
                _ => {}
            }
        }
        match sf::member(&sigs, label) {
            Some(Member::Item(Item {
                bare: Bare::Bin(b), ..
            })) => s.value = b.clone(),
            _ => return Err(fail("bad_signature", format!("no Signature for {label}"))),
        }
        out.push(s);
    }
    if out.is_empty() {
        return Err(fail(
            "missing_signature",
            "Signature-Input has no signatures",
        ));
    }
    Ok(out)
}

/// Parse Signature-Input and Signature. Labels and covered components must not repeat (RFC 9421 §4.1, §2.5).
pub fn signatures(m: &Message) -> Result<Vec<Signature>, VerifyError> {
    parse_signatures(&Msg::from(m))
}

/// Choose a signature by label, else by tag, else the only one.
pub fn pick_signature<'a>(
    sigs: &'a [Signature],
    label: Option<&str>,
    tag: Option<&str>,
) -> Result<&'a Signature, VerifyError> {
    let hit = match (label, tag) {
        (Some(l), _) => sigs.iter().find(|s| s.label == l),
        (None, Some(t)) => sigs.iter().find(|s| s.tag.as_deref() == Some(t)),
        (None, None) if sigs.len() == 1 => sigs.first(),
        _ => None,
    };
    hit.ok_or_else(|| match (label, tag) {
        (Some(l), _) => fail("bad_signature", format!("no signature labeled {l}")),
        (None, Some(t)) => fail("bad_signature", format!("no signature with tag={t:?}")),
        _ => fail(
            "bad_signature",
            format!(
                "the message has {} signatures: choose one by label or tag",
                sigs.len()
            ),
        ),
    })
}

/// The RFC 9530 Content-Digest field for a body (sha-256).
pub fn content_digest(body: &[u8]) -> String {
    wba::content_digest(body)
}

/// Check a body against a Content-Digest field (sha-256 or sha-512).
pub fn check_digest(field: &str, body: &[u8]) -> Result<(), VerifyError> {
    let mut known = 0;
    if let Ok((d, _)) = sf::parse_dictionary(field) {
        for (k, m) in &d {
            let sum: Vec<u8> = match k.as_str() {
                "sha-256" => Sha256::digest(body).to_vec(),
                "sha-512" => Sha512::digest(body).to_vec(),
                _ => continue,
            };
            known += 1;
            match m {
                Member::Item(Item {
                    bare: Bare::Bin(b), ..
                }) if *b == sum => {}
                _ => {
                    return Err(fail(
                        "digest_mismatch",
                        "the body doesn't match Content-Digest",
                    ))
                }
            }
        }
    }
    if known == 0 {
        return Err(fail(
            "digest_mismatch",
            "Content-Digest has no sha-256 or sha-512 digest",
        ));
    }
    Ok(())
}

// --- verifying ---

/// Resolves a keyid to a raw Ed25519 public key; an error is unknown_key (or your own VerifyError).
pub type KeyResolver<'a> = &'a dyn Fn(&str) -> Result<[u8; 32], VerifyError>;

/// Which signature to verify and how.
pub struct VerifyOptions<'a> {
    /// Verify the signature with this label.
    pub label: Option<String>,
    /// Or the first one with this tag (else the only one).
    pub tag: Option<String>,
    pub keys: KeyResolver<'a>,
    /// Seconds since epoch. Default now.
    pub now: Option<i64>,
    /// How far created may be ahead of now, in seconds. Default 60.
    pub max_skew: i64,
    /// If set, how old created may be, in seconds.
    pub max_age: Option<i64>,
    /// Component names that must be covered.
    pub required: Vec<String>,
    /// Reject a nonce seen before (signatures with a nonce).
    pub nonces: Option<Arc<dyn NonceStore>>,
    pub field_types: FieldTypes,
}

impl<'a> VerifyOptions<'a> {
    /// Options with defaults and this key resolver.
    pub fn new(keys: KeyResolver<'a>) -> Self {
        VerifyOptions {
            label: None,
            tag: None,
            keys,
            now: None,
            max_skew: 60,
            max_age: None,
            required: Vec::new(),
            nonces: None,
            field_types: FieldTypes::new(),
        }
    }
}

/// A verified signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub label: String,
    /// Covered component identifiers.
    pub components: Vec<String>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub base: String,
}

/// Verify one signature of a message: content digest, time, key, then the signature.
pub fn verify_message(m: &Message, o: &VerifyOptions<'_>) -> Result<Verified, VerifyError> {
    let msg = Msg::from(m);
    let sigs = parse_signatures(&msg)?;
    let s = pick_signature(&sigs, o.label.as_deref(), o.tag.as_deref())?;
    verify(&msg, s, o)
}

/// Verify a signature from [`signatures`]; `label` and `tag` are ignored.
pub fn verify_signature(
    m: &Message,
    s: &Signature,
    o: &VerifyOptions<'_>,
) -> Result<Verified, VerifyError> {
    verify(&Msg::from(m), s, o)
}

fn verify(m: &Msg, s: &Signature, o: &VerifyOptions<'_>) -> Result<Verified, VerifyError> {
    for name in &o.required {
        if !s.covers(name) {
            return Err(fail("bad_signature", format!("{name} must be covered")));
        }
    }
    if let Some(alg) = s.alg.as_deref().filter(|a| *a != "ed25519") {
        return Err(fail(
            "bad_signature",
            format!("alg {alg:?} is not supported (ed25519 only)"),
        ));
    }
    for c in s.comps.iter().filter(|c| c.name == "content-digest") {
        let ctx = match (sf::param(&c.params, "req"), &m.request) {
            (Some(_), Some(r)) => r.as_ref(),
            _ => m,
        };
        if let Some(body) = &ctx.body {
            check_digest(&values(&ctx.headers, "content-digest").join(", "), body)?;
        }
    }
    let now = o.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    if let Some(created) = s.created {
        if created > now + o.max_skew {
            return Err(fail(
                "clock_skew",
                format!("created is {}s ahead of the clock", created - now),
            ));
        }
        if o.max_age.is_some_and(|age| created < now - age) {
            return Err(fail(
                "clock_skew",
                format!("the signature is {}s old", now - created),
            ));
        }
    }
    if s.expires.is_some_and(|e| now > e) {
        return Err(fail("clock_skew", "the signature expired"));
    }
    let pub_ = (o.keys)(s.keyid.as_deref().unwrap_or(""))?;
    let vk =
        VerifyingKey::from_bytes(&pub_).map_err(|_| fail("unknown_key", "not an Ed25519 key"))?;
    let b = base(m, &s.comps, &s.params, &o.field_types).map_err(|e| fail("bad_signature", e))?;
    let sig: [u8; 64] = s
        .value
        .as_slice()
        .try_into()
        .map_err(|_| fail("bad_signature", "signature must be 64 bytes"))?;
    vk.verify_strict(b.as_bytes(), &EdSignature::from_bytes(&sig))
        .map_err(|_| fail("bad_signature", "the signature doesn't match the message"))?;
    if let (Some(store), Some(nonce)) = (&o.nonces, &s.nonce) {
        let mut ttl = o.max_age.map_or(2 * o.max_skew, |a| a + o.max_skew);
        if let Some(e) = s.expires {
            ttl = ttl.max(e - now + o.max_skew);
        }
        let key = format!("{} {nonce}", s.keyid.as_deref().unwrap_or(""));
        if !store.add(&key, Duration::from_secs(ttl.max(0) as u64)) {
            return Err(fail(
                "nonce_replayed",
                "this signature was already accepted once",
            ));
        }
    }
    Ok(Verified {
        label: s.label.clone(),
        components: s.covered.iter().map(|c| c.id.clone()).collect(),
        keyid: s.keyid.clone(),
        alg: s.alg.clone(),
        nonce: s.nonce.clone(),
        tag: s.tag.clone(),
        created: s.created,
        expires: s.expires,
        base: b,
    })
}
