//! Web Bot Auth wire format: RFC 9421 signature base, structured-field
//! parsing, RFC 7638 thumbprints and RFC 9530 Content-Digest.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const TAG: &str = "web-bot-auth";
pub const LABEL: &str = "sig1";
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
pub const MAX_LIFETIME: i64 = 300;

/// An Ed25519 public key in a key directory.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kid: String,
    #[serde(
        default,
        rename = "messh_name",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(
        default,
        rename = "messh_fingerprint",
        skip_serializing_if = "String::is_empty"
    )]
    pub fingerprint: String,
}

/// Body of `<agent>/.well-known/http-message-signatures-directory`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Directory {
    pub keys: Vec<Jwk>,
}

/// RFC 7638 JWK thumbprint of a raw Ed25519 public key.
pub fn thumbprint(public_key: &[u8; 32]) -> String {
    let canon = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(public_key)
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canon.as_bytes()))
}

/// SSH wire-format string: u32 length, then the bytes.
pub fn ssh_string(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// The key's SSH fingerprint, as ssh-keygen -l and messh print it: `SHA256:…`.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let mut blob = ssh_string(b"ssh-ed25519");
    blob.extend(ssh_string(public_key));
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)))
}

pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

pub fn quote(s: &str) -> String {
    serde_json::to_string(s).expect("string serializes")
}

pub fn params(names: &[&str], created: i64, expires: i64, keyid: &str, nonce: &str) -> String {
    let inner: Vec<String> = names.iter().map(|n| quote(n)).collect();
    format!(
        r#"({});created={};expires={};keyid={};alg="ed25519";nonce={};tag="{}""#,
        inner.join(" "),
        created,
        expires,
        quote(keyid),
        quote(nonce),
        TAG
    )
}

pub fn base(components: &[(String, String)], sig_params: &str) -> Vec<u8> {
    let mut s = String::new();
    for (name, value) in components {
        s.push_str(&quote(name));
        s.push_str(": ");
        s.push_str(value);
        s.push('\n');
    }
    s.push_str("\"@signature-params\": ");
    s.push_str(sig_params);
    s.into_bytes()
}

#[derive(Debug, Clone)]
pub struct SigParams {
    pub label: String,
    pub components: Vec<String>,
    pub params: HashMap<String, String>,
    pub raw: String,
}

impl SigParams {
    pub fn covers(&self, c: &str) -> bool {
        self.components.iter().any(|x| x == c)
    }
}

fn split_top(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let (mut out, mut depth, mut in_str, mut start, mut i) =
        (Vec::new(), 0i32, false, 0usize, 0usize);
    while i < b.len() {
        let c = b[i];
        if in_str && c == b'\\' {
            i += 2;
            continue;
        }
        if c == b'"' {
            in_str = !in_str;
        } else if !in_str {
            match c {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(s[start..i].trim().to_string());
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    out.push(s[start..].trim().to_string());
    out
}

fn unquote(v: &str) -> Result<String, String> {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        serde_json::from_str(v).map_err(|e| e.to_string())
    } else {
        Ok(v.to_string())
    }
}

fn member(label: &str, raw: &str) -> Result<SigParams, String> {
    if !raw.starts_with('(') {
        return Err("Signature-Input member is not an inner list".into());
    }
    let end = raw.find(')').ok_or("unterminated inner list")?;
    let mut components = Vec::new();
    for item in raw[1..end].split_whitespace() {
        if !(item.starts_with('"') && item.ends_with('"')) {
            return Err(format!("bad component {item}"));
        }
        components.push(unquote(item)?);
    }
    let mut params = HashMap::new();
    for p in raw[end + 1..].split(';').skip(1) {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        params.insert(k.trim().to_string(), unquote(v)?);
    }
    Ok(SigParams {
        label: label.to_string(),
        components,
        params,
        raw: raw.to_string(),
    })
}

pub fn pick_web_bot_auth(header: &str) -> Result<SigParams, String> {
    for m in split_top(header) {
        if let Some((label, raw)) = m.split_once('=') {
            let sp = member(label, raw)?;
            if sp.params.get("tag").map(String::as_str) == Some(TAG) {
                return Ok(sp);
            }
        }
    }
    Err(r#"no signature with tag="web-bot-auth""#.into())
}

pub fn signature_bytes(header: &str, label: &str) -> Result<Vec<u8>, String> {
    for m in split_top(header) {
        if let Some((l, v)) = m.split_once('=') {
            if l == label && v.len() > 2 && v.starts_with(':') && v.ends_with(':') {
                return STANDARD
                    .decode(&v[1..v.len() - 1])
                    .map_err(|e| e.to_string());
            }
        }
    }
    Err(format!("no Signature for {label}"))
}

pub fn parse_agent(header: &str, label: &str) -> Result<String, String> {
    let h = header.trim();
    if h.starts_with('"') {
        return unquote(h);
    }
    for m in split_top(h) {
        if let Some((l, v)) = m.split_once('=') {
            if l == label {
                return unquote(v);
            }
        }
    }
    Err(format!("Signature-Agent has no value for {label}"))
}

/// Decode a JWK; None if malformed or if kid isn't its thumbprint.
pub fn jwk_public_key(k: &Jwk) -> Option<[u8; 32]> {
    if k.kty != "OKP" || k.crv != "Ed25519" {
        return None;
    }
    let pub_: [u8; 32] = URL_SAFE_NO_PAD.decode(&k.x).ok()?.try_into().ok()?;
    if !k.kid.is_empty() && k.kid != thumbprint(&pub_) {
        return None;
    }
    Some(pub_)
}

/// Minimal URL split: (scheme, authority, path, query). No fragments are signed.
pub fn split_url(url: &str) -> Option<(String, String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let rest = rest.split('#').next().unwrap_or("");
    let (authority, pq) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }
    let (path, query) = pq.split_once('?').unwrap_or((pq, ""));
    let path = if path.is_empty() { "/" } else { path };
    Some((
        scheme.to_ascii_lowercase(),
        authority.to_string(),
        path.to_string(),
        query.to_string(),
    ))
}
