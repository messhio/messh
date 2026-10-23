//! Key sources. Keys are used locally; they never go to messh.

use crate::{wba, Error};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, Error as Pkcs8Error};
use ed25519_dalek::{Signer as _, SigningKey};
use std::path::PathBuf;
use std::sync::Arc;

/// Implement to sign in a KMS, HSM or ssh-agent.
pub trait Signer: Send + Sync {
    /// Raw 32-byte Ed25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// Ed25519 signature over `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

/// Where the signing key comes from.
#[derive(Clone)]
#[non_exhaustive]
pub enum KeySource {
    /// Unencrypted ssh-ed25519 OpenSSH key or PKCS#8 PEM, e.g. `~/.ssh/id_ed25519`.
    File(PathBuf),
    /// Environment variable: PEM text, or base64 of PEM or PKCS#8 DER.
    Env(String),
    /// Raw 32-byte Ed25519 seed.
    Seed([u8; 32]),
    /// Your own signer.
    Signer(Arc<dyn Signer>),
    /// A key held by ssh-agent (`SSH_AUTH_SOCK`), such as a passphrase-protected
    /// key you added with ssh-add; the private key stays in the agent. With
    /// several Ed25519 keys loaded, `fingerprint` (`SHA256:…`) picks the one
    /// you published; `None` picks the only one.
    SshAgent { fingerprint: Option<String> },
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::File(p) => write!(f, "KeySource::File({})", p.display()),
            KeySource::Env(n) => write!(f, "KeySource::Env({n})"),
            KeySource::Seed(_) => f.write_str("KeySource::Seed(…)"),
            KeySource::Signer(_) => f.write_str("KeySource::Signer(…)"),
            KeySource::SshAgent { fingerprint } => {
                write!(f, "KeySource::SshAgent({fingerprint:?})")
            }
        }
    }
}

struct LocalSigner(SigningKey);

impl Signer for LocalSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn key_err(msg: impl Into<String>) -> Error {
    Error::new("invalid_key", msg)
}

impl KeySource {
    pub(crate) fn load(&self) -> Result<Arc<dyn Signer>, Error> {
        match self {
            KeySource::File(path) => {
                let path = expand(path);
                let data = std::fs::read(&path).map_err(|e| {
                    let hint = if e.kind() == std::io::ErrorKind::NotFound {
                        "; create one with ssh-keygen -t ed25519, then messh publish"
                    } else {
                        ""
                    };
                    key_err(format!("read {}: {e}{hint}", path.display()))
                })?;
                parse(&data)
            }
            KeySource::Env(name) => {
                let v = std::env::var(name).unwrap_or_default();
                let v = v.trim();
                if v.is_empty() {
                    return Err(key_err(format!("environment variable {name} is empty")));
                }
                if v.contains("-----BEGIN") {
                    parse(v.as_bytes())
                } else {
                    let raw = STANDARD
                        .decode(v)
                        .map_err(|_| key_err(format!("{name} is neither PEM nor base64")))?;
                    parse(&raw)
                }
            }
            KeySource::Seed(seed) => Ok(Arc::new(LocalSigner(SigningKey::from_bytes(seed)))),
            KeySource::Signer(s) => Ok(s.clone()),
            KeySource::SshAgent { fingerprint } => ssh_agent(fingerprint.as_deref()),
        }
    }
}

fn expand(p: &std::path::Path) -> PathBuf {
    match (p.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => p.to_path_buf(),
    }
}

fn parse(data: &[u8]) -> Result<Arc<dyn Signer>, Error> {
    let text = String::from_utf8_lossy(data);
    let key = if text.contains("OPENSSH PRIVATE KEY") {
        openssh(&text)?
    } else if text.contains("ENCRYPTED PRIVATE KEY") {
        return Err(key_err(
            "encrypted keys aren't supported; load the key into ssh-agent and use KeySource::SshAgent",
        ));
    } else if text.contains("-----BEGIN") {
        SigningKey::from_pkcs8_pem(&text)
            .map_err(|e: Pkcs8Error| key_err(format!("PKCS#8: {e}")))?
    } else {
        SigningKey::from_pkcs8_der(data).map_err(|e| key_err(format!("PKCS#8: {e}")))?
    };
    Ok(Arc::new(LocalSigner(key)))
}

/// Unpack the openssh-key-v1 container (PROTOCOL.key) to the Ed25519 seed.
fn openssh(pem: &str) -> Result<SigningKey, Error> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let buf = STANDARD
        .decode(b64.trim())
        .map_err(|_| key_err("bad OpenSSH base64"))?;
    let magic = b"openssh-key-v1\0";
    if !buf.starts_with(magic) {
        return Err(key_err("not an OpenSSH private key"));
    }
    let mut r = Reader {
        b: &buf[magic.len()..],
    };
    let cipher = r.str()?;
    r.str()?;
    r.str()?;
    if cipher != b"none" {
        return Err(key_err(
            "passphrase-protected key; load it into ssh-agent (ssh-add) and use KeySource::SshAgent",
        ));
    }
    if r.u32()? != 1 {
        return Err(key_err("expected one key"));
    }
    r.str()?;
    let mut p = Reader { b: r.str()? };
    if p.u32()? != p.u32()? {
        return Err(key_err("OpenSSH check bytes differ"));
    }
    if p.str()? != b"ssh-ed25519" {
        return Err(key_err("need an ssh-ed25519 key"));
    }
    let public = p.str()?;
    let sk = p.str()?;
    if sk.len() != 64 || &sk[32..] != public {
        return Err(key_err("malformed ssh-ed25519 private key"));
    }
    let seed: [u8; 32] = sk[..32].try_into().expect("32 bytes");
    Ok(SigningKey::from_bytes(&seed))
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32, Error> {
        if self.b.len() < 4 {
            return Err(key_err("truncated OpenSSH key"));
        }
        let v = u32::from_be_bytes(self.b[..4].try_into().expect("4 bytes"));
        self.b = &self.b[4..];
        Ok(v)
    }
    fn str(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        if n > self.b.len() {
            return Err(key_err("truncated OpenSSH key"));
        }
        let (s, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(s)
    }
}

// ssh-agent protocol (draft-miller-ssh-agent): u32 length, message type, payload.
const AGENTC_REQUEST_IDENTITIES: u8 = 11;
const AGENT_IDENTITIES_ANSWER: u8 = 12;
const AGENTC_SIGN_REQUEST: u8 = 13;
const AGENT_SIGN_RESPONSE: u8 = 14;

fn ssh_agent(fingerprint: Option<&str>) -> Result<Arc<dyn Signer>, Error> {
    let path = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| cfg!(windows).then(|| r"\\.\pipe\openssh-ssh-agent".to_string()))
        .ok_or_else(|| {
            key_err("ssh-agent isn't running (SSH_AUTH_SOCK is not set); start it: eval \"$(ssh-agent)\" && ssh-add")
        })?;
    let reply = agent_call(&path, &[AGENTC_REQUEST_IDENTITIES])
        .map_err(|e| key_err(format!("ssh-agent at {path}: {e}")))?;
    if reply.first() != Some(&AGENT_IDENTITIES_ANSWER) {
        return Err(key_err(format!(
            "ssh-agent at {path}: it wouldn't list its keys"
        )));
    }
    let malformed = |_| key_err(format!("ssh-agent at {path}: malformed reply"));
    let mut r = Reader { b: &reply[1..] };
    let mut keys: Vec<(Vec<u8>, [u8; 32], String)> = Vec::new();
    for _ in 0..r.u32().map_err(malformed)? {
        let blob = r.str().map_err(malformed)?;
        r.str().map_err(malformed)?; // comment
        let mut b = Reader { b: blob };
        if b.str().map_err(malformed)? != b"ssh-ed25519" {
            continue;
        }
        if let Ok(public) = <[u8; 32]>::try_from(b.str().map_err(malformed)?) {
            keys.push((blob.to_vec(), public, wba::fingerprint(&public)));
        }
    }
    let listed = keys
        .iter()
        .map(|k| k.2.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let pick: Vec<_> = keys
        .iter()
        .filter(|k| fingerprint.is_none_or(|f| k.2 == f))
        .collect();
    match (keys.len(), pick.as_slice()) {
        (0, _) => Err(key_err("ssh-agent has no Ed25519 keys; add yours with ssh-add ~/.ssh/id_ed25519")),
        (_, []) => Err(key_err(format!(
            "ssh-agent has no key {}; it has {listed}",
            fingerprint.unwrap_or_default()
        ))),
        (_, [k]) => Ok(Arc::new(AgentSigner { path, blob: k.0.clone(), public: k.1 })),
        (n, _) => Err(key_err(format!(
            "ssh-agent has {n} Ed25519 keys; choose one with KeySource::SshAgent {{ fingerprint }}: {listed}"
        ))),
    }
}

struct AgentSigner {
    path: String,
    blob: Vec<u8>,
    public: [u8; 32],
}

impl Signer for AgentSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        let mut msg = vec![AGENTC_SIGN_REQUEST];
        msg.extend(wba::ssh_string(&self.blob));
        msg.extend(wba::ssh_string(message));
        msg.extend([0u8; 4]);
        let reply = agent_call(&self.path, &msg).map_err(|e| format!("ssh-agent: {e}"))?;
        if reply.first() != Some(&AGENT_SIGN_RESPONSE) {
            return Err("ssh-agent refused to sign; is the key still loaded (ssh-add -l)?".into());
        }
        let unexpected = || "ssh-agent returned an unexpected signature".to_string();
        let mut r = Reader { b: &reply[1..] };
        let mut sig = Reader {
            b: r.str().map_err(|_| unexpected())?,
        };
        if sig.str().map_err(|_| unexpected())? != b"ssh-ed25519" {
            return Err(unexpected());
        }
        <[u8; 64]>::try_from(sig.str().map_err(|_| unexpected())?).map_err(|_| unexpected())
    }
}

fn agent_call(path: &str, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    fn round_trip(s: &mut (impl Read + Write), msg: &[u8]) -> std::io::Result<Vec<u8>> {
        s.write_all(&wba::ssh_string(msg))?;
        let mut n = [0u8; 4];
        s.read_exact(&mut n)?;
        let n = u32::from_be_bytes(n) as usize;
        if n > 1 << 20 {
            return Err(std::io::Error::other("reply too large"));
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf)?;
        Ok(buf)
    }
    #[cfg(windows)]
    if path.starts_with(r"\\.\pipe\") {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        return round_trip(&mut f, msg);
    }
    #[cfg(unix)]
    {
        let mut s = std::os::unix::net::UnixStream::connect(path)?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        s.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        round_trip(&mut s, msg)
    }
    #[cfg(not(unix))]
    Err(std::io::Error::other(format!("can't connect to {path}")))
}
