//! Production behavior: environment config, whoami, ssh-agent, the verifier's
//! directory cache policy. Runs against a local fake registry.

use messh::verify::{Request, Verifier, VerifyConfig};
use messh::{Client, KeySource, PublishedKey};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn vectors() -> (PathBuf, Value) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("web-bot-auth.json")).unwrap())
            .unwrap();
    let key = dir.join(doc["key"]["files"]["openssh"].as_str().unwrap());
    (key, doc["key"]["jwk"].clone())
}

/// A fake registry: dirs[identity] is a directory, absent for 404, "error" for 500.
struct Registry {
    url: String,
    dirs: Arc<Mutex<HashMap<String, String>>>,
    hits: Arc<AtomicUsize>,
}

impl Registry {
    fn start(dirs: &[(&str, String)]) -> Registry {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let dirs = Arc::new(Mutex::new(
            dirs.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<HashMap<_, _>>(),
        ));
        let hits = Arc::new(AtomicUsize::new(0));
        let (d, h) = (dirs.clone(), hits.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (d, h) = (d.clone(), h.clone());
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let mut r = BufReader::new(stream.try_clone().unwrap());
                    r.read_line(&mut line).unwrap();
                    while r
                        .read_line(&mut String::new())
                        .map(|n| n > 2)
                        .unwrap_or(false)
                    {}
                    h.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50)); // let concurrent misses overlap
                    let id = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .split('/')
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    let body = d.lock().unwrap().get(&id).cloned();
                    let resp = match body.as_deref() {
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                        Some("error") => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                        Some(b) => format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()),
                    };
                    let mut s = stream;
                    let _ = s.write_all(resp.as_bytes());
                });
            }
        });
        Registry { url, dirs, hits }
    }
    fn set(&self, id: &str, d: Option<String>) {
        let mut dirs = self.dirs.lock().unwrap();
        match d {
            Some(d) => dirs.insert(id.into(), d),
            None => dirs.remove(id),
        };
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn jwks(jwk: &Value) -> String {
    format!(r#"{{"keys":[{jwk}]}}"#)
}

struct Setup {
    reg: Registry,
    clock: Arc<AtomicI64>,
    verifier: Arc<Verifier>,
    key: PathBuf,
}

impl Setup {
    fn new(dirs: &[(&str, String)], trust: &[&str]) -> Setup {
        let (key, _) = vectors();
        let reg = Registry::start(dirs);
        let clock = Arc::new(AtomicI64::new(1_800_000_000));
        let c = clock.clone();
        let verifier = Verifier::new(
            VerifyConfig::trust(trust.to_vec())
                .registry(&reg.url, "")
                .clock(move || c.load(Ordering::SeqCst)),
        );
        Setup {
            reg,
            clock,
            verifier: Arc::new(verifier),
            key,
        }
    }
    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }
    fn send(&self, identity: &str) -> String {
        let c = self.clock.clone();
        let client = Client::builder(identity)
            .key(KeySource::File(self.key.clone()))
            .registry(self.reg.url.clone())
            .clock(move || c.load(Ordering::SeqCst))
            .build()
            .unwrap();
        let url = "https://api.example/hello";
        let headers = client.sign("GET", url, None).unwrap();
        match self.verifier.verify(&Request {
            method: "GET",
            url,
            headers: &headers,
            body: b"",
        }) {
            Ok(_) => "ok".into(),
            Err(e) => e.code().into(),
        }
    }
}

#[test]
fn fingerprint_and_whoami() {
    let (key, jwk) = vectors();
    let fp = jwk["messh_fingerprint"].as_str().unwrap();
    let reg = Registry::start(&[("mukul", jwks(&jwk)), ("empty", r#"{"keys":[]}"#.into())]);
    let as_ = |id: &str| {
        Client::builder(id)
            .key(KeySource::File(key.clone()))
            .registry(reg.url.clone())
            .build()
            .unwrap()
    };
    assert_eq!(as_("mukul").fingerprint(), fp);
    assert_eq!(
        as_("mukul").whoami().unwrap(),
        PublishedKey {
            identity: "mukul".into(),
            key_name: "sdk-test".into(),
            key_id: jwk["kid"].as_str().unwrap().into(),
            fingerprint: fp.into(),
            agent_url: format!("{}/mukul", reg.url),
        }
    );
    let e = as_("nobody").whoami().unwrap_err();
    assert_eq!(e.code(), "not_published");
    assert!(e.message().contains("no user nobody"), "{e}");
    let e = as_("empty").whoami().unwrap_err();
    assert_eq!(e.code(), "not_published");
    assert!(e.message().contains(fp), "{e}");
    let gone = Client::builder("mukul")
        .key(KeySource::File(key))
        .registry("http://127.0.0.1:1")
        .build()
        .unwrap();
    assert_eq!(gone.whoami().unwrap_err().code(), "registry_unreachable");
}

#[test]
fn missing_key_file_says_how_to_fix_it() {
    let e = Client::builder("mukul")
        .key(KeySource::File("/nonexistent/id_ed25519".into()))
        .build()
        .unwrap_err();
    assert!(e.message().contains("ssh-keygen -t ed25519"), "{e}");
}

// Environment variables are process-wide, so everything that sets them runs in this one test.
#[test]
fn environment_and_ssh_agent() {
    let (key, jwk) = vectors();
    std::env::remove_var("MESSH_KEY");
    std::env::set_var("MESSH_IDENTITY", "mukul");
    std::env::set_var("MESSH_KEY_FILE", &key);
    std::env::set_var("MESSH_REGISTRY", "https://registry.example/");
    let c = Client::from_env().unwrap();
    assert_eq!(
        (c.identity(), c.key_id(), c.agent().as_str()),
        (
            "mukul",
            jwk["kid"].as_str().unwrap(),
            "https://registry.example/mukul"
        )
    );
    std::env::remove_var("MESSH_IDENTITY");
    let e = Client::from_env().unwrap_err();
    assert_eq!(e.code(), "invalid_identity");
    assert!(e.message().contains("MESSH_IDENTITY"));
    for k in ["MESSH_KEY_FILE", "MESSH_REGISTRY"] {
        std::env::remove_var(k);
    }

    // A real ssh-agent holding the conformance key signs byte-identically to the file.
    let Some(agent_bin) = [
        "/usr/bin/ssh-agent",
        "/opt/homebrew/bin/ssh-agent",
        "/usr/local/bin/ssh-agent",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists()) else {
        eprintln!("ssh-agent not installed; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("messh-agent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, copy) = (dir.join("agent.sock"), dir.join("id"));
    std::fs::copy(&key, &copy).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&copy, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let mut agent = std::process::Command::new(agent_bin)
        .args(["-D", "-a"])
        .arg(&sock)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let added = std::process::Command::new("ssh-add")
        .arg(&copy)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "ssh-add: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    std::env::set_var("SSH_AUTH_SOCK", &sock);
    let sign = |k: KeySource| {
        let c = Client::builder("mukul")
            .key(k)
            .clock(|| 1760882531)
            .nonce(|| "b3k2pUe8Qz1".into())
            .build()
            .unwrap();
        c.sign(
            "POST",
            "https://api.acme.dev/deployments",
            Some(br#"{"env":"staging"}"#),
        )
        .unwrap()
    };
    let via_agent = sign(KeySource::SshAgent { fingerprint: None });
    let result = (
        via_agent == sign(KeySource::File(key.clone())),
        Client::builder("mukul")
            .key(KeySource::SshAgent {
                fingerprint: Some("SHA256:nope".into()),
            })
            .build(),
    );
    agent.kill().ok();
    agent.wait().ok();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.0, "agent and file signatures differ");
    let e = result.1.unwrap_err();
    assert!(
        e.message()
            .contains(jwk["messh_fingerprint"].as_str().unwrap()),
        "{e}"
    );
}

#[test]
fn untrusted_callers_never_trigger_a_fetch() {
    let (_, jwk) = vectors();
    let s = Setup::new(&[("mukul", jwks(&jwk))], &["alice"]);
    assert_eq!(s.send("mukul"), "untrusted");
    assert_eq!(s.reg.hits(), 0);
}

#[test]
fn unknown_identities_are_remembered_for_30s() {
    let s = Setup::new(&[], &["*"]);
    assert_eq!(s.send("ghost"), "unknown_key");
    s.advance(10);
    assert_eq!(s.send("ghost"), "unknown_key");
    assert_eq!(s.reg.hits(), 1);
    s.advance(21);
    s.send("ghost");
    assert_eq!(s.reg.hits(), 2);
}

#[test]
fn new_keys_work_within_30s() {
    let (_, jwk) = vectors();
    let s = Setup::new(&[("mukul", r#"{"keys":[]}"#.into())], &["*"]);
    assert_eq!(s.send("mukul"), "unknown_key");
    s.reg.set("mukul", Some(jwks(&jwk)));
    s.advance(10);
    assert_eq!(s.send("mukul"), "unknown_key");
    s.advance(21);
    assert_eq!(s.send("mukul"), "ok");
    s.advance(60);
    assert_eq!(s.send("mukul"), "ok");
    assert_eq!(s.reg.hits(), 2);
}

#[test]
fn not_found_is_never_stale_but_an_outage_is() {
    let (_, jwk) = vectors();
    let s = Setup::new(&[("mukul", jwks(&jwk))], &["*"]);
    assert_eq!(s.send("mukul"), "ok");
    s.reg.set("mukul", Some("error".into()));
    s.advance(301);
    assert_eq!(s.send("mukul"), "ok");
    s.advance(2);
    assert_eq!(s.send("mukul"), "ok");
    assert_eq!(s.reg.hits(), 2, "no retry within 5 s of a failure");
    s.reg.set("mukul", None);
    s.advance(5);
    assert_eq!(s.send("mukul"), "unknown_key");
}

#[test]
fn concurrent_misses_share_one_fetch() {
    let (_, jwk) = vectors();
    let s = Arc::new(Setup::new(&[("mukul", jwks(&jwk))], &["*"]));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || s.send("mukul"))
        })
        .collect();
    let got: Vec<String> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(got, vec!["ok"; 4]);
    assert_eq!(s.reg.hits(), 1);
}
