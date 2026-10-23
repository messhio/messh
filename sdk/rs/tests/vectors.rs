use messh::verify::{Request, Verifier, VerifyConfig};
use messh::wba::Directory;
use messh::{Client, KeySource};
use serde_json::Value;
use std::path::PathBuf;

fn vec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn doc() -> Value {
    serde_json::from_str(&std::fs::read_to_string(vec_dir().join("web-bot-auth.json")).unwrap())
        .unwrap()
}

fn file(d: &Value, kind: &str) -> PathBuf {
    vec_dir().join(d["key"]["files"][kind].as_str().unwrap())
}

#[test]
fn sign_vectors() {
    let d = doc();
    for c in d["sign"].as_array().unwrap() {
        let created = c["created"].as_i64().unwrap();
        let nonce = c["nonce"].as_str().unwrap().to_string();
        let client = Client::builder("mukul")
            .key(KeySource::File(file(&d, "openssh")))
            .registry("https://registry.example")
            .clock(move || created)
            .nonce(move || nonce.clone())
            .build()
            .unwrap();
        let body = c["body"].as_str().map(str::as_bytes);
        let got = client
            .sign(
                c["method"].as_str().unwrap(),
                c["url"].as_str().unwrap(),
                body,
            )
            .unwrap();
        let want = c["expected_headers"].as_object().unwrap();
        assert_eq!(got.len(), want.len(), "{}", c["name"]);
        for (k, v) in got {
            assert_eq!(want[&k].as_str().unwrap(), v, "{} {k}", c["name"]);
        }
    }
}

#[test]
fn key_sources() {
    let d = doc();
    let want = d["key"]["jwk"]["kid"].as_str().unwrap();
    let pkcs8 = std::fs::read(file(&d, "pkcs8")).unwrap();
    std::env::set_var(
        "MESSH_TEST_KEY",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pkcs8),
    );
    let seed: [u8; 32] = (0..32)
        .map(|i| {
            u8::from_str_radix(
                &d["key"]["seed_hex"].as_str().unwrap()[i * 2..i * 2 + 2],
                16,
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    for (name, src) in [
        ("openssh", KeySource::File(file(&d, "openssh"))),
        ("pkcs8", KeySource::File(file(&d, "pkcs8"))),
        ("env", KeySource::Env("MESSH_TEST_KEY".into())),
        ("seed", KeySource::Seed(seed)),
    ] {
        assert_eq!(
            Client::builder("mukul").key(src).build().unwrap().key_id(),
            want,
            "{name}"
        );
    }
    assert_eq!(
        Client::builder("mukul")
            .key(KeySource::File(file(&d, "public")))
            .build()
            .unwrap_err()
            .code(),
        "invalid_key"
    );
    assert_eq!(
        Client::builder("Not A User")
            .key(KeySource::Seed(seed))
            .build()
            .unwrap_err()
            .code(),
        "invalid_identity"
    );
}

fn verifier(c: &Value, trust: &[&str], registry: bool) -> Verifier {
    let dir: Directory =
        serde_json::from_value(serde_json::json!({ "keys": c["directory_keys"] })).unwrap();
    let now = c["now"].as_i64().unwrap();
    let mut cfg = VerifyConfig::trust(trust.iter().copied())
        .clock(move || now)
        .directory(move |_, _| Ok(dir.clone()));
    if registry {
        cfg = cfg.registry("https://registry.example", "");
    }
    Verifier::new(cfg)
}

fn headers(c: &Value) -> Vec<(String, String)> {
    c["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn verify_vectors() {
    for c in doc()["verify"].as_array().unwrap() {
        let v = verifier(c, &["*"], true);
        let h = headers(c);
        let body = c["body"].as_str().unwrap_or("").as_bytes().to_vec();
        let req = Request {
            method: c["method"].as_str().unwrap(),
            url: c["url"].as_str().unwrap(),
            headers: &h,
            body: &body,
        };
        let got = match v.verify(&req) {
            Ok(a) => {
                assert_eq!(
                    (a.identity.as_str(), a.key_name.as_str()),
                    ("mukul", "sdk-test")
                );
                assert_eq!(
                    v.verify(&req).unwrap_err().code(),
                    "nonce_replayed",
                    "{}",
                    c["name"]
                );
                "ok"
            }
            Err(e) => e.code(),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn trust_and_registry() {
    let d = doc();
    let c = &d["verify"][0];
    let h = headers(c);
    let req = Request {
        method: "GET",
        url: c["url"].as_str().unwrap(),
        headers: &h,
        body: b"",
    };
    let e = verifier(c, &["alice"], true).verify(&req).unwrap_err();
    assert_eq!((e.code(), e.status()), ("untrusted", 403));
    assert_eq!(
        verifier(c, &["*"], false).verify(&req).unwrap_err().code(),
        "untrusted"
    );
}

#[cfg(feature = "http")]
#[test]
fn http_adapter() {
    let d = doc();
    let c = d["verify"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok-post")
        .unwrap();
    let mut b = http::Request::builder()
        .method("POST")
        .uri(c["url"].as_str().unwrap());
    for (k, v) in headers(c) {
        b = b.header(k, v);
    }
    let body = c["body"].as_str().unwrap().as_bytes().to_vec();
    let req = b.body(body.clone()).unwrap();
    assert_eq!(
        verifier(c, &["mukul"], true)
            .verify_http(&req, &body)
            .unwrap()
            .identity,
        "mukul"
    );
}
