use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use messh::httpsig::{
    component_value, sign_message, verify_message, Message, SignOptions, VerifyOptions,
};
use messh::verify::{verify_directory, Request, Verifier, VerifyConfig, VerifyError};
use messh::wba::{Directory, Jwk};
use messh::{directory_response, Client, KeySource, Signer};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

fn doc() -> Option<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/http-message-signatures.json"
    );
    std::fs::read_to_string(path)
        .ok()
        .map(|s| serde_json::from_str(&s).unwrap())
}

fn seed(d: &Value, name: &str) -> [u8; 32] {
    let hex = d["keys"][name]["seed_hex"].as_str().unwrap();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn public(d: &Value, name: &str) -> [u8; 32] {
    URL_SAFE_NO_PAD
        .decode(d["keys"][name]["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

struct SeedSigner(SigningKey);

impl Signer for SeedSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn pairs(v: &Value) -> Vec<(String, String)> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|p| (p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()))
                .collect()
        })
        .unwrap_or_default()
}

fn message(m: &Value) -> Message {
    Message {
        method: m["method"].as_str().unwrap_or("").into(),
        url: m["url"].as_str().unwrap_or("").into(),
        headers: pairs(&m["headers"]),
        body: m["body"].as_str().map(|b| b.as_bytes().to_vec()),
        status: m["status"].as_u64().unwrap_or(0) as u16,
        request: m
            .get("request")
            .filter(|r| !r.is_null())
            .map(|r| Box::new(message(r))),
        trailers: pairs(&m["trailers"]),
        request_target: m["request_target"].as_str().unwrap_or("").into(),
    }
}

fn types(d: &Value) -> HashMap<String, String> {
    serde_json::from_value(d["field_types"].clone()).unwrap()
}

#[test]
fn component_vectors() {
    let Some(d) = doc() else { return };
    for c in d["components"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let got = component_value(
            &message(&d["messages"][c["message"].as_str().unwrap()]),
            c["component"].as_str().unwrap(),
            &types(&d),
        );
        if c["error"].as_bool().unwrap_or(false) {
            assert!(got.is_err(), "{name}: got {got:?}, want an error");
        } else {
            let want = (
                c["identifier"].as_str().unwrap().to_string(),
                c["value"].as_str().unwrap().to_string(),
            );
            assert_eq!(got, Ok(want), "{name}");
        }
    }
}

#[test]
fn sign_vectors() {
    let Some(d) = doc() else { return };
    for c in d["sign"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let p = &c["params"];
        let s = |k: &str| p[k].as_str().map(String::from);
        let o = SignOptions {
            label: c["label"].as_str().unwrap().into(),
            components: c["components"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().into())
                .collect(),
            created: p["created"].as_i64(),
            expires: p["expires"].as_i64(),
            keyid: s("keyid"),
            alg: s("alg"),
            nonce: s("nonce"),
            tag: s("tag"),
            field_types: types(&d),
        };
        let signer = SeedSigner(SigningKey::from_bytes(&seed(
            &d,
            c["key"].as_str().unwrap(),
        )));
        let signed = sign_message(&message(&c["message"]), &signer, &o)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(signed.base, c["expected_base"].as_str().unwrap(), "{name}");
        for (k, v) in signed.headers() {
            assert_eq!(
                v,
                c["expected_headers"][k.as_str()].as_str().unwrap(),
                "{name} {k}"
            );
        }
    }
}

#[test]
fn verify_vectors() {
    let Some(d) = doc() else { return };
    for c in d["verify"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let keys_map: HashMap<String, [u8; 32]> = c["keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(kid, n)| (kid.clone(), public(&d, n.as_str().unwrap())))
            .collect();
        let keys = |kid: &str| {
            keys_map
                .get(kid)
                .copied()
                .ok_or_else(|| VerifyError::new("unknown_key", "unknown key"))
        };
        let mut o = VerifyOptions::new(&keys);
        o.label = c["label"].as_str().map(String::from);
        o.tag = c["tag"].as_str().map(String::from);
        o.now = c["now"].as_i64();
        o.max_age = c["max_age"].as_i64();
        o.field_types = types(&d);
        let got = match verify_message(&message(&c["message"]), &o) {
            Ok(v) => {
                assert_eq!(v.label, c["expect_label"].as_str().unwrap(), "{name}");
                "ok".to_string()
            }
            Err(e) => e.code().to_string(),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn web_bot_auth_vectors() {
    let Some(d) = doc() else { return };
    let wba = &d["web_bot_auth"];
    for c in wba["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let now = c["now"].as_i64().unwrap();
        let dirs: HashMap<String, Vec<String>> =
            serde_json::from_value(c["directories"].clone()).unwrap();
        let keys = d["keys"].clone();
        let mut cfg = VerifyConfig::trust(
            c["trust"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().to_string()),
        )
        .registry(wba["registry"].as_str().unwrap(), "")
        .clock(move || now)
        .directory(move |agent_url, _| {
            Ok(Directory {
                keys: dirs
                    .get(agent_url)
                    .map(|names| {
                        names
                            .iter()
                            .map(|n| Jwk {
                                kty: "OKP".into(),
                                crv: "Ed25519".into(),
                                x: keys[n]["x"].as_str().unwrap().into(),
                                kid: keys[n]["thumbprint"].as_str().unwrap().into(),
                                ..Jwk::default()
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        });
        if let Some(r) = c["require"].as_array() {
            cfg = cfg.require_components(r.iter().map(|x| x.as_str().unwrap().to_string()));
        }
        let v = Verifier::new(cfg);
        let m = &c["message"];
        let headers = pairs(&m["headers"]);
        let req = Request {
            method: m["method"].as_str().unwrap(),
            url: m["url"].as_str().unwrap(),
            headers: &headers,
            body: m["body"].as_str().unwrap_or("").as_bytes(),
        };
        match v.verify(&req) {
            Ok(a) => {
                assert_eq!(c["expect"], "ok", "{name}");
                assert_eq!(
                    (a.identity.as_str(), a.external),
                    (
                        c["identity"].as_str().unwrap(),
                        c["external"].as_bool().unwrap_or(false)
                    ),
                    "{name}"
                );
            }
            Err(e) => assert_eq!(e.code(), c["expect"].as_str().unwrap(), "{name}: {e}"),
        }
    }
}

#[test]
fn client_dictionary_agent() {
    let Some(d) = doc() else { return };
    for c in d["sign"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| !c["client"].is_null())
    {
        let cl = &c["client"];
        let (created, nonce) = (
            cl["created"].as_i64().unwrap(),
            cl["nonce"].as_str().unwrap().to_string(),
        );
        let client = Client::builder(cl["identity"].as_str().unwrap())
            .key(KeySource::Seed(seed(&d, c["key"].as_str().unwrap())))
            .registry(cl["registry"].as_str().unwrap())
            .clock(move || created)
            .nonce(move || nonce.clone())
            .agent_dictionary(true)
            .build()
            .unwrap();
        let got = client
            .sign(
                c["message"]["method"].as_str().unwrap(),
                c["message"]["url"].as_str().unwrap(),
                None,
            )
            .unwrap();
        for (k, v) in got {
            assert_eq!(
                v,
                c["expected_headers"][k.as_str()].as_str().unwrap(),
                "{k}"
            );
        }
    }
}

#[test]
fn directory_vectors() {
    let Some(d) = doc() else { return };
    let s = &d["directory"]["sign"];
    let keys: Vec<KeySource> = s["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| KeySource::Seed(seed(&d, n.as_str().unwrap())))
        .collect();
    let r = directory_response(
        s["authority"].as_str().unwrap(),
        &keys,
        s["created"].as_i64().unwrap(),
        Duration::from_secs(s["expires_in"].as_u64().unwrap()),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        s["expected_body"].as_str().unwrap()
    );
    for (k, v) in s["expected_headers"].as_object().unwrap() {
        let got = r
            .headers
            .iter()
            .find(|(h, _)| h == k)
            .map(|(_, v)| v.as_str());
        assert_eq!(got, v.as_str(), "{k}");
    }
    for c in d["directory"]["verify"].as_array().unwrap() {
        let headers: Vec<(String, String)> = c["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect();
        let (_, signed) = verify_directory(
            c["url"].as_str().unwrap(),
            &headers,
            c["body"].as_str().unwrap().as_bytes(),
            c["now"].as_i64().unwrap(),
        )
        .unwrap();
        let mut got: Vec<String> = signed.into_iter().collect();
        got.sort();
        let mut want: Vec<String> = c["expect_signed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect();
        want.sort();
        assert_eq!(got, want, "{}", c["name"]);
    }
}
