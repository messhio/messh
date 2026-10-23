//! Live check against the running stack.
use messh::verify::{Request, Verifier, VerifyConfig};
use messh::{Client, KeySource};

fn check(ok: bool, step: &str, detail: impl std::fmt::Debug) {
    if ok {
        println!("PASS rs  {step}");
    } else {
        println!("FAIL rs  {step}: {detail:?}");
        std::process::exit(1);
    }
}

fn main() {
    let (app, registry, key) = (
        std::env::var("APP").unwrap(),
        std::env::var("REGISTRY").unwrap(),
        std::env::var("KEY").unwrap(),
    );
    let client = Client::builder("mukul")
        .key(KeySource::File(key.into()))
        .registry(registry.clone())
        .build()
        .unwrap();

    let (status, body) = client
        .send("GET", &format!("{app}/api/hello"), None)
        .unwrap();
    let body = String::from_utf8_lossy(&body).to_string();
    check(
        status == 200 && body.contains(r#""key":"sdk-test""#),
        "GET /api/hello → 200 mukul · sdk-test",
        &body,
    );
    let (status, body) = client
        .send(
            "POST",
            &format!("{app}/api/deploy"),
            Some(br#"{"env":"staging"}"#),
        )
        .unwrap();
    let body = String::from_utf8_lossy(&body).to_string();
    check(
        status == 200 && body.contains(r#""method":"POST""#),
        "POST /api/deploy with body → 200",
        &body,
    );

    let (url, payload) = ("http://api.example/orders?id=7", br#"{"qty":1}"#);
    let headers = client.sign("POST", url, Some(payload)).unwrap();
    let v = Verifier::new(VerifyConfig::trust(["mukul"]).registry(&registry, ""));
    let a = v.verify(&Request {
        method: "POST",
        url,
        headers: &headers,
        body: payload,
    });
    check(
        matches!(&a, Ok(a) if a.identity == "mukul" && a.key_name == "sdk-test"),
        "verifier with live messh directory → mukul · sdk-test",
        &a,
    );

    let headers = client.sign("GET", "http://api.example/x", None).unwrap();
    let strict = Verifier::new(VerifyConfig::trust(["alice"]).registry(&registry, ""));
    let e = strict.verify(&Request {
        method: "GET",
        url: "http://api.example/x",
        headers: &headers,
        body: b"",
    });
    check(
        matches!(&e, Err(e) if e.code() == "untrusted" && e.status() == 403),
        "identity outside trust list → 403 untrusted",
        &e,
    );
}
