# messh for Rust

Sign and verify HTTP requests as a [messh](https://messh.io) identity with **Web Bot Auth**: RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`.

```sh
cargo add messh                    # features: fetch (default, ureq), http (http::Request helpers)
```

## Sign (agent)

```rust
use messh::{Client, KeySource};

let client = Client::builder("mukul").key(KeySource::File("~/.ssh/id_ed25519".into())).build()?;
let headers = client.sign("POST", "https://api.example.com/deploy", Some(br#"{"env":"staging"}"#))?;
// add headers to your reqwest / hyper / ureq request, or: client.send("POST", url, Some(body))?
```

## Agents and CI

Configure it with environment variables instead of code: `MESSH_IDENTITY`, `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. `whoami` checks the key is published, so a missing `messh publish` fails at startup with `not_published` instead of every API answering 401.

```rust
let client = Client::from_env()?;
let me = client.whoami()?; // identity, key_name, key_id, fingerprint, agent_url
```

Passphrase-protected key? Load it into ssh-agent (`ssh-add`) and use `KeySource::SshAgent { fingerprint: None }`.

## Verify (API)

```rust
use messh::verify::{Request, VerifyConfig, Verifier};

let verifier = Verifier::new(VerifyConfig::trust(["mukul"]));
let agent = verifier.verify(&Request { method: "POST", url: &url, headers: &headers, body: &body })?;
// verify is blocking on a directory cache miss: use spawn_blocking on tokio
```

Full reference (every function, input and error code): https://github.com/messhio/messh/blob/main/sdk/README.md

License: Apache-2.0
