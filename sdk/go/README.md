# messh for Go

Sign and verify HTTP requests as a [messh](https://messh.io) identity with **Web Bot Auth**: RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`. Standard library only.

```sh
go get messh.io/go/messh
```

## Sign (agent)

```go
client, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile("~/.ssh/id_ed25519")))
resp, err := client.Post("https://api.example.com/deploy", "application/json", strings.NewReader(`{"env":"staging"}`))
```

Use the ssh-ed25519 key you published with `messh publish`. The private key never leaves your machine.

## Agents and CI

Configure it with environment variables instead of code: `MESSH_IDENTITY`, `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. `WhoAmI` checks the key is published, so a missing `messh publish` fails at startup with `not_published` instead of every API answering 401.

```go
client, err := messh.NewClientFromEnv()
me, err := client.WhoAmI(ctx) // Identity, KeyName, KeyID, Fingerprint, AgentURL
```

Passphrase-protected key? Load it into ssh-agent (`ssh-add`) and use `messh.WithKey(messh.SSHAgent(""))`.

## Verify (API)

```go
v, err := verify.New(verify.Trust("mukul"))        // or "*" for any messh identity
http.ListenAndServe(":8080", v.Middleware(mux))
// in a handler:
agent := verify.AgentFrom(r.Context())            // agent.Identity, agent.KeyName
```

Keys come from `https://messh.io/<user>/.well-known/http-message-signatures-directory` and are cached for 5 minutes. Replays, clock skew and revoked keys are rejected with stable error codes.

## New in 0.2.0

Any HTTP message signature (RFC 9421), not only Web Bot Auth:

```go
import "messh.io/go/messh/httpsig"

m, _ := httpsig.NewRequest("POST", "https://example.com/foo", header, body)
s, _ := httpsig.Sign(m, signer, httpsig.SignOptions{Components: []string{"@method", "@authority", "content-digest"},
    Created: time.Now(), KeyID: "k1", Tag: "my-app"})
s.AddTo(header)
v, err := httpsig.Verify(m, httpsig.VerifyOptions{Tag: "my-app", Keys: myKeys})
```

Other Web Bot Auth agents, and agents that sign less, alongside messh identities:

```go
v, _ := verify.New(verify.Trust("mukul", "https://agent.example"), verify.RequireComponents("@authority", "signature-agent"))
```

Clients: `messh.WithAgentDictionary()`, `WithComponents`, `WithLabel`, `WithTag`. Self-hosted key directories:
`messh.DirectoryResponse`. The full list is in [CHANGELOG.md](https://github.com/messhio/messh/blob/main/sdk/CHANGELOG.md).

Full reference (every function, input and error code): https://github.com/messhio/messh/blob/main/sdk/README.md

License: Apache-2.0
