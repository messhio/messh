# messh SDKs changelog

All five SDKs (Go, Python, JS/TS, Rust, Java) share one version and one contract, checked by the vectors in
[`../spec/vectors`](../spec/vectors).

## 0.2.0

Everything in 0.1.0 still works the same way. By default a 0.2.0 client sends byte-for-byte the signatures 0.1.0
sends, so verifiers already deployed (messh.io included) keep accepting them, and 0.1.0 code compiles unchanged.
The new features are opt-in.

### RFC 9421 for any HTTP message (`httpsig`)

A new module signs and verifies any HTTP message signature, not just Web Bot Auth:

| | Go | Python | JS/TS | Rust | Java |
|---|---|---|---|---|---|
| module | `messh.io/go/messh/httpsig` | `messh.httpsig` | `@messh/sdk/httpsig` | `messh::httpsig` | `io.messh.httpsig` |
| sign | `httpsig.Sign` | `sign_message` | `signMessage` | `sign_message` | `HttpSig.sign` |
| verify | `httpsig.Verify` | `verify_message` | `verifyMessage` | `verify_message` | `HttpSig.verify` |
| one component | `httpsig.Component` | `component_value` | `componentValue` | `component_value` | `HttpSig.componentValue` |

- **Any label, tag or keyid.** Pick the signature by label or tag. Keys come from your resolver, so `test-key-ed25519`
  from RFC 9421 works as well as a JWK thumbprint.
- **Every derived component:** `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`,
  `@query`, `@query-param;name=…` and `@status`.
- **Every field parameter:** `sf` (strict structured-field serialization), `key` (one dictionary member), `bs`
  (byte-sequence wrapping), `req` (a request component inside a response signature) and `tr` (trailers).
- **Responses**, with the request they answer, for `req` components.
- **Content-Digest** (`sha-256` and `sha-512`) is checked when the message has a body and the digest is covered.
- **Time and replay:** `created` must not be in the future, `expires` is enforced, and you can set a maximum age and a
  nonce store.
- **A real Structured Fields parser and serializer** (RFC 8941) replaces the hand-written splitting in 0.1.0.

Components are written as plain names (`@method`, `content-type`) or as serialized identifiers with parameters
(`"example-dict";key="a"`, `"@authority";req`).

### Web Bot Auth

**Client** (all optional; the defaults are 0.1.0's):
- extra covered components
- a different label or tag
- the dictionary form of `Signature-Agent` from newer drafts: `Signature-Agent: sig1="https://messh.io/mukul"`,
  covered as `"signature-agent";key="sig1"`

**Verifier:**
- **Every `Signature-Agent` form:**
  - a string
  - a dictionary picked by the `key` parameter of the covered component
  - a dictionary member named like the signature label (as in 0.1.0)
  - an inline key directory (`data:application/http-message-signatures-directory;base64,…`)
- **Agents that aren't messh identities.** Put an agent's origin in the trust list (`https://agent.example`). Its key
  directory is fetched from `<origin>/.well-known/http-message-signatures-directory`, with the same cache rules. Trust
  inline keys as `jwk:<thumbprint>`. `*` still means any messh identity. The verified agent says `external` for these.
- **`@target-uri` counts as covering `@authority`, `@path` and `@query`.** Required components are configurable, for
  agents that sign less than messh's default (`@method @authority @path signature-agent`). A query or body must still
  be covered.
- **Signed key directories** (draft-meunier-http-message-signatures-directory §5). When a directory response carries
  signatures (tag `http-message-signatures-directory`), the keys they verify are marked as signed, and the verified
  agent says `signed_directory`. Opt in to ignoring unsigned keys, as the draft recommends. It's off by default,
  because messh.io doesn't sign directories yet.
- **Rejects input RFC 9421 forbids:** duplicate signature labels, duplicate covered components, and an `alg` other
  than `ed25519`.

### Key directories you host yourself

`DirectoryResponse` / `directory_response` / `directoryResponse` / `Directory.response` builds the JSON key directory
for your keys and signs it, one signature per key, the way Cloudflare's tools expect:
`binding0=("@authority";req "content-digest");…;tag="http-message-signatures-directory"`.

### Not included

- **Signature timing measurements** (Cloudflare's `SignatureTiming`): a benchmarking aid, not part of the protocol.
  Time the call yourself.
- **Algorithms other than Ed25519:** Web Bot Auth uses Ed25519, and Cloudflare's crate implements only Ed25519 too.

### Behavior changes (spec fixes)

- `@method` is taken exactly as sent (RFC 9421 §2.2.1). 0.1.0 verifiers uppercased it. Standard methods are already
  uppercase, so only nonstandard lowercase methods see a difference.
- `@signature-params` is rebuilt from the parsed `Signature-Input` (strict serialization) instead of reusing its raw
  text. messh clients already send it strictly serialized.

## 0.1.0

First release: sign as a messh identity, and verify against messh key directories.
