# messh SDKs: Go · Python · JS/TS · Rust · Java

Each SDK has two halves:

- **Client:** signs outgoing HTTP requests as a messh identity, using **Web Bot Auth** (RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`).
- **Verifier:** checks incoming requests. It finds the signer's public key in messh's key directory, then applies your trust list.

All five produce byte-identical signatures and give the same verdicts. They are tested against the shared vectors in [`../spec/vectors/web-bot-auth.json`](../spec/vectors/web-bot-auth.json) and against the live Docker stack.

| | Package | Runtime deps | Tested |
|---|---|---|---|
| Go | `messh.io/go/messh` + `messh.io/go/messh/verify` | none (stdlib) | `go vet`, `go test` |
| Python | `messh-sdk` on PyPI, import `messh` (`messh.verify`) | `cryptography` (extras: `httpx`, `requests`) | unittest |
| JS/TS | `@messh/sdk` + `@messh/sdk/verify` | none (`node:crypto`), Node 20+ | `tsc --strict`, `node --test` |
| Rust | crate `messh` (`messh::verify`) | ed25519-dalek, sha2, base64, serde; `ureq` (feature `fetch`, default); `http` (feature `http`) | `cargo test`, `clippy -D warnings`, Rust 1.85+ |
| Java | `io.messh:messh-sdk` (`io.messh.verify`) | none (JDK 17+) | JUnit 5, `-Xlint:all -Werror` |

```sh
./sdk/test.sh       # unit + conformance tests, all five, in Docker
./sdk/interop.sh    # live: each SDK → sample app, and verifier → live messh directory
```

---

## What you supply

### To sign (client)

| Input | Required | Example | Notes |
|---|---|---|---|
| **identity** | ✅ | `"mukul"` | Your messh username (3–30 chars, `a-z 0-9 -`) |
| **key** | default `~/.ssh/id_ed25519` | key file, env var, seed, or your own signer | Must be the **ssh-ed25519 key you published** with `messh publish`. Private keys stay local. |
| registry | default `https://messh.io` | `http://localhost:8080` | Base URL; it becomes `Signature-Agent: "<registry>/<identity>"` |
| expires in | default 60 s (1–300) | `30` | Signature lifetime |
| per request: **method, absolute URL, body** | ✅ | `"POST"`, `https://api.acme.dev/deploy`, `{"env":"staging"}` | A body is covered by `Content-Digest`. Pass `host` only if you send a different Host header. |

**From the environment** (agents, CI, containers): `fromEnv()` reads `MESSH_IDENTITY` (required), `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. Arguments you pass win over the environment.

**Key formats:** an unencrypted OpenSSH `ssh-ed25519` private key, PKCS#8 PEM, base64 PKCS#8 DER (env), or a raw 32-byte seed. **Passphrase-protected keys** (and 1Password, Secretive or YubiKey agents) work through **ssh-agent**: the key stays in the agent, and with several Ed25519 keys loaded you pick one by fingerprint. KMS and HSM keys work through **your own `Signer`**: `publicKey() → 32 bytes` and `sign(bytes) → 64 bytes`.

**Check before the first request:** `whoami()` looks up your key directory on the registry and returns how APIs will see you (identity, key name, key ID, fingerprint). If the key isn't published it fails with `not_published` and says what to run, instead of every API answering 401 `unknown_key`. `fingerprint` is the key's `SHA256:…`, as `messh keys` and `ssh-keygen -l` print it.

**Client errors** (`code`): `invalid_identity`, `invalid_key`, `invalid_option`, `sign_failed` (Rust adds `send_failed`); from `whoami()`: `not_published`, `registry_unreachable`. Messages say how to fix the problem, e.g. a missing key file names `ssh-keygen -t ed25519` and `messh publish`.

**What gets added to the request:** `Signature-Agent`, `Signature-Input`, `Signature`, and `Content-Digest` when there's a body. Covered components: `@method @authority @path [@query] [content-digest] signature-agent`, plus `created`, `expires`, `keyid` (RFC 7638 JWK thumbprint), `alg="ed25519"`, `nonce` and `tag="web-bot-auth"`.

### To verify (API)

| Input | Required | Default | Notes |
|---|---|---|---|
| **trust** | ✅ | none | messh usernames allowed in (`["mukul"]`), or `["*"]` for any valid messh signer |
| registries | | `https://messh.io` | Accepted `Signature-Agent` origins. Optionally maps origin → fetch URL (e.g. `http://localhost:8080` → `http://registry:8080` inside Docker). Agents from other origins get **403 `untrusted`** and are never fetched. |
| max skew | | 60 s | Allowed \|now − created\| |
| cache TTL | | 300 s | How long a key directory is reused |
| stale-if-error | | 3600 s | Keep verifying with cached keys while messh is down |
| nonce store | | in memory | Plug in a shared store (Redis etc.) when you run more than one instance |
| max body bytes | | 1 MiB | Largest body the middleware reads; bigger ones get **413 `body_too_large`** (Go applies it in `Verify`; Rust takes the body from you) |
| per request: **method, full URL, headers, raw body** | ✅ | | The authority is the `Host` header if present, else the URL's host |

**Key directory cache** (the same policy in every SDK):

- Directories are reused for the cache TTL. A revoked key leaves the directory, so the TTL bounds how long it can still verify.
- An unknown `keyid` refetches its signer's directory, at most every 30 s, so a key published a moment ago works almost at once.
- Unknown identities (404) are remembered the same way.
- Callers outside `trust` are refused **before** any fetch, so they can't make your API call messh.
- One fetch per directory runs at a time; concurrent requests wait for it.
- While messh is unreachable, cached keys keep working for stale-if-error, retried at most every 5 s. A 404 is never answered from the stale cache.
- At most 10,000 directories are kept; the least recently stored go first.

**Returns** an `Agent` with `identity`, `keyName`, `keyId`, `fingerprint`, `agentUrl` and `created`. **Failures** carry `code` + `status`:

| code | status | when |
|---|---|---|
| `missing_signature` | 401 | No `Signature` / `Signature-Input` (middleware adds `Accept-Signature`) |
| `bad_signature` | 401 | Signature wrong, required component not covered, wrong tag or alg, body not covered |
| `digest_mismatch` | 401 | Body ≠ `Content-Digest` |
| `clock_skew` | 401 | `created` outside ±max skew, expired, or lifetime > 300 s |
| `nonce_replayed` | 401 | Same signature seen before |
| `unknown_key` | 401 | No such messh user, or `keyid` isn't one of their active keys (revoked keys disappear from the directory) |
| `untrusted` | 403 | Not in `trust` (checked before any fetch), or a `Signature-Agent` from a registry you don't accept |
| `body_too_large` | 413 | The body is over max body bytes (middleware) |

The order of checks: headers → digest → time → trust → key → signature → replay. Trust moved ahead of the key lookup (`06-signed-requests-spec.md` checks it last) so untrusted callers never cause a directory fetch.

---

## Go: `messh.io/go/messh`

```go
// Client
func NewClient(identity string, opts ...Option) (*Client, error)
func NewClientFromEnv(opts ...Option) (*Client, error) // MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE, MESSH_REGISTRY
func WithKey(k KeySource) Option                 // default KeyFile("~/.ssh/id_ed25519")
func WithRegistry(url string) Option             // default "https://messh.io"
func WithExpiry(d time.Duration) Option          // default 60s, max 300s
func WithHTTPClient(h *http.Client) Option
func WithClock(now func() time.Time) Option      // tests
func WithNonce(f func() string) Option           // tests

func (c *Client) Sign(req *http.Request) error   // adds the headers in place
func (c *Client) Do(req *http.Request) (*http.Response, error)
func (c *Client) Get(url string) (*http.Response, error)
func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error)
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper // sign everything through an http.Client
func (c *Client) KeyID() string
func (c *Client) Agent() string
func (c *Client) Fingerprint() string                       // SHA256:…
func (c *Client) WhoAmI(ctx context.Context) (*PublishedKey, error)
type PublishedKey struct{ Identity, KeyName, KeyID, Fingerprint, AgentURL string }

// Keys
type Signer interface { Public() ed25519.PublicKey; Sign(message []byte) ([]byte, error) }
func KeyFile(path string) KeySource                         // a leading ~/ is $HOME
func KeyEnv(name string) KeySource
func KeySeed(seed []byte) KeySource
func SSHAgent(fingerprint string) KeySource                 // SSH_AUTH_SOCK; "" = the only Ed25519 key
func KeySigner(s Signer) KeySource
type Error struct{ Code, Message string }

// Verifier: package verify
func New(opts ...Option) (*Verifier, error)            // Trust(...) required
func Trust(patterns ...string) Option
func Registry(origin, fetchBase string) Option         // fetchBase "" = origin
func MaxSkew(d time.Duration) Option
func CacheTTL(d time.Duration) Option
func StaleIfError(d time.Duration) Option
func Nonces(s NonceStore) Option                       // interface{ Add(key string, ttl time.Duration) bool }
func HTTPClient(h *http.Client) Option
func MaxBodyBytes(n int64) Option                      // default 1 MiB → 413 body_too_large
func StaticDirectory(dir *Directory) Option            // tests / air-gapped
func DirectoryFunc(f func(ctx context.Context, agentURL, identity string) (*Directory, error)) Option
func (v *Verifier) Verify(r *http.Request) (*Agent, error) // body stays readable
func (v *Verifier) Middleware(next http.Handler) http.Handler
func AgentFrom(ctx context.Context) *Agent
type Agent struct{ Identity, KeyName, KeyID, Fingerprint, AgentURL string; Created time.Time }
type Error struct{ Code, Message string; Status int }
```

```go
client, _ := messh.NewClient("mukul", messh.WithKey(messh.KeyFile("~/.ssh/id_ed25519")))
me, err := client.WhoAmI(ctx) // not_published if the key isn't on messh yet
resp, _ := client.Post("https://api.acme.dev/deploy", "application/json", strings.NewReader(`{"env":"staging"}`))

v, _ := verify.New(verify.Trust("mukul"))
http.ListenAndServe(":8080", v.Middleware(mux)) // handlers: verify.AgentFrom(r.Context()).Identity
```

## Python: `messh-sdk` (import `messh`)

```python
# Client
Client(identity: str, *, key: KeySource | None = None, registry: str = "https://messh.io",
       expires_in: int = 60, timeout: float = 30.0, clock=None, nonce=None)
Client.sign(method: str, url: str, body: bytes | str | None = None, host: str | None = None) -> dict[str, str]
Client.request(method, url, *, json=None, data=None, headers=None) -> Response   # stdlib transport
Client.get(url, **kw) -> Response;  Client.post(url, **kw) -> Response
Client.from_env(**overrides) -> Client       # MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE, MESSH_REGISTRY
Client.key_id -> str;  Client.agent -> str;  Client.fingerprint -> str   # SHA256:…
Client.whoami() -> PublishedKey(identity, key_name, key_id, fingerprint, agent_url)
Response(status: int, headers: dict, body: bytes)  .ok  .json()  .text()
messh.MesshAuth(client)            # httpx.Auth        (pip install "messh-sdk[httpx]")
messh.requests.MesshAuth(client)   # requests AuthBase (pip install "messh-sdk[requests]")

# Keys
key_file(path) ; key_env(name) ; key_seed(seed: bytes)
ssh_agent(fingerprint: str | None = None, socket_path: str | None = None)   # SSH_AUTH_SOCK
class Signer(Protocol): public_key() -> bytes ; sign(message: bytes) -> bytes   # pass an instance as key=
MesshError(code, message)

# Verifier: messh.verify
Verifier(trust: Sequence[str], *, registries: Sequence[str] | Mapping[str, str] | None = None,
         max_skew: int = 60, cache_ttl: float = 300, stale_if_error: float = 3600,
         nonce_store: NonceStore | None = None, timeout: float = 5.0, max_body_bytes: int = 1 << 20,
         clock=None, directory=None)
Verifier.verify(method: str, url: str, headers: Mapping | Iterable[tuple], body: bytes = b"") -> Agent
await Verifier.averify(method, url, headers, body=b"") -> Agent
MesshAuthMiddleware(app, verifier=None, paths=("/",), **verifier_options)   # ASGI: FastAPI / Starlette
current_agent(request: Request) -> Agent                                   # FastAPI Depends
Agent(identity, key_name, key_id, fingerprint, agent_url, created)
VerifyError(code, message, status)  .to_dict()
```

```python
client = Client("mukul", key=key_file("~/.ssh/id_ed25519"))   # or Client.from_env()
client.whoami()                                               # not_published if the key isn't on messh yet
client.post("https://api.acme.dev/deploy", json={"env": "staging"})

app.add_middleware(MesshAuthMiddleware, trust=["mukul"], paths=["/api/"])
@app.post("/api/deploy")
def deploy(agent: Agent = Depends(current_agent)): ...
```

## JS / TS: `@messh/sdk`

```ts
// Client
MesshClient.create(options: {
  identity: string; key?: KeySource; registry?: string; expiresIn?: number;
  clock?: () => number; nonce?: () => string;
}): Promise<MesshClient>
MesshClient.fromEnv(overrides?: Partial<ClientOptions>): Promise<MesshClient>  // MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE, MESSH_REGISTRY
client.sign(input: { method: string; url: string | URL; body?: Uint8Array | string | null; host?: string }): Promise<Record<string, string>>
client.signRequest(request: Request): Promise<Request>
client.fetch(input: string | URL, init?: RequestInit): Promise<Response>   // body: string | Uint8Array
client.keyId: string;  client.agent: string;  client.fingerprint: string   // SHA256:…
client.whoami(): Promise<PublishedKey>   // { identity, keyName, keyId, fingerprint, agentUrl }

// Keys
keyFile(path: string) ; keyEnv(name: string) ; keySeed(seed: Uint8Array)
sshAgent(options?: { fingerprint?: string; socket?: string })   // SSH_AUTH_SOCK
interface Signer { publicKey(): Uint8Array | Promise<Uint8Array>; sign(data: Uint8Array): Uint8Array | Promise<Uint8Array> }
class MesshError { code: string }

// Verifier: "@messh/sdk/verify"
new Verifier(options: {
  trust: string[]; registries?: string[] | Record<string, string>; maxSkew?: number; cacheTtl?: number;
  staleIfError?: number; nonceStore?: NonceStore; timeoutMs?: number; maxBodyBytes?: number; clock?: () => number;
  directory?: Directory | ((agentUrl: string, identity: string) => Promise<Directory>);
})
verifier.verify(input: { method: string; url: string | URL; headers: Headers | Record<string, string | string[]>; body?: Uint8Array | string | null }): Promise<Agent>
verifier.verifyRequest(request: Request): Promise<Agent>        // Workers, Hono, Next.js, Deno, Bun
messhAuth(options: VerifierOptions & { verifier?: Verifier; trustProxy?: boolean })  // Express: mount BEFORE express.json()
interface Agent { identity; keyName; keyId; fingerprint; agentUrl; created }
class VerifyError { code: string; status: number; detail: string; toJSON() }
```

```ts
const client = await MesshClient.create({ identity: "mukul", key: keyFile("~/.ssh/id_ed25519") }); // or MesshClient.fromEnv()
await client.whoami(); // not_published if the key isn't on messh yet
await client.fetch("https://api.acme.dev/deploy", { method: "POST", body: JSON.stringify({ env: "staging" }) });

app.use("/api", messhAuth({ trust: ["mukul"] }));   // then req.agent.identity, req.body, req.rawBody
```

## Rust: `messh`

```rust
// Client
Client::builder(identity: impl Into<String>) -> ClientBuilder
Client::from_env() -> Result<Client, Error>              // MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE, MESSH_REGISTRY
Client::builder_from_env() -> Result<ClientBuilder, Error>
ClientBuilder::key(KeySource) / registry(impl Into<String>) / expires_in(Duration)
             / clock(impl Fn() -> i64) / nonce(impl Fn() -> String) / build() -> Result<Client, Error>
client.sign(method: &str, url: &str, body: Option<&[u8]>) -> Result<Vec<(String, String)>, Error>
client.sign_with_host(method, url, body, host: Option<&str>) -> Result<Vec<(String, String)>, Error>
client.sign_request<B: AsRef<[u8]>>(&mut http::Request<B>) -> Result<(), Error>          // feature "http"
client.send(method, url, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), Error>          // feature "fetch"
client.key_id() -> &str;  client.agent() -> String;  client.fingerprint() -> String   // SHA256:…
client.whoami() -> Result<PublishedKey, Error>                                         // feature "fetch"

// Keys
#[non_exhaustive] enum KeySource { File(PathBuf), Env(String), Seed([u8; 32]), Signer(Arc<dyn Signer>),
                                   SshAgent { fingerprint: Option<String> } }
trait Signer: Send + Sync { fn public_key(&self) -> [u8; 32]; fn sign(&self, m: &[u8]) -> Result<[u8; 64], String>; }
Error::code() -> &'static str

// Verifier: messh::verify
VerifyConfig::trust(patterns: impl IntoIterator<Item = impl Into<String>>) -> VerifyConfig
  .registry(origin: &str, fetch_base: &str) .max_skew(Duration) .cache_ttl(Duration)
  .stale_if_error(Duration) .timeout(Duration) .nonce_store(Arc<dyn NonceStore>) .clock(..) .directory(..)
Verifier::new(VerifyConfig) -> Verifier
verifier.verify(&Request { method: &str, url: &str, headers: &[(String, String)], body: &[u8] }) -> Result<Agent, VerifyError>
verifier.verify_http<B>(&http::Request<B>, body: &[u8]) -> Result<Agent, VerifyError>   // feature "http"
struct Agent { identity, key_name, key_id, fingerprint, agent_url: String, created: i64 }
VerifyError::code() / status() / message() / to_json()
```

`verify` is blocking: the first request per identity fetches its directory. On tokio, call it inside `spawn_blocking`.

## Java: `io.messh:messh-sdk`

```java
// Client
MesshClient.builder(String identity)
    .key(KeySource) .registry(String) .expiresIn(Duration) .httpClient(HttpClient)
    .clock(LongSupplier) .nonce(Supplier<String>) .build() -> MesshClient
MesshClient.fromEnv() ; MesshClient.builderFromEnv()   // MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE, MESSH_REGISTRY
Map<String, String> sign(String method, URI uri, byte[] body)              // body may be null
Map<String, String> sign(String method, URI uri, byte[] body, String host)
HttpRequest.Builder newRequest(String method, URI uri, byte[] body)        // already signed
<T> HttpResponse<T> send(String method, URI uri, byte[] body, BodyHandler<T> h)
<T> CompletableFuture<HttpResponse<T>> sendAsync(String method, URI uri, byte[] body, BodyHandler<T> h)
String keyId();  String agent();  String fingerprint();   // SHA256:…
PublishedKey whoami();   // record(identity, keyName, keyId, fingerprint, agentUrl)

// Keys
KeySource.file(Path) ; KeySource.env(String) ; KeySource.seed(byte[]) ; KeySource.signer(Signer)
KeySource.sshAgent() ; KeySource.sshAgent(String fingerprint) ; KeySource.sshAgent(String fingerprint, Path socket)
interface Signer { byte[] publicKey(); byte[] sign(byte[] message); }
MesshException.code()   // unchecked

// Verifier: io.messh.verify
MesshVerifier.builder()
    .trust(String...) .registry(String origin, String fetchBase) .maxSkew(Duration) .cacheTtl(Duration)
    .staleIfError(Duration) .timeout(Duration) .maxBodyBytes(long) .nonceStore(NonceStore) .httpClient(HttpClient)
    .clock(LongSupplier) .directory(BiFunction<String, String, List<Map<String, Object>>>) .build()
Agent verify(String method, URI uri, Map<String, List<String>> headers, byte[] body)
new MesshHttpFilter(MesshVerifier)    // JDK HttpServer; agent in exchange.getAttribute(MesshHttpFilter.AGENT)
record Agent(String identity, String keyName, String keyId, String fingerprint, String agentUrl, long created)
VerifyException.code() / status() / toJson()   // unchecked
```

```java
MesshClient client = MesshClient.builder("mukul").key(KeySource.file(Path.of("~/.ssh/id_ed25519"))).build();
client.send("POST", URI.create("https://api.acme.dev/deploy"), "{\"env\":\"staging\"}".getBytes(UTF_8), BodyHandlers.ofString());

MesshVerifier verifier = MesshVerifier.builder().trust("mukul").build();
server.createContext("/api", handler).getFilters().add(new MesshHttpFilter(verifier));
```

---

## Not done yet

- **Publishing:** see [`PUBLISHING.md`](PUBLISHING.md). Names: npm `@messh/sdk`, PyPI `messh-sdk` (`messh` is taken), crate `messh`, Maven `io.messh:messh-sdk`, Go `messh.io/go/messh`.
- **Key stores:** ssh-agent is built in. OS keychains, AWS/GCP/Vault and PKCS#11 aren't; use your own `Signer` (any of them can implement `publicKey`/`sign`).
- **Framework adapters included:**
  - Go: `net/http`
  - Python: ASGI, httpx, requests
  - TS: Express/Connect and fetch `Request`
  - Rust: the `http` crate
  - Java: JDK `HttpServer`

  **Not included yet:** Django, Flask, Fastify-native, an axum/tower layer, a Servlet filter and a Spring Boot starter. Each one is a thin wrapper over `verify(...)`.
- **Nonce store:** only in-memory ships. Multi-instance APIs need a shared store; the interface is one method.
- **Directory trust:** the directory is fetched over HTTPS from the registries you list. The Web Bot Auth drafts also want the directory response itself signed, which needs a client-signed directory on messh. JWK `kid`s are checked against their keys' thumbprints.
- **`Signature-Agent` shape:** `"<registry>/<user>"` (a path), as messh serves it. It isn't a bare origin.
