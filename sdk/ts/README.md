# @messh/sdk

Sign and verify HTTP requests as a [messh](https://messh.io) identity with **Web Bot Auth**: RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`. No runtime dependencies; Node 20+.

```sh
npm install @messh/sdk
```

## Sign (agent)

```ts
import { MesshClient, keyFile } from "@messh/sdk";

const client = await MesshClient.create({ identity: "mukul", key: keyFile("~/.ssh/id_ed25519") });
await client.fetch("https://api.example.com/deploy", { method: "POST", body: JSON.stringify({ env: "staging" }) });
```

Use the ssh-ed25519 key you published with `messh publish`. The private key never leaves your machine.

## Agents and CI

Configure it with environment variables instead of code: `MESSH_IDENTITY`, `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. `whoami` checks the key is published, so a missing `messh publish` fails at startup with `not_published` instead of every API answering 401.

```ts
const client = await MesshClient.fromEnv();
const me = await client.whoami(); // { identity, keyName, keyId, fingerprint, agentUrl }
```

Passphrase-protected key? Load it into ssh-agent (`ssh-add`) and pass `key: sshAgent()`.

## Verify (API)

```ts
import { messhAuth, Verifier } from "@messh/sdk/verify";

app.use("/api", messhAuth({ trust: ["mukul"] }));    // Express: mount before express.json(); then req.agent

const verifier = new Verifier({ trust: ["mukul"] }); // fetch-style runtimes (Workers, Hono, Next.js)
const agent = await verifier.verifyRequest(request);
```

## New in 0.2.0

Any HTTP message signature (RFC 9421), not only Web Bot Auth:

```ts
import { signMessage, verifyMessage } from "@messh/sdk/httpsig";

const s = await signMessage({ method: "POST", url, headers, body }, signer, { components: ["@method", "@authority", "content-digest"], keyid: "k1", tag: "my-app" });
await verifyMessage(signed, { tag: "my-app", keys: (kid) => publicKeys[kid] });
```

Other Web Bot Auth agents, and agents that sign less, alongside messh identities:

```ts
new Verifier({ trust: ["mukul", "https://agent.example"], requireComponents: ["@authority", "signature-agent"] });
```

Clients: `MesshClient.create({ ..., agentDictionary: true, components, label, tag })`. Self-hosted key directories:
`directoryResponse(...)`. The full list is in [CHANGELOG.md](https://github.com/messhio/messh/blob/main/sdk/CHANGELOG.md).

Full reference (every function, input and error code): https://github.com/messhio/messh/blob/main/sdk/README.md

License: Apache-2.0
