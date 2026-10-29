# messh for Java

Sign and verify HTTP requests as a [messh](https://messh.io) identity with **Web Bot Auth**: RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`. JDK 17+, no dependencies.

```kotlin
implementation("io.messh:messh-sdk:0.1.0")
```

## Sign (agent)

```java
MesshClient client = MesshClient.builder("mukul")
    .key(KeySource.file(Path.of(System.getProperty("user.home"), ".ssh", "id_ed25519")))
    .build();
client.send("POST", URI.create("https://api.example.com/deploy"),
    "{\"env\":\"staging\"}".getBytes(UTF_8), HttpResponse.BodyHandlers.ofString());
```

## Agents and CI

Configure it with environment variables instead of code: `MESSH_IDENTITY`, `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. `whoami` checks the key is published, so a missing `messh publish` fails at startup with `not_published` instead of every API answering 401.

```java
MesshClient client = MesshClient.fromEnv();
PublishedKey me = client.whoami(); // identity, keyName, keyId, fingerprint, agentUrl
```

Passphrase-protected key? Load it into ssh-agent (`ssh-add`) and use `KeySource.sshAgent()`.

## Verify (API)

```java
MesshVerifier verifier = MesshVerifier.builder().trust("mukul").build();
Agent agent = verifier.verify(method, uri, headers, body);   // throws VerifyException(code, status)
// JDK HttpServer: server.createContext("/api", h).getFilters().add(new MesshHttpFilter(verifier));
```

## New in 0.2.0

Any HTTP message signature (RFC 9421), not only Web Bot Auth:

```java
HttpSig.Signed s = HttpSig.sign(HttpMessage.request("POST", url, headers, body), signer,
    HttpSig.SignOptions.of("@method", "@authority", "content-digest").keyid("k1").tag("my-app"));
HttpSig.Verified v = HttpSig.verify(signed, HttpSig.VerifyOptions.keys(kid -> publicKeys.get(kid)).tag("my-app"));
```

Other Web Bot Auth agents, and agents that sign less, alongside messh identities:

```java
MesshVerifier.builder().trust("mukul", "https://agent.example").requireComponents("@authority", "signature-agent").build();
```

Clients: `.agentDictionary(true)`, `.components(...)`, `.label(...)`, `.tag(...)`. Self-hosted key directories:
`Directories.response(...)`. The full list is in [CHANGELOG.md](https://github.com/messhio/messh/blob/main/sdk/CHANGELOG.md).

Full reference (every function, input and error code): https://github.com/messhio/messh/blob/main/sdk/README.md

License: Apache-2.0
