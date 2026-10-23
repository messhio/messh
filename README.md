# messh

Your name. Your keys. A name that resolves to verified SSH keys, for people and their agents.

This repo is the open-source part of [messh.io](https://messh.io): the `messh` CLI, the SDKs that sign and verify
HTTP requests as a messh identity (Web Bot Auth: RFC 9421 HTTP Message Signatures with Ed25519), and the
conformance vectors they share.

> **Preview.** The registry at [messh.io](https://messh.io) is live. Four SDKs are published:
> JS / TS ([`@messh/sdk`](https://www.npmjs.com/package/@messh/sdk) on npm), Python
> ([`messh-sdk`](https://pypi.org/project/messh-sdk/) on PyPI), Go ([`messh.io/go/messh`](https://pkg.go.dev/messh.io/go/messh))
> and Rust ([`messh`](https://crates.io/crates/messh) on crates.io). Java builds from `sdk/java` for now.

## CLI

```sh
brew install messhio/tap/messh
curl -fsSL https://messh.io/install.sh | sh
```

```text
messh login                         sign in (device code)
messh publish [--key F] [--name N]  publish your SSH public key under your name
messh add <user>                    let <user> into this machine (authorized_keys)
messh curl <url>                    send a request signed as you (Web Bot Auth)
messh version
```

## SDKs

| | Install | Source |
|---|---|---|
| JS / TS | `npm install @messh/sdk` | [`sdk/ts`](sdk/ts) |
| Python | `pip install messh-sdk` | [`sdk/py`](sdk/py) |
| Go | `go get messh.io/go/messh` | [`sdk/go`](sdk/go) |
| Rust | `cargo add messh` | [`sdk/rs`](sdk/rs) |
| Java | `io.messh:messh-sdk` (Maven Central) | [`sdk/java`](sdk/java) |

[`sdk/README.md`](sdk/README.md) lists what each SDK takes and returns.

## Layout

| Path | What |
|---|---|
| `cli` | the `messh` CLI (uses `sdk/go`) |
| `sdk` | the five SDKs; `sdk/test.sh` runs them all against the vectors |
| `spec/vectors` | conformance vectors every SDK must reproduce; `gen/` is the reference implementation that writes them |

## Develop

Everything runs in Docker:

```sh
make test    # the CLI, all five SDKs, and a check that spec/vectors is what its generator writes
```

CI runs the same checks on every push and pull request. A `cli-vX.Y.Z` tag publishes the CLI to GitHub Releases and
Homebrew; an `sdk-vX.Y.Z` tag publishes the SDKs. See [`sdk/PUBLISHING.md`](sdk/PUBLISHING.md).

## License

[Apache-2.0](LICENSE)
