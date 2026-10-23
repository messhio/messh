# Publishing the SDKs and the CLI

Names (checked 2026-10-22):

| Registry | Name | Install | Status |
|---|---|---|---|
| npm | `@messh/sdk` | `npm install @messh/sdk` | free: create the npm org `messh` |
| PyPI | `messh-sdk` (import `messh`) | `pip install messh-sdk` | `messh` is taken (an SSH config tool, last release 2019); `messh-sdk` is free |
| crates.io | `messh` | `cargo add messh` | free |
| Maven Central | `io.messh:messh-sdk` | `implementation("io.messh:messh-sdk:0.1.0")` | free; needs DNS proof of messh.io |
| Go | `messh.io/go/messh` | `go get messh.io/go/messh` | served from `github.com/messhio/messh-go`; the web app's `/go/messh` route serves the import path |

The source repo is `github.com/messhio/messh`: this repo, the CLI and the SDKs.

## One-time setup (≈ 1 hour, mostly waiting on emails and DNS)

1. **GitHub** (done): the org `messhio` has `messh` (this repo) and `messh-go` (empty; the release workflow fills it).
2. **Go mirror deploy key:**
   - Run `ssh-keygen -t ed25519 -f go_mirror -N ''`.
   - Add `go_mirror.pub` to `messhio/messh-go` → Settings → Deploy keys, with **write access**.
   - Save `go_mirror` (the private key) as the secret `GO_MIRROR_DEPLOY_KEY` in `messhio/messh`.
3. **Go vanity URL:** nothing to deploy once the app runs at `https://messh.io`: the web app (`messhio/messh-app`) serves the go-import page at `/go/messh` (and `/go/messh/verify`). Until then, or if messh.io is served from somewhere else, deploy the static copy in messh-app's `site/` instead, for example to Cloudflare Pages. Check it with `curl -s 'https://messh.io/go/messh?go-get=1' | grep go-import`.
4. **npm:**
   - Create an account with 2FA, then go to npmjs.com → **Add Organization** → `messh` (free, public).
   - Create an *Automation* access token and save it as the secret `NPM_TOKEN`.
5. **PyPI:** create an account with 2FA, then go to **Publishing → Add a pending publisher**:

   | Field | Value |
   |---|---|
   | project | `messh-sdk` |
   | owner | `messhio` |
   | repo | `messh` |
   | workflow | `release-sdks.yml` |
   | environment | `pypi` |

   Then in GitHub, go to `messhio/messh` → Settings → Environments → create `pypi`. No token is needed.
6. **crates.io:** log in with GitHub and verify your email. Then create an API token (scope: publish-new, publish-update) and save it as `CARGO_REGISTRY_TOKEN`.
7. **Maven Central** (central.sonatype.com):
   - Sign up, then **Namespaces → Add `io.messh`**. It shows a verification key; add it in Cloudflare DNS as a **TXT record on `messh.io`**, then click Verify.
   - **Generate User Token**, and save the two parts as `MAVEN_CENTRAL_USERNAME` and `MAVEN_CENTRAL_PASSWORD`.
   - Make a signing key: `gpg --quick-gen-key "messh <you@your-email>" ed25519 sign 2y`.
   - Publish it: `gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>`.
   - Save `gpg --armor --export-secret-keys <KEYID>` as `MAVEN_GPG_PRIVATE_KEY`, and its passphrase as `MAVEN_GPG_PASSPHRASE`.
8. **Optional:** ask PyPI for the abandoned `messh` name under PEP 541 at https://github.com/pypi/support (it takes weeks and isn't guaranteed). Until then, `messh-sdk` is the name.

## Every release

```sh
./sdk/test.sh                      # all five SDKs, conformance vectors
./sdk/check-version.sh             # prints the version; fails if any package differs
git tag sdk-v0.1.0 && git push origin sdk-v0.1.0
```

`.github/workflows/release-sdks.yml` then:
1. Checks that the tag matches all five versions.
2. Runs every test suite.
3. Publishes:
   - npm, with provenance
   - PyPI, through trusted publishing
   - crates.io
   - Maven Central: signed, plus sources and javadoc jars
   - Go: pushes `sdk/go` to `messhio/messh-go`, tags `v0.1.0`, and pings proxy.golang.org

**To bump the version**, change it in all of these, and `check-version.sh` will tell you if you missed one:
- `sdk/go/client.go`
- `sdk/py/pyproject.toml` and `sdk/py/src/messh/client.py`
- `sdk/ts/package.json` and `sdk/ts/src/index.ts`
- `sdk/rs/Cargo.toml`
- `sdk/java/pom.xml` and `MesshClient.java`

Published versions are permanent on every registry; you can yank or deprecate them, but never reuse a version number.

## The CLI

```sh
git tag cli-v0.1.0 && git push origin cli-v0.1.0
```

`.github/workflows/release-cli.yml` then tests the CLI, builds it for macOS and Linux (Intel and Apple Silicon),
attaches the four binaries and `SHA256SUMS` to a GitHub Release, and writes `Formula/messh.rb` in
`messhio/homebrew-tap`, so `brew install messhio/tap/messh` installs it. messh.io's `install.sh` serves the same
files: the API image downloads the release named by `CLI_VERSION` in messh-app's `deploy/.env`.

One-time setup (done): the secret `TAP_DEPLOY_KEY`, a deploy key with write access to `messhio/homebrew-tap`.
The CLI and the SDKs have separate version numbers.

## Checked locally (no upload)

| | Dry run | Result |
|---|---|---|
| npm | `npm pack --dry-run` | 13 files, 18.8 kB: dist, README, LICENSE |
| PyPI | `python -m build && twine check` | wheel + sdist PASSED, SPDX `Apache-2.0`, no warnings |
| crates.io | `cargo publish --dry-run` | packages, verifies and stops at the upload step |
| Maven | `mvn -P release package -Dgpg.skip` | jar + sources + javadoc |
| Go | module tested on its own (as in `messh-go`) | `go vet` + `go test` pass |

## Before the first public release

- **License:** every package says **Apache-2.0** and ships its text. The handoff notes list that as placeholder copy, so confirm it's the license you want.
- **Revoke the test key:** `messh keys revoke sdk-test`. The vector key in `spec/vectors/` is public test material and must never be trusted in production. It's only on the local Docker registry, but don't publish it to the real messh.io.
- **Version 0.1.0:** it's marked Alpha (Python classifier). Bump to 1.0 only once the wire format is final; see the open items in `README.md`.
