# Publishing the SDKs and the CLI

Names (checked 2026-10-22):

| Registry | Name | Install | Status |
|---|---|---|---|
| npm | `@messh/sdk` | `npm install @messh/sdk` | published: 0.1.0 with provenance (2026-10-23) |
| PyPI | `messh-sdk` (import `messh`) | `pip install messh-sdk` | `messh` is taken (an SSH config tool, last release 2019); `messh-sdk` is free |
| crates.io | `messh` | `cargo add messh` | published: 0.1.0 (2026-10-23) |
| Maven Central | `io.messh:messh-sdk` | `implementation("io.messh:messh-sdk:0.1.0")` | free; needs DNS proof of messh.io |
| Go | `messh.io/go/messh` | `go get messh.io/go/messh` | published: v0.1.0 (2026-10-23), the `sdk/go` directory of this repo, tagged `sdk/go/vX.Y.Z`; messh.io's `/go/messh` page points Go there |

The source repo is `github.com/messhio/messh`: this repo, the CLI and the SDKs.

## One-time setup (≈ 1 hour, mostly waiting on emails and DNS)

1. **GitHub** (done): the org `messhio` has `messh`, this repo.
2. **Go:** nothing to set up. The module is `sdk/go` in this repo: the go-import page names the directory (a field
   Go 1.25 added; every supported Go reads it, and older ones fetch through proxy.golang.org, which does), so a
   release is just the tag `sdk/go/vX.Y.Z`.
3. **Go vanity URL** (live since 2026-10-23): nothing to deploy while the app runs at `https://messh.io`: the web app (`messhio/messh-app`) serves the go-import page at `/go/messh` (and `/go/messh/verify`). Until then, or if messh.io is served from somewhere else, deploy the static copy in messh-app's `site/` instead, for example to Cloudflare Pages. Check it with `curl -s 'https://messh.io/go/messh?go-get=1' | grep go-import`.
4. **npm** (the org `messh` exists):
   - npmjs.com → your avatar → **Access Tokens** → **Generate New Token** → **Granular Access Token**.
     Packages and scopes: **Read and write**, scope `@messh`. Tick **Bypass two-factor authentication**, so CI can
     publish. npm caps write tokens at 90 days, so note when it expires.
   - Save it as the secret `NPM_TOKEN` in `messhio/messh` (Settings → Secrets and variables → Actions).
   - After the first publish you can drop the token: on npmjs.com, `@messh/sdk` → Settings → **Trusted Publisher** →
     GitHub Actions, `messhio/messh`, workflow `release-sdks.yml`.
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

Until every registry is set up, publish one at a time: Actions → release-sdks → Run workflow, and pick the registry
(`gh workflow run release-sdks.yml -R messhio/messh -f registry=npm`). It publishes the version in the package files
after the same tests.

`.github/workflows/release-sdks.yml` then:
1. Checks that the tag matches all five versions.
2. Runs every test suite.
3. Publishes:
   - npm, with provenance
   - PyPI, through trusted publishing
   - crates.io
   - Maven Central: signed, plus sources and javadoc jars
   - Go: tags `sdk/go/v0.1.0` here and asks proxy.golang.org to fetch it

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

One-time setup: the secret `TAP_DEPLOY_KEY`, a deploy key with write access to `messhio/homebrew-tap` (deploy keys
must be turned on for the org first). Until it's set, the workflow skips the tap with a warning; update it by hand
from a clone of `messhio/homebrew-tap`:

```sh
curl -fsSLO https://github.com/messhio/messh/releases/download/cli-v0.1.0/SHA256SUMS
/path/to/messh/cli/release/formula.sh 0.1.0 SHA256SUMS > Formula/messh.rb   # then commit and push
```

The CLI and the SDKs have separate version numbers.

## Checked locally (no upload)

| | Dry run | Result |
|---|---|---|
| npm | `npm pack --dry-run` | 13 files, 18.8 kB: dist, README, LICENSE |
| PyPI | `python -m build && twine check` | wheel + sdist PASSED, SPDX `Apache-2.0`, no warnings |
| crates.io | `cargo publish --dry-run` | packages, verifies and stops at the upload step |
| Maven | `mvn -P release package -Dgpg.skip` | jar + sources + javadoc |
| Go | module tested on its own (`GOWORK=off`) | `go vet` + `go test` pass |

## Before the first public release

- **License:** every package says **Apache-2.0** and ships its text. The handoff notes list that as placeholder copy, so confirm it's the license you want.
- **Revoke the test key:** `messh keys revoke sdk-test`. The vector key in `spec/vectors/` is public test material and must never be trusted in production. It's only on the local Docker registry, but don't publish it to the real messh.io.
- **Version 0.1.0:** it's marked Alpha (Python classifier). Bump to 1.0 only once the wire format is final; see the open items in `README.md`.
