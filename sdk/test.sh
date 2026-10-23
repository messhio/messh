#!/usr/bin/env bash
# Unit + conformance tests for all five SDKs, in Docker (spec/vectors is shared).
set -euo pipefail
cd "$(dirname "$0")/.."
run() { docker run --rm -v "$PWD":/w "$@"; }
echo "== go";     run -w /w/sdk/go -e GOWORK=off golang:1.25-alpine sh -c 'go vet ./... && go test ./...'
echo "== python"; run -w /w/sdk/py python:3.12-slim sh -c 'pip install -q --root-user-action=ignore . "fastapi>=0.100" 2>/dev/null; python -m unittest discover -s tests'
echo "== ts";     run -w /w/sdk/ts node:22-alpine sh -c 'npm install -s --no-audit --no-fund >/dev/null && npm test -s'
echo "== rust";   run -v messh-cargo:/usr/local/cargo/registry -w /w/sdk/rs rust:1-slim cargo test --all-features -q
echo "== java";   run -v messh-m2:/root/.m2 -w /w/sdk/java maven:3.9-eclipse-temurin-21 mvn -q -B test
echo "all SDK tests passed"
