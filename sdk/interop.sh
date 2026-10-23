#!/usr/bin/env bash
# Live check of all five SDKs against the running Docker stack (registry + botapp).
# Needs: the MVP stack (github.com/messhio/messh-mvp, `docker compose up -d` there), and
# spec/vectors/test_ed25519 published as mukul's key "sdk-test"
# (messh publish --key spec/vectors/test_ed25519.pub --name sdk-test).
set -euo pipefail
cd "$(dirname "$0")/.."
NET=${NET:-messh-mvp_default}
ENV=(-e APP=http://botapp:8090 -e REGISTRY=http://registry:8080 -e KEY=/w/spec/vectors/test_ed25519)
run() { docker run --rm --network "$NET" -v "$PWD":/w "${ENV[@]}" "$@"; }

run -w /w/sdk/go -e GOWORK=off golang:1.25-alpine go run ./examples/interop
run -w /w/sdk/py python:3.12-slim sh -c 'pip install -q --root-user-action=ignore . 2>/dev/null; python examples/interop.py'
run -w /w/sdk/ts node:22-alpine sh -c 'npm run -s build && node examples/interop.mjs'
run -v messh-cargo:/usr/local/cargo/registry -w /w/sdk/rs rust:1-slim cargo run -q --example interop
run -v messh-m2:/root/.m2 -w /w/sdk/java maven:3.9-eclipse-temurin-21 sh -c \
  'mvn -q -B test-compile dependency:build-classpath -Dmdep.outputFile=/tmp/cp >/dev/null && java -cp target/classes:target/test-classes:$(cat /tmp/cp) io.messh.examples.Interop'
echo "all five SDKs passed the live check"
