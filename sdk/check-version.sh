#!/usr/bin/env bash
# Prints the SDK version; fails if the five packages disagree (or differ from $1, e.g. the tag).
set -euo pipefail
cd "$(dirname "$0")"
go=$(sed -n 's/^const Version = "\(.*\)"/\1/p' go/client.go)
py=$(sed -n 's/^version = "\(.*\)"/\1/p' py/pyproject.toml)
pyc=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' py/src/messh/client.py)
ts=$(sed -n 's/^  "version": "\(.*\)",/\1/p' ts/package.json)
tsc=$(sed -n 's/^export const VERSION = "\(.*\)";/\1/p' ts/src/index.ts)
rs=$(sed -n 's/^version = "\(.*\)"/\1/p' rs/Cargo.toml | head -1)
java=$(awk '/<artifactId>messh-sdk<\/artifactId>/{f=1} f && /<version>/{gsub(/.*<version>|<\/version>.*/, ""); print; exit}' java/pom.xml)
javac=$(sed -n 's/.*VERSION = "\(.*\)";/\1/p' java/src/main/java/io/messh/MesshClient.java)
want=${1:-$go}
bad=0
for pair in "go:$go" "python:$py" "python __version__:$pyc" "npm:$ts" "ts VERSION:$tsc" "rust:$rs" "maven:$java" "java VERSION:$javac"; do
  [ "${pair#*:}" = "$want" ] || { echo "version mismatch: ${pair%%:*} is ${pair#*:}, want $want" >&2; bad=1; }
done
[ $bad = 0 ] && echo "$want"
