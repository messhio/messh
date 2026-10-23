#!/bin/sh
# Prints the Homebrew formula for a CLI release: cli/release/formula.sh <version> <SHA256SUMS>
# (release-cli.yml writes it to messhio/homebrew-tap as Formula/messh.rb).
set -eu
v=$1 sums=$2
url="https://github.com/messhio/messh/releases/download/cli-v$v"
sha() {
  h=$(awk -v f="messh-$1" '$2 == f { print $1 }' "$sums")
  [ -n "$h" ] || { echo "no messh-$1 in $sums" >&2; exit 1; }
  echo "$h"
}
darwin_arm64=$(sha darwin-arm64)
darwin_amd64=$(sha darwin-amd64)
linux_arm64=$(sha linux-arm64)
linux_amd64=$(sha linux-amd64)

cat <<EOF
# Written by github.com/messhio/messh (.github/workflows/release-cli.yml) on each release; don't edit here.
class Messh < Formula
  desc "Publish SSH keys under your name and sign HTTP requests as you"
  homepage "https://messh.io"
  version "$v"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "$url/messh-darwin-arm64"
      sha256 "$darwin_arm64"
    end
    on_intel do
      url "$url/messh-darwin-amd64"
      sha256 "$darwin_amd64"
    end
  end

  on_linux do
    on_arm do
      url "$url/messh-linux-arm64"
      sha256 "$linux_arm64"
    end
    on_intel do
      url "$url/messh-linux-amd64"
      sha256 "$linux_amd64"
    end
  end

  def install
    binary = Dir["messh*"].first
    chmod 0755, binary
    bin.install binary => "messh"
  end

  test do
    assert_match "messh #{version}", shell_output("#{bin}/messh version")
  end
end
EOF
