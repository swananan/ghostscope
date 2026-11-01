#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
binary="${1:?usage: package.sh BINARY}"
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml)
if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "v$version" ]]; then
  echo "Release tag $RELEASE_TAG does not match workspace version $version" >&2
  exit 1
fi
[[ "$("$binary" --version)" == "ghostscope $version" ]]
python3 scripts/release/check_binary.py "$binary"

mkdir -p target/dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -m 755 "$binary" "$stage/ghostscope"
cp config.toml config-zh.toml LICENSE LICENSE-MIT LICENSE-GPL README.md "$stage/"
archive="ghostscope-v$version-x86_64-linux.tar.gz"
tar -czf "target/dist/$archive" -C "$stage" .
(cd target/dist && sha256sum "$archive" > "$archive.sha256")
echo "Packaged target/dist/$archive"
