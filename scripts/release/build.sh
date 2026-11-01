#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Keep local and CI release builds on the same Ubuntu 20.04 / LLVM 22 image.
image=ghcr.io/swananan/ghostscope-build@sha256:6ef243d05b1157004a96d87f1abb35c499819d3c5d51d86379f8bf3b7ceb540f
mkdir -p target
docker pull "$image"
docker run --rm \
  -v "$PWD:/workspace" -w /workspace \
  -e CARGO_TARGET_DIR=/workspace/target/release-build \
  -e CARGO_HOME=/workspace/target/release-cargo-home \
  -e "RELEASE_OWNER=$(id -u):$(id -g)" \
  -e LLVM_SYS_221_PREFIX=/opt/llvm-22 \
  -e LLVM_CONFIG_PATH=/opt/llvm-22/bin/llvm-config \
  -e 'RUSTFLAGS=-C link-arg=-Wl,--as-needed' \
  "$image" bash -lc '
    mkdir -p /workspace/target/dist
    trap '\''chown -R "$RELEASE_OWNER" "$CARGO_TARGET_DIR" "$CARGO_HOME" /workspace/target/dist'\'' EXIT
    cargo build --locked --release -p ghostscope
  '
bash scripts/release/package.sh target/release-build/release/ghostscope
