#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.88.0}"
BUILD_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/ghostscope-diagnostic-target}"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ghostscope-diagnostic.XXXXXX")"
TARGET_BINARY="$RUN_DIR/rust-adapter-rejection"
OUTPUT_FILE="$RUN_DIR/ghostscope-output.log"
TARGET_PID=""

cleanup() {
  if [[ -n "$TARGET_PID" ]]; then
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
  rm -rf "$RUN_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required to compile the Rust fixture" >&2
  exit 1
fi

if [[ "${GHOSTSCOPE_NO_SUDO:-0}" != "1" ]] \
  && [[ "$(id -u)" -ne 0 ]] \
  && ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required unless GHOSTSCOPE_NO_SUDO=1 is set" >&2
  exit 1
fi

export CARGO_TARGET_DIR="$BUILD_DIR"

echo "Building GhostScope in $BUILD_DIR"
cargo build \
  --manifest-path "$REPO_DIR/Cargo.toml" \
  -p ghostscope \
  --all-features

echo "Compiling the rejection fixture with Rust $RUST_TOOLCHAIN"
rustup run "$RUST_TOOLCHAIN" rustc \
  --edition=2018 \
  -g \
  -C opt-level=0 \
  -C link-dead-code \
  "$REPO_DIR/e2e-tests/tests/fixtures/rust_adapter_rejection_program/alloc.rs" \
  -o "$TARGET_BINARY"

"$TARGET_BINARY" &
TARGET_PID=$!
sleep 0.3
if ! kill -0 "$TARGET_PID" 2>/dev/null; then
  echo "the Rust fixture exited before GhostScope started" >&2
  exit 1
fi

GHOSTSCOPE=("$BUILD_DIR/debug/ghostscope")
if [[ "${GHOSTSCOPE_NO_SUDO:-0}" != "1" ]] && [[ "$(id -u)" -ne 0 ]]; then
  GHOSTSCOPE=(sudo "${GHOSTSCOPE[@]}")
fi

TRACE_SCRIPT='trace observe_adapter_rejection {
    print "value={}", G_REJECTED_STRING;
}'

echo "Running GhostScope against target PID $TARGET_PID"
set +e
"${GHOSTSCOPE[@]}" \
  -p "$TARGET_PID" \
  --no-log \
  --no-status \
  -s "$TRACE_SCRIPT" \
  2>&1 | tee "$OUTPUT_FILE"
GHOSTSCOPE_STATUS=${PIPESTATUS[0]}
set -e

if [[ "$GHOSTSCOPE_STATUS" -eq 0 ]]; then
  echo "GhostScope unexpectedly accepted the rejected fixture" >&2
  exit 1
fi

if ! grep -Fq \
  "Rust value adapter diagnostic (ordinary DWARF fallback also failed):" \
  "$OUTPUT_FILE"; then
  echo "GhostScope failed without the expected adapter diagnostic" >&2
  exit 1
fi

echo
echo "Rust adapter rejection diagnostic reproduced successfully."
