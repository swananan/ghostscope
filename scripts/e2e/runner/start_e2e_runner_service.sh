#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DEFAULT_REPO_DIR="${DEFAULT_REPO_DIR:-${REPO_DIR:-$SCRIPT_REPO_DIR}}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8788}"
LLVM_PREFIX="${LLVM_PREFIX:-/usr/lib/llvm-18}"
CARGO_HOME_DIR="${CARGO_HOME_DIR:-}"
DEFAULT_SUDO="${DEFAULT_SUDO:-1}"
SERVICE_TOKEN="${E2E_SERVICE_TOKEN:-}"

ARGS=(
  --host "$HOST"
  --port "$PORT"
  --repo "$DEFAULT_REPO_DIR"
  --llvm-prefix "$LLVM_PREFIX"
)

if [[ "$DEFAULT_SUDO" == "1" ]]; then
  ARGS+=(--default-sudo)
fi

if [[ -n "$CARGO_HOME_DIR" ]]; then
  ARGS+=(--cargo-home "$CARGO_HOME_DIR")
fi

if [[ -n "$SERVICE_TOKEN" ]]; then
  ARGS+=(--token "$SERVICE_TOKEN")
fi

exec python3 "$SCRIPT_DIR/e2e_runner_service.py" "${ARGS[@]}"
