#!/usr/bin/env bash
set -euo pipefail

# Build the sysmon eBPF object (CO-RE) with an isolated toolchain/target.
# This keeps the main project on Rust 1.88 while using a different toolchain
# suitable for bpf targets.
#
# Usage:
#   ./ghostscope-process/ebpf/build_sysmon_bpf.sh
#
# Optional env vars:
#   TOOLCHAIN      - rustup toolchain to use (default: nightly-2024-07-01)
#   TARGET         - bpf target triple (default: bpfel-unknown-none)
#   SKIP_RUST_SRC  - if set to 1, do not install rust-src (default: install)

TOOLCHAIN="${TOOLCHAIN:-nightly-2024-07-01}"
TARGET="${TARGET:-both}"
SKIP_RUST_SRC="${SKIP_RUST_SRC:-0}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# Try to locate repo root (contains Cargo.toml). Prefer git, fallback to relative path.
if command -v git >/dev/null 2>&1 && git -C "${SCRIPT_DIR}" rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
else
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
fi
BPF_CRATE="${SCRIPT_DIR}/sysmon-bpf"
OUT_DIR="${SCRIPT_DIR}/obj"
OUT_OBJ="${OUT_DIR}/sysmon-bpf.o"

# Enforce xtask usage only
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found. Please install Rust and Cargo." >&2
  exit 1
fi
echo "==> Using cargo run --manifest-path (ebpf/xtask) to build eBPF"
ARGS=(--manifest-path "${SCRIPT_DIR}/xtask/Cargo.toml" -- build-ebpf --toolchain "${TOOLCHAIN}" --target "${TARGET}")
if [[ "${SKIP_RUST_SRC}" == "1" ]]; then
  ARGS+=(--skip-rust_src)
fi
cargo run "${ARGS[@]}"

# Verify endian-specific outputs exist and are ELF
LE_OBJ="${SCRIPT_DIR}/obj/sysmon-bpf.bpfel.o"
BE_OBJ="${SCRIPT_DIR}/obj/sysmon-bpf.bpfeb.o"

for OBJ in "${LE_OBJ}" "${BE_OBJ}"; do
  if [[ ! -f "${OBJ}" ]]; then
    echo "ERROR: expected output not found: ${OBJ}" >&2
    exit 1
  fi
  MAGIC_HEX="$(dd if="${OBJ}" bs=4 count=1 2>/dev/null | od -An -t x1 | tr -d ' \n')"
  if [[ "${MAGIC_HEX}" != "7f454c46"* ]]; then
    echo "ERROR: ${OBJ} is not an ELF object (magic=${MAGIC_HEX}), aborting" >&2
    exit 1
  fi
done

echo "==> Ready: ${LE_OBJ} ($(stat -c%s "${LE_OBJ}" 2>/dev/null || wc -c < "${LE_OBJ}") bytes, ELF)"
echo "==> Ready: ${BE_OBJ} ($(stat -c%s "${BE_OBJ}" 2>/dev/null || wc -c < "${BE_OBJ}") bytes, ELF)"
echo "Done."
