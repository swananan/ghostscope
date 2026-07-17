#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX_FILE="$ROOT_DIR/rust-compat-toolchains.txt"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/rust_compat_program"
SOURCE="$FIXTURE_DIR/main.rs"

configured_toolchains() {
    if [[ -n "${GHOSTSCOPE_RUST_COMPAT_TOOLCHAINS:-}" ]]; then
        printf '%s\n' "$GHOSTSCOPE_RUST_COMPAT_TOOLCHAINS" \
            | tr ',' '\n' \
            | sed '/^[[:space:]]*$/d'
        return
    fi

    sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$MATRIX_FILE"
}

while IFS= read -r toolchain; do
    toolchain="$(printf '%s' "$toolchain" | xargs)"
    safe_toolchain="$(printf '%s' "$toolchain" | sed 's/[^A-Za-z0-9]/_/g')"
    output_dir="$FIXTURE_DIR/bin/$safe_toolchain"
    binary="$output_dir/rust_compat_program"

    printf '==> compiling Rust compatibility fixture with %s\n' "$toolchain"
    mkdir -p "$output_dir"
    rustup run "$toolchain" rustc \
        --edition=2018 \
        -g \
        -C opt-level=0 \
        "$SOURCE" \
        -o "$binary"
done < <(configured_toolchains)
