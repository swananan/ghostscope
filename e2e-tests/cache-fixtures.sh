#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$ROOT_DIR/.." && pwd)"
CACHE_DIR="$ROOT_DIR/.fixture-cache"
ARCHIVE="$CACHE_DIR/fixture-binaries.tar"

# Keep this discovery logic aligned with compile-fixtures.sh and the fixture
# registry in tests/common/mod.rs. CI caches this generated archive instead of
# maintaining a separate hand-written list of fixture binaries.
log() {
    printf '==> %s\n' "$*"
}

fixture_cache_paths() {
    (
        cd "$REPO_DIR"
        # C and C++ fixture binaries are generated directly under each
        # *_program directory. Exclude object files and source files by keeping
        # executable outputs plus standalone debug files for split-debug tests.
        find e2e-tests/tests/fixtures \
            -mindepth 2 \
            -maxdepth 2 \
            -type f \
            ! -path '*/entry_value_breg_program/*' \
            \( -perm -111 -o -name '*.debug' \) \
            -print

        # Cargo places the Rust fixture binary below target/debug, outside the
        # maxdepth-limited C/C++ fixture output convention above.
        local rust_binary="e2e-tests/tests/fixtures/rust_global_program/target/debug/rust_global_program"
        if [[ -f "$rust_binary" ]]; then
            printf '%s\n' "$rust_binary"
        fi
    ) | LC_ALL=C sort -u
}

pack_fixture_cache() {
    local paths=()
    mapfile -t paths < <(fixture_cache_paths)

    if [[ "${#paths[@]}" -eq 0 ]]; then
        printf 'no fixture outputs found to cache\n' >&2
        return 1
    fi

    mkdir -p "$CACHE_DIR"
    tar -cf "$ARCHIVE" -C "$REPO_DIR" "${paths[@]}"
    log "packed ${#paths[@]} fixture cache outputs into ${ARCHIVE#$REPO_DIR/}"
}

unpack_fixture_cache() {
    if [[ ! -f "$ARCHIVE" ]]; then
        printf 'fixture cache archive not found: %s\n' "$ARCHIVE" >&2
        return 1
    fi

    tar -xf "$ARCHIVE" -C "$REPO_DIR"
    log "restored fixture cache outputs from ${ARCHIVE#$REPO_DIR/}"
}

case "${1:-}" in
    list)
        fixture_cache_paths
        ;;
    pack)
        pack_fixture_cache
        ;;
    unpack)
        unpack_fixture_cache
        ;;
    *)
        printf 'usage: %s {list|pack|unpack}\n' "$0" >&2
        exit 2
        ;;
esac
