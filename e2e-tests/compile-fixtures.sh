#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$ROOT_DIR/tests/fixtures"
RUST_FIXTURE_DIR="$FIXTURES_DIR/rust_global_program"

# cache-fixtures.sh discovers CI cache contents from the compiled outputs this
# script leaves under tests/fixtures. If a new fixture writes binaries outside a
# *_program directory or below a deeper target path, update that helper too.
if [[ -n "${CLANG_BIN:-}" ]]; then
    CLANG_BIN="$CLANG_BIN"
elif command -v clang-18 >/dev/null 2>&1; then
    CLANG_BIN="clang-18"
else
    CLANG_BIN="clang"
fi

if [[ -n "${GCC_BIN:-}" ]]; then
    GCC_BIN="$GCC_BIN"
else
    GCC_BIN="gcc"
fi

log() {
    printf '==> %s\n' "$*"
}

run_make_fixture() {
    local fixture="$1"
    shift
    log "make ${fixture} $*"
    (
        cd "$FIXTURES_DIR/$fixture"
        make "$@"
    )
}

run_cargo_fixture() {
    local fixture_dir="$1"
    shift
    log "cargo $(basename "$fixture_dir") $*"
    (
        cd "$fixture_dir"
        cargo "$@"
    )
}

run_make_fixture sample_program clean
run_make_fixture sample_program all

run_make_fixture complex_types_program clean
run_make_fixture complex_types_program all complex_types_program_nopie

run_make_fixture member_pointer_program clean
run_make_fixture member_pointer_program all

run_make_fixture globals_program clean
run_make_fixture globals_program all

run_make_fixture late_globals_program clean
run_make_fixture late_globals_program all

run_make_fixture short_lived_long_comm_program clean
run_make_fixture short_lived_long_comm_program all

run_make_fixture scalar_types_program clean
run_make_fixture scalar_types_program all

run_cargo_fixture "$RUST_FIXTURE_DIR" clean
run_cargo_fixture "$RUST_FIXTURE_DIR" build --locked

run_make_fixture inline_callsite_program clean
run_make_fixture inline_callsite_program all
run_make_fixture inline_callsite_program \
    all \
    "CC=${CLANG_BIN}" \
    "CFLAGS=-Wall -Wextra -gdwarf-5 -O3" \
    "BINARY=inline_callsite_program_clang_dwarf5" \
    "OBJ=inline_callsite_program_clang_dwarf5.o"

run_make_fixture inline_call_value_program clean
run_make_fixture inline_call_value_program all

run_make_fixture partitioned_ranges_program clean
run_make_fixture partitioned_ranges_program all
run_make_fixture partitioned_ranges_program \
    all \
    "CC=${GCC_BIN}" \
    "CFLAGS=-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -freorder-blocks-and-partition" \
    "BINARY=partitioned_ranges_program_gcc_dwarf5_sections" \
    "OBJ=partitioned_ranges_program_gcc_dwarf5_sections.o"
run_make_fixture partitioned_ranges_program \
    all \
    "CC=${CLANG_BIN}" \
    "CFLAGS=-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -fbasic-block-sections=all" \
    "BINARY=partitioned_ranges_program_clang_dwarf5_rnglistx" \
    "OBJ=partitioned_ranges_program_clang_dwarf5_rnglistx.o"

run_make_fixture cpp_complex_program clean
run_make_fixture cpp_complex_program all

run_make_fixture static_scope_program clean
run_make_fixture static_scope_program all
run_make_fixture static_scope_program \
    all \
    "CC=${CLANG_BIN}" \
    "CFLAGS=-Wall -Wextra -gdwarf-5 -O0" \
    "BINARY=static_scope_program_clang_dwarf5" \
    "OBJ=static_scope_program_clang_dwarf5.o"

run_make_fixture entry_value_recovery_program clean
run_make_fixture entry_value_recovery_program all
run_make_fixture entry_value_recovery_program \
    all \
    "CC=${CLANG_BIN}" \
    "CFLAGS=-Wall -Wextra -gdwarf-5 -O3" \
    "BINARY=entry_value_recovery_program_clang_dwarf5" \
    "OBJ=entry_value_recovery_program_clang_dwarf5.o"

# entry_value_breg_program is still synthesized in Rust test code because its
# debuglink payload is patched with custom DWARF sections at runtime.
