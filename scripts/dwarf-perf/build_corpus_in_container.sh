#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <output-dir>" >&2
    exit 1
fi

OUT_DIR=$1
QUERY_OUT_DIR="$OUT_DIR/query-hotspot"
PARSE_OUT_DIR="$OUT_DIR/parse-stress"
RUST_PARSE_OUT_DIR="$OUT_DIR/rust-parse-stress"
WORK_DIR="$OUT_DIR/_build"
PARSE_SRC_DIR="$WORK_DIR/parse-stress-src"
PARSE_OBJ_DIR="$WORK_DIR/parse-stress-obj"
RUST_PARSE_SRC_DIR="$WORK_DIR/rust-parse-stress-src"
MANIFEST_PATH="$OUT_DIR/manifest.json"
PARSE_CONFIG_PATH="$PARSE_SRC_DIR/generation_config.json"
RUST_PARSE_CONFIG_PATH="$RUST_PARSE_SRC_DIR/generation_config.json"

CC=${DWARF_PERF_CC:-gcc}
RUSTC=${DWARF_PERF_RUSTC:-rustc}
DWARF_VERSION=${DWARF_PERF_DWARF_VERSION:-5}
COMMON_CFLAGS=(
    -std=c11
    -Wall
    -Wextra
    -Werror
    -g3
    -O0
    "-gdwarf-${DWARF_VERSION}"
    -fno-omit-frame-pointer
    -fno-inline
    -fno-optimize-sibling-calls
    -ffile-prefix-map=/workspace=/workspace
    -fdebug-prefix-map=/workspace=/workspace
)
COMMON_LDFLAGS=()

if [[ -n "${DWARF_PERF_CFLAGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_CFLAGS=(${DWARF_PERF_CFLAGS})
else
    EXTRA_CFLAGS=()
fi

if [[ -n "${DWARF_PERF_LDFLAGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_LDFLAGS=(${DWARF_PERF_LDFLAGS})
else
    EXTRA_LDFLAGS=()
fi

if [[ -n "${DWARF_PERF_RUSTFLAGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_RUSTFLAGS=(${DWARF_PERF_RUSTFLAGS})
else
    EXTRA_RUSTFLAGS=()
fi

PARSE_STRESS_PRESET=${PARSE_STRESS_PRESET:-large}
RUST_PARSE_STRESS_PRESET=${RUST_PARSE_STRESS_PRESET:-large}

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "compiler not found: $CC" >&2
    exit 1
fi

if ! command -v "$RUSTC" >/dev/null 2>&1; then
    echo "rust compiler not found: $RUSTC" >&2
    exit 1
fi

mkdir -p "$QUERY_OUT_DIR" "$PARSE_OUT_DIR" "$RUST_PARSE_OUT_DIR" "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR" "$RUST_PARSE_SRC_DIR"
rm -rf "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR" "$RUST_PARSE_SRC_DIR"
mkdir -p "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR" "$RUST_PARSE_SRC_DIR"

QUERY_SRC="$REPO_ROOT/scripts/dwarf-perf/corpus/src/query-hotspot/query_hotspot.c"
QUERY_BIN="$QUERY_OUT_DIR/query_hotspot"
QUERY_MARKER_LINE=$(grep -n "DWARF_PERF_QUERY_HOTSPOT" "$QUERY_SRC" | cut -d: -f1)

"$CC" \
    "${COMMON_CFLAGS[@]}" \
    "${EXTRA_CFLAGS[@]}" \
    -fno-pie \
    -no-pie \
    -o "$QUERY_BIN" \
    "$QUERY_SRC" \
    "${COMMON_LDFLAGS[@]}" \
    "${EXTRA_LDFLAGS[@]}"

generator_args=(
    --output-dir "$PARSE_SRC_DIR"
    --preset "$PARSE_STRESS_PRESET"
)

if [[ -n "${PARSE_STRESS_UNITS:-}" ]]; then
    generator_args+=(--units "$PARSE_STRESS_UNITS")
fi

if [[ -n "${PARSE_STRESS_TYPES_PER_UNIT:-}" ]]; then
    generator_args+=(--types-per-unit "$PARSE_STRESS_TYPES_PER_UNIT")
fi

if [[ -n "${PARSE_STRESS_FUNCTIONS_PER_UNIT:-}" ]]; then
    generator_args+=(--functions-per-unit "$PARSE_STRESS_FUNCTIONS_PER_UNIT")
fi

if [[ -n "${PARSE_STRESS_HISTORY_LEN:-}" ]]; then
    generator_args+=(--history-len "$PARSE_STRESS_HISTORY_LEN")
fi

python3 "$REPO_ROOT/scripts/dwarf-perf/generate_parse_stress.py" "${generator_args[@]}"

PARSE_STRESS_PRESET=$(jq -r '.preset' "$PARSE_CONFIG_PATH")
PARSE_STRESS_UNITS=$(jq -r '.units' "$PARSE_CONFIG_PATH")
PARSE_STRESS_TYPES_PER_UNIT=$(jq -r '.types_per_unit' "$PARSE_CONFIG_PATH")
PARSE_STRESS_FUNCTIONS_PER_UNIT=$(jq -r '.functions_per_unit' "$PARSE_CONFIG_PATH")
PARSE_STRESS_HISTORY_LEN=$(jq -r '.history_len' "$PARSE_CONFIG_PATH")
PARSE_STRESS_GENERATED_C_FILES=$(jq -r '.generated_c_files' "$PARSE_CONFIG_PATH")
PARSE_STRESS_GENERATED_HEADER_FILES=$(jq -r '.generated_header_files' "$PARSE_CONFIG_PATH")

mapfile -t parse_sources < <(find "$PARSE_SRC_DIR" -name '*.c' -print | sort)
parse_objects=()

for source_path in "${parse_sources[@]}"; do
    source_name=$(basename "$source_path" .c)
    object_path="$PARSE_OBJ_DIR/${source_name}.o"
    "$CC" \
        "${COMMON_CFLAGS[@]}" \
        "${EXTRA_CFLAGS[@]}" \
        -I"$PARSE_SRC_DIR" \
        -c \
        -o "$object_path" \
        "$source_path"
    parse_objects+=("$object_path")
done

PARSE_BIN="$PARSE_OUT_DIR/parse_stress"
"$CC" \
    "${parse_objects[@]}" \
    -o "$PARSE_BIN" \
    "${COMMON_LDFLAGS[@]}" \
    "${EXTRA_LDFLAGS[@]}"

rust_generator_args=(
    --output-dir "$RUST_PARSE_SRC_DIR"
    --preset "$RUST_PARSE_STRESS_PRESET"
)

if [[ -n "${RUST_PARSE_STRESS_MODULES:-}" ]]; then
    rust_generator_args+=(--modules "$RUST_PARSE_STRESS_MODULES")
fi

if [[ -n "${RUST_PARSE_STRESS_TYPES_PER_MODULE:-}" ]]; then
    rust_generator_args+=(--types-per-module "$RUST_PARSE_STRESS_TYPES_PER_MODULE")
fi

if [[ -n "${RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE:-}" ]]; then
    rust_generator_args+=(--functions-per-module "$RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE")
fi

python3 "$REPO_ROOT/scripts/dwarf-perf/generate_rust_parse_stress.py" "${rust_generator_args[@]}"

RUST_PARSE_STRESS_PRESET=$(jq -r '.preset' "$RUST_PARSE_CONFIG_PATH")
RUST_PARSE_STRESS_MODULES=$(jq -r '.modules' "$RUST_PARSE_CONFIG_PATH")
RUST_PARSE_STRESS_TYPES_PER_MODULE=$(jq -r '.types_per_module' "$RUST_PARSE_CONFIG_PATH")
RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE=$(jq -r '.functions_per_module' "$RUST_PARSE_CONFIG_PATH")
RUST_PARSE_STRESS_GENERATED_MODULE_FILES=$(jq -r '.generated_module_files' "$RUST_PARSE_CONFIG_PATH")
RUST_PARSE_STRESS_GENERATED_RUST_FILES=$(jq -r '.generated_rust_files' "$RUST_PARSE_CONFIG_PATH")

RUST_PARSE_BIN="$RUST_PARSE_OUT_DIR/rust_parse_stress"
"$RUSTC" \
    --edition=2021 \
    --remap-path-prefix "$REPO_ROOT=/workspace" \
    -C debuginfo=2 \
    -C opt-level=0 \
    -C force-frame-pointers=yes \
    -C link-dead-code=yes \
    "${EXTRA_RUSTFLAGS[@]}" \
    -o "$RUST_PARSE_BIN" \
    "$RUST_PARSE_SRC_DIR/main.rs"

query_sha=$(sha256sum "$QUERY_BIN" | awk '{print $1}')
parse_sha=$(sha256sum "$PARSE_BIN" | awk '{print $1}')
rust_parse_sha=$(sha256sum "$RUST_PARSE_BIN" | awk '{print $1}')
query_size=$(stat -c '%s' "$QUERY_BIN")
parse_size=$(stat -c '%s' "$PARSE_BIN")
rust_parse_size=$(stat -c '%s' "$RUST_PARSE_BIN")

jq -n \
    --arg builder_image "${DWARF_PERF_BUILDER_IMAGE_REF:-unspecified}" \
    --arg compiler "$CC" \
    --arg rustc "$RUSTC" \
    --arg query_path "query-hotspot/query_hotspot" \
    --arg query_sha "$query_sha" \
    --arg query_source "scripts/dwarf-perf/corpus/src/query-hotspot/query_hotspot.c" \
    --arg query_function "dwarf_perf_query_hotspot" \
    --arg query_marker "DWARF_PERF_QUERY_HOTSPOT" \
    --arg parse_path "parse-stress/parse_stress" \
    --arg parse_sha "$parse_sha" \
    --arg parse_generator "scripts/dwarf-perf/generate_parse_stress.py" \
    --arg parse_preset "$PARSE_STRESS_PRESET" \
    --arg rust_parse_path "rust-parse-stress/rust_parse_stress" \
    --arg rust_parse_sha "$rust_parse_sha" \
    --arg rust_parse_generator "scripts/dwarf-perf/generate_rust_parse_stress.py" \
    --arg rust_parse_preset "$RUST_PARSE_STRESS_PRESET" \
    --argjson dwarf_version "$DWARF_VERSION" \
    --argjson query_line "$QUERY_MARKER_LINE" \
    --argjson query_size "$query_size" \
    --argjson parse_size "$parse_size" \
    --argjson rust_parse_size "$rust_parse_size" \
    --argjson parse_units "$PARSE_STRESS_UNITS" \
    --argjson parse_types_per_unit "$PARSE_STRESS_TYPES_PER_UNIT" \
    --argjson parse_functions_per_unit "$PARSE_STRESS_FUNCTIONS_PER_UNIT" \
    --argjson parse_history_len "$PARSE_STRESS_HISTORY_LEN" \
    --argjson parse_generated_c_files "$PARSE_STRESS_GENERATED_C_FILES" \
    --argjson parse_generated_header_files "$PARSE_STRESS_GENERATED_HEADER_FILES" \
    --argjson rust_parse_modules "$RUST_PARSE_STRESS_MODULES" \
    --argjson rust_parse_types_per_module "$RUST_PARSE_STRESS_TYPES_PER_MODULE" \
    --argjson rust_parse_functions_per_module "$RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE" \
    --argjson rust_parse_generated_module_files "$RUST_PARSE_STRESS_GENERATED_MODULE_FILES" \
    --argjson rust_parse_generated_rust_files "$RUST_PARSE_STRESS_GENERATED_RUST_FILES" \
    '{
        schema_version: 1,
        builder_image: $builder_image,
        compiler: {
            cc: $compiler,
            rustc: $rustc,
            dwarf_version: $dwarf_version
        },
        artifacts: [
            {
                name: "query-hotspot",
                kind: "single-address-query",
                relative_path: $query_path,
                sha256: $query_sha,
                size_bytes: $query_size,
                source_path: $query_source,
                query_anchor: {
                    function: $query_function,
                    source_marker: $query_marker,
                    source_line: $query_line
                }
            },
            {
                name: "parse-stress",
                kind: "fast-parse",
                relative_path: $parse_path,
                sha256: $parse_sha,
                size_bytes: $parse_size,
                generator: {
                    script: $parse_generator,
                    preset: $parse_preset,
                    units: $parse_units,
                    types_per_unit: $parse_types_per_unit,
                    functions_per_unit: $parse_functions_per_unit,
                    history_len: $parse_history_len,
                    generated_c_files: $parse_generated_c_files,
                    generated_header_files: $parse_generated_header_files
                }
            },
            {
                name: "rust-parse-stress",
                kind: "fast-parse",
                language: "rust",
                relative_path: $rust_parse_path,
                sha256: $rust_parse_sha,
                size_bytes: $rust_parse_size,
                generator: {
                    script: $rust_parse_generator,
                    preset: $rust_parse_preset,
                    modules: $rust_parse_modules,
                    types_per_module: $rust_parse_types_per_module,
                    functions_per_module: $rust_parse_functions_per_module,
                    generated_module_files: $rust_parse_generated_module_files,
                    generated_rust_files: $rust_parse_generated_rust_files
                }
            }
        ]
    }' >"$MANIFEST_PATH"

echo "Built DWARF perf corpus into $OUT_DIR"
echo "  query-hotspot: $QUERY_BIN"
echo "  parse-stress:  $PARSE_BIN"
echo "  rust-parse-stress: $RUST_PARSE_BIN"
echo "  manifest:      $MANIFEST_PATH"

if [[ "$(id -u)" -eq 0 && -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
    chown -R "${HOST_UID}:${HOST_GID}" "$OUT_DIR"
fi
