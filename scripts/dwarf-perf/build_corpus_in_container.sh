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
WORK_DIR="$OUT_DIR/_build"
PARSE_SRC_DIR="$WORK_DIR/parse-stress-src"
PARSE_OBJ_DIR="$WORK_DIR/parse-stress-obj"
MANIFEST_PATH="$OUT_DIR/manifest.json"

CC=${DWARF_PERF_CC:-gcc}
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

PARSE_STRESS_UNITS=${PARSE_STRESS_UNITS:-16}
PARSE_STRESS_TYPES_PER_UNIT=${PARSE_STRESS_TYPES_PER_UNIT:-10}
PARSE_STRESS_FUNCTIONS_PER_UNIT=${PARSE_STRESS_FUNCTIONS_PER_UNIT:-24}
PARSE_STRESS_HISTORY_LEN=${PARSE_STRESS_HISTORY_LEN:-8}

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "compiler not found: $CC" >&2
    exit 1
fi

mkdir -p "$QUERY_OUT_DIR" "$PARSE_OUT_DIR" "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR"
rm -rf "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR"
mkdir -p "$PARSE_SRC_DIR" "$PARSE_OBJ_DIR"

QUERY_SRC="$REPO_ROOT/perf-corpus/src/query-hotspot/query_hotspot.c"
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

python3 "$REPO_ROOT/scripts/dwarf-perf/generate_parse_stress.py" \
    --output-dir "$PARSE_SRC_DIR" \
    --units "$PARSE_STRESS_UNITS" \
    --types-per-unit "$PARSE_STRESS_TYPES_PER_UNIT" \
    --functions-per-unit "$PARSE_STRESS_FUNCTIONS_PER_UNIT" \
    --history-len "$PARSE_STRESS_HISTORY_LEN"

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

query_sha=$(sha256sum "$QUERY_BIN" | awk '{print $1}')
parse_sha=$(sha256sum "$PARSE_BIN" | awk '{print $1}')
query_size=$(stat -c '%s' "$QUERY_BIN")
parse_size=$(stat -c '%s' "$PARSE_BIN")

jq -n \
    --arg builder_image "${DWARF_PERF_BUILDER_IMAGE_REF:-unspecified}" \
    --arg compiler "$CC" \
    --arg query_path "query-hotspot/query_hotspot" \
    --arg query_sha "$query_sha" \
    --arg query_source "perf-corpus/src/query-hotspot/query_hotspot.c" \
    --arg query_function "dwarf_perf_query_hotspot" \
    --arg query_marker "DWARF_PERF_QUERY_HOTSPOT" \
    --arg parse_path "parse-stress/parse_stress" \
    --arg parse_sha "$parse_sha" \
    --arg parse_generator "scripts/dwarf-perf/generate_parse_stress.py" \
    --argjson dwarf_version "$DWARF_VERSION" \
    --argjson query_line "$QUERY_MARKER_LINE" \
    --argjson query_size "$query_size" \
    --argjson parse_size "$parse_size" \
    --argjson parse_units "$PARSE_STRESS_UNITS" \
    --argjson parse_types_per_unit "$PARSE_STRESS_TYPES_PER_UNIT" \
    --argjson parse_functions_per_unit "$PARSE_STRESS_FUNCTIONS_PER_UNIT" \
    --argjson parse_history_len "$PARSE_STRESS_HISTORY_LEN" \
    '{
        schema_version: 1,
        builder_image: $builder_image,
        compiler: {
            cc: $compiler,
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
                    units: $parse_units,
                    types_per_unit: $parse_types_per_unit,
                    functions_per_unit: $parse_functions_per_unit,
                    history_len: $parse_history_len
                }
            }
        ]
    }' >"$MANIFEST_PATH"

echo "Built DWARF perf corpus into $OUT_DIR"
echo "  query-hotspot: $QUERY_BIN"
echo "  parse-stress:  $PARSE_BIN"
echo "  manifest:      $MANIFEST_PATH"
