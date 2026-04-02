#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
IMAGE_REF=${DWARF_PERF_BUILDER_IMAGE:-ghostscope-dwarf-perf-builder:dev}

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [output-dir]" >&2
    exit 1
fi

OUT_DIR=${1:-"perf-corpus/out"}
if [[ "$OUT_DIR" != /* ]]; then
    OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi

mkdir -p "$OUT_DIR"

case "$OUT_DIR" in
    "$REPO_ROOT" | "$REPO_ROOT"/*) ;;
    *)
        echo "output dir must stay inside the repo: $OUT_DIR" >&2
        exit 1
        ;;
esac

CONTAINER_OUT_DIR="/workspace${OUT_DIR#"$REPO_ROOT"}"

env_args=()
for var_name in \
    DWARF_PERF_CC \
    DWARF_PERF_DWARF_VERSION \
    DWARF_PERF_CFLAGS \
    DWARF_PERF_LDFLAGS \
    PARSE_STRESS_UNITS \
    PARSE_STRESS_TYPES_PER_UNIT \
    PARSE_STRESS_FUNCTIONS_PER_UNIT \
    PARSE_STRESS_HISTORY_LEN
do
    if [[ -n "${!var_name:-}" ]]; then
        env_args+=(-e "$var_name")
    fi
done

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e DWARF_PERF_BUILDER_IMAGE_REF="$IMAGE_REF" \
    "${env_args[@]}" \
    -v "$REPO_ROOT:/workspace" \
    -w /workspace \
    "$IMAGE_REF" \
    bash /workspace/scripts/dwarf-perf/build_corpus_in_container.sh "$CONTAINER_OUT_DIR"
