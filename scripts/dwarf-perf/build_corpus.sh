#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
DEFAULT_IMAGE_REF_FILE="$SCRIPT_DIR/builder_image_ref.txt"

if [[ -n "${DWARF_PERF_BUILDER_IMAGE:-}" ]]; then
    IMAGE_REF=$DWARF_PERF_BUILDER_IMAGE
elif [[ -f "$DEFAULT_IMAGE_REF_FILE" ]]; then
    IMAGE_REF=$(<"$DEFAULT_IMAGE_REF_FILE")
else
    echo "builder image ref is not configured; set DWARF_PERF_BUILDER_IMAGE or add $DEFAULT_IMAGE_REF_FILE" >&2
    exit 1
fi

if [[ -z "$IMAGE_REF" ]]; then
    echo "builder image ref is empty" >&2
    exit 1
fi

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [output-dir]" >&2
    exit 1
fi

OUT_DIR=${1:-"scripts/dwarf-perf/corpus/out"}
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
    DWARF_PERF_CXX \
    DWARF_PERF_DWARF_VERSION \
    DWARF_PERF_CFLAGS \
    DWARF_PERF_CXXFLAGS \
    DWARF_PERF_LDFLAGS \
    DWARF_PERF_RUSTC \
    DWARF_PERF_RUSTFLAGS \
    PARSE_STRESS_PRESET \
    PARSE_STRESS_UNITS \
    PARSE_STRESS_TYPES_PER_UNIT \
    PARSE_STRESS_FUNCTIONS_PER_UNIT \
    PARSE_STRESS_HISTORY_LEN \
    RUST_PARSE_STRESS_PRESET \
    RUST_PARSE_STRESS_MODULES \
    RUST_PARSE_STRESS_TYPES_PER_MODULE \
    RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE \
    CPP_TEMPLATE_STRESS_PRESET \
    CPP_TEMPLATE_STRESS_UNITS \
    CPP_TEMPLATE_STRESS_FAMILIES_PER_UNIT \
    CPP_TEMPLATE_STRESS_INSTANTIATIONS_PER_FAMILY \
    CPP_TEMPLATE_STRESS_METHODS_PER_FAMILY \
    RUST_GENERIC_STRESS_PRESET \
    RUST_GENERIC_STRESS_MODULES \
    RUST_GENERIC_STRESS_FAMILIES_PER_MODULE \
    RUST_GENERIC_STRESS_MONOMORPHS_PER_FAMILY \
    CPP_DEEP_NAMESPACE_PRESET \
    CPP_DEEP_NAMESPACE_UNITS \
    CPP_DEEP_NAMESPACE_NAMESPACE_DEPTH \
    CPP_DEEP_NAMESPACE_BRANCHES_PER_UNIT \
    CPP_DEEP_NAMESPACE_FUNCTIONS_PER_BRANCH
do
    if [[ -n "${!var_name:-}" ]]; then
        env_args+=(-e "$var_name")
    fi
done

docker run --rm \
    -e DWARF_PERF_BUILDER_IMAGE_REF="$IMAGE_REF" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    "${env_args[@]}" \
    -v "$REPO_ROOT:/workspace" \
    -w /workspace \
    "$IMAGE_REF" \
    bash /workspace/scripts/dwarf-perf/build_corpus_in_container.sh "$CONTAINER_OUT_DIR"

# Keep index tooling independent of the pinned compiler image and its outputs.
INDEX_IMAGE=${DWARF_PERF_INDEX_TOOLS_IMAGE:-ghostscope-dwarf-perf-index-tools:local}
if [[ -z "${DWARF_PERF_INDEX_TOOLS_IMAGE:-}" ]]; then
    docker build -f "$REPO_ROOT/docker/dwarf-perf-builder/index-tools.Dockerfile" \
        -t "$INDEX_IMAGE" "$REPO_ROOT/docker/dwarf-perf-builder"
fi
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/workspace" -w /workspace "$INDEX_IMAGE" \
    python3 scripts/dwarf-perf/build_index_corpus.py "$CONTAINER_OUT_DIR"

echo "Host corpus: $OUT_DIR (see manifest.json for all artifacts)"
