#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

BUILD_CORPUS=1
RUNS=10
CORPUS_DIR="$REPO_ROOT/scripts/dwarf-perf/corpus/out"
RESULTS_DIR="$REPO_ROOT/perf-results"
RESULT_NAME=""
CARGO_TARGET_DIR_VALUE="$REPO_ROOT/.target_tmp/dwarf-perf"

usage() {
    cat <<'EOF'
usage: run_baseline.sh [options]

Options:
  --skip-build           reuse an existing corpus directory
  --corpus-dir PATH      corpus output directory (default: scripts/dwarf-perf/corpus/out)
  --results-dir PATH     result directory (default: perf-results)
  --result-name NAME     result file stem (default: timestamp-based)
  --runs N               benchmark runs for parse and query baselines (default: 10)
  --cargo-target-dir P   cargo target dir for dwarf-tool (default: .target_tmp/dwarf-perf)
  -h, --help             show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            BUILD_CORPUS=0
            shift
            ;;
        --corpus-dir)
            CORPUS_DIR=$2
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR=$2
            shift 2
            ;;
        --result-name)
            RESULT_NAME=$2
            shift 2
            ;;
        --runs)
            RUNS=$2
            shift 2
            ;;
        --cargo-target-dir)
            CARGO_TARGET_DIR_VALUE=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ "$CORPUS_DIR" != /* ]]; then
    CORPUS_DIR="$REPO_ROOT/$CORPUS_DIR"
fi

if [[ "$RESULTS_DIR" != /* ]]; then
    RESULTS_DIR="$REPO_ROOT/$RESULTS_DIR"
fi

if [[ "$CARGO_TARGET_DIR_VALUE" != /* ]]; then
    CARGO_TARGET_DIR_VALUE="$REPO_ROOT/$CARGO_TARGET_DIR_VALUE"
fi

if [[ -z "$RESULT_NAME" ]]; then
    RESULT_NAME=$(date -u +"dwarf-perf-%Y%m%dT%H%M%SZ")
fi

mkdir -p "$RESULTS_DIR"

if [[ "$BUILD_CORPUS" -eq 1 ]]; then
    "$SCRIPT_DIR/build_corpus.sh" "$CORPUS_DIR"
fi

MANIFEST_PATH="$CORPUS_DIR/manifest.json"
if [[ ! -f "$MANIFEST_PATH" ]]; then
    echo "manifest not found: $MANIFEST_PATH" >&2
    exit 1
fi

QUERY_SOURCE=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .source_path' "$MANIFEST_PATH")
QUERY_LINE=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .query_anchor.source_line' "$MANIFEST_PATH")
QUERY_BINARY_REL=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .relative_path' "$MANIFEST_PATH")
PARSE_BINARY_REL=$(jq -r '.artifacts[] | select(.name=="parse-stress") | .relative_path' "$MANIFEST_PATH")

QUERY_BINARY="$CORPUS_DIR/$QUERY_BINARY_REL"
PARSE_BINARY="$CORPUS_DIR/$PARSE_BINARY_REL"
QUERY_SOURCE_ABS="$REPO_ROOT/$QUERY_SOURCE"
RESULT_PATH="$RESULTS_DIR/$RESULT_NAME.json"

if [[ ! -f "$QUERY_BINARY" ]]; then
    echo "query binary not found: $QUERY_BINARY" >&2
    exit 1
fi

if [[ ! -f "$PARSE_BINARY" ]]; then
    echo "parse binary not found: $PARSE_BINARY" >&2
    exit 1
fi

PARSE_OUTPUT=$(CARGO_TARGET_DIR="$CARGO_TARGET_DIR_VALUE" \
    cargo run -q -p dwarf-tool -- \
    -t "$PARSE_BINARY" \
    benchmark --runs "$RUNS")

QUERY_OUTPUT=$(CARGO_TARGET_DIR="$CARGO_TARGET_DIR_VALUE" \
    cargo run -q -p dwarf-tool -- \
    -t "$QUERY_BINARY" \
    benchmark-source-line "${QUERY_SOURCE_ABS}:${QUERY_LINE}" \
    --runs "$RUNS" \
    --json)

PARSE_AVG_MS=$(printf '%s\n' "$PARSE_OUTPUT" | awk '/Average load time:/ {gsub("ms","",$4); print $4}')
PARSE_P50_MS=$(printf '%s\n' "$PARSE_OUTPUT" | awk '/P50:/ {gsub("ms","",$2); print $2}')
PARSE_P95_MS=$(printf '%s\n' "$PARSE_OUTPUT" | awk '/P95:/ {gsub("ms","",$2); print $2}')
PARSE_MIN_MS=$(printf '%s\n' "$PARSE_OUTPUT" | awk '/Min:/ {gsub("ms","",$2); print $2}')
PARSE_MAX_MS=$(printf '%s\n' "$PARSE_OUTPUT" | awk '/Max:/ {gsub("ms","",$2); print $2}')
QUERY_JSON=$(printf '%s\n' "$QUERY_OUTPUT" | sed -n '/^{/,$p')
QUERY_LOADING_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.loading_time_ms')
QUERY_FIRST_RUN_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.first_run_ms')
QUERY_AVG_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.average_ms')
QUERY_P50_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.p50_ms')
QUERY_P95_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.p95_ms')
QUERY_MIN_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.min_ms')
QUERY_MAX_MS=$(printf '%s\n' "$QUERY_JSON" | jq '.benchmark.max_ms')
QUERY_TOTAL_VARS=$(printf '%s\n' "$QUERY_JSON" | jq '.total_variables')
QUERY_ADDRESS_COUNT=$(printf '%s\n' "$QUERY_JSON" | jq '.address_count')
QUERY_FIRST_ADDRESS=$(printf '%s\n' "$QUERY_JSON" | jq -r '.first_address // empty')

jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg repo_root "$REPO_ROOT" \
    --arg corpus_dir "$CORPUS_DIR" \
    --arg manifest "$MANIFEST_PATH" \
    --arg results_path "$RESULT_PATH" \
    --arg query_binary "$QUERY_BINARY" \
    --arg parse_binary "$PARSE_BINARY" \
    --arg query_source "$QUERY_SOURCE_ABS" \
    --arg query_line "$QUERY_LINE" \
    --arg query_first_address "$QUERY_FIRST_ADDRESS" \
    --argjson runs "$RUNS" \
    --argjson parse_avg_ms "$PARSE_AVG_MS" \
    --argjson parse_p50_ms "$PARSE_P50_MS" \
    --argjson parse_p95_ms "$PARSE_P95_MS" \
    --argjson parse_min_ms "$PARSE_MIN_MS" \
    --argjson parse_max_ms "$PARSE_MAX_MS" \
    --argjson query_loading_ms "$QUERY_LOADING_MS" \
    --argjson query_first_run_ms "$QUERY_FIRST_RUN_MS" \
    --argjson query_avg_ms "$QUERY_AVG_MS" \
    --argjson query_p50_ms "$QUERY_P50_MS" \
    --argjson query_p95_ms "$QUERY_P95_MS" \
    --argjson query_min_ms "$QUERY_MIN_MS" \
    --argjson query_max_ms "$QUERY_MAX_MS" \
    --argjson query_total_variables "$QUERY_TOTAL_VARS" \
    --argjson query_address_count "$QUERY_ADDRESS_COUNT" \
    --slurpfile manifest_json "$MANIFEST_PATH" \
    '{
        schema_version: 2,
        generated_at: $generated_at,
        repo_root: $repo_root,
        corpus_dir: $corpus_dir,
        manifest_path: $manifest,
        result_path: $results_path,
        parse_benchmark: {
            description: "Fast parse benchmark: analyzer load plus initial DWARF fast-parse/index build.",
            binary: $parse_binary,
            runs: $runs,
            metrics_ms: {
                average: $parse_avg_ms,
                p50: $parse_p50_ms,
                p95: $parse_p95_ms,
                min: $parse_min_ms,
                max: $parse_max_ms
            }
        },
        query_benchmark: {
            description: "End-to-end source-line query benchmark: source-line lookup, address resolution, and variable collection for all matched addresses.",
            binary: $query_binary,
            source: {
                path: $query_source,
                line: ($query_line | tonumber)
            },
            loading_time_ms: $query_loading_ms,
            runs: $runs,
            metrics_ms: {
                first_run: $query_first_run_ms,
                average: $query_avg_ms,
                p50: $query_p50_ms,
                p95: $query_p95_ms,
                min: $query_min_ms,
                max: $query_max_ms
            }
        },
        query_result: {
            description: "Snapshot of the matched query result for the benchmarked source line.",
            source: {
                path: $query_source,
                line: ($query_line | tonumber)
            },
            first_address: $query_first_address,
            address_count: $query_address_count,
            total_variables: $query_total_variables
        },
        corpus_manifest: $manifest_json[0]
    }' >"$RESULT_PATH"

echo "Fast parse benchmark:"
echo "  meaning: analyzer load + initial DWARF fast-parse/index build"
echo "  binary: $PARSE_BINARY"
echo "  runs: $RUNS"
echo "  average: ${PARSE_AVG_MS}ms"
echo "  p50: ${PARSE_P50_MS}ms"
echo "  p95: ${PARSE_P95_MS}ms"
echo "  min: ${PARSE_MIN_MS}ms"
echo "  max: ${PARSE_MAX_MS}ms"
echo
echo "Source-line query benchmark:"
echo "  meaning: source-line lookup + address resolution + variable collection for matched addresses"
echo "  source: ${QUERY_SOURCE_ABS}:${QUERY_LINE}"
echo "  binary: $QUERY_BINARY"
echo "  loading time: ${QUERY_LOADING_MS}ms"
echo "  runs: $RUNS"
echo "  first run: ${QUERY_FIRST_RUN_MS}ms"
echo "  average: ${QUERY_AVG_MS}ms"
echo "  p50: ${QUERY_P50_MS}ms"
echo "  p95: ${QUERY_P95_MS}ms"
echo "  min: ${QUERY_MIN_MS}ms"
echo "  max: ${QUERY_MAX_MS}ms"
echo
echo "Query result snapshot:"
echo "  addresses: $QUERY_ADDRESS_COUNT"
echo "  total variables: $QUERY_TOTAL_VARS"
if [[ -n "$QUERY_FIRST_ADDRESS" ]]; then
    echo "  first address: $QUERY_FIRST_ADDRESS"
fi
echo
echo "Result JSON: $RESULT_PATH"
