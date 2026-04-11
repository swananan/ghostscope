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
PARSE_TARGET_NAME=""

usage() {
    cat <<'EOF'
usage: run_baseline.sh [options]

Options:
  --skip-build           reuse an existing corpus directory
  --corpus-dir PATH      corpus output directory (default: scripts/dwarf-perf/corpus/out)
  --results-dir PATH     result directory (default: perf-results)
  --result-name NAME     result file stem (default: timestamp-based)
  --runs N               benchmark runs for parse and query baselines (default: 10)
  --parse-target NAME    run only one parse artifact from the manifest
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
        --parse-target)
            PARSE_TARGET_NAME=$2
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

require_json_value() {
    local name=$1
    local value=$2
    local output=$3
    if [[ -z "$value" || "$value" == "null" ]]; then
        echo "failed to parse required benchmark field: $name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    printf '%s' "$value"
}

optional_json_value() {
    local value=$1
    if [[ -z "$value" || "$value" == "null" ]]; then
        printf 'null'
    else
        printf '%s' "$value"
    fi
}

display_metric_ms() {
    local value=$1
    if [[ "$value" == "null" ]]; then
        printf 'n/a'
    else
        printf '%sms' "$value"
    fi
}

timestamp_utc() {
    date -u +"%H:%M:%S"
}

log_stage() {
    printf '[%s] %s\n' "$(timestamp_utc)" "$*"
}

print_parse_summary() {
    local target_name=$1
    local binary_path=$2

    echo "Fast parse benchmark:"
    echo "  meaning: analyzer load + initial DWARF fast-parse/index build"
    echo "  artifact: $target_name"
    echo "  binary: $binary_path"
    echo "  runs: $RUNS"
    echo "  average: ${PARSE_AVG_MS}ms"
    echo "  p50: ${PARSE_P50_MS}ms"
    echo "  p95: ${PARSE_P95_MS}ms"
    echo "  min: ${PARSE_MIN_MS}ms"
    echo "  max: ${PARSE_MAX_MS}ms"
    echo "  internal modules: ${PARSE_INTERNAL_MODULE_COUNT}"
    echo "  parse phase avg: $(display_metric_ms "$PARSE_PHASE_AVG_MS")"
    echo "  parse phase p50: $(display_metric_ms "$PARSE_PHASE_P50_MS")"
    echo "  parse phase p95: $(display_metric_ms "$PARSE_PHASE_P95_MS")"
    echo "  index phase avg: $(display_metric_ms "$INDEX_PHASE_AVG_MS")"
    echo "  index phase p50: $(display_metric_ms "$INDEX_PHASE_P50_MS")"
    echo "  index phase p95: $(display_metric_ms "$INDEX_PHASE_P95_MS")"
    echo "  internal total avg: $(display_metric_ms "$INTERNAL_TOTAL_AVG_MS")"
    echo "  internal total p50: $(display_metric_ms "$INTERNAL_TOTAL_P50_MS")"
    echo "  internal total p95: $(display_metric_ms "$INTERNAL_TOTAL_P95_MS")"
    echo
}

print_query_summary() {
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
}

run_query_benchmark() {
    local query_output
    local query_json

    log_stage "Running source-line query benchmark on query-hotspot"
    query_output=$(CARGO_TARGET_DIR="$CARGO_TARGET_DIR_VALUE" \
        cargo run -q -p dwarf-tool -- \
        -t "$QUERY_BINARY" \
        benchmark-source-line "${QUERY_SOURCE_ABS}:${QUERY_LINE}" \
        --runs "$RUNS" \
        --json)

    query_json=$(printf '%s\n' "$query_output" | sed -n '/^{/,$p')
    QUERY_LOADING_MS=$(require_json_value "query loading time" "$(printf '%s\n' "$query_json" | jq '.loading_time_ms')" "$query_json")
    QUERY_FIRST_RUN_MS=$(require_json_value "query first run" "$(printf '%s\n' "$query_json" | jq '.benchmark.first_run_ms')" "$query_json")
    QUERY_AVG_MS=$(require_json_value "query average" "$(printf '%s\n' "$query_json" | jq '.benchmark.average_ms')" "$query_json")
    QUERY_P50_MS=$(require_json_value "query p50" "$(printf '%s\n' "$query_json" | jq '.benchmark.p50_ms')" "$query_json")
    QUERY_P95_MS=$(require_json_value "query p95" "$(printf '%s\n' "$query_json" | jq '.benchmark.p95_ms')" "$query_json")
    QUERY_MIN_MS=$(require_json_value "query min" "$(printf '%s\n' "$query_json" | jq '.benchmark.min_ms')" "$query_json")
    QUERY_MAX_MS=$(require_json_value "query max" "$(printf '%s\n' "$query_json" | jq '.benchmark.max_ms')" "$query_json")
    QUERY_TOTAL_VARS=$(require_json_value "query total variables" "$(printf '%s\n' "$query_json" | jq '.total_variables')" "$query_json")
    QUERY_ADDRESS_COUNT=$(require_json_value "query address count" "$(printf '%s\n' "$query_json" | jq '.address_count')" "$query_json")
    QUERY_FIRST_ADDRESS=$(printf '%s\n' "$query_json" | jq -r '.first_address // empty')
    log_stage "Completed source-line query benchmark"
}

run_parse_benchmark() {
    local parse_binary=$1
    local parse_target=$2
    local progress_label=${3:-}
    local parse_output

    if [[ -n "$progress_label" ]]; then
        log_stage "Running fast-parse benchmark ${progress_label} for ${parse_target}"
    else
        log_stage "Running fast-parse benchmark for ${parse_target}"
    fi
    parse_output=$(CARGO_TARGET_DIR="$CARGO_TARGET_DIR_VALUE" \
        cargo run -q -p dwarf-tool -- \
        -t "$parse_binary" \
        benchmark --runs "$RUNS")

    PARSE_AVG_MS=$(require_json_value "parse average" "$(printf '%s\n' "$parse_output" | awk '/Average load time:/ {gsub("ms","",$4); print $4}')" "$parse_output")
    PARSE_P50_MS=$(require_json_value "parse p50" "$(printf '%s\n' "$parse_output" | awk '/P50:/ {gsub("ms","",$2); print $2}')" "$parse_output")
    PARSE_P95_MS=$(require_json_value "parse p95" "$(printf '%s\n' "$parse_output" | awk '/P95:/ {gsub("ms","",$2); print $2}')" "$parse_output")
    PARSE_MIN_MS=$(require_json_value "parse min" "$(printf '%s\n' "$parse_output" | awk '/Min:/ {gsub("ms","",$2); print $2}')" "$parse_output")
    PARSE_MAX_MS=$(require_json_value "parse max" "$(printf '%s\n' "$parse_output" | awk '/Max:/ {gsub("ms","",$2); print $2}')" "$parse_output")
    PARSE_INTERNAL_MODULE_COUNT=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal module count:/ {print $4}')")
    PARSE_PHASE_AVG_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Parse avg:/ {gsub("ms","",$3); print $3}')")
    PARSE_PHASE_P50_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Parse p50:/ {gsub("ms","",$3); print $3}')")
    PARSE_PHASE_P95_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Parse p95:/ {gsub("ms","",$3); print $3}')")
    PARSE_PHASE_MIN_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Parse min:/ {gsub("ms","",$3); print $3}')")
    PARSE_PHASE_MAX_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Parse max:/ {gsub("ms","",$3); print $3}')")
    INDEX_PHASE_AVG_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Index avg:/ {gsub("ms","",$3); print $3}')")
    INDEX_PHASE_P50_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Index p50:/ {gsub("ms","",$3); print $3}')")
    INDEX_PHASE_P95_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Index p95:/ {gsub("ms","",$3); print $3}')")
    INDEX_PHASE_MIN_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Index min:/ {gsub("ms","",$3); print $3}')")
    INDEX_PHASE_MAX_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Index max:/ {gsub("ms","",$3); print $3}')")
    INTERNAL_TOTAL_AVG_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal total avg:/ {gsub("ms","",$4); print $4}')")
    INTERNAL_TOTAL_P50_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal total p50:/ {gsub("ms","",$4); print $4}')")
    INTERNAL_TOTAL_P95_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal total p95:/ {gsub("ms","",$4); print $4}')")
    INTERNAL_TOTAL_MIN_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal total min:/ {gsub("ms","",$4); print $4}')")
    INTERNAL_TOTAL_MAX_MS=$(optional_json_value "$(printf '%s\n' "$parse_output" | awk '/Internal total max:/ {gsub("ms","",$4); print $4}')")
    log_stage "Completed fast-parse benchmark for ${parse_target}"
}

write_baseline_json() {
    local output_path=$1
    local target_name=$2
    local parse_binary=$3

    log_stage "Writing baseline JSON for ${target_name} -> ${output_path}"
    jq -n \
        --arg generated_at "$GENERATED_AT" \
        --arg repo_root "$REPO_ROOT" \
        --arg corpus_dir "$CORPUS_DIR" \
        --arg manifest "$MANIFEST_PATH" \
        --arg results_path "$output_path" \
        --arg query_binary "$QUERY_BINARY" \
        --arg parse_binary "$parse_binary" \
        --arg parse_artifact_name "$target_name" \
        --arg query_source "$QUERY_SOURCE_ABS" \
        --arg query_line "$QUERY_LINE" \
        --arg query_first_address "$QUERY_FIRST_ADDRESS" \
        --argjson runs "$RUNS" \
        --argjson parse_avg_ms "$PARSE_AVG_MS" \
        --argjson parse_p50_ms "$PARSE_P50_MS" \
        --argjson parse_p95_ms "$PARSE_P95_MS" \
        --argjson parse_min_ms "$PARSE_MIN_MS" \
        --argjson parse_max_ms "$PARSE_MAX_MS" \
        --argjson parse_internal_module_count "$PARSE_INTERNAL_MODULE_COUNT" \
        --argjson parse_phase_avg_ms "$PARSE_PHASE_AVG_MS" \
        --argjson parse_phase_p50_ms "$PARSE_PHASE_P50_MS" \
        --argjson parse_phase_p95_ms "$PARSE_PHASE_P95_MS" \
        --argjson parse_phase_min_ms "$PARSE_PHASE_MIN_MS" \
        --argjson parse_phase_max_ms "$PARSE_PHASE_MAX_MS" \
        --argjson index_phase_avg_ms "$INDEX_PHASE_AVG_MS" \
        --argjson index_phase_p50_ms "$INDEX_PHASE_P50_MS" \
        --argjson index_phase_p95_ms "$INDEX_PHASE_P95_MS" \
        --argjson index_phase_min_ms "$INDEX_PHASE_MIN_MS" \
        --argjson index_phase_max_ms "$INDEX_PHASE_MAX_MS" \
        --argjson internal_total_avg_ms "$INTERNAL_TOTAL_AVG_MS" \
        --argjson internal_total_p50_ms "$INTERNAL_TOTAL_P50_MS" \
        --argjson internal_total_p95_ms "$INTERNAL_TOTAL_P95_MS" \
        --argjson internal_total_min_ms "$INTERNAL_TOTAL_MIN_MS" \
        --argjson internal_total_max_ms "$INTERNAL_TOTAL_MAX_MS" \
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
                artifact_name: $parse_artifact_name,
                binary: $parse_binary,
                runs: $runs,
                metrics_ms: {
                    average: $parse_avg_ms,
                    p50: $parse_p50_ms,
                    p95: $parse_p95_ms,
                    min: $parse_min_ms,
                    max: $parse_max_ms
                },
                internal_metrics_ms: {
                    module_count: $parse_internal_module_count,
                    parse_phase: {
                        average: $parse_phase_avg_ms,
                        p50: $parse_phase_p50_ms,
                        p95: $parse_phase_p95_ms,
                        min: $parse_phase_min_ms,
                        max: $parse_phase_max_ms
                    },
                    index_phase: {
                        average: $index_phase_avg_ms,
                        p50: $index_phase_p50_ms,
                        p95: $index_phase_p95_ms,
                        min: $index_phase_min_ms,
                        max: $index_phase_max_ms
                    },
                    internal_total: {
                        average: $internal_total_avg_ms,
                        p50: $internal_total_p50_ms,
                        p95: $internal_total_p95_ms,
                        min: $internal_total_min_ms,
                        max: $internal_total_max_ms
                    }
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
        }' >"$output_path"
    log_stage "Wrote baseline JSON for ${target_name}"
}

ordered_parse_targets() {
    local primary_target=$1
    shift
    local target

    printf '%s\n' "$primary_target"
    for target in "$@"; do
        if [[ "$target" == "$primary_target" ]]; then
            continue
        fi
        printf '%s\n' "$target"
    done
}

if [[ "$BUILD_CORPUS" -eq 1 ]]; then
    log_stage "Building corpus into ${CORPUS_DIR}"
    "$SCRIPT_DIR/build_corpus.sh" "$CORPUS_DIR"
    log_stage "Completed corpus build"
else
    log_stage "Reusing existing corpus at ${CORPUS_DIR}"
fi

MANIFEST_PATH="$CORPUS_DIR/manifest.json"
if [[ ! -f "$MANIFEST_PATH" ]]; then
    echo "manifest not found: $MANIFEST_PATH" >&2
    exit 1
fi

log_stage "Loading corpus manifest from ${MANIFEST_PATH}"
QUERY_SOURCE=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .source_path' "$MANIFEST_PATH")
QUERY_LINE=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .query_anchor.source_line' "$MANIFEST_PATH")
QUERY_BINARY_REL=$(jq -r '.artifacts[] | select(.name=="query-hotspot") | .relative_path' "$MANIFEST_PATH")

QUERY_BINARY="$CORPUS_DIR/$QUERY_BINARY_REL"
QUERY_SOURCE_ABS="$REPO_ROOT/$QUERY_SOURCE"
RESULT_PATH="$RESULTS_DIR/$RESULT_NAME.json"
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ ! -f "$QUERY_BINARY" ]]; then
    echo "query binary not found: $QUERY_BINARY" >&2
    exit 1
fi

run_query_benchmark

if [[ -n "$PARSE_TARGET_NAME" ]]; then
    log_stage "Single-target mode enabled for ${PARSE_TARGET_NAME}"
    PARSE_BINARY_REL=$(jq -r --arg parse_target "$PARSE_TARGET_NAME" '.artifacts[] | select(.name==$parse_target) | .relative_path' "$MANIFEST_PATH")
    if [[ -z "$PARSE_BINARY_REL" || "$PARSE_BINARY_REL" == "null" ]]; then
        echo "parse artifact not found in manifest: $PARSE_TARGET_NAME" >&2
        exit 1
    fi

    PARSE_BINARY="$CORPUS_DIR/$PARSE_BINARY_REL"
    if [[ ! -f "$PARSE_BINARY" ]]; then
        echo "parse binary not found: $PARSE_BINARY" >&2
        exit 1
    fi

    run_parse_benchmark "$PARSE_BINARY" "$PARSE_TARGET_NAME"
    write_baseline_json "$RESULT_PATH" "$PARSE_TARGET_NAME" "$PARSE_BINARY"
    print_parse_summary "$PARSE_TARGET_NAME" "$PARSE_BINARY"
    print_query_summary
    log_stage "Finished single-target baseline run"
    echo "Result JSON: $RESULT_PATH"
    exit 0
fi

mapfile -t ALL_PARSE_TARGETS < <(jq -r '.artifacts[] | select(.kind=="fast-parse") | .name' "$MANIFEST_PATH")
if [[ "${#ALL_PARSE_TARGETS[@]}" -eq 0 ]]; then
    echo "no fast-parse artifacts found in manifest: $MANIFEST_PATH" >&2
    exit 1
fi

PRIMARY_PARSE_TARGET=${ALL_PARSE_TARGETS[0]}
for target in "${ALL_PARSE_TARGETS[@]}"; do
    if [[ "$target" == "parse-stress" ]]; then
        PRIMARY_PARSE_TARGET=$target
        break
    fi
done

mapfile -t ORDERED_PARSE_TARGETS < <(ordered_parse_targets "$PRIMARY_PARSE_TARGET" "${ALL_PARSE_TARGETS[@]}")
log_stage "Default mode enabled: running all fast-parse targets (${#ORDERED_PARSE_TARGETS[@]})"
log_stage "Primary parse target: ${PRIMARY_PARSE_TARGET}"

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
additional_args=()
primary_result=""
target_total=${#ORDERED_PARSE_TARGETS[@]}
target_idx=0

for target in "${ORDERED_PARSE_TARGETS[@]}"; do
    target_idx=$((target_idx + 1))
    parse_binary_rel=$(jq -r --arg parse_target "$target" '.artifacts[] | select(.name==$parse_target) | .relative_path' "$MANIFEST_PATH")
    if [[ -z "$parse_binary_rel" || "$parse_binary_rel" == "null" ]]; then
        echo "parse artifact not found in manifest: $target" >&2
        exit 1
    fi

    parse_binary="$CORPUS_DIR/$parse_binary_rel"
    if [[ ! -f "$parse_binary" ]]; then
        echo "parse binary not found: $parse_binary" >&2
        exit 1
    fi

    run_parse_benchmark "$parse_binary" "$target" "[$target_idx/$target_total]"
    target_json="$temp_dir/${target}.json"
    write_baseline_json "$target_json" "$target" "$parse_binary"
    print_parse_summary "$target" "$parse_binary"

    if [[ -z "$primary_result" ]]; then
        primary_result=$target_json
    else
        additional_args+=(--additional "$target_json")
    fi
done

log_stage "Combining per-target baselines into ${RESULT_PATH}"
python3 "$SCRIPT_DIR/combine_baselines.py" \
    --primary "$primary_result" \
    "${additional_args[@]}" \
    --output "$RESULT_PATH"
log_stage "Completed combined baseline output"

print_query_summary
log_stage "Finished full baseline run"
echo "Primary parse target: $PRIMARY_PARSE_TARGET"
echo "Parse targets: ${ORDERED_PARSE_TARGETS[*]}"
echo "Result JSON: $RESULT_PATH"
