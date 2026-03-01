#!/usr/bin/env bash
set -euo pipefail

# GhostScope AI-agent e2e entrypoint.
# Priority:
# 1) e2e runner service (HTTP)
# 2) local CI-equivalent commands fallback

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

SERVICE_URL="${E2E_SERVICE_URL:-http://127.0.0.1:8788}"
USE_SERVICE="${E2E_USE_SERVICE:-1}"
SERVICE_TOKEN="${E2E_SERVICE_TOKEN:-}"
E2E_SUDO="${E2E_SUDO:-1}"
E2E_REPO_DIR="${E2E_REPO_DIR:-}"
E2E_TEST_CASE="${E2E_TEST_CASE:-}"
POLL_INTERVAL="${E2E_POLL_INTERVAL:-5}"
MAX_WAIT_SEC="${E2E_MAX_WAIT_SEC:-7200}"
LOG_TAIL="${E2E_LOG_TAIL:-160}"

if [[ -z "${LLVM_SYS_181_PREFIX:-}" ]]; then
  export LLVM_SYS_181_PREFIX="/usr/lib/llvm-18"
fi

CARGO_BIN=""

is_true() {
  local v="${1:-}"
  case "${v,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

json_bool() {
  if is_true "$1"; then
    printf 'true'
  else
    printf 'false'
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

json_get() {
  local key="$1"
  python3 -c '
import json
import sys
key = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
value = data.get(key)
print("" if value is None else value)
' "$key"
}

print_service_log_tail() {
  local job_id="$1"
  local response
  local auth_args=()
  if [[ -n "$SERVICE_TOKEN" ]]; then
    auth_args=(-H "X-Auth-Token: $SERVICE_TOKEN")
  fi
  if ! response="$(curl -fsS "${auth_args[@]}" "${SERVICE_URL}/runs/${job_id}/log?tail=${LOG_TAIL}")"; then
    echo "[e2e] warning: failed to fetch log tail for ${job_id}" >&2
    return
  fi

  echo "[e2e] ===== log tail (last ${LOG_TAIL}) for job ${job_id} ====="
  python3 -c '
import json
import sys
try:
    data = json.load(sys.stdin)
except Exception:
    print("<invalid log response>")
    raise SystemExit(0)
for line in data.get("lines", []):
    print(line)
' <<<"$response"
  echo "[e2e] ===== end log tail ====="
}

run_local_ci() {
  require_cmd cargo
  CARGO_BIN="$(command -v cargo)"

  local repo_dir
  if [[ -n "$E2E_REPO_DIR" ]]; then
    repo_dir="$E2E_REPO_DIR"
  else
    repo_dir="$DEFAULT_REPO_DIR"
  fi

  if [[ ! -d "$repo_dir" || ! -f "$repo_dir/Cargo.toml" ]]; then
    echo "[e2e] invalid E2E_REPO_DIR (Cargo.toml not found): $repo_dir" >&2
    return 2
  fi

  local build_no_run_cmd=("$CARGO_BIN" test --no-run --all-features)
  local run_test_cmd=("$CARGO_BIN" test --all-features)
  if [[ -n "$E2E_TEST_CASE" ]]; then
    build_no_run_cmd+=("$E2E_TEST_CASE")
    run_test_cmd+=("$E2E_TEST_CASE")
  fi

  echo "[e2e] service unavailable or disabled, running local CI-equivalent commands"
  echo "[e2e] repo_dir=${repo_dir} test_case=${E2E_TEST_CASE:-<all>}"
  echo "[e2e] LLVM_SYS_181_PREFIX=${LLVM_SYS_181_PREFIX}"

  (
    cd "$repo_dir"
    "${build_no_run_cmd[@]}"
    "$CARGO_BIN" build -p dwarf-tool

    if is_true "$E2E_SUDO" && [[ "$(id -u)" -ne 0 ]]; then
      echo "[e2e] running final step with sudo"
      sudo -E "${run_test_cmd[@]}"
    else
      echo "[e2e] running final step without sudo"
      "${run_test_cmd[@]}"
    fi
  )
}

run_service_ci() {
  require_cmd curl
  require_cmd python3

  local auth_args=()
  if [[ -n "$SERVICE_TOKEN" ]]; then
    auth_args=(-H "X-Auth-Token: $SERVICE_TOKEN")
  fi

  if ! curl -fsS "${SERVICE_URL}/health" >/dev/null; then
    return 10
  fi

  local post_body
  post_body="$(
    E2E_SUDO_BOOL="$(json_bool "$E2E_SUDO")" \
    E2E_REPO_DIR="$E2E_REPO_DIR" \
    E2E_TEST_CASE="$E2E_TEST_CASE" \
    python3 -c '
import json
import os

payload = {"sudo": os.environ.get("E2E_SUDO_BOOL", "false") == "true"}
repo_dir = os.environ.get("E2E_REPO_DIR", "").strip()
test_case = os.environ.get("E2E_TEST_CASE", "").strip()

if repo_dir:
    payload["repo"] = repo_dir
if test_case:
    payload["test_case"] = test_case

print(json.dumps(payload))
'
  )"

  local submit_resp
  submit_resp="$(curl -fsS -X POST "${auth_args[@]}" \
    -H 'Content-Type: application/json' \
    -d "$post_body" \
    "${SERVICE_URL}/runs")"

  local job_id submit_status submit_repo submit_case
  job_id="$(json_get id <<<"$submit_resp")"
  submit_status="$(json_get status <<<"$submit_resp")"
  submit_repo="$(json_get repo <<<"$submit_resp")"
  submit_case="$(json_get test_case <<<"$submit_resp")"

  if [[ -z "$job_id" ]]; then
    echo "[e2e] failed to parse job id from service response: $submit_resp" >&2
    return 11
  fi

  echo "[e2e] submitted job_id=${job_id} status=${submit_status} sudo=$(json_bool "$E2E_SUDO") repo=${submit_repo:-<default>} test_case=${submit_case:-<all>}"

  local started_at now elapsed
  started_at="$(date +%s)"

  while true; do
    local resp st ec
    resp="$(curl -fsS "${auth_args[@]}" "${SERVICE_URL}/runs/${job_id}")"
    st="$(json_get status <<<"$resp")"
    ec="$(json_get exit_code <<<"$resp")"

    echo "[e2e] job=${job_id} status=${st} exit_code=${ec}"

    if [[ "$st" == "succeeded" ]]; then
      print_service_log_tail "$job_id"
      return 0
    fi

    if [[ "$st" == "failed" ]]; then
      print_service_log_tail "$job_id"
      if [[ -n "$ec" && "$ec" != "None" ]]; then
        return "$ec"
      fi
      return 1
    fi

    now="$(date +%s)"
    elapsed="$(( now - started_at ))"
    if (( elapsed > MAX_WAIT_SEC )); then
      echo "[e2e] timeout waiting for job ${job_id} (> ${MAX_WAIT_SEC}s)" >&2
      print_service_log_tail "$job_id"
      return 124
    fi

    sleep "$POLL_INTERVAL"
  done
}

main() {
  echo "[e2e] entrypoint: scripts/e2e_runner/run_e2e_runner.sh"
  echo "[e2e] service=${SERVICE_URL} use_service=${USE_SERVICE} e2e_sudo=${E2E_SUDO} repo=${E2E_REPO_DIR:-$DEFAULT_REPO_DIR} test_case=${E2E_TEST_CASE:-<all>}"

  if is_true "$USE_SERVICE"; then
    run_service_ci
    local rc=$?
    if [[ "$rc" -eq 0 ]]; then
      echo "[e2e] completed via service"
      return 0
    fi

    # Fallback only when service path itself is unavailable/broken.
    # If service executed tests and returned test failure, propagate it.
    if [[ "$rc" -eq 10 || "$rc" -eq 11 ]]; then
      echo "[e2e] service path unavailable (rc=${rc}), fallback to local" >&2
    else
      echo "[e2e] service executed run and failed (rc=${rc}), not falling back" >&2
      return "$rc"
    fi
  fi

  run_local_ci
  echo "[e2e] completed via local fallback"
}

main "$@"
