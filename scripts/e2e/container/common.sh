#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DEFAULT_RUNTIME_IMAGE="ghcr.io/swananan/ghostscope-e2e-runtime@sha256:d5df1b977c38f7a51bbf28b878f2246705a05b83ac6df7cb6be8f8a4de4105f4"
DEFAULT_SMOKE_TESTS=(
  test_invalid_pid_handling
  test_correct_pid_filtering
  test_pid_specificity_with_multiple_processes
)

want_nocapture() {
  case "${CONTAINER_SCRIPT_NOCAPTURE_OVERRIDE:-}" in
    1)
      return 0
      ;;
    0)
      return 1
      ;;
  esac

  case "${E2E_CARGO_NOCAPTURE:-}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

print_container_script_usage() {
  local mode="$1"

  case "$mode" in
    full)
      cat <<EOF
Usage: $0 [--nocapture] [--capture] [cargo-test-args...]

Runs the full ghostscope container e2e suite for the topology wired into this script.
Use --nocapture to append '-- --nocapture' to cargo test.
EOF
      ;;
    topology)
      cat <<EOF
Usage: $0 [--nocapture] [--capture] [test-case]

Runs the topology-focused ghostscope container e2e test wired into this script.
Use --nocapture to append '-- --nocapture' to cargo test.
EOF
      ;;
    smoke)
      cat <<EOF
Usage: $0 [--nocapture] [--capture] [test-case...]

Runs the smoke ghostscope container e2e cases wired into this script.
Use --nocapture to append '-- --nocapture' to cargo test.
EOF
      ;;
    matrix)
      cat <<EOF
Usage: $0 [--nocapture] [--capture]

Runs the primary container e2e matrix:
  host -> docker-private (full)
  docker-private -> same docker-private (full)
  docker-host -> same docker-host (smoke)
EOF
      ;;
    *)
      echo "unknown container e2e script mode: $mode" >&2
      return 1
      ;;
  esac
}

parse_container_script_args() {
  local mode="$1"
  shift

  CONTAINER_SCRIPT_NOCAPTURE_OVERRIDE=""
  CONTAINER_SCRIPT_SHOW_HELP=0
  CONTAINER_SCRIPT_ARGS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --nocapture|-n)
        CONTAINER_SCRIPT_NOCAPTURE_OVERRIDE=1
        ;;
      --capture)
        CONTAINER_SCRIPT_NOCAPTURE_OVERRIDE=0
        ;;
      --help|-h)
        CONTAINER_SCRIPT_SHOW_HELP=1
        ;;
      --)
        shift
        CONTAINER_SCRIPT_ARGS+=("$@")
        break
        ;;
      *)
        CONTAINER_SCRIPT_ARGS+=("$1")
        ;;
    esac
    shift
  done

  if [[ $CONTAINER_SCRIPT_SHOW_HELP -eq 1 ]]; then
    print_container_script_usage "$mode"
  fi
}

append_cargo_test_runner_args() {
  local -n cargo_args_ref=$1
  shift

  local -a runner_args=("$@")
  if want_nocapture; then
    runner_args+=(--nocapture)
  fi

  if [[ ${#runner_args[@]} -gt 0 ]]; then
    cargo_args_ref+=(-- "${runner_args[@]}")
  fi
}

resolve_cargo_bin() {
  if [[ -n "${CARGO_BIN:-}" && -x "${CARGO_BIN}" ]]; then
    printf '%s\n' "$CARGO_BIN"
    return 0
  fi

  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
    return 0
  fi

  if [[ -n "${SUDO_USER:-}" ]]; then
    local sudo_home
    sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [[ -n "$sudo_home" && -x "$sudo_home/.cargo/bin/cargo" ]]; then
      printf '%s\n' "$sudo_home/.cargo/bin/cargo"
      return 0
    fi
  fi

  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    printf '%s\n' "$HOME/.cargo/bin/cargo"
    return 0
  fi

  echo "failed to locate cargo; set CARGO_BIN explicitly" >&2
  return 1
}

cleanup_e2e_container_session() {
  if [[ -z "${E2E_SANDBOX_SESSION:-}" ]]; then
    return 0
  fi

  local ids
  ids=$(docker ps -aq --filter "label=ghostscope.session=$E2E_SANDBOX_SESSION")
  if [[ -n "$ids" ]]; then
    docker rm -f $ids >/dev/null
  fi
}

init_e2e_container_session() {
  local label="${1:-container-e2e}"
  if [[ -z "${E2E_SANDBOX_SESSION:-}" ]]; then
    export E2E_SANDBOX_SESSION="${label}-$(date +%s)-$$"
    trap cleanup_e2e_container_session EXIT INT TERM
  fi
}

execute_topology_cargo() {
  local ghostscope_sandbox="$1"
  local target_sandbox="$2"
  local target_mode="$3"
  shift 3

  local cargo_bin
  cargo_bin="$(resolve_cargo_bin)"

  local -a prefix=()
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    prefix=(env)
  else
    prefix=(sudo -E env)
  fi

  local -a cmd=(
    "${prefix[@]}"
    PATH="$PATH"
    E2E_SANDBOX_SESSION="$E2E_SANDBOX_SESSION"
    E2E_CONTAINER_IMAGE="${E2E_CONTAINER_IMAGE:-$DEFAULT_RUNTIME_IMAGE}"
    E2E_CHILD_CONTAINER_IMAGE="${E2E_CHILD_CONTAINER_IMAGE:-${E2E_CONTAINER_IMAGE:-$DEFAULT_RUNTIME_IMAGE}}"
    E2E_GHOSTSCOPE_SANDBOX="$ghostscope_sandbox"
    E2E_TARGET_SANDBOX="$target_sandbox"
    E2E_TARGET_MODE="$target_mode"
    "$cargo_bin"
    "$@"
  )

  echo "[container-e2e] ${cmd[*]}"
  (
    cd "$REPO_DIR"
    "${cmd[@]}"
  )
}

build_ghostscope_e2e_prereqs() {
  local cargo_bin
  cargo_bin="$(resolve_cargo_bin)"

  echo "[container-e2e] building ghostscope CLI and dwarf-tool prerequisites"
  (
    cd "$REPO_DIR"
    "$cargo_bin" build -p ghostscope -p dwarf-tool --all-features
  )
}

run_ghostscope_container_full() {
  local ghostscope_sandbox="$1"
  local target_sandbox="$2"
  local target_mode="${3:-same}"
  shift 3 || true

  parse_container_script_args full "$@"
  if [[ $CONTAINER_SCRIPT_SHOW_HELP -eq 1 ]]; then
    return 0
  fi

  init_e2e_container_session "${ghostscope_sandbox}-to-${target_sandbox}-${target_mode}"
  build_ghostscope_e2e_prereqs

  local -a cargo_args=(test -p ghostscope-e2e-tests --tests --all-features)
  if [[ ${#CONTAINER_SCRIPT_ARGS[@]} -gt 0 ]]; then
    cargo_args+=("${CONTAINER_SCRIPT_ARGS[@]}")
  fi
  append_cargo_test_runner_args cargo_args

  echo "[container-e2e] session=$E2E_SANDBOX_SESSION topology=${ghostscope_sandbox}->${target_sandbox} mode=$target_mode"
  execute_topology_cargo "$ghostscope_sandbox" "$target_sandbox" "$target_mode" "${cargo_args[@]}"
}

run_ghostscope_container_topology_case() {
  local ghostscope_sandbox="$1"
  local target_sandbox="$2"
  local target_mode="$3"
  local test_binary="$4"
  local default_test_case="$5"
  shift 5 || true

  parse_container_script_args topology "$@"
  if [[ $CONTAINER_SCRIPT_SHOW_HELP -eq 1 ]]; then
    return 0
  fi

  init_e2e_container_session "${ghostscope_sandbox}-to-${target_sandbox}-${target_mode}"
  build_ghostscope_e2e_prereqs

  local -a cargo_args=(test -p ghostscope-e2e-tests --all-features --test "$test_binary")
  if [[ ${#CONTAINER_SCRIPT_ARGS[@]} -gt 0 ]]; then
    cargo_args+=("${CONTAINER_SCRIPT_ARGS[@]}")
  else
    cargo_args+=("$default_test_case")
  fi
  append_cargo_test_runner_args cargo_args --test-threads=1

  echo "[container-e2e] session=$E2E_SANDBOX_SESSION topology=${ghostscope_sandbox}->${target_sandbox} mode=$target_mode test=${cargo_args[6]:-$default_test_case}"
  execute_topology_cargo "$ghostscope_sandbox" "$target_sandbox" "$target_mode" "${cargo_args[@]}"
}

run_ghostscope_container_smoke() {
  local ghostscope_sandbox="$1"
  local target_sandbox="$2"
  shift 2

  parse_container_script_args smoke "$@"
  if [[ $CONTAINER_SCRIPT_SHOW_HELP -eq 1 ]]; then
    return 0
  fi

  local -a tests=("${CONTAINER_SCRIPT_ARGS[@]}")

  if [[ ${#tests[@]} -eq 0 ]]; then
    tests=("${DEFAULT_SMOKE_TESTS[@]}")
  fi

  init_e2e_container_session "${ghostscope_sandbox}-to-${target_sandbox}-smoke"
  build_ghostscope_e2e_prereqs

  local test_case
  for test_case in "${tests[@]}"; do
    local -a cargo_args=(test -p ghostscope-e2e-tests --all-features --test script_execution "$test_case")
    append_cargo_test_runner_args cargo_args
    echo "[container-e2e] session=$E2E_SANDBOX_SESSION smoke=$test_case topology=${ghostscope_sandbox}->${target_sandbox}"
    execute_topology_cargo \
      "$ghostscope_sandbox" \
      "$target_sandbox" \
      same \
      "${cargo_args[@]}"
  done
}
