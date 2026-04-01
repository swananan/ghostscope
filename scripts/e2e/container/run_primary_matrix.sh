#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

parse_container_script_args matrix "$@"
if [[ $CONTAINER_SCRIPT_SHOW_HELP -eq 1 ]]; then
  exit 0
fi

run_ghostscope_container_full host docker-private same "$@"
run_ghostscope_container_full docker-private docker-private same "$@"
run_ghostscope_container_smoke docker-host docker-host "$@"
