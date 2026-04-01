#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
run_ghostscope_container_topology_case   docker-private   docker-private   child-container   container_topology_execution   test_attach_from_private_container_to_child_container_target   "$@"
