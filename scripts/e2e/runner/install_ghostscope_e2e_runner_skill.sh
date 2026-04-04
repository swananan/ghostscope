#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
exec "$REPO_ROOT/scripts/skills/install_skill.sh" ghostscope-e2e-runner --codex "$@"
