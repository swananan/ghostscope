#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=""
REPO_ROOT=""

if [[ -n "${BASH_SOURCE[0]:-}" && -e "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi

if [[ -n "$REPO_ROOT" && -x "$REPO_ROOT/scripts/skills/install_skill.sh" ]]; then
  exec "$REPO_ROOT/scripts/skills/install_skill.sh" ghostscope-e2e-runner --codex "$@"
fi

INSTALLER_URL="${GHOSTSCOPE_SKILL_INSTALLER_URL:-https://raw.githubusercontent.com/${GHOSTSCOPE_SKILL_REPO:-swananan/ghostscope}/main/scripts/skills/install_skill.sh}"

curl -fsSL "$INSTALLER_URL" \
  | bash -s -- ghostscope-e2e-runner --codex "$@"
