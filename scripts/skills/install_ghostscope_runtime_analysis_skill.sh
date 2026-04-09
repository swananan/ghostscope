#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=""

if [[ -n "${BASH_SOURCE[0]:-}" && -e "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/install_skill.sh" ]]; then
  exec "$SCRIPT_DIR/install_skill.sh" ghostscope-runtime-analysis "$@"
fi

INSTALLER_URL="${GHOSTSCOPE_SKILL_INSTALLER_URL:-https://raw.githubusercontent.com/${GHOSTSCOPE_SKILL_REPO:-swananan/ghostscope}/main/scripts/skills/install_skill.sh}"

curl -fsSL "$INSTALLER_URL" \
  | bash -s -- ghostscope-runtime-analysis "$@"
