#!/usr/bin/env bash
set -euo pipefail

MODE="link"
FORCE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --copy)
      MODE="copy"
      shift
      ;;
    --link)
      MODE="link"
      shift
      ;;
    --force)
      FORCE="1"
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Install GhostScope shared Codex skill.

Usage:
  ./scripts/e2e/runner/install_codex_skill.sh [--link|--copy] [--force]

Options:
  --link   Install as symlink (default)
  --copy   Install as copied directory
  --force  Replace existing destination if present
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SKILL_NAME="ghostscope-e2e-runner"
SKILL_SRC="$REPO_ROOT/skills/$SKILL_NAME"

if [[ ! -d "$SKILL_SRC" || ! -f "$SKILL_SRC/SKILL.md" ]]; then
  echo "Skill source not found: $SKILL_SRC" >&2
  exit 1
fi

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
DEST_ROOT="$CODEX_HOME/skills"
DEST="$DEST_ROOT/$SKILL_NAME"

mkdir -p "$DEST_ROOT"

if [[ -e "$DEST" || -L "$DEST" ]]; then
  if [[ "$FORCE" != "1" ]]; then
    echo "Destination already exists: $DEST" >&2
    echo "Re-run with --force to replace it." >&2
    exit 1
  fi
  rm -rf "$DEST"
fi

if [[ "$MODE" == "link" ]]; then
  ln -s "$SKILL_SRC" "$DEST"
else
  cp -a "$SKILL_SRC" "$DEST"
fi

echo "Installed skill '$SKILL_NAME' to: $DEST"
echo "Restart Codex to pick up new skills."
