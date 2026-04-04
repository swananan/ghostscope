#!/usr/bin/env bash
set -euo pipefail

MODE="link"
FORCE="0"
INSTALL_CODEX="0"
INSTALL_CLAUDE="0"
EXPLICIT_TARGETS="0"
PRINT_VERSION="0"
SKILL_NAME=""

usage() {
  cat <<'EOF'
Install a shared GhostScope skill into Codex and/or Claude Code personal skill directories.

Usage:
  ./scripts/skills/install_skill.sh <skill-name> [--link|--copy] [--force] [--codex|--claude|--all] [--print-version]

Options:
  --link    Install as symlink (default)
  --copy    Install as copied directory
  --force   Replace an existing installed skill
  --codex   Install into ${CODEX_HOME:-$HOME/.codex}/skills
  --claude  Install into ${CLAUDE_HOME:-$HOME/.claude}/skills
  --all     Install into both Codex and Claude Code skill directories
  --print-version  Print the source skill version and exit

When no target flag is provided, the script auto-detects Codex and Claude Code by
checking CODEX_HOME / CLAUDE_HOME, existing ~/.codex / ~/.claude homes, and the
presence of the codex / claude commands.
EOF
}

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
    --codex)
      INSTALL_CODEX="1"
      EXPLICIT_TARGETS="1"
      shift
      ;;
    --claude)
      INSTALL_CLAUDE="1"
      EXPLICIT_TARGETS="1"
      shift
      ;;
    --all)
      INSTALL_CODEX="1"
      INSTALL_CLAUDE="1"
      EXPLICIT_TARGETS="1"
      shift
      ;;
    --print-version)
      PRINT_VERSION="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$SKILL_NAME" ]]; then
        echo "Unexpected extra positional argument: $1" >&2
        usage >&2
        exit 2
      fi
      SKILL_NAME="$1"
      shift
      ;;
  esac
done

if [[ -z "$SKILL_NAME" ]]; then
  usage >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKILL_SRC="$REPO_ROOT/skills/$SKILL_NAME"
SKILL_VERSION_FILE="$SKILL_SRC/VERSION"
SKILL_VERSION="0.0.0-dev"

if [[ ! -d "$SKILL_SRC" || ! -f "$SKILL_SRC/SKILL.md" ]]; then
  echo "Skill source not found: $SKILL_SRC" >&2
  exit 1
fi

if [[ -f "$SKILL_VERSION_FILE" ]]; then
  SKILL_VERSION="$(tr -d '[:space:]' < "$SKILL_VERSION_FILE")"
fi

if [[ -z "$SKILL_VERSION" ]]; then
  echo "Skill version is empty for: $SKILL_SRC" >&2
  exit 1
fi

if [[ "$PRINT_VERSION" == "1" ]]; then
  printf '%s\n' "$SKILL_VERSION"
  exit 0
fi

if [[ "$EXPLICIT_TARGETS" != "1" ]]; then
  if [[ -n "${CODEX_HOME:-}" || -d "$HOME/.codex" ]] || command -v codex >/dev/null 2>&1; then
    INSTALL_CODEX="1"
  fi
  if [[ -n "${CLAUDE_HOME:-}" || -d "$HOME/.claude" ]] || command -v claude >/dev/null 2>&1; then
    INSTALL_CLAUDE="1"
  fi
fi

if [[ "$INSTALL_CODEX" != "1" && "$INSTALL_CLAUDE" != "1" ]]; then
  echo "Could not detect Codex or Claude Code skill homes." >&2
  echo "Re-run with --codex, --claude, or --all." >&2
  exit 1
fi

install_one() {
  local tool_name="$1"
  local tool_home="$2"
  local dest_root="$tool_home/skills"
  local dest="$dest_root/$SKILL_NAME"
  local state_root="$dest_root/.ghostscope-state"
  local state_file="$state_root/$SKILL_NAME.version"
  local installed_version=""

  mkdir -p "$dest_root"
  mkdir -p "$state_root"

  if [[ -f "$state_file" ]]; then
    installed_version="$(tr -d '[:space:]' < "$state_file")"
  fi

  if [[ "$FORCE" != "1" && ( -e "$dest" || -L "$dest" ) ]]; then
    if [[ -z "$installed_version" ]]; then
      echo "Destination already exists for $tool_name: $dest" >&2
      echo "No managed version metadata was found. Re-run with --force to replace it." >&2
      exit 1
    fi

    if [[ "$installed_version" == "$SKILL_VERSION" ]]; then
      echo "'$SKILL_NAME' for $tool_name is already at version $SKILL_VERSION: $dest"
      return
    fi

    echo "Upgrading '$SKILL_NAME' for $tool_name: $installed_version -> $SKILL_VERSION"
  fi

  if [[ -e "$dest" || -L "$dest" ]]; then
    rm -rf "$dest"
  fi

  if [[ "$MODE" == "link" ]]; then
    ln -s "$SKILL_SRC" "$dest"
  else
    cp -a "$SKILL_SRC" "$dest"
  fi

  printf '%s\n' "$SKILL_VERSION" > "$state_file"
  echo "Installed '$SKILL_NAME' v$SKILL_VERSION for $tool_name at: $dest"
}

if [[ "$INSTALL_CODEX" == "1" ]]; then
  install_one "Codex" "${CODEX_HOME:-$HOME/.codex}"
fi

if [[ "$INSTALL_CLAUDE" == "1" ]]; then
  install_one "Claude Code" "${CLAUDE_HOME:-$HOME/.claude}"
fi

echo "Restart Codex and/or Claude Code to pick up the new skill."
