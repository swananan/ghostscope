#!/usr/bin/env bash
set -euo pipefail

MODE="link"
MODE_EXPLICIT="0"
FORCE="0"
INSTALL_CODEX="0"
INSTALL_CLAUDE="0"
EXPLICIT_TARGETS="0"
PRINT_VERSION="0"
SKILL_NAME=""
REPO="${GHOSTSCOPE_SKILL_REPO:-swananan/ghostscope}"
REQUESTED_REF="${GHOSTSCOPE_SKILL_REF:-}"
ARCHIVE_URL_OVERRIDE="${GHOSTSCOPE_SKILL_ARCHIVE_URL:-}"
SKILL_SRC=""
SKILL_SOURCE_KIND=""
SKILL_SOURCE_REF=""
SKILL_VERSION="0.0.0-dev"
TMPDIR_CREATED=""

cleanup() {
  if [[ -n "$TMPDIR_CREATED" && -d "$TMPDIR_CREATED" ]]; then
    rm -rf "$TMPDIR_CREATED"
  fi
}

trap cleanup EXIT

usage() {
  cat <<'EOF'
Install a shared GhostScope skill into Codex and/or Claude Code personal skill directories.

Usage:
  ./scripts/skills/install_skill.sh <skill-name> [--link|--copy] [--force] [--codex|--claude|--all] [--print-version]
  curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/skills/install_skill.sh | bash -s -- <skill-name> [--copy] [--force] [--codex|--claude|--all] [--print-version]

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

Remote mode:
  When the script cannot find a local GhostScope checkout, it downloads the skill
  from the latest GitHub release. If no release is available, it falls back to
  the repository's main branch.

Environment:
  GHOSTSCOPE_SKILL_REPO         Override the GitHub repo (default: swananan/ghostscope)
  GHOSTSCOPE_SKILL_REF          Override the Git ref to download in remote mode
  GHOSTSCOPE_SKILL_ARCHIVE_URL  Override the archive URL in remote mode
EOF
}

log() {
  echo "==> $*" >&2
}

ensure_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found: $cmd" >&2
    exit 1
  fi
}

make_tempdir() {
  if [[ -z "$TMPDIR_CREATED" ]]; then
    TMPDIR_CREATED="$(mktemp -d)"
  fi
}

resolve_latest_release_ref() {
  ensure_command curl

  local redirect_url=""
  local normalized_url=""
  local tag=""

  if redirect_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"; then
    normalized_url="${redirect_url%%[\?#]*}"
    if [[ "$normalized_url" == "https://github.com/${REPO}/releases/tag/"* ]]; then
      tag="${normalized_url##*/}"
    fi
    if [[ -n "$tag" ]]; then
      printf '%s\n' "$tag"
      return 0
    fi
  fi

  printf '%s\n' "main"
}

resolve_local_skill_source() {
  local script_path="${BASH_SOURCE[0]:-}"
  local script_dir=""
  local repo_root=""
  local candidate=""

  if [[ -z "$script_path" || ! -e "$script_path" ]]; then
    return 1
  fi

  script_dir="$(cd "$(dirname "$script_path")" && pwd)"
  repo_root="$(cd "$script_dir/../.." && pwd)"
  candidate="$repo_root/skills/$SKILL_NAME"

  if [[ ! -d "$candidate" || ! -f "$candidate/SKILL.md" ]]; then
    return 1
  fi

  SKILL_SRC="$candidate"
  SKILL_SOURCE_KIND="local"
  SKILL_SOURCE_REF="local-checkout"
  return 0
}

resolve_remote_skill_source() {
  ensure_command curl
  ensure_command tar
  make_tempdir

  local archive_url="$ARCHIVE_URL_OVERRIDE"
  local archive_path="$TMPDIR_CREATED/ghostscope-skill.tar.gz"
  local skill_file=""

  if [[ -z "$archive_url" ]]; then
    if [[ -z "$REQUESTED_REF" ]]; then
      REQUESTED_REF="$(resolve_latest_release_ref)"
    fi
    archive_url="https://codeload.github.com/${REPO}/tar.gz/${REQUESTED_REF}"
  fi

  if [[ -z "$REQUESTED_REF" ]]; then
    REQUESTED_REF="archive-url"
  fi

  log "Downloading '$SKILL_NAME' from ${REPO}@${REQUESTED_REF}"
  curl -fsSL "$archive_url" -o "$archive_path"
  tar -xzf "$archive_path" -C "$TMPDIR_CREATED"

  skill_file="$(find "$TMPDIR_CREATED" -path "*/skills/$SKILL_NAME/SKILL.md" -type f -print -quit)"
  if [[ -z "$skill_file" ]]; then
    echo "Skill source not found in downloaded archive: $SKILL_NAME" >&2
    exit 1
  fi

  SKILL_SRC="$(dirname "$skill_file")"
  SKILL_SOURCE_KIND="remote"
  SKILL_SOURCE_REF="$REQUESTED_REF"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --copy)
      MODE="copy"
      MODE_EXPLICIT="1"
      shift
      ;;
    --link)
      MODE="link"
      MODE_EXPLICIT="1"
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

if ! resolve_local_skill_source; then
  resolve_remote_skill_source
fi

if [[ ! -d "$SKILL_SRC" || ! -f "$SKILL_SRC/SKILL.md" ]]; then
  echo "Skill source not found: $SKILL_SRC" >&2
  exit 1
fi

if [[ "$SKILL_SOURCE_KIND" == "remote" ]]; then
  if [[ "$MODE_EXPLICIT" == "1" && "$MODE" == "link" ]]; then
    echo "--link is only supported when installing from a local GhostScope checkout." >&2
    exit 1
  fi
  if [[ "$MODE_EXPLICIT" != "1" ]]; then
    MODE="copy"
  fi
fi

SKILL_VERSION_FILE="$SKILL_SRC/VERSION"
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

if [[ "$SKILL_SOURCE_KIND" == "remote" ]]; then
  log "Installed from ${REPO}@${SKILL_SOURCE_REF}"
fi

echo "Restart Codex and/or Claude Code to pick up the new skill."
