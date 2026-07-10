#!/usr/bin/env bash
set -euo pipefail

REPO="swananan/ghostscope"
BIN_NAME="ghostscope"
DEFAULT_OS="$(uname -s)"
DEFAULT_ARCH="$(uname -m)"
USER_DEFAULT_PREFIX=""
if [[ -n "${HOME:-}" ]]; then
  USER_DEFAULT_PREFIX="$HOME/.ghostscope"
fi
DEFAULT_PREFIX="${USER_DEFAULT_PREFIX:-/usr/local}"
DEFAULT_VERSION="latest"
INSTALL_SOURCE="release"
EXTRACTED_ASSET_DIR=""
DEBUG="${DEBUG:-0}"

usage() {
cat <<'EOF'
Install GhostScope from GitHub releases or build it from source.

Usage: install.sh [options]

Options:
  --prefix DIR          Installation prefix (default: ~/.ghostscope or PREFIX env)
  --destdir DIR         Optional staging directory prepended to installation paths
  --version VER         Release tag or semver (default: latest)
  --arch ARCH           Target architecture: x86_64/amd64 only (default: host uname -m)
  --from-source         Build with cargo instead of downloading a release
  --profile NAME        Cargo profile when using --from-source (release|debug)
  --skip-config         Do not create ~/.ghostscope/config.toml
  --config-template FILE
                        Use a custom config template (default: repository config.toml)
  -h, --help            Show this message and exit

Environment:
  PREFIX                Alternative way to set the installation prefix
  DESTDIR               Alternative way to set the staging directory
  GITHUB_TOKEN          Personal access token to increase GitHub API limits
EOF
}

log() {
  echo "==> $*" >&2
}

debug_log() {
  if [[ "$DEBUG" == "1" ]]; then
    echo "::: $*" >&2
  fi
}

expand_path() {
  local raw="$1"
  if [[ "$raw" == "~" ]]; then
    if [[ -n "${HOME:-}" ]]; then
      printf '%s\n' "$HOME"
    else
      printf '%s\n' "$raw"
    fi
    return
  fi
  if [[ "$raw" == "~/"* ]]; then
    if [[ -n "${HOME:-}" ]]; then
      printf '%s/%s\n' "$HOME" "${raw:2}"
    else
      printf '%s\n' "$raw"
    fi
    return
  fi
  printf '%s\n' "$raw"
}

cleanup() {
  if [[ -n "${TMPDIR_CREATED:-}" ]]; then
    rm -rf "$TMPDIR_CREATED"
  fi
}

trap cleanup EXIT
TMPDIR_CREATED=""

ensure_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' not found" >&2
    exit 1
  fi
}

github_api_request() {
  ensure_command curl
  local endpoint="$1"
  local url="https://api.github.com/repos/${REPO}${endpoint}"
  local headers=(-fsSL "-H" "Accept: application/vnd.github+json" "-H" "User-Agent: ghostscope-installer")
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    headers+=("-H" "Authorization: Bearer ${GITHUB_TOKEN}" "-H" "X-GitHub-Api-Version: 2022-11-28")
  fi
  local response
  if ! response="$(curl "${headers[@]}" "$url" 2>/dev/null)"; then
    debug_log "curl request failed for ${url}"
    return 1
  fi
  printf '%s\n' "$response"
}

map_arch() {
  # Normalize the only architecture currently supported by GhostScope.
  local arch="$1"
  case "$arch" in
    x86_64|amd64) echo "x86_64" ;;
    *)
      echo "error: unsupported architecture '$arch'; GhostScope currently supports only x86_64 (amd64)" >&2
      return 1
      ;;
  esac
}

ensure_supported_os() {
  local os="$1"
  case "$os" in
    Linux) return 0 ;;
    *)
      echo "error: unsupported operating system '$os'; GhostScope currently supports only Linux x86_64" >&2
      return 1
      ;;
  esac
}

release_tag_from_url() {
  local url="$1"
  case "$url" in
    *"/releases/tag/"*)
      printf '%s\n' "${url##*/}"
      ;;
    *)
      return 1
      ;;
  esac
}

latest_release_tag_from_feed() {
  ensure_command curl
  ensure_command python3

  local feed_url="https://github.com/${REPO}/releases.atom"
  local feed
  if ! feed="$(curl -fsSL "$feed_url" 2>/dev/null)"; then
    debug_log "curl request failed for ${feed_url}"
    return 1
  fi

  python3 - "$feed" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

feed = sys.argv[1]
ns = {"atom": "http://www.w3.org/2005/Atom"}

try:
    root = ET.fromstring(feed)
except ET.ParseError:
    raise SystemExit(1)

for entry in root.findall("atom:entry", ns):
    link = entry.find("atom:link[@rel='alternate']", ns)
    href = link.get("href", "") if link is not None else ""
    match = re.search(r"/releases/tag/([^/?#]+)$", href)
    if match:
        print(match.group(1))
        raise SystemExit(0)

raise SystemExit(1)
PY
}

release_asset_names_for_tag() {
  local tag="$1"
  local arch="$2"
  local aliases=("$arch")

  case "$arch" in
    x86_64) aliases+=("amd64") ;;
    amd64) aliases+=("x86_64") ;;
  esac

  local alias
  for alias in "${aliases[@]}"; do
    printf '%s\n' \
      "${BIN_NAME}-${tag}-${alias}-linux.tar.gz" \
      "${BIN_NAME}-${tag}-${alias}-unknown-linux-gnu.tar.gz" \
      "${BIN_NAME}-${tag}-${alias}.tar.gz"
  done | awk '!seen[$0]++'
}

resolve_release_asset_from_tag() {
  local tag="$1"
  local arch="$2"

  ensure_command curl

  local asset_name
  while IFS= read -r asset_name; do
    [[ -n "$asset_name" ]] || continue
    local download_url="https://github.com/${REPO}/releases/download/${tag}/${asset_name}"
    debug_log "Trying direct release asset URL: $download_url"
    if curl -fsSIL -o /dev/null "$download_url" 2>/dev/null; then
      printf '%s\n%s\n%s\n' "$tag" "$download_url" "$asset_name"
      return 0
    fi
  done < <(release_asset_names_for_tag "$tag" "$arch")

  return 1
}

resolve_release_asset() {
  local version="$1"
  local arch="$2"
  local json=""
  local endpoint=""
  local tag=""
  local direct_result=""

  debug_log "Resolving release for version='$version' arch='$arch'"
  if [[ "$version" == "latest" ]]; then
    log "Fetching latest release metadata"
    endpoint="/releases/latest"
    json="$(github_api_request "$endpoint")" || true
    debug_log "GET /releases/latest returned length=${#json}"
    if [[ -z "$json" ]]; then
      log "Latest release API unavailable; checking redirect"
      ensure_command curl
      local redirect_url
      if redirect_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"; then
        tag="$(release_tag_from_url "$redirect_url" || true)"
        debug_log "Redirect latest -> tag=$tag"
        if [[ -n "$tag" && "$tag" != "latest" ]]; then
          if direct_result="$(resolve_release_asset_from_tag "$tag" "$arch")"; then
            log "Using release tag $tag from redirect"
            printf '%s' "$direct_result"
            return 0
          fi
        fi
      fi
      if [[ -z "$json" ]]; then
        log "Checking releases feed for latest tag"
        tag="$(latest_release_tag_from_feed || true)"
        debug_log "Feed latest -> tag=$tag"
        if [[ -n "$tag" ]]; then
          if direct_result="$(resolve_release_asset_from_tag "$tag" "$arch")"; then
            log "Using release tag $tag from Atom feed"
            printf '%s' "$direct_result"
            return 0
          fi
        fi
      fi
      if [[ -z "$json" ]]; then
        log "Checking recent releases for pre-release"
        local releases_json=""
        releases_json="$(github_api_request "/releases?per_page=20")" || true
        debug_log "GET /releases?per_page=20 returned length=${#releases_json}"
        if [[ -n "$releases_json" ]]; then
          log "Latest stable release unavailable; falling back to most recent release (including pre-releases)"
          ensure_command python3
          local first_release=""
          if first_release="$(
            python3 - "$releases_json" <<'PY'
import json, sys

payload = json.loads(sys.argv[1])
for item in payload:
    if isinstance(item, dict):
        print(json.dumps(item))
        break
else:
    raise SystemExit(1)
PY
          )"; then
            if [[ -n "$first_release" ]]; then
              json="$first_release"
            fi
          fi
        fi
      fi
    fi
  else
    local candidates=()
    candidates+=("/releases/tags/$version")
    if [[ "$version" != v* ]]; then
      candidates=("/releases/tags/v$version" "${candidates[@]}")
    fi
    for endpoint in "${candidates[@]}"; do
      if json="$(github_api_request "$endpoint")"; then
        break
      fi
    done
    if [[ -z "$json" ]]; then
      local candidate_tags=("$version")
      if [[ "$version" != v* ]]; then
        candidate_tags=("v$version" "${candidate_tags[@]}")
      fi
      for tag in "${candidate_tags[@]}"; do
        if direct_result="$(resolve_release_asset_from_tag "$tag" "$arch")"; then
          log "Using direct release asset URL for tag $tag"
          printf '%s' "$direct_result"
          return 0
        fi
      done
    fi
  fi

  if [[ -z "$json" ]]; then
    echo "error: unable to fetch release metadata for version '$version'" >&2
    if [[ "$version" != "latest" && "$version" != v* ]]; then
      echo "       hint: try prefixing the version with 'v', e.g. --version v${version}" >&2
    fi
    return 1
  fi

  ensure_command python3
  debug_log "Parsing release JSON snippet (length=${#json})"
  local result
  if ! result="$(
    python3 - "$arch" "$json" <<'PY'
import json, sys

arch = sys.argv[1]
payload = json.loads(sys.argv[2])
tag = payload.get("tag_name")
if not tag:
    print("error: release payload missing tag_name", file=sys.stderr)
    sys.exit(1)

assets = payload.get("assets") or []
if not assets:
    print(f"error: release {tag!r} does not contain any downloadable assets", file=sys.stderr)
    sys.exit(1)

aliases = {arch}
if arch == "x86_64":
    aliases.add("amd64")
elif arch == "amd64":
    aliases.add("x86_64")

patterns = []
for alias in aliases:
    patterns.extend([
        f"-{alias}-linux.tar.gz",
        f"-{alias}-unknown-linux-gnu.tar.gz",
        f"-{alias}.tar.gz",
        f"{alias}.tar.gz",
    ])

chosen = None
for asset in assets:
    name = asset.get("name") or ""
    url = asset.get("browser_download_url")
    if not url or not name:
        continue
    for pattern in patterns:
        if pattern in name:
            chosen = asset
            break
    if chosen:
        break

if not chosen:
    candidates = ", ".join(a.get("name", "<unnamed>") for a in assets)
    print(
        f"error: no release asset matched supported architecture '{arch}'. "
        f"Available assets: {candidates}",
        file=sys.stderr,
    )
    sys.exit(1)

name = chosen.get("name")
url = chosen.get("browser_download_url")
if not name or not url:
    print("error: selected asset is missing required fields", file=sys.stderr)
    sys.exit(1)

print(tag)
print(url)
print(name)
PY
  )"; then
    return 1
  fi

  echo "$result"
}

download_and_unpack() {
  local download_url="$1"
  local asset_name="$2"

  ensure_command curl
  ensure_command tar

  local tmpdir="$TMPDIR_CREATED"
  if [[ -z "$tmpdir" ]]; then
    tmpdir="$(mktemp -d)"
    TMPDIR_CREATED="$tmpdir"
  fi

  local archive_name="$asset_name"
  if [[ -z "$archive_name" ]]; then
    archive_name="$(basename "$download_url")"
  fi
  debug_log "Resolved download asset: url=$download_url name=$archive_name"
  local archive="$tmpdir/$archive_name"

  log "Downloading ${download_url}"
  if ! curl -fSL --progress-bar -o "$archive" "$download_url"; then
    log "curl progress-bar mode failed; retrying without progress display"
    if ! curl -fSL -o "$archive" "$download_url"; then
      echo "error: failed to download release asset from ${download_url}" >&2
      echo "       hint: verify that the requested version and architecture are published" >&2
      return 1
    fi
  fi

  if [[ ! -f "$archive" ]]; then
    echo "error: failed to download release asset from ${download_url}" >&2
    echo "       hint: verify that the requested version and architecture are published" >&2
    return 1
  fi

  log "Unpacking archive ${archive_name}"
  if ! tar -xzf "$archive" -C "$tmpdir"; then
    echo "error: failed to unpack archive ${archive}" >&2
    return 1
  fi

  EXTRACTED_ASSET_DIR="$tmpdir"
  debug_log "Archive extracted into $tmpdir"

  local bin_path
  bin_path="$(find "$tmpdir" -maxdepth 3 -type f -name "$BIN_NAME" -perm -u+x | head -n 1 || true)"
  if [[ -z "$bin_path" ]]; then
    echo "error: binary '$BIN_NAME' not found in unpacked archive" >&2
    echo "       contents extracted to: $tmpdir" >&2
    return 1
  fi

  echo "$bin_path"
}

build_from_source() {
  local profile="$1"
  local project_root="$2"

  ensure_command cargo

  log "Building GhostScope from source (profile: $profile)"
  local cargo_flags=("--locked" "-p" "$BIN_NAME")
  if [[ "$profile" == "release" ]]; then
    cargo_flags+=("--release")
  fi

  (cd "$project_root" && cargo build "${cargo_flags[@]}")

  local target_dir="target/$profile"
  [[ "$profile" == "release" ]] && target_dir="target/release"
  local bin_path="$project_root/$target_dir/$BIN_NAME"

  if [[ ! -x "$bin_path" ]]; then
    echo "error: expected binary not found at $bin_path" >&2
    exit 1
  fi

  echo "$bin_path"
}

compute_install_path() {
  local prefix="$1"
  local destdir="$2"

  local prefix_dir="${prefix%/}"
  local dest_dir="${destdir%/}"

  if [[ -z "$prefix_dir" ]]; then
    prefix_dir="/"
  elif [[ "${prefix_dir:0:1}" != "/" ]]; then
    echo "warning: prefix '$prefix_dir' is not an absolute path" >&2
  fi

  local install_root="$prefix_dir"
  if [[ -n "$dest_dir" ]]; then
    install_root="${dest_dir}${prefix_dir}"
  fi

  echo "$install_root/bin/$BIN_NAME"
}

install_binary() {
  ensure_command install
  local source="$1"
  local destination="$2"
  log "Installing $BIN_NAME to $destination"
  install -Dm755 "$source" "$destination"
}

install_config() {
  local project_root="$1"
  local config_template="$2"
  local destdir="$3"
  local skip_config="$4"

  if [[ "$skip_config" == "true" ]]; then
    log "Skipping config installation (requested)"
    return
  fi

  if [[ -n "$destdir" ]]; then
    log "Skipping config installation because DESTDIR is set (user configs are not staged)"
    return
  fi

  if [[ -z "${HOME:-}" ]]; then
    echo "warning: HOME is not set; skipping config creation" >&2
    return
  fi

  local template_path=""

  if [[ -n "$config_template" ]]; then
    template_path="$config_template"
  elif [[ "$INSTALL_SOURCE" == "release" && -n "$EXTRACTED_ASSET_DIR" ]]; then
    local release_config
    release_config="$(find "$EXTRACTED_ASSET_DIR" -maxdepth 3 -type f -name "config.toml" | head -n 1 || true)"
    if [[ -n "$release_config" ]]; then
      template_path="$release_config"
      log "Using config template from release archive: $template_path"
    fi
  fi

  if [[ -z "$template_path" ]]; then
    template_path="$project_root/config.toml"
  fi

  if [[ ! -f "$template_path" ]]; then
    echo "warning: config template not found at $template_path; skipping" >&2
    return
  fi

  local config_dir="$HOME/.ghostscope"
  local config_path="$config_dir/config.toml"

  if [[ -f "$config_path" ]]; then
    log "Config already exists at $config_path (leaving untouched)"
    return
  fi

  log "Creating default config at $config_path"
  mkdir -p "$config_dir"
  install -Dm644 "$template_path" "$config_path"
}

print_path_hint() {
  local prefix="$1"
  local destdir="$2"

  if [[ -n "${HOME:-}" && -z "$destdir" ]]; then
    local default_prefix="$HOME/.ghostscope"
    if [[ "$prefix" == "$default_prefix" ]]; then
      local bin_dir="$default_prefix/bin"
      cat <<EOF
GhostScope is now installed under $bin_dir.
Add one of the following lines to your shell config so \`ghostscope\` stays on PATH:
  Bash: echo 'export PATH="\$HOME/.ghostscope/bin:\$PATH"' >> ~/.bashrc
  Zsh : echo 'export PATH="\$HOME/.ghostscope/bin:\$PATH"' >> ~/.zshrc
  Fish: echo 'set -Ux PATH \$HOME/.ghostscope/bin \$PATH' >> ~/.config/fish/config.fish

Restart your shell and run \`ghostscope\` to verify.
EOF
      return
    fi
  fi

  cat <<EOF
GhostScope is installed under $prefix.
For system-wide usage consider copying your config to /etc/ghostscope/config.toml
or run ghostscope with \`--config /path/to/config.toml\` when using sudo.
EOF
}

main() {
  local prefix="${PREFIX:-$DEFAULT_PREFIX}"
  local destdir="${DESTDIR:-}"
  local version="$DEFAULT_VERSION"
  local arch="$DEFAULT_ARCH"
  local from_source="false"
  local profile="release"
  local skip_config="false"
  local config_template=""

  INSTALL_SOURCE="release"
  EXTRACTED_ASSET_DIR=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix)
        [[ $# -gt 1 ]] || { echo "error: --prefix requires a value" >&2; usage; return 1; }
        prefix="$2"
        shift 2
        ;;
      --destdir)
        [[ $# -gt 1 ]] || { echo "error: --destdir requires a value" >&2; usage; return 1; }
        destdir="$2"
        shift 2
        ;;
      --version)
        [[ $# -gt 1 ]] || { echo "error: --version requires a value" >&2; usage; return 1; }
        version="$2"
        shift 2
        ;;
      --arch)
        [[ $# -gt 1 ]] || { echo "error: --arch requires a value" >&2; usage; return 1; }
        arch="$2"
        shift 2
        ;;
      --from-source)
        from_source="true"
        shift
        ;;
      --profile)
        [[ $# -gt 1 ]] || { echo "error: --profile requires a value" >&2; usage; return 1; }
        profile="$2"
        shift 2
        ;;
      --skip-config)
        skip_config="true"
        shift
        ;;
      --config-template)
        [[ $# -gt 1 ]] || { echo "error: --config-template requires a value" >&2; usage; return 1; }
        config_template="$2"
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        echo "error: unknown option '$1'" >&2
        usage
        return 1
        ;;
    esac
  done

  prefix="$(expand_path "$prefix")"
  if [[ -n "$destdir" ]]; then
    destdir="$(expand_path "$destdir")"
  fi
  if [[ -n "$config_template" ]]; then
    config_template="$(expand_path "$config_template")"
  fi

  if [[ "$from_source" == "true" ]]; then
    if [[ "$profile" != "release" && "$profile" != "debug" ]]; then
      echo "error: unsupported profile '$profile' (use release or debug)" >&2
      return 1
    fi
  fi

  if ! ensure_supported_os "$DEFAULT_OS"; then
    return 1
  fi

  local host_arch
  if ! host_arch="$(map_arch "$DEFAULT_ARCH")"; then
    return 1
  fi
  local mapped_arch
  if ! mapped_arch="$(map_arch "$arch")"; then
    return 1
  fi
  if [[ "$host_arch" != "$mapped_arch" ]]; then
    echo "error: cross-architecture installation is not supported (host=$host_arch requested=$mapped_arch)" >&2
    return 1
  fi

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local project_root
  project_root="$(cd "$script_dir/.." && pwd)"

  local bin_path
  if [[ "$from_source" == "true" ]]; then
    INSTALL_SOURCE="source"
    bin_path="$(build_from_source "$profile" "$project_root")"
  else
    local release_info
    if ! release_info="$(resolve_release_asset "$version" "$mapped_arch")"; then
      return 1
    fi
    local resolved_tag=""
    local download_url=""
    local asset_name=""
    local release_fields=()
    mapfile -t release_fields <<<"$release_info"
    local field_count="${#release_fields[@]}"
    while (( field_count > 0 )) && [[ -z "${release_fields[field_count-1]}" ]]; do
      unset "release_fields[field_count-1]"
      field_count=$((field_count - 1))
    done
    if (( field_count >= 1 )); then
      resolved_tag="${release_fields[0]}"
    fi
    if (( field_count >= 2 )); then
      download_url="${release_fields[1]}"
    fi
    if (( field_count >= 3 )); then
      asset_name="${release_fields[2]}"
    fi

    debug_log "Resolved release fields: count=${field_count} tag=${resolved_tag} url=${download_url} asset=${asset_name}"

    if [[ -z "$download_url" || -z "$asset_name" ]]; then
      echo "error: internal error resolving release asset (download_url or asset_name missing)" >&2
      return 1
    fi
    if ! bin_path="$(download_and_unpack "$download_url" "$asset_name")"; then
      return 1
    fi
    version="$resolved_tag"
    log "Using release tag $version (arch: $mapped_arch, asset: $asset_name)"
  fi

  local install_path
  install_path="$(compute_install_path "$prefix" "$destdir")"
  install_binary "$bin_path" "$install_path"

  install_config "$project_root" "$config_template" "$destdir" "$skip_config"

  log "GhostScope installation complete."
  log "Binary installed at: $install_path"
  if [[ "$skip_config" != "true" && -z "$destdir" && -n "${HOME:-}" ]]; then
    log "User config location: $HOME/.ghostscope/config.toml"
  fi

  print_path_hint "$prefix" "$destdir"
}

main "$@"
