#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-ghostscope-dwarf-perf-builder:local}"

docker build \
  -f "$REPO_DIR/docker/dwarf-perf-builder/Dockerfile" \
  -t "$IMAGE_NAME" \
  "$REPO_DIR"

echo "built image: $IMAGE_NAME"
