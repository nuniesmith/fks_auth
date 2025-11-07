#!/usr/bin/env bash
set -euo pipefail

# Multi-arch build helper for fks_master
# Usage: ./scripts/buildx-multiarch.sh <image> [--push]

IMAGE=${1:-fks_master:latest}
PUSH=${2:-}

PLATFORMS="linux/amd64,linux/arm64"

echo "[buildx] Ensuring builder exists"
docker buildx inspect fks_builder >/dev/null 2>&1 || docker buildx create --name fks_builder --use

echo "[buildx] Building $IMAGE for $PLATFORMS"
CMD=(docker buildx build --platform "$PLATFORMS" -t "$IMAGE" -f Dockerfile .)
if [[ "$PUSH" == "--push" ]]; then
  CMD+=(--push)
else
  CMD+=(--load)
fi
echo "${CMD[@]}"
"${CMD[@]}"
echo "[buildx] Done"
