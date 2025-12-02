#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[auth] Stopping existing containers..."
docker compose down

echo "[auth] Rebuilding images..."
docker compose build

echo "[auth] Starting containers in detached mode..."
docker compose up -d
