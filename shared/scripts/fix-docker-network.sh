#!/usr/bin/env bash
# Shim: fix-docker-network moved to fixit/fix-docker-network.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixit/fix-docker-network.sh"
if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
