#!/bin/bash
# (Relocated) Tailscale verification placeholder.
set -euo pipefail
echo "[INFO] Checking tailscale status..."; if command -v tailscale >/dev/null 2>&1; then tailscale status || true; else echo "tailscale not installed"; fi
