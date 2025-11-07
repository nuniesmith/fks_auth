#!/usr/bin/env bash
# domains/ssl/manager.sh
# TODO RESTORE: Full SSL certificate lifecycle logic (issue/renew/self-signed, DH params, deploy to nginx) was in legacy root ssl-manager.sh
# Minimal placeholder provides command surface so callers do not break.
set -euo pipefail

show_help(){ cat <<EOF
SSL Manager (placeholder)
Usage: $0 <command>
Commands:
  issue-self    Generate self-signed certs (NOT IMPLEMENTED)
  issue-le      Issue/renew Let's Encrypt certs (NOT IMPLEMENTED)
  renew         Alias of issue-le
  status        Show cert directory summary
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SSL_DIR="$ROOT_DIR/ssl"
mkdir -p "$SSL_DIR"

cmd=${1:-help}
case $cmd in
  status)
    echo "[SSL] Directory: $SSL_DIR"; find "$SSL_DIR" -maxdepth 2 -type f -printf '%P\n' || true ;;
  issue-self|issue-le|renew)
    echo "[TODO] Implement '$cmd' logic (restoration pending)." >&2; exit 3 ;;
  help|--help|-h) show_help ;;
  *) echo "Unknown: $cmd"; show_help; exit 1;;
esac