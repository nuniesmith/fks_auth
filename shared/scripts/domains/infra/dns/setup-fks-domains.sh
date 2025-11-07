#!/usr/bin/env bash
# domains/infra/dns/setup-fks_domains.sh
# TODO RESTORE: DNS + Cloudflare + nginx config generation logic from original setup-fks_domains.sh
set -euo pipefail

case ${1:-plan} in
  plan) echo "[DNS] Would enumerate required records (placeholder)." ;;
  apply) echo "[TODO] Implement Cloudflare API calls to create/update records." ;;
  nginx) echo "[TODO] Emit nginx server block config." ;;
  *) echo "Usage: $0 [plan|apply|nginx]"; exit 1;;
esac