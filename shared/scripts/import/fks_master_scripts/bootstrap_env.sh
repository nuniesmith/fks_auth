#!/usr/bin/env bash
set -euo pipefail
# Unified environment bootstrap for FKS services.
# Usage: source scripts/bootstrap_env.sh [--minimal]

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINIMAL=0
if [[ "${1:-}" == "--minimal" ]]; then MINIMAL=1; fi

log(){ echo -e "[bootstrap-env] $1"; }

# Prefer existing .env; create from example or synthesize a basic one
create_env(){
  if [[ -f .env ]]; then log ".env already exists"; return; fi
  if [[ -f .env.example ]]; then cp .env.example .env; log "Created .env from .env.example"; return; fi
  cat > .env <<'EOF'
FKS_ENV=local
FKS_LOG_LEVEL=info
FKS_API_PORT=8000
EOF
  log "Created minimal .env"
}

pushd "$ROOT_DIR" >/dev/null
create_env

# Export key vars
set -a
source .env || true
set +a

# Python shared path (in case sitecustomize not yet picked up)
if [[ -d fks_api/shared/python/src ]]; then
  export PYTHONPATH="fks_api/shared/python/src:${PYTHONPATH:-}"
fi

# Summary
log "Environment bootstrapped (FKS_ENV=${FKS_ENV:-unset})"
popd >/dev/null
