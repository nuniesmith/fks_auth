#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
log(){ echo -e "[integration] $1"; }
FAILURES=()

SKIP_COMPOSE=false
PROFILE=minimal

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-compose) SKIP_COMPOSE=true; shift;;
    --profile) PROFILE=$2; shift 2;;
    -h|--help) echo "Usage: $0 [--skip-compose] [--profile minimal|core|full]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

log "Updating submodules recursively" 
git submodule update --init --recursive --jobs 8

check(){
  local desc="$1"; shift
  if "$@"; then
    log "✅ $desc"
  else
    log "❌ $desc"
    FAILURES+=("$desc")
  fi
}

# Rust services (cargo check)
RUST_SERVICES=(fks_nodes fks_execution fks_docker_builder fks_config)
for svc in "${RUST_SERVICES[@]}"; do
  if [ -d "../$svc" ]; then
    log "cargo check $svc"
    if ! (cd "../$svc" && cargo check --quiet); then FAILURES+=("cargo check $svc"); fi
  fi
done

# Python services (pytest)
PY_SERVICES=(fks_api fks_engine fks_worker fks_training fks_transformer fks_data)
for svc in "${PY_SERVICES[@]}"; do
  if [ -d "../$svc" ]; then
    log "pytest $svc"
    if ! (cd "../$svc" && if [ -f requirements.txt ]; then pip install -q -r requirements.txt; fi; python -m pytest -q); then
      FAILURES+=("pytest $svc")
    fi
  fi
done

# Web build
if [ -d ../fks_web ]; then
  log "web build"
  if command -v pnpm >/dev/null 2>&1; then
    if ! (cd ../fks_web && pnpm install --frozen-lockfile && pnpm build); then FAILURES+=("web build"); fi
  else
    if ! (cd ../fks_web && npm install --no-audit --no-fund && npm run build); then FAILURES+=("web build"); fi
  fi
fi

# API smoke (start uvicorn briefly if possible)
if [ -d ../fks_api/src/fks_api ]; then
  log "API smoke test"
  (cd ../fks_api/src && nohup python -m fks_api.fastapi_main >/tmp/fks_api_smoke.log 2>&1 & echo $! > /tmp/fks_api_smoke.pid || true)
  sleep 3
  if command -v curl >/dev/null 2>&1; then
    if ! curl -fsS http://127.0.0.1:8000/health >/dev/null; then FAILURES+=("api health endpoint"); fi
  fi
  if [ -f /tmp/fks_api_smoke.pid ]; then kill $(cat /tmp/fks_api_smoke.pid) 2>/dev/null || true; fi
fi

if [[ "$SKIP_COMPOSE" = false ]]; then
  log "Compose smoke (profile=$PROFILE)"
  if ! bash "$ROOT_DIR/scripts/e2e_compose_smoke.sh" --profile "$PROFILE" --generate --timeout 40; then
    FAILURES+=("compose smoke ($PROFILE)")
  fi
fi

log "Summary"
if [ ${#FAILURES[@]} -eq 0 ]; then
  log "All integration checks passed"
  exit 0
else
  for f in "${FAILURES[@]}"; do log "FAIL: $f"; done
  exit 1
fi
