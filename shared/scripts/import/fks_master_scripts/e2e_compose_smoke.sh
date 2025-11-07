#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# e2e_compose_smoke.sh
#   Spins up a generated compose (or provided) and checks core service health.
#   Options:
#     -p|--profile <minimal|core|full>   (default: minimal)
#     -g|--generate                      Force (re)generate compose via script
#     -f|--file <compose.yml>            Use existing compose file
#     -t|--timeout <seconds>             Health wait timeout per service (default 60)
#     --no-teardown                      Keep stack running after test
# -----------------------------------------------------------------------------

log(){ echo -e "[e2e] $1"; }
PROFILE=minimal
GENERATE=false
COMPOSE_FILE=""
TIMEOUT=60
TEARDOWN=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile) PROFILE=$2; shift 2;;
    -g|--generate) GENERATE=true; shift;;
    -f|--file) COMPOSE_FILE=$2; shift 2;;
    -t|--timeout) TIMEOUT=$2; shift 2;;
    --no-teardown) TEARDOWN=false; shift;;
    -h|--help) grep '^# ' "$0"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

GEN_SCRIPT="$(dirname "$0")/generate_compose.sh"
if [[ "$GENERATE" = true || -z "$COMPOSE_FILE" ]]; then
  COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.generated.yml}
  log "Generating compose (profile=$PROFILE) -> $COMPOSE_FILE"
  bash "$GEN_SCRIPT" --profile "$PROFILE" --output "$COMPOSE_FILE" --force >/dev/null
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  log "Compose file $COMPOSE_FILE not found; abort"; exit 1; fi

log "Bringing up services (profile=$PROFILE)"
docker compose -f "$COMPOSE_FILE" up -d --build

# Determine expected core services for chosen profile
declare -a SERVICES=(api web)
case $PROFILE in
  core) SERVICES=(api data worker engine transformer web);;
  full) SERVICES=(api data worker engine transformer web redis timescaledb nginx);;
esac

# Maps of ports for health endpoints (only those we actively check)
declare -A PORTS=( [api]=8000 [data]=9001 [engine]=9010 [transformer]=8089 [web]=3000 )

wait_for() {
  local name=$1
  local url=$2
  local t=$TIMEOUT
  local start=$(date +%s)
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "✓ $name healthy ($url) in $(( $(date +%s)-start ))s"; return 0; fi
    if (( $(date +%s)-start >= t )); then
      log "✗ TIMEOUT waiting for $name ($url)"; return 1; fi
    sleep 2
  done
}

FAIL=0
for svc in "${SERVICES[@]}"; do
  port=${PORTS[$svc]:-}
  [[ -z "$port" ]] && continue
  endpoint="http://localhost:${port}/health"
  wait_for "$svc" "$endpoint" || FAIL=1
done

if [[ $FAIL -ne 0 ]]; then
  log "One or more services failed health checks";
  docker compose -f "$COMPOSE_FILE" ps
  docker compose -f "$COMPOSE_FILE" logs --tail=100 || true
  [[ "$TEARDOWN" = true ]] && docker compose -f "$COMPOSE_FILE" down -v || true
  exit 1
fi

log "All health checks passed"

if [[ "$TEARDOWN" = true ]]; then
  log "Tearing down stack"
  docker compose -f "$COMPOSE_FILE" down -v
else
  log "Leaving stack running (compose file: $COMPOSE_FILE)"
fi

log "E2E compose smoke complete"
