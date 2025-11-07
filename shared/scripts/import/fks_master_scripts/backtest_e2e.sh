#!/usr/bin/env bash
set -euo pipefail
# Orchestrated E2E backtest smoke using generated compose stack.
# Steps:
#   1. Generate & start minimal/core stack (needs api + engine + worker + data when available)
#   2. Wait for API health
#   3. Trigger synthetic backtest (placeholder endpoint)
#   4. Assert response structure / keyword
#   5. Teardown

log(){ echo -e "[backtest-e2e] $1"; }
PROFILE=core
TIMEOUT=80
KEEP=false
ENDPOINT="/api/status"   # Placeholder to be replaced with /backtest/run or similar
EXPECT="operational"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile) PROFILE=$2; shift 2;;
    -t|--timeout) TIMEOUT=$2; shift 2;;
    -e|--endpoint) ENDPOINT=$2; shift 2;;
    -x|--expect) EXPECT=$2; shift 2;;
    --keep) KEEP=true; shift;;
    -h|--help) grep '^#' "$0"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

GEN_SCRIPT="$(dirname "$0")/generate_compose.sh"
COMPOSE_FILE="docker-compose.backtest.yml"

log "Generating compose (profile=$PROFILE)"
bash "$GEN_SCRIPT" --profile "$PROFILE" --output "$COMPOSE_FILE" --force >/dev/null

log "Starting stack"
docker compose -f "$COMPOSE_FILE" up -d --build

wait_for() {
  local name=$1 url=$2 timeout=$3; local start=$(date +%s)
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "✓ $name healthy in $(( $(date +%s)-start ))s"; return 0; fi
    if (( $(date +%s)-start >= timeout )); then
      log "✗ timeout waiting for $name ($url)"; return 1; fi
    sleep 2
  done
}

if ! wait_for api http://127.0.0.1:8000/health "$TIMEOUT"; then
  docker compose -f "$COMPOSE_FILE" logs --tail=120 api || true
  [[ "$KEEP" = false ]] && docker compose -f "$COMPOSE_FILE" down -v || true
  exit 1
fi

log "Trigger placeholder backtest endpoint: $ENDPOINT"
RESP=$(curl -fsS "http://127.0.0.1:8000$ENDPOINT" || true)
log "Response: ${RESP:0:180}"
if [[ "$RESP" != *"$EXPECT"* ]]; then
  log "Expectation '$EXPECT' not found in response";
  [[ "$KEEP" = false ]] && docker compose -f "$COMPOSE_FILE" down -v || true
  exit 1
fi

log "Backtest placeholder succeeded (found '$EXPECT')"

if [[ "$KEEP" = false ]]; then
  log "Tearing down stack"
  docker compose -f "$COMPOSE_FILE" down -v
else
  log "Keeping stack running (compose: $COMPOSE_FILE)"
fi

log "Backtest E2E complete"
