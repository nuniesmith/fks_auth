#!/usr/bin/env bash
# remote-validate.sh
# Purpose: Validate Redis + Authelia stack health on a (remote) desktop host over SSH or locally.
# Usage (local):   ./scripts/maintenance/remote-validate.sh --local
# Usage (remote):  ./scripts/maintenance/remote-validate.sh user@host [/path/to/project] [--auto-fix-overcommit]
# Or from your laptop: bash scripts/maintenance/remote-validate.sh user@desktop
# The script will SSH and perform checks inside the project directory.

set -euo pipefail

PROJECT_PATH="${2:-fks}"  # default relative path after SSH login if provided (adjusted for --local later)
REMOTE_TARGET=""
AUTO_FIX_OVERC=false
LOCAL_MODE=false

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

log() { printf "%b[%s]%b %s\n" "$COLOR_BLUE" "INFO" "$COLOR_RESET" "$1"; }
ok() { printf "%b[%s]%b %s\n" "$COLOR_GREEN" "OK" "$COLOR_RESET" "$1"; }
warn() { printf "%b[%s]%b %s\n" "$COLOR_YELLOW" "WARN" "$COLOR_RESET" "$1"; }
err() { printf "%b[%s]%b %s\n" "$COLOR_RED" "ERR" "$COLOR_RESET" "$1"; }

if [[ $# -eq 0 ]]; then
  cat <<'USAGE'
Remote / Local validation helper for Redis & Authelia.

Examples:
  # Run locally (already on desktop)
  ./scripts/maintenance/remote-validate.sh --local

  # Run against remote desktop
  ./scripts/maintenance/remote-validate.sh user@desktop-host
  ./scripts/maintenance/remote-validate.sh user@desktop-host /home/user/oryx/code/repos/fks

Flags:
  --auto-fix-overcommit  Apply vm.overcommit_memory=1 if not set (requires sudo)
  --local                Run all checks locally without SSH

USAGE
  exit 1
fi

for arg in "$@"; do
  case "$arg" in
    --auto-fix-overcommit) AUTO_FIX_OVERC=true ;;
    --local) LOCAL_MODE=true ;;
  esac
done

if ! $LOCAL_MODE; then
  REMOTE_TARGET="$1"
else
  # In local mode, default to current directory if provided path doesn't exist
  if [[ ! -d "$PROJECT_PATH" ]]; then
    PROJECT_PATH="."
  fi
fi

# Commands to execute remotely or locally
remote_exec() {
  if $LOCAL_MODE; then
    bash -c "$1"
  else
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$REMOTE_TARGET" "$1"
  fi
}

# Build one multi-line script that runs remotely for determinism
REMOTE_SCRIPT=$(cat <<'EOF_REMOTE'
set -euo pipefail
printf "\n=== Step 1: Context =====================================\n"
uname -a || true
id || true

printf "\n=== Step 2: Navigate to project =========================\n"
echo "Target project directory: PROJECT_DIR_PLACEHOLDER"
cd "PROJECT_DIR_PLACEHOLDER" || { echo "Project dir not found"; exit 2; }

printf "\n=== Step 3: Check .env Redis password ===================\n"
if [[ -f .env ]]; then
  REDIS_PW=$(grep -E '^REDIS_PASSWORD=' .env | head -n1 | cut -d'=' -f2- | tr -d '"' ) || true
  if [[ -z "${REDIS_PW}" ]]; then
    echo "REDIS_PASSWORD is empty in .env -> healthcheck will fail.";
  else
    echo "REDIS_PASSWORD present (length ${#REDIS_PW})";
  fi
else
  echo ".env file missing";
fi

printf "\n=== Step 4: System tuning (vm.overcommit_memory) =========\n"
if [[ -r /proc/sys/vm/overcommit_memory ]]; then
  CURRENT=$(cat /proc/sys/vm/overcommit_memory)
  echo "Current vm.overcommit_memory=$CURRENT"
  if [[ "$CURRENT" -ne 1 ]]; then
    echo "Recommend setting to 1 (temporary): sudo sysctl vm.overcommit_memory=1"
  fi
fi

printf "\n=== Step 5: Launch core services ========================\n"
if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    CMD='docker compose'
  elif command -v docker-compose >/dev/null 2>&1; then
    CMD='docker-compose'
  else
    echo "Neither docker compose plugin nor docker-compose found"; exit 3;
  fi
  $CMD ps >/dev/null 2>&1 || $CMD up -d redis authelia nginx
  echo "Ensuring core services running... (using $CMD)"
  $CMD up -d redis authelia nginx
else
  echo "Docker not installed on host"; exit 3;
fi

printf "\n=== Step 6: Wait for container health ===================\n"
ATTEMPTS=30
SLEEP=3
for svc in redis authelia nginx; do
  i=0
  while true; do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$(docker ps --filter name=${svc} --format '{{.Names}}' | head -n1)" 2>/dev/null || echo 'unknown')
    if [[ "$STATUS" == "healthy" ]]; then
      echo "$svc: healthy"; break
    fi
    if [[ "$STATUS" == "unhealthy" ]]; then echo "$svc: unhealthy"; break; fi
    if (( i++ >= ATTEMPTS )); then echo "$svc: timeout waiting for health"; break; fi
    sleep $SLEEP
  done
done

printf "\n=== Step 7: Redis direct check ==========================\n"
REDIS_CONT=$(docker ps --filter name=redis --format '{{.Names}}' | head -n1)
if [[ -n "$REDIS_CONT" ]]; then
  if [[ -n "${REDIS_PW:-}" ]]; then
    docker exec "$REDIS_CONT" redis-cli -a "$REDIS_PW" PING || true
  else
    docker exec "$REDIS_CONT" redis-cli PING || true
  fi
fi

printf "\n=== Step 8: Authelia health endpoint ====================\n"
# Determine mapped port (default 9091 internal - may be published differently)
AUTHELIA_CONT=$(docker ps --filter name=authelia --format '{{.Names}}' | head -n1)
if [[ -n "$AUTHELIA_CONT" ]]; then
  # Try container namespace first, then host via exposed port 9091
  if docker exec "$AUTHELIA_CONT" wget -q -T2 -O- http://127.0.0.1:9091/api/health >/dev/null 2>&1; then
    docker exec "$AUTHELIA_CONT" wget -q -O- http://127.0.0.1:9091/api/health || true
  else
    # host attempt
    curl -fsS http://127.0.0.1:9091/api/health || echo "Host access to Authelia health failed"
  fi
fi

printf "\n=== Step 9: DNS / hosts for test domains ================\n"
for d in fkstrading.xyz fkstrading.test; do
  getent hosts "$d" || echo "Domain $d not resolvable (if expected, add to /etc/hosts for local testing)";
done

printf "\n=== Step 10: Summary ====================================\n"
(docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'redis|authelia|nginx') || true

EOF_REMOTE
)

# Replace placeholder with provided project path (quoted safely)
REMOTE_SCRIPT=${REMOTE_SCRIPT//PROJECT_DIR_PLACEHOLDER/$PROJECT_PATH}

log "Executing validation ($([[ $LOCAL_MODE == true ]] && echo 'local' || echo "remote: $REMOTE_TARGET"))..."

if $LOCAL_MODE; then
  eval "$REMOTE_SCRIPT"
else
  remote_exec "$REMOTE_SCRIPT"
fi

log "Validation script complete." 
