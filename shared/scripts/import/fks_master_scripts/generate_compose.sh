#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# generate_compose.sh
#   Dynamic docker compose generator leveraging shared/docker Dockerfile.
#   Profiles:
#     minimal -> api + web
#     core    -> api + data + worker + engine + transformer + web
#     full    -> core + redis + timescaledb + nginx + monitoring
#   Options:
#     -o|--output <file>   Output file (default: docker-compose.generated.yml)
#     -p|--profile <name>  Profile (minimal|core|full) (default: core)
#     --with-db            Force include redis & timescaledb even if profile=minimal
#     --no-build           Omit build sections (assume pre-built images)
#     --force              Overwrite existing output file
#     --print              Print resulting compose file to stdout
#     -h|--help            Show usage
# -----------------------------------------------------------------------------

usage() {
  grep '^#' "$0" | sed 's/^# //' | sed '1,/^generate_compose.sh/d' | sed '1,2d';
}

OUT_FILE="docker-compose.generated.yml"
PROFILE="core"
WITH_DB=false
NO_BUILD=false
FORCE=false
PRINT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT_FILE=$2; shift 2;;
    -p|--profile) PROFILE=$2; shift 2;;
    --with-db) WITH_DB=true; shift;;
    --no-build) NO_BUILD=true; shift;;
    --force) FORCE=true; shift;;
    --print) PRINT=true; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

log(){ echo -e "[compose-gen] $1"; }

if [[ -f "$OUT_FILE" && "$FORCE" = false ]]; then
  log "File $OUT_FILE already exists (use --force to overwrite). Exiting."; exit 0;
fi

# Locate shared Dockerfile
SHARED_DOCKERFILE=""
for candidate in ../../shared/docker/Dockerfile ../shared/docker/Dockerfile ./shared/docker/Dockerfile; do
  if [[ -f "$candidate" ]]; then SHARED_DOCKERFILE=$candidate; break; fi
done
if [[ -z "$SHARED_DOCKERFILE" ]]; then
  log "WARNING: shared Dockerfile not found; build sections will fallback to local contexts.";
fi

# Service repo relative paths (from fks_master directory)
declare -A SERVICE_PATHS=(
  [api]=../fks_api
  [data]=../fks_data
  [worker]=../fks_worker
  [engine]=../fks_engine
  [transformer]=../fks_transformer
  [web]=../fks_web
)

# Determine service sets by profile
case "$PROFILE" in
  minimal) SERVICES=(api web);;
  core) SERVICES=(api data worker engine transformer web);;
  full) SERVICES=(api data worker engine transformer web redis timescaledb nginx prometheus grafana);;
  *) echo "Invalid profile: $PROFILE"; exit 1;;
esac

if [[ "$WITH_DB" = true ]]; then
  # ensure redis & timescaledb present
  SERVICES+=($(for s in redis timescaledb; do [[ " ${SERVICES[*]} " =~ " $s " ]] || echo $s; done))
fi

# Helper to emit build block
emit_build() {
  local svc=$1
  local type=$2
  local runtime=$3
  local port=$4
  local extra_args=$5
  if [[ "$NO_BUILD" = true ]]; then return; fi
  local ctx="${SERVICE_PATHS[$svc]:-.}"
  echo "    build:"
  echo "      context: ${ctx}"
  if [[ -n "$SHARED_DOCKERFILE" ]]; then
    # Compute relative path from context to shared Dockerfile if possible
    if command -v realpath >/dev/null 2>&1; then
      local ctx_abs=$(realpath "$ctx")
      local df_abs=$(realpath "$SHARED_DOCKERFILE")
      local rel_path=$(CTX="$ctx_abs" DF="$df_abs" python3 - <<'PY' || echo "$SHARED_DOCKERFILE"
import os,sys
ctx=os.environ.get('CTX')
df=os.environ.get('DF')
if not ctx or not df:
    print(df or '')
else:
    try:
        print(os.path.relpath(df, ctx))
    except Exception:
        print(df)
PY
      )
      echo "      dockerfile: $rel_path"
    else
      echo "      dockerfile: $SHARED_DOCKERFILE"
    fi
  fi
  echo "      args:"
  echo "        SERVICE_TYPE: ${type}"
  [[ -n "$runtime" ]] && echo "        SERVICE_RUNTIME: ${runtime}"
  [[ -n "$port" ]] && echo "        SERVICE_PORT: ${port}" 
  [[ -n "$extra_args" ]] && echo "$extra_args" | sed 's/^/        /'
}

log "Generating compose (profile=$PROFILE services=${SERVICES[*]}) -> $OUT_FILE"

{
  cat <<'YAML'
name: fks-generated
services:
YAML

  for svc in "${SERVICES[@]}"; do
    case $svc in
      api)
        cat <<'YAML'
  api:
    container_name: fks_api
YAML
        emit_build api api python 8000 "" || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: api
      APP_ENV: ${APP_ENV:-development}
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
YAML
        ;;
      data)
        cat <<'YAML'
  data:
    container_name: fks_data
YAML
        emit_build data data python 9001 "" || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: data
      APP_ENV: ${APP_ENV:-development}
    ports:
      - "9001:9001"
YAML
        ;;
      worker)
        cat <<'YAML'
  worker:
    container_name: fks_worker
YAML
        emit_build worker worker python "" "" || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: worker
      APP_ENV: ${APP_ENV:-development}
YAML
        ;;
      engine)
        cat <<'YAML'
  engine:
    container_name: fks_engine
YAML
        emit_build engine engine python 9010 "" || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: engine
      APP_ENV: ${APP_ENV:-development}
    ports:
      - "9010:9010"
YAML
        ;;
      transformer)
        cat <<'YAML'
  transformer:
    container_name: fks_transformer
YAML
        emit_build transformer transformer python 8089 "" || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: transformer
      APP_ENV: ${APP_ENV:-development}
    ports:
      - "8089:8089"
YAML
        ;;
      web)
        cat <<'YAML'
  web:
    container_name: fks_web
YAML
  emit_build web web node 3000 $'BUILD_NODE: "true"\nBUILD_PYTHON: "false"' || true
        cat <<'YAML'
    environment:
      SERVICE_TYPE: web
      SERVICE_RUNTIME: node
      APP_ENV: ${APP_ENV:-development}
    ports:
      - "3000:3000"
    depends_on:
      - api
YAML
        ;;
      redis)
        cat <<'YAML'
  redis:
    image: redis:latest
    container_name: fks_redis
YAML
        ;;
      timescaledb)
        cat <<'YAML'
  timescaledb:
    image: timescale/timescaledb:latest-pg17
    container_name: fks_timescaledb
YAML
        ;;
      nginx)
        cat <<'YAML'
  nginx:
    image: nginx:latest
    container_name: fks_nginx
    depends_on:
      - api
      - web
    ports:
      - "80:80"
YAML
        ;;
      prometheus)
        cat <<'YAML'
  prometheus:
    image: prom/prometheus:latest
    container_name: fks_prometheus
    ports:
      - "9090:9090"
YAML
        ;;
      grafana)
        cat <<'YAML'
  grafana:
    image: grafana/grafana:latest
    container_name: fks_grafana
    ports:
      - "3001:3000"
YAML
        ;;
    esac
  done

  # Simple network definition
  cat <<'YAML'
networks:
  default:
    name: fks-generated-network
YAML
} > "$OUT_FILE"

log "Wrote $OUT_FILE"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if docker compose -f "$OUT_FILE" config >/dev/null 2>&1; then
    log "Validated compose syntax"
  else
    log "WARNING: docker compose config validation failed"
  fi
else
  log "docker compose not available for validation"
fi

if [[ "$PRINT" = true ]]; then
  echo "---------------- Generated Compose ----------------"
  cat "$OUT_FILE"
fi

log "Done"
