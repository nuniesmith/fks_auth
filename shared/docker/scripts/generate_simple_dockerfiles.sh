#!/usr/bin/env bash
set -euo pipefail

# Generates simplified Dockerfiles per service based on runtime mapping.
# It WILL NOT overwrite an existing Dockerfile unless --force is provided.
# Advanced unified build remains available at shared/docker/Dockerfile.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE_DIR="$ROOT_DIR/shared/docker/templates"
FORCE=0

usage(){
  cat <<EOF
Usage: $0 [--force]
Creates simplified Dockerfiles for services.
Runtimes inferred by service name mapping inside this script.
--force  Overwrite existing Dockerfile
EOF
}

if [[ "+${*}+" == *+--help+* ]]; then usage; exit 0; fi
if [[ "+${*}+" == *+--force+* ]]; then FORCE=1; fi

declare -A SERVICE_RUNTIME=(
  [fks_api]=python
  [fks_auth]=python
  [fks_data]=python
  [fks_engine]=python
  [fks_worker]=python
  [fks_training]=python
  [fks_transformer]=python
  [fks_master]=python
  [fks_config]=rust
  [fks_execution]=rust
  [fks_nodes]=rust
  [fks_web]=node
  [fks_ninja]=dotnet
  [fks_nginx]=nginx
)

for svc in "${!SERVICE_RUNTIME[@]}"; do
  runtime=${SERVICE_RUNTIME[$svc]}
  svc_path="$ROOT_DIR/fks/$svc"
  [ -d "$svc_path" ] || { echo "Skip $svc (dir missing)"; continue; }
  template="$TEMPLATE_DIR/${runtime}.Dockerfile"
  out="$svc_path/Dockerfile.simple"
  if [ ! -f "$template" ]; then
    echo "Template missing for runtime $runtime (service $svc)" >&2
    continue
  fi
  if [ -f "$out" ] && [ $FORCE -eq 0 ]; then
    echo "Exists: $out (use --force to overwrite)"
  else
    cp "$template" "$out"
    echo "Wrote $out (runtime=$runtime)"
  fi
  # Optionally create a README note
  note="$svc_path/DOCKERFILE_SELECTION.md"
  if [ ! -f "$note" ]; then
    cat > "$note" <<NOTE
# Dockerfile Options

This service supports two build strategies:

1. Simplified: 
   docker build -f Dockerfile.simple -t ${svc}:simple .

2. Unified (full multi-runtime + GPU support) shared file:
   docker build -f ../../shared/docker/Dockerfile -t ${svc}:unified \
     --build-arg SERVICE_RUNTIME=${runtime} .

Default repository Dockerfile may still be the unified version; adopt the simple one by renaming if desired.
NOTE
  fi
done

echo "Done. Review *.simple files before replacing primary Dockerfile(s)."
