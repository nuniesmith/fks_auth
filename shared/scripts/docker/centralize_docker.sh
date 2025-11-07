#!/usr/bin/env bash
# centralize_docker.sh
#
# Purpose:
#   Propagate canonical Docker/compose templates from shared/docker into each service under ./fks/.
#   Creates (or updates) per-service Dockerfile + docker-compose.override.yml with lightweight token substitution.
#
# Tokens supported in templates (if present):
#   __SERVICE_NAME__  -> service directory name (e.g., fks_api)
#   __IMAGE_NAME__    -> lowercased service name (e.g., fks_api)
#
# Usage:
#   ./shared/scripts/docker/centralize_docker.sh [--services "fks_api fks_auth"] [--dry-run] \
#       [--dockerfile-template shared/docker/Dockerfile] \
#       [--compose-template shared/docker/compose/docker-compose.template.yml]
#
# Behavior:
#   - Skips services that already have a Dockerfile hash matching the template (idempotent).
#   - Writes backup of existing Dockerfile as Dockerfile.bak.<timestamp> before overwriting.
#   - Adds a provenance header to managed files.
#
set -euo pipefail

SERVICES=""
DOCKERFILE_TEMPLATE="shared/docker/Dockerfile"
COMPOSE_TEMPLATE="shared/docker/compose/docker-compose.template.yml"
DRY_RUN=0

info()  { echo -e "[INFO]  $*"; }
warn()  { echo -e "[WARN]  $*" >&2; }
error() { echo -e "[ERROR] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --services) SERVICES="$2"; shift 2;;
    --dockerfile-template) DOCKERFILE_TEMPLATE="$2"; shift 2;;
    --compose-template) COMPOSE_TEMPLATE="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) error "Unknown arg: $1";;
  esac
done

[[ -d fks ]] || error "Run from monorepo root (missing ./fks)."
[[ -f "$DOCKERFILE_TEMPLATE" ]] || error "Dockerfile template not found: $DOCKERFILE_TEMPLATE"
[[ -f "$COMPOSE_TEMPLATE" ]] || error "Compose template not found: $COMPOSE_TEMPLATE"

if [[ -z "$SERVICES" ]]; then
  mapfile -t SERVICE_DIRS < <(find fks -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | sort)
  SERVICES="${SERVICE_DIRS[*]}"
fi

timestamp() { date +%Y%m%d_%H%M%S; }
sha256() { sha256sum "$1" | awk '{print $1}'; }

render_template() {
  local template_file="$1" svc="$2" outfile="$3"
  local image_name="${svc,,}"
  sed -e "s/__SERVICE_NAME__/$svc/g" \
      -e "s/__IMAGE_NAME__/$image_name/g" "$template_file" > "$outfile"
}

process_service() {
  local svc="${1:-}"
  [[ -z "$svc" ]] && return 0
  local svc_path="fks/$svc"
  [[ -d "$svc_path" ]] || { warn "Skip missing $svc_path"; return; }

  local dockerfile_target="$svc_path/Dockerfile"
  local compose_target="$svc_path/docker-compose.override.yml"

  # Dockerfile
  local tmp_docker
  tmp_docker=$(mktemp)
  render_template "$DOCKERFILE_TEMPLATE" "$svc" "$tmp_docker"
  # Prepend provenance header
  { echo "# Managed by centralize_docker.sh (source: $DOCKERFILE_TEMPLATE)"; cat "$tmp_docker"; } > "$tmp_docker.managed"
  mv "$tmp_docker.managed" "$tmp_docker"

  if [[ -f "$dockerfile_target" ]]; then
    local current_hash desired_hash
    desired_hash=$(sha256 "$tmp_docker")
    current_hash=$(sha256 "$dockerfile_target")
    if [[ "$current_hash" == "$desired_hash" ]]; then
      info "[$svc] Dockerfile already up to date"
    else
      info "[$svc] Updating Dockerfile (hash mismatch)"
      if [[ $DRY_RUN -eq 0 ]]; then
        cp "$dockerfile_target" "$dockerfile_target.bak.$(timestamp)"
        mv "$tmp_docker" "$dockerfile_target"
      fi
    fi
  else
    info "[$svc] Creating new Dockerfile from template"
    [[ $DRY_RUN -eq 1 ]] || mv "$tmp_docker" "$dockerfile_target"
  fi

  # Compose override
  local tmp_compose
  tmp_compose=$(mktemp)
  render_template "$COMPOSE_TEMPLATE" "$svc" "$tmp_compose"
  { echo "# Managed by centralize_docker.sh (source: $COMPOSE_TEMPLATE)"; cat "$tmp_compose"; } > "$tmp_compose.managed"
  mv "$tmp_compose.managed" "$tmp_compose"
  if [[ -f "$compose_target" ]]; then
    local cur_hash des_hash
    des_hash=$(sha256 "$tmp_compose")
    cur_hash=$(sha256 "$compose_target")
    if [[ "$cur_hash" == "$des_hash" ]]; then
      info "[$svc] compose override already up to date"
    else
      info "[$svc] Updating compose override"
      [[ $DRY_RUN -eq 1 ]] || { cp "$compose_target" "$compose_target.bak.$(timestamp)"; mv "$tmp_compose" "$compose_target"; }
    fi
  else
    info "[$svc] Creating compose override"
    [[ $DRY_RUN -eq 1 ]] || mv "$tmp_compose" "$compose_target"
  fi
}

SERVICES=$(echo "$SERVICES" | tr '\n' ' ' | tr -s ' ')
IFS=' ' read -r -a SERVICE_ARRAY <<< "$SERVICES"
info "Services: ${SERVICE_ARRAY[*]}"
[[ $DRY_RUN -eq 1 ]] && info "Dry-run: no files will be written"

for s in "${SERVICE_ARRAY[@]:-}"; do
  process_service "$s" || warn "Service '$s' processing encountered an error"
done

info "Docker centralization complete."
