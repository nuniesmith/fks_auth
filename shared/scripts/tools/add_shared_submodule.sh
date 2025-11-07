#!/usr/bin/env bash
# add_shared_submodule.sh
#
# Purpose:
#   Ensure every FKS service repo under ./fks/ has access to the shared python package.
#   Provides two strategies:
#     1. symlink  (default) -> fast, single working tree copy
#     2. submodule          -> adds git submodule pointing to external remote (if provided)
#
#   By default we create idempotent symlinks:
#      <service>/shared_python  -> ../../shared/python/src/shared_python
#      <service>/shared_python -> ../../shared/python/src/shared_python
#
# Usage:
#   ./shared/scripts/tools/add_shared_submodule.sh [--mode symlink|submodule] [--services "fks_api fks_auth"] \
#       [--package-path shared/python] [--remote <git_url>] [--dry-run]
#
# Notes:
#   - If --mode submodule is selected you must supply --remote (origin of shared repo) unless it already exists.
#   - Safe to re-run; will skip existing correct links.
#   - Designed for monorepo root execution.

set -euo pipefail

MODE="symlink"
SERVICES=""
PACKAGE_PATH="shared/python"
REMOTE=""
DRY_RUN=0

info()  { echo -e "[INFO]  $*"; }
warn()  { echo -e "[WARN]  $*" >&2; }
error() { echo -e "[ERROR] $*" >&2; exit 1; }

usage() { sed -n '1,/^set -euo/p' "$0" | sed '$d'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --services) SERVICES="$2"; shift 2;;
    --package-path) PACKAGE_PATH="$2"; shift 2;;
    --remote) REMOTE="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) error "Unknown arg: $1";;
  esac
done

[[ -d fks ]] || error "Run from monorepo root (expected ./fks directory)."
[[ -d "$PACKAGE_PATH" ]] || error "Package path '$PACKAGE_PATH' not found."

# Auto-discover services if none specified
if [[ -z "$SERVICES" ]]; then
  mapfile -t SERVICE_DIRS < <(find fks -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | sort)
  # Exclude legacy shared dir if present
  SERVICES="${SERVICE_DIRS[*]}"
fi

TARGET_REL_SHARED="../../$PACKAGE_PATH/src/shared_python"
TARGET_REL_FKS="../../$PACKAGE_PATH/src/shared_python"

add_symlinks() {
  local svc="$1"
  local svc_path="fks/$svc"
  [[ -d "$svc_path" ]] || { warn "Skip missing $svc_path"; return; }
  # Define name/target pairs in an array for iteration
  local pairs=( "shared_python=$TARGET_REL_SHARED" "shared_python=$TARGET_REL_FKS" )
  local pair name target_rel link_path existing
  for pair in "${pairs[@]}"; do
    name="${pair%%=*}"
    target_rel="${pair#*=}"
    link_path="$svc_path/$name"
    if [[ -L "$link_path" || -d "$link_path" ]]; then
      if [[ -L "$link_path" ]]; then
        existing=$(readlink "$link_path") || existing=""
        if [[ "$existing" == "$target_rel" ]]; then
          info "[$svc] $name symlink already correct -> $target_rel"
          continue
        else
          warn "[$svc] $name symlink points to $existing (expected $target_rel); updating"
          [[ $DRY_RUN -eq 1 ]] || rm -f "$link_path"
        fi
      else
        warn "[$svc] $name exists as directory/file; skipping (manual review)"
        continue
      fi
    fi
    info "[$svc] create symlink $name -> $target_rel"
    [[ $DRY_RUN -eq 1 ]] || ln -s "$target_rel" "$link_path"
  done
}

add_submodule() {
  local svc="$1"
  local svc_path="fks/$svc"
  [[ -d "$svc_path" ]] || { warn "Skip missing $svc_path"; return; }
  [[ -n "$REMOTE" ]] || error "--remote required for submodule mode"
  local sub_path="$svc_path/shared_python"
  if [[ -d "$sub_path/.git" ]]; then
    info "[$svc] submodule already present"
  else
    info "[$svc] adding submodule at $sub_path"
    if [[ $DRY_RUN -eq 0 ]]; then
      git submodule add "$REMOTE" "$sub_path" || warn "[$svc] submodule add may have failed (already?)"
    fi
  fi
}

IFS=' ' read -r -a SERVICE_ARRAY <<< "$SERVICES"

info "Mode: $MODE"
info "Services: ${SERVICE_ARRAY[*]}"
[[ $DRY_RUN -eq 1 ]] && info "Dry-run mode: no changes will be written"

case "$MODE" in
  symlink)
    for s in "${SERVICE_ARRAY[@]}"; do add_symlinks "$s"; done;;
  submodule)
    for s in "${SERVICE_ARRAY[@]}"; do add_submodule "$s"; done;;
  *) error "Unsupported mode: $MODE";;
esac

info "Completed shared package linkage process."
