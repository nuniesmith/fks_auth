#!/usr/bin/env bash
# Assist rollback to monorepo deployment if microrepo cutover needs reverting.
# Performs: freeze micro pipeline triggers, re-enable monorepo branch deploy, optional tag revert.
# Usage: ./migration/rollback-helper.sh --mono-root . --micro-root ./_out --tag cutover-2025-08-22 --rollback-tag rollback-2025-08-22 [--dry-run]
set -euo pipefail
MONO_ROOT=""; MICRO_ROOT=""; CUTOVER_TAG=""; ROLLBACK_TAG=""; DRY=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --mono-root) MONO_ROOT=$2; shift 2;;
    --micro-root) MICRO_ROOT=$2; shift 2;;
    --tag) CUTOVER_TAG=$2; shift 2;;
    --rollback-tag) ROLLBACK_TAG=$2; shift 2;;
    --dry-run) DRY=1; shift;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done
[[ -z $MONO_ROOT || -z $CUTOVER_TAG || -z $ROLLBACK_TAG ]] && { echo "Missing required args" >&2; exit 1; }
log(){ echo "[ROLLBACK] $*" >&2; }
run(){ if ((DRY)); then echo "DRY: $*" >&2; else eval "$*"; fi }

# 1. Tag rollback point in monorepo
if [[ -d $MONO_ROOT/.git ]]; then
  pushd "$MONO_ROOT" >/dev/null
  log "Creating rollback tag $ROLLBACK_TAG"
  run git tag -f "$ROLLBACK_TAG"
  popd >/dev/null
fi

# 2. Guidance for disabling microrepo deploys (manual - placeholder)
log "(Manual) Disable GitHub Actions deploy workflows in microrepos or set maintenance mode env var"

# 3. Guidance for switching traffic back (DNS / LB)
log "(Manual) Point DNS / load balancer back to monorepo deployment endpoints"

# 4. Optional: revert infra submodule references if infra repo exists in micro-root
for repo in "$MICRO_ROOT"/*; do
  [[ -d $repo/.git ]] || continue
  if [[ -f $repo/.gitmodules ]]; then
    log "(Info) Consider locking submodules in $(basename "$repo") to pre-cutover commits"
  fi
done

log "Rollback helper completed (manual steps may remain)"
