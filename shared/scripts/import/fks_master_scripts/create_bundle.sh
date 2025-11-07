#!/usr/bin/env bash
set -euo pipefail
# create_bundle.sh
# Produce a compressed git bundle snapshot of the entire mono repo for disaster recovery.
# The bundle contains all refs (branches + tags) unless you pass a specific ref list.
# Usage:
#   ./fks_master/scripts/create_bundle.sh                # full bundle named bundles/mono-YYYYmmdd-HHMM.bundle
#   ./fks_master/scripts/create_bundle.sh --refs main v1.0.0  # only selected refs
#   ./fks_master/scripts/create_bundle.sh --output /tmp/my.bundle
#   ./fks_master/scripts/create_bundle.sh --prune         # also prune packed unreachable objects first
#
# Restore:
#   git clone <repo-url> restored --mirror (optional fresh repo)
#   cd restored
#   git bundle unbundle /path/to/mono-20250823-1200.bundle
#   # or directly: git clone mono-20250823-1200.bundle restored
#
# Verify:
#   git bundle verify mono-20250823-1200.bundle
#
# Cron example (daily 01:00 UTC):
#   0 1 * * * /path/to/repo/fks_master/scripts/create_bundle.sh --quiet >> /path/to/repo/logs/bundle_cron.log 2>&1

OUTPUT=""
PRUNE=false
QUIET=false
REFS=()
DATE_TAG=$(date +%Y%m%d-%H%M)
DEFAULT_DIR="bundles"
mkdir -p "$DEFAULT_DIR"

log(){ $QUIET || echo "[bundle] $1"; }
err(){ echo "[bundle][err] $1" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT=$2; shift 2;;
    --prune) PRUNE=true; shift;;
    --refs) # collect following args until next -- or end
      shift
      while [[ $# -gt 0 && $1 != --* ]]; do REFS+=("$1"); shift; done;;
    --quiet) QUIET=true; shift;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) err "Unknown arg $1"; exit 1;;
  esac
done

if [[ -z $OUTPUT ]]; then
  OUTPUT="${DEFAULT_DIR}/mono-${DATE_TAG}.bundle"
fi

if $PRUNE; then
  log "Pruning repository objects (git gc --prune=now)"
  git gc --prune=now --aggressive || err "gc failed (continuing)"
fi

if [[ ${#REFS[@]} -eq 0 ]]; then
  log "Creating full bundle $OUTPUT (all refs)"
  git bundle create "$OUTPUT" --all
else
  log "Creating selective bundle $OUTPUT (refs: ${REFS[*]})"
  git bundle create "$OUTPUT" "${REFS[@]}"
fi

if git bundle verify "$OUTPUT" >/dev/null 2>&1; then
  log "Bundle verified: $OUTPUT"
else
  err "Bundle did not verify"
  exit 2
fi

log "Done"
