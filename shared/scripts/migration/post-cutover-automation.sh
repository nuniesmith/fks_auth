#!/usr/bin/env bash
# Post-cutover automation: tag/archive monorepo, update cross-links, run integration compose test, verify submodules.
# Usage: ./migration/post-cutover-automation.sh --mono-root . --micro-root ./_out --org yourorg \
#          --infra-repo fks_infra --compose-file docker-compose.yml --tag cutover-2025-08-22 \
#          [--archive] [--push-tags] [--dry-run]
set -euo pipefail

MONO_ROOT=""; MICRO_ROOT=""; ORG=""; INFRA_REPO="fks_infra"; COMPOSE_FILE="docker-compose.yml"; TAG=""; ARCHIVE=0; PUSH_TAGS=0; DRY=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --mono-root) MONO_ROOT=$2; shift 2;;
    --micro-root) MICRO_ROOT=$2; shift 2;;
    --org) ORG=$2; shift 2;;
    --infra-repo) INFRA_REPO=$2; shift 2;;
    --compose-file) COMPOSE_FILE=$2; shift 2;;
    --tag) TAG=$2; shift 2;;
    --archive) ARCHIVE=1; shift;;
    --push-tags) PUSH_TAGS=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done

[[ -z $MONO_ROOT || -z $MICRO_ROOT || -z $ORG || -z $TAG ]] && { echo "Missing required args" >&2; exit 1; }
[[ ! -d $MONO_ROOT/.git ]] && { echo "Invalid monorepo root" >&2; exit 1; }

log(){ echo "[POST] $*" >&2; }
run(){ if (( DRY )); then echo "DRY: $*" >&2; else eval "$*"; fi }

# 1. Tag monorepo
log "Tagging monorepo with $TAG"
pushd "$MONO_ROOT" >/dev/null
run git tag -f "$TAG"
if (( PUSH_TAGS )); then run git push -f origin "$TAG"; fi
if (( ARCHIVE )); then
  log "Marking repository archived (manual GitHub API step required)"
fi
popd >/dev/null

# 2. Generate cross-link README snippet mapping
MAP_FILE="$MONO_ROOT/extraction-map.yml"
SNIPPET="$MICRO_ROOT/cross-link-snippet.md"
log "Generating cross-link snippet $SNIPPET"
{
  echo "## Repository Mapping (Cutover $TAG)"; echo; echo '| Service | Paths | Submodules |'; echo '|---------|-------|------------|'
  awk '/^services:/ {s=1;next} s && /^[^ ]/ {s=0} s {print}' "$MAP_FILE" | \
    awk '/^[ ]{2}[a-z0-9-]+:/ {gsub(":",""); svc=$1} /paths:/ {mode=1; paths=""} /^      - / && mode {sub(/^      - /,""); paths=paths $0 ","} /submodules:/ {sub(/^.*\[/,""); sub(/].*$/,""); subs=$0; sub(/,$/,"",paths); gsub(/,$/,"",paths); print "| " svc " | " paths " | " subs " |"; mode=0 }'
} > "$SNIPPET"

# 3. Validate submodule currency across microrepos
log "Scanning microrepos for submodule drift"
DRIFT_REPORT="$MICRO_ROOT/submodule-drift-post.md"
: > "$DRIFT_REPORT"
for repo in "$MICRO_ROOT"/*; do
  [[ -d $repo/.git ]] || continue
  if [[ -f $repo/.gitmodules ]]; then
    pushd "$repo" >/dev/null
    outdated=$(git submodule status 2>/dev/null | grep '^+' || true)
    if [[ -n $outdated ]]; then
      echo "### $(basename "$repo")" >> "$DRIFT_REPORT"
      echo '```' >> "$DRIFT_REPORT"
      git submodule status >> "$DRIFT_REPORT"
      echo '```' >> "$DRIFT_REPORT"
    fi
    popd >/dev/null
  fi
done
[[ -s $DRIFT_REPORT ]] || echo "All submodules up to date" > "$DRIFT_REPORT"

# 4. Compose integration test (infra repo)
INFRA_DIR="$MICRO_ROOT/$INFRA_REPO"
if [[ -d $INFRA_DIR ]]; then
  log "Running docker-compose integration smoke ($COMPOSE_FILE)"
  pushd "$INFRA_DIR" >/dev/null
  if [[ -f $COMPOSE_FILE ]]; then
    run docker compose -f "$COMPOSE_FILE" pull
    run docker compose -f "$COMPOSE_FILE" up -d
    sleep 5
    # Basic health check (look for containers unhealthy/exited)
    unhealthy=$(docker ps --format '{{.Names}} {{.Status}}' | grep -E 'unhealthy|Exited' || true)
    if [[ -n $unhealthy ]]; then
      echo "[ERROR] Unhealthy containers:\n$unhealthy" >&2
    fi
    run docker compose -f "$COMPOSE_FILE" down -v
  else
    log "Compose file $COMPOSE_FILE missing in infra repo"
  fi
  popd >/dev/null
else
  log "Infra repo directory $INFRA_DIR not found under micro-root"
fi

# 5. Aggregate report
REPORT="$MICRO_ROOT/post-cutover-report.md"
log "Writing report $REPORT"
{
  echo "# Post-Cutover Automation Report ($TAG)"; echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo
  echo "## Cross-Link Mapping"; echo; cat "$SNIPPET"; echo
  echo "## Submodule Drift"; echo; cat "$DRIFT_REPORT"; echo
  echo "## Notes"; echo "- Tag: $TAG"; (( ARCHIVE )) && echo "- Archive flag set (manual GitHub archive step pending)" || true
} > "$REPORT"

log "Done"
