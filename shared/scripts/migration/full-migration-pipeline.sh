#!/usr/bin/env bash
# High-level orchestrator: extraction -> verification -> optional push.
# Usage: ./migration/full-migration-pipeline.sh \
#   --mono /path/to/mono \
#   --out /tmp/extracted \
#   --org yourorg \
#   [--only fks_api,fks_engine] [--skip-shared] [--parallel 4] [--push] [--remote-prefix git@github.com:yourorg]
# Environment overrides:
#   PUSH_BRANCH (default: main)
#   VERIFY_PARALLEL (if --parallel omitted)
set -euo pipefail

MONO=""; OUT=""; ORG="yourorg"; ONLY=""; SKIP_SHARED=0; PARALLEL=""; DO_PUSH=0; REMOTE_PREFIX="git@github.com:yourorg";
RUN_DASHBOARD=1; RUN_SUBMOD_INIT=0; RUN_CROSSLINK=0; POST_AUTOMATE=0; CUTOVER_TAG=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --mono) MONO=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --org) ORG=$2; shift 2;;
    --only) ONLY=$2; shift 2;;
    --skip-shared) SKIP_SHARED=1; shift;;
    --parallel) PARALLEL=$2; shift 2;;
    --push) DO_PUSH=1; shift;;
    --remote-prefix) REMOTE_PREFIX=$2; shift 2;;
  --no-dashboard) RUN_DASHBOARD=0; shift;;
  --init-submodules) RUN_SUBMOD_INIT=1; shift;;
  --update-cross-links) RUN_CROSSLINK=1; shift;;
  --post-automate) POST_AUTOMATE=1; shift;;
  --cutover-tag) CUTOVER_TAG=$2; shift 2;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

[[ -z $MONO || -z $OUT ]] && { echo "--mono and --out required"; exit 1; }
if (( POST_AUTOMATE )) && [[ -z $CUTOVER_TAG ]]; then echo "--cutover-tag required with --post-automate" >&2; exit 1; fi
mkdir -p "$OUT"

echo "[STEP] Extraction"
CMD=("$MONO/migration/run-extraction.sh")
[[ -n $ONLY ]] && CMD+=(--only "$ONLY")
(( SKIP_SHARED )) && CMD+=(--skip-shared)
CMD+=("$MONO" "$OUT" "$ORG")
"${CMD[@]}"

echo "[STEP] Verification"
VERIFY_CMD=("$MONO/migration/verify-split.sh" "$OUT")
[[ -n $PARALLEL ]] && VERIFY_CMD+=(--parallel "$PARALLEL") || { [[ -n ${VERIFY_PARALLEL:-} ]] && VERIFY_CMD+=(--parallel "$VERIFY_PARALLEL"); }
VERIFY_CMD+=(--json-out "$OUT/verify-report.json" --fail-on-fail)
"${VERIFY_CMD[@]}" || VERIFY_EXIT=$? || true
VERIFY_EXIT=${VERIFY_EXIT:-0}

if (( RUN_DASHBOARD )); then
  echo "[STEP] Governance Dashboard"
  "$MONO/migration/generate-dashboard.sh" "$OUT/verify-report.json" /dev/null /dev/null /dev/null /dev/null "$OUT/governance-dashboard.md" || true
fi

if (( RUN_SUBMOD_INIT )); then
  echo "[STEP] Init Submodules"
  "$MONO/migration/init-all-submodules.sh" --micro-root "$OUT" --pull || true
fi

if (( RUN_CROSSLINK )); then
  if [[ -f $OUT/cross-link-snippet.md ]]; then
    echo "[STEP] Update Cross-links (existing snippet)"
    "$MONO/migration/update-cross-links.sh" --micro-root "$OUT" --snippet "$OUT/cross-link-snippet.md" || true
  else
    echo "[INFO] No snippet found; you can run post-cutover automation later" >&2
  fi
fi

if (( POST_AUTOMATE )); then
  echo "[STEP] Post Cutover Automation"
  "$MONO/migration/post-cutover-automation.sh" --mono-root "$MONO" --micro-root "$OUT" --org "$ORG" --tag "$CUTOVER_TAG" --dry-run || true
fi

if (( DO_PUSH )); then
  echo "[STEP] Push new repos (if remotes exist)"
  for repo_dir in "$OUT"/*; do
    [[ -d $repo_dir/.git ]] || continue
    name=$(basename "$repo_dir")
    pushd "$repo_dir" >/dev/null
    remote_url="${REMOTE_PREFIX}/${name}.git"
    if git ls-remote "$remote_url" &>/dev/null; then
      echo "[PUSH] $name -> $remote_url"
      git remote add origin "$remote_url" 2>/dev/null || true
      git push -u origin ${PUSH_BRANCH:-main} || true
    else
      echo "[SKIP] Remote not reachable: $remote_url" >&2
    fi
    popd >/dev/null
  done
fi

jq -r '.[] | "\(.repo): \(.status)"' "$OUT/verify-report.json" | sed 's/^/[RESULT] /'

if (( VERIFY_EXIT != 0 )); then
  if [[ ! -d $MONO/.git ]]; then
    echo "[WARN] Non-zero verification in fallback mode (code $VERIFY_EXIT) allowing continuation" >&2
  else
    echo "[FAIL] Verification failed with code $VERIFY_EXIT" >&2
    exit $VERIFY_EXIT
  fi
fi

echo "[DONE] Full pipeline complete. Reports in $OUT"
echo "[HINT] To run post-cutover automation later: migration/post-cutover-automation.sh --mono-root $MONO --micro-root $OUT --org $ORG --tag <cutover-tag>"
