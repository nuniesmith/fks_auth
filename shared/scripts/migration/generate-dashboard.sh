#!/usr/bin/env bash
# Generate consolidated governance dashboard markdown.
# Inputs (optional environment vars or positional):
#   1: verify JSON (list of repo objects)
#   2: verify delta markdown (optional)
#   3: sbom aggregate JSON (optional)
#   4: sbom delta markdown (optional)
#   5: submodule drift markdown (optional)
#   6: output file (default governance-dashboard.md)
set -euo pipefail
VERIFY_JSON=${1:-verify.json}
VERIFY_DELTA=${2:-verify-delta.md}
SBOM_JSON=${3:-aggregate-sbom.json}
SBOM_DELTA=${4:-sbom-delta.md}
DRIFT_MD=${5:-drift-report.md}
OUT=${6:-governance-dashboard.md}

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

section() { local t=$1; echo "\n## $t\n"; }

{
  echo "# Governance Dashboard"
  echo
  echo "Generated: $now"
  echo
  # Verification summary
  if [[ -f $VERIFY_JSON ]]; then
    section "Verification Status"
    jq -r 'group_by(.status) | map({status:.[0].status, count:length}) | ("Status | Count", "------ | -----", (.[].status + " | " + (.[].count|tostring)))' "$VERIFY_JSON" 2>/dev/null || echo "(unable to summarize verify.json)"
    total=$(jq 'length' "$VERIFY_JSON")
    fails=$(jq '[ .[] | select(.status=="fail") ] | length' "$VERIFY_JSON")
    warns=$(jq '[ .[] | select(.status=="warn") ] | length' "$VERIFY_JSON")
    oks=$(jq '[ .[] | select(.status=="ok") ] | length' "$VERIFY_JSON")
    echo "\nTotal: $total | Fail: $fails | Warn: $warns | OK: $oks"
  fi
  # Verification delta snippet
  if [[ -f $VERIFY_DELTA ]]; then
    section "Recent Verification Delta"
    sed -n '1,120p' "$VERIFY_DELTA"
  fi
  # SBOM aggregate overview
  if [[ -f $SBOM_JSON ]]; then
    section "SBOM Overview"
    repos=$(jq '[.[].repo] | length' "$SBOM_JSON" 2>/dev/null || echo 0)
    licenses=$(jq '[.[].license]|unique|length' "$SBOM_JSON" 2>/dev/null || echo 0)
    echo "Repositories with SBOM: $repos | Unique Licenses: $licenses"
    top_licenses=$(jq -r '[.[].license]|map(select(length>0))|group_by(.)|map({k:.[0], c:length})|sort_by(-.c)|.[0:5]|map("- " + (.k//"(none)") + " (" + (.c|tostring) + ")")|.[]' "$SBOM_JSON" 2>/dev/null || true)
    [[ -n $top_licenses ]] && echo "$top_licenses"
  fi
  # SBOM delta snippet
  if [[ -f $SBOM_DELTA ]]; then
    section "Recent SBOM Delta"
    sed -n '1,120p' "$SBOM_DELTA"
  fi
  # Submodule drift snippet
  if [[ -f $DRIFT_MD ]]; then
    section "Submodule Drift"
    sed -n '1,80p' "$DRIFT_MD"
  fi
  # Pinned dependency snapshots (collect any pinned-deps.json under extracted services)
  if ls */pinned-deps.json >/dev/null 2>&1; then
    section "Pinned Rust Dependencies"
    for f in */pinned-deps.json; do
      svc=${f%%/*}
      echo "### $svc"; echo '```json'; cat "$f"; echo '```'
    done
  fi
  echo
  echo "---"
  echo "End of report"
} > "$OUT"

echo "[DASHBOARD] Wrote $OUT" >&2
