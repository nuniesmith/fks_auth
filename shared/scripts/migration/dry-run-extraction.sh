#!/usr/bin/env bash
# Perform a dry-run extraction: clone, filter, list resulting tree sizes, without pushing.
# Usage: ./migration/dry-run-extraction.sh /path/to/mono-root /tmp/output fks_api
set -euo pipefail
MONO=${1:-}
OUT=${2:-}
TARGET=${3:-}
[[ -z $MONO || -z $OUT || -z $TARGET ]] && echo "Usage: $0 <mono-root> <out-dir> <target-repo-name>" && exit 1
MAP="$MONO/extraction-map.yml"
[[ -f $MAP ]] || { echo "Missing map $MAP"; exit 1; }
mkdir -p "$OUT"
# Parse target paths
paths=$(awk -v t="  $TARGET:" '$0==t{f=1} f&&/paths:/{getline; while($0 ~ /^ {6}-/){gsub(/#.*/,"",
$0); sub(/^ {6}- /,"",$0); print; getline} f=0}' "$MAP")
[[ -z $paths ]] && { echo "No paths for $TARGET"; exit 1; }
work="$OUT/$TARGET-dry"
rm -rf "$work"
cp -R "$MONO" "$work"
pushd "$work" >/dev/null
for p in $paths; do keep+=(--path "$p"); done
python - <<'PY'
# verify git-filter-repo existence without executing in this script (informative only)
PY
if ! command -v git-filter-repo >/dev/null; then echo "[WARN] git-filter-repo not installed; skipping actual filtering"; else
  git filter-repo "${keep[@]}" --force
fi
# Size report
find . -type f | wc -l | awk '{print "Files:" $1}'
{ du -sh . 2>/dev/null || true; }
find . -maxdepth 2 -type d -exec bash -c 'echo -n "{} "; find "{}" -type f | wc -l' \; | head -n 30
popd >/dev/null
