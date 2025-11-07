#!/usr/bin/env bash
# Generate remediation plan for outdated submodules across extracted repos.
# Usage: ./migration/generate-submodule-remediation.sh <extracted-base> [output-md]
set -euo pipefail
BASE=${1:-}
OUT=${2:-submodule-remediation.md}
[[ -z $BASE ]] && echo "Usage: $0 <extracted-base> [output]" >&2 && exit 1
[[ ! -d $BASE ]] && echo "Directory $BASE not found" >&2 && exit 1

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "# Submodule Remediation Plan" > "$OUT"
echo >> "$OUT"
echo "Generated: $now" >> "$OUT"
echo >> "$OUT"
need_any=0
for repo in "$BASE"/*; do
  [[ -d $repo/.git ]] || continue
  name=$(basename "$repo")
  [[ -f $repo/.gitmodules ]] || continue
  pushd "$repo" >/dev/null
  outdated=$(git submodule status 2>/dev/null | awk '/^\+/') || true
  [[ -z $outdated ]] && { popd >/dev/null; continue; }
  need_any=1
  echo "## $name" >> "$OUT"
  echo >> "$OUT"
  echo "| Submodule | Suggested Command (tag first fallback main) |" >> "$OUT"
  echo "|-----------|---------------------------------------------|" >> "$OUT"
  while IFS= read -r line; do
    sm_path=$(echo "$line" | awk '{print $2}')
    sm_name=${sm_path##*/}
    echo "| $sm_name | (cd $name && ./update-submodules.sh bump $sm_name tag || ./update-submodules.sh bump $sm_name main) |" >> "$OUT"
  done <<<"$outdated"
  echo >> "$OUT"
  popd >/dev/null
done

if (( need_any == 0 )); then
  echo "All submodules up-to-date." >> "$OUT"
fi

echo "[REMEDIATION] Wrote $OUT" >&2
