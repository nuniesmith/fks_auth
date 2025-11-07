#!/usr/bin/env bash
set -euo pipefail
# Simple duplicate finder using sha256 sums; avoids external deps.
# Usage: ./tools/find_duplicates.sh > duplicates.report

TMP=$(mktemp)
trap 'rm -f $TMP' EXIT

# Hash all regular files excluding .git and backups and large build dirs (node_modules, target)
find . -type f \
  -not -path '*/.git/*' \
  -not -path '*fks_backup_*/*' \
  -not -path '*/node_modules/*' \
  -not -path '*/target/*' \
  -print0 | xargs -0 sha256sum > "$TMP"

# Print groups with identical hash (size >1)
awk '{h=$1; $1=""; sub(/^ +/ ,""); files[h]=files[h]"\n"$0; count[h]++} END {for (h in count) if (count[h]>1) {print "HASH "h" ("count[h]" files):" files[h]"\n"}}' "$TMP" | sort > duplicates.report

DUP_GROUPS=$(grep -c '^HASH ' duplicates.report || true)
TOTAL_DUPS=$(awk '/^HASH / {c+=$3} END{print c}' duplicates.report 2>/dev/null || echo 0)

echo "Duplicate groups: $DUP_GROUPS (see duplicates.report)."
