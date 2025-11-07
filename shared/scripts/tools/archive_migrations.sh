#!/usr/bin/env bash
set -euo pipefail
# Move old migration scripts into archive/migration preserving structure
ARCHIVE_DIR=archive/migration
DAYS=${DAYS:-60}
DRY_RUN=${DRY_RUN:-false}
VERBOSE=${VERBOSE:-false}
mkdir -p "${ARCHIVE_DIR}"

NOW=$(date +%s)
CUTOFF=$((DAYS*24*3600))
MOVE_COUNT=0

while IFS= read -r -d '' f; do
  MTIME=$(stat -c %Y "$f") || continue
  AGE=$((NOW - MTIME))
  if (( AGE > CUTOFF )); then
    rel=${f#./}
    dest="$ARCHIVE_DIR/$rel"
    $VERBOSE && echo "Archive candidate ($((AGE/86400))d): $rel -> $dest"
    if ! $DRY_RUN; then
      mkdir -p "$(dirname "$dest")"
      git mv "$rel" "$dest" 2>/dev/null || mv "$rel" "$dest"
    fi
    ((MOVE_COUNT++))
  fi
done < <(find . -type f -path '*/migration/*' -print0)

if $DRY_RUN; then
  echo "Dry run complete. Candidates: $MOVE_COUNT"
else
  echo "Archived $MOVE_COUNT old migration files into $ARCHIVE_DIR (git mv when possible)."
fi
