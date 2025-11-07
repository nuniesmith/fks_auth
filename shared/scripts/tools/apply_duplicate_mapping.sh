#!/usr/bin/env bash
set -euo pipefail
# Apply duplicate_mapping.tsv: move duplicate originals to trash (non-destructive).

usage() {
  cat <<EOF
Usage: $0 [options] [mapping_file]
  --dry-run       Show candidates only
  --tag NAME      Tag suffix for trash snapshot (default: dups)
  -h, --help      Help
Environment: DRY_RUN=true also respected.
EOF
}

MAP_FILE="duplicate_mapping.tsv"
TAG="dups"
DRY_RUN=${DRY_RUN:-false}
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY_RUN=true; shift;;
    --tag) TAG=$2; shift 2;;
    -h|--help) usage; exit 0;;
    *) MAP_FILE=$1; shift;;
  esac
done

TRASH_SCRIPT=tools/move_to_trash.sh
TMP=list.to.trash.$$;

[[ -f $MAP_FILE ]] || { echo "Mapping file not found: $MAP_FILE" >&2; exit 1; }
[[ -x $TRASH_SCRIPT ]] || { echo "Trash script not executable: $TRASH_SCRIPT" >&2; exit 1; }

grep -v '^#' "$MAP_FILE" | awk -F'\t' 'NF>=4 && $3=="remove" {print $1}' | sort -u > "$TMP" || true
COUNT=$(wc -l < "$TMP" || echo 0)
echo "Duplicate removal candidates: $COUNT (mapping: $MAP_FILE)"
if [[ $COUNT -eq 0 ]]; then rm -f "$TMP"; echo "Nothing to do."; exit 0; fi
echo "Preview (up to 15):"; head -n 15 "$TMP"

if $DRY_RUN; then
  echo "Dry run: no files moved. Use --dry-run false or omit flag to apply."
  rm -f "$TMP"; exit 0
fi

"$TRASH_SCRIPT" -l "$TMP" --tag "$TAG" || { echo "Trash operation failed" >&2; rm -f "$TMP"; exit 1; }
rm -f "$TMP"
echo "Duplicates moved to trash snapshot (tag: $TAG). Review manifest then optionally purge later."
