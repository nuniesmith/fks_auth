#!/usr/bin/env bash
set -euo pipefail

TRASH_ROOT=".trash"
SNAPSHOT=""
DRY_RUN=false
LIMIT=""
OVERWRITE=false

usage() {
  cat <<EOF
Usage: $0 --snapshot DIR [options]
  --snapshot DIR   Snapshot directory name under .trash (e.g. 20250825_120000_tag)
  -t DIR           Trash root if not .trash
  -n, --dry-run    Show actions without restoring
  --limit N        Only restore first N entries
  --overwrite      Overwrite existing files (default: skip if exists)
  -h, --help       Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --snapshot) SNAPSHOT=$2; shift 2;;
    -t) TRASH_ROOT=$2; shift 2;;
    -n|--dry-run) DRY_RUN=true; shift;;
    --limit) LIMIT=$2; shift 2;;
    --overwrite) OVERWRITE=true; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z $SNAPSHOT ]]; then echo "--snapshot required" >&2; exit 1; fi
SNAP_DIR="$TRASH_ROOT/$SNAPSHOT"
MANIFEST="$SNAP_DIR/manifest.tsv"
if [[ ! -f $MANIFEST ]]; then echo "Manifest not found: $MANIFEST" >&2; exit 1; fi

count=0
restored=0
while IFS=$'\t' read -r orig trashed; do
  [[ -z $orig ]] && continue
  src="$SNAP_DIR/$trashed"
  dest="$orig"
  if [[ ! -e $src ]]; then
    echo "Missing source in trash: $src" >&2
    continue
  fi
  mkdir -p "$(dirname "$dest")"
  ((count++))
  if [[ -n $LIMIT && $count -gt $LIMIT ]]; then break; fi
  if [[ -e $dest && $OVERWRITE = false ]]; then
    echo "SKIP (exists): $dest" >&2
    continue
  fi
  echo "RESTORE: $trashed -> $dest" >&2
  if ! $DRY_RUN; then
    mv -f "$src" "$dest"
  fi
  ((restored++))
done < "$MANIFEST"

echo "Restored $restored files (limit=${LIMIT:-none})" >&2
