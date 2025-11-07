#!/usr/bin/env bash
set -uo pipefail  # omit -e to manage errors manually inside loop

LIST_FILE="candidate_removals.list"
TRASH_ROOT=".trash"
DRY_RUN=false
LIMIT=""
SNAP_TS=""
TAG=""
VERBOSE=false

usage() {
  cat <<EOF
Usage: $0 [options]
  -l, --list FILE       List of files to trash (default: candidate_removals.list)
  -n, --dry-run         Show actions only, don't move files
  --limit N             Only process first N entries
  -t, --trash-dir DIR   Trash root directory (default: .trash)
  --tag NAME            Optional tag suffix for snapshot dir
  -v, --verbose         Verbose logging
  -h, --help            Show this help

Creates snapshot directory: .trash/YYYYMMDD_HHMMSS[_TAG]
Writes manifest: snapshot/manifest.tsv (orig_path\ttrashed_path)
Safe: will not overwrite existing files in trash; duplicates get numeric suffix.
Restore with: tools/restore_from_trash.sh --snapshot <dir>
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--list) LIST_FILE=$2; shift 2;;
    -n|--dry-run) DRY_RUN=true; shift;;
    --limit) LIMIT=$2; shift 2;;
    -t|--trash-dir) TRASH_ROOT=$2; shift 2;;
    --tag) TAG=$2; shift 2;;
  -v|--verbose) VERBOSE=true; shift;;
  -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ ! -f $LIST_FILE ]]; then
  echo "List file not found: $LIST_FILE" >&2; exit 1; fi

mkdir -p "$TRASH_ROOT"
SNAP_TS=$(date +%Y%m%d_%H%M%S)
SNAP_DIR="$TRASH_ROOT/${SNAP_TS}${TAG:+_$TAG}"
MANIFEST="$SNAP_DIR/manifest.tsv"

echo "Creating snapshot: $SNAP_DIR" >&2
$DRY_RUN || mkdir -p "$SNAP_DIR"
$DRY_RUN || : > "$MANIFEST"

count=0
processed=0
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  # Strip leading ./ if present
  orig="$path"
  [[ $orig == ./* ]] && rel=${orig#./} || rel=$orig
  # Skip if inside trash already
  if [[ $rel == $TRASH_ROOT/* ]]; then
    continue
  fi
  # Skip version control and common dependency/cache dirs
  case "$rel" in
    *.git|*.git/*|.git/*|*/.git|*/.git/*) continue;;
    node_modules/*|*/node_modules/*) continue;;
    *.venv/*|.venv/*|*/.venv/*) continue;;
    target/*|*/target/*) continue;;
  *dist-info/*) continue;;
  *egg-info/*) : ;; # allow egg-info small text files to be trashed if desired
  esac
  ((count++))
  if [[ -n $LIMIT && $count -gt $LIMIT ]]; then
    break
  fi
  if [[ ! -e $rel ]]; then
    continue
  fi
  # Skip directories; we only trash individual files
  if [[ -d $rel ]]; then
    continue
  fi
  # Determine destination path (mirror original path under files/ subtree to avoid collision with metadata)
  dest_dir="$SNAP_DIR/files/$(dirname "$rel")"
  dest_file="$SNAP_DIR/files/$rel"
  if [[ -e $dest_file ]]; then
    # add numeric suffix
    i=1
    while [[ -e ${dest_file}__${i} ]]; do i=$((i+1)); done
    dest_file=${dest_file}__${i}
  fi
  $VERBOSE && echo "TRASH: $rel -> ${dest_file#$SNAP_DIR/}" >&2
  if ! $DRY_RUN; then
    mkdir -p "$dest_dir" || { echo "WARN: mkdir failed for $dest_dir" >&2; continue; }
    if mv "$rel" "$dest_file" 2>/dev/null; then
      echo -e "$rel\t${dest_file#$SNAP_DIR/}" >> "$MANIFEST"
      $VERBOSE && echo "MOVED: $rel" >&2
    else
      echo "WARN: Failed to move $rel (permission/lock)" >&2
      continue
    fi
  fi
  ((processed++))
done < "$LIST_FILE"

echo "Processed $processed files (limit=${LIMIT:-none})" >&2
if $DRY_RUN; then
  echo "Dry run complete. No files moved." >&2
else
  echo "Snapshot manifest: $MANIFEST" >&2
fi
