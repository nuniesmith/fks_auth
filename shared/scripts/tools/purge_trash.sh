#!/usr/bin/env bash
set -euo pipefail
TRASH_ROOT=".trash"
AGE_DAYS=30
DRY_RUN=false

usage(){ cat <<EOF
Usage: $0 [options]
  -t DIR       Trash root (default .trash)
  -a DAYS      Delete snapshots older than DAYS (default 30)
  -n           Dry run
  -h           Help
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -t) TRASH_ROOT=$2; shift 2;;
    -a) AGE_DAYS=$2; shift 2;;
    -n) DRY_RUN=true; shift;;
    -h) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1;;
  esac
done

[[ -d $TRASH_ROOT ]] || { echo "No trash dir ($TRASH_ROOT)"; exit 0; }
CUTOFF=$(date -d "-$AGE_DAYS days" +%s)

find "$TRASH_ROOT" -mindepth 1 -maxdepth 1 -type d | while read -r snap; do
  mt=$(stat -c %Y "$snap" 2>/dev/null || echo 0)
  if (( mt < CUTOFF )); then
    echo "PURGE: $snap"
    $DRY_RUN || rm -rf "$snap"
  fi
done
