#!/usr/bin/env bash
set -euo pipefail
# Find files under size threshold (default 100 bytes) excluding .git and backups
THRESHOLD=${1:-100}
PRUNE_DIRS='( -path "*/.git" -o -path "*fks_backup_*" )'
# shellcheck disable=SC2016
find . -type f -size -${THRESHOLD}c \
  -not -path '*/.git/*' \
  -not -path '*fks_backup_*/*' \
  -not -path '*/.trash/*' \
  -not -path '*/node_modules/*' \
  -not -path '*/target/*' \
  -not -path '*/.venv/*' \
  -print | sort > small_files.list

# Summarize by extension
awk -F. 'NF>1 {ext=$NF} NF==1 {ext="(noext)"} {count[ext]++} END {for (e in count) printf "%6d %s\n", count[e], e | "sort -nr"}' small_files.list > small_files.summary

echo "Listed $(wc -l < small_files.list) files under ${THRESHOLD} bytes into small_files.list"
echo "Extension summary -> small_files.summary"

echo "Next: review and refine keep list (small_files.keep) OR run ./tools/generate_candidate_removals.sh"
