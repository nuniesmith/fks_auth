#!/usr/bin/env bash
set -euo pipefail
REPORT=${1:-CLEANUP_REPORT.md}

# Collect manifests
mapfile -t MANIFESTS < <(find .trash -maxdepth 2 -type f -name manifest.tsv | sort || true)
TOTAL=0
TMP=$(mktemp)
: > "$TMP"
SNAP_TABLE=$(mktemp)
: > "$SNAP_TABLE"

for m in "${MANIFESTS[@]}"; do
  [ -f "$m" ] || continue
  COUNT=$(grep -c "" "$m" || true)
  SNAP=${m#*.trash/}
  SNAP=${SNAP%/manifest.tsv}
  printf "%s\t%d\n" "$SNAP" "$COUNT" >> "$SNAP_TABLE"
  TOTAL=$((TOTAL+COUNT))
  awk -F"\t" 'NF>0{print $1}' "$m" >> "$TMP"
done

sort -u "$TMP" > moved_files.list

# Stats by root directory (second path component)
awk -F/ 'NF>1 {root=$2} NF<=1 {root="."} {count[root]++} END {for (r in count) printf "%s\t%d\n", r, count[r]}' moved_files.list | sort -k2,2nr > moved_by_root.tsv

# Stats by extension
awk -F. 'NF>1 {ext=$NF} NF==1 {ext="(noext)"} {count[ext]++} END {for (e in count) printf "%s\t%d\n", e, count[e]}' moved_files.list | sort -k2,2nr > moved_by_ext.tsv

# Top basenames
awk -F/ '{print $NF}' moved_files.list | sort | uniq -c | sort -nr | head -n 25 > moved_top_basenames.txt

{
  echo "# Repository Cleanup Report"
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## Snapshot Summary"
  echo
  echo '| Snapshot | Files |'
  echo '|----------|-------|'
  while IFS=$'\t' read -r s c; do printf '| %s | %s |\n' "$s" "$c"; done < "$SNAP_TABLE"
  echo "| Total | $TOTAL |"
  echo
  echo "## Moved Files by Top-Level Directory"
  echo
  echo '| Root | Count |'
  echo '|------|-------|'
  while IFS=$'\t' read -r r c; do printf '| %s | %s |\n' "$r" "$c"; done < moved_by_root.tsv
  echo
  echo "## Moved Files by Extension (Top 20)"
  echo
  echo '| Extension | Count |'
  echo '|-----------|-------|'
  head -n 20 moved_by_ext.tsv | while IFS=$'\t' read -r e c; do printf '| %s | %s |\n' "$e" "$c"; done
  echo
  echo "## Most Frequent Basenames (Top 25)"
  echo '```'
  cat moved_top_basenames.txt
  echo '```'
  echo
  echo '## Notes'
  echo '- Files are stored under .trash/<snapshot>/files/ with original relative paths.'
  echo '- Restore with tools/restore_from_trash.sh.'
  echo '- Consider purging snapshots after verification: tools/purge_trash.sh -n / then run without -n.'
  echo
  echo '## Restore Example'
  echo '```bash'
  if [ ${#MANIFESTS[@]} -gt 0 ]; then echo "./tools/restore_from_trash.sh --snapshot ${SNAP} --limit 1 -n"; else echo '# (No snapshots found)'; fi
  echo '```'
} > "$REPORT"

echo "Created report: $REPORT (Total moved: $TOTAL)"
