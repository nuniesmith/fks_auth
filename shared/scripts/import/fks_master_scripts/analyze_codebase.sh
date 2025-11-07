#!/usr/bin/env bash
set -euo pipefail
# analyze_codebase.sh
# Lightweight repository analysis producing counts of key file types, TODO/FIXME density,
# average lines per file for major languages, and top 10 largest source files.
# Usage:
#   ./fks_master/scripts/analyze_codebase.sh [--json report.json] [--top 15] [--root <path>] [--exclude path1,path2]
# Example:
#   ./fks_master/scripts/analyze_codebase.sh --json analysis.json --top 20
#
# Output sections:
#  - File type counts (by extension)
#  - TODO / FIXME counts and density
#  - Average line length per language
#  - Top N largest files (lines)
#  - Summary JSON (optional)

ROOT="${PWD}"
TOP=10
JSON_OUT=""
EXCLUDES=()

log(){ echo "[analyze] $1"; }
err(){ echo "[analyze][err] $1" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_OUT=$2; shift 2;;
    --top) TOP=$2; shift 2;;
    --root) ROOT=$2; shift 2;;
    --exclude) IFS=',' read -r -a EXCLUDES <<< "$2"; shift 2;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) err "Unknown arg $1"; exit 1;;
  esac
done

cd "$ROOT"

EX_ARGS=()
for e in "${EXCLUDES[@]}"; do
  EX_ARGS+=( -path "./$e" -prune -o )
done

# Collect files (exclude .git and bundles by default)
MAPFILE -t FILES < <(eval find . -type d -name .git -prune -o -type f ! -name '*.bundle' -print)

# Data structures
# shellcheck disable=SC2034
EXT_COUNTS=()
TOTAL_LINES=0
LANG_LINES=()
TODO_COUNT=0
FIXME_COUNT=0

# Helper to map extension to logical language key
lang_key(){
  case "$1" in
    py) echo python;;
    rs) echo rust;;
    ts|tsx|js|jsx) echo node;;
    sh) echo shell;;
    md) echo markdown;;
    yml|yaml) echo yaml;;
    toml) echo toml;;
    cs) echo csharp;;
    *) echo other;;
  esac
}

# Temporary file for size ranking
TMP_SIZES=$(mktemp)
trap 'rm -f "$TMP_SIZES"' EXIT

for f in "${FILES[@]}"; do
  # Skip excluded paths
  SKIP=false
  for e in "${EXCLUDES[@]}"; do
    [[ $f == ./$e/* ]] && SKIP=true && break
  done
  $SKIP && continue

  ext=${f##*.}
  [[ $ext == $f ]] && ext="(none)"
  lines=$(wc -l < "$f" || echo 0)
  TOTAL_LINES=$((TOTAL_LINES + lines))
  EXT_COUNTS[$ext]=$(( ${EXT_COUNTS[$ext]:-0} + 1 ))
  lang=$(lang_key "$ext")
  LANG_LINES[$lang]=$(( ${LANG_LINES[$lang]:-0} + lines ))
  # TODO / FIXME search (simple)
  if grep -q 'TODO' "$f" 2>/dev/null; then
    c=$(grep -c 'TODO' "$f" || echo 0); TODO_COUNT=$((TODO_COUNT + c)); fi
  if grep -q 'FIXME' "$f" 2>/dev/null; then
    c=$(grep -c 'FIXME' "$f" || echo 0); FIXME_COUNT=$((FIXME_COUNT + c)); fi
  echo -e "$lines\t$f" >> "$TMP_SIZES"
done

log "File type counts:" | sed 's/^//' # no-op for style
for k in "${!EXT_COUNTS[@]}"; do
  printf '%8s  %5d\n' "$k" "${EXT_COUNTS[$k]}"
done | sort

log "\nLines per logical language:" 
for k in "${!LANG_LINES[@]}"; do
  printf '%12s  %7d\n' "$k" "${LANG_LINES[$k]}"
done | sort

TOTAL_TODO=$((TODO_COUNT + FIXME_COUNT))
DENSITY=0
[[ $TOTAL_LINES -gt 0 ]] && DENSITY=$(( (TOTAL_TODO * 1000) / TOTAL_LINES )) # per 1k lines

echo -e "\nTODO: $TODO_COUNT  FIXME: $FIXME_COUNT  (density: ${DENSITY} per 1000 LOC)"

echo -e "\nTop $TOP largest files (by lines):"
sort -nr "$TMP_SIZES" | head -n "$TOP" | awk -F'\t' '{printf "%7d  %s\n", $1, $2}'

if [[ -n $JSON_OUT ]]; then
  {
    echo '{'
    echo '  "total_lines":' "$TOTAL_LINES",','
    echo '  "todo":' "$TODO_COUNT",','
    echo '  "fixme":' "$FIXME_COUNT",','
    echo '  "todo_fixme_density_per_1k":' "$DENSITY",','
    echo '  "ext_counts": {'
    first=true
    for k in "${!EXT_COUNTS[@]}"; do
      $first || echo ','
      printf '    "%s": %d' "$k" "${EXT_COUNTS[$k]}"
      first=false
    done
    echo -e '\n  },'
    echo '  "lang_lines": {'
    first=true
    for k in "${!LANG_LINES[@]}"; do
      $first || echo ','
      printf '    "%s": %d' "$k" "${LANG_LINES[$k]}"
      first=false
    done
    echo -e '\n  },'
    echo '  "top_files": ['
    sort -nr "$TMP_SIZES" | head -n "$TOP" | awk -F'\t' '{printf "    {\"lines\": %s, \"path\": \"%s\"},\n", $1, $2}' | sed '$ s/,$//'
    echo '  ]'
    echo '}'
  } > "$JSON_OUT"
  log "Wrote JSON report to $JSON_OUT"
fi

log "Done"
