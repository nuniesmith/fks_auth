#!/usr/bin/env bash
## fks_master/docs cleanup & consolidation utility
## Goals (Step 1 / Prompt 1):
##  - Capture a reproducible snapshot of current docs structure
##  - Detect duplicate file contents (hash based) using shared tool
##  - Archive high‑churn / noisy historical docs (e.g. GITHUB_ACTIONS_*, GITHUB_SECRETS_*)
##  - Produce a post‑move structure + summary report
##  - Support dry‑run (-n) and verbose (-v) modes
##
## Safe idempotent operation: repeated runs won't re‑move already archived files.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/cleanup_docs.sh [options]
  -n, --dry-run    Show planned actions only (no file moves)
  -v, --verbose    Verbose logging
  -h, --help       This help

Environment overrides:
  DOCS_DIR   Directory containing docs (default: repo_root/docs)

Archive strategy:
  Patterns in TOP_LEVEL_PATTERNS are moved from docs/ -> docs/archived/github_actions_auto/
  unless already present under docs/archived/.

Reports:
  docs/cleanup_reports/file_structure_pre.txt
  docs/cleanup_reports/file_structure_post.txt
  docs/cleanup_reports/duplicates_docs.report (hash duplicate groups inside docs)
  docs/cleanup_reports/summary_<timestamp>.md

Dry run prints planned moves prefixed with DRY-RUN: .
EOF
}

DRY_RUN=false
VERBOSE=false
for arg in "$@"; do
  case "$arg" in
    -n|--dry-run) DRY_RUN=true ; shift ;;
    -v|--verbose) VERBOSE=true ; shift ;;
    -h|--help) usage; exit 0 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOCS_DIR=${DOCS_DIR:-"$ROOT_DIR/docs"}
ARCHIVE_PARENT="$DOCS_DIR/archived"
ARCHIVE_BUCKET="$ARCHIVE_PARENT/github_actions_auto"
REPORT_DIR="$DOCS_DIR/cleanup_reports"
TOOLS_DIR="$ROOT_DIR/shared/scripts/tools"

mkdir -p "$ARCHIVE_BUCKET" "$REPORT_DIR"

log() { echo "[cleanup_docs] $*"; }
vlog() { $VERBOSE && echo "[cleanup_docs][debug] $*" || true; }

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# 1. Capture pre structure
PRE_STRUCT="$REPORT_DIR/file_structure_pre.txt"
if command -v git >/dev/null 2>&1; then
  (cd "$ROOT_DIR" && git ls-files docs | sort > "$PRE_STRUCT") || true
fi
if [ ! -s "$PRE_STRUCT" ]; then
  (cd "$DOCS_DIR" && find . -type f | sed 's#^./##' | sort > "$PRE_STRUCT")
fi

# 2. Duplicate detection (docs scope only)
if [ -f "$TOOLS_DIR/find_duplicates.sh" ]; then
  ( cd "$DOCS_DIR" && bash "$TOOLS_DIR/find_duplicates.sh" >/dev/null 2>&1 || true )
  [ -f "$DOCS_DIR/duplicates.report" ] && mv "$DOCS_DIR/duplicates.report" "$REPORT_DIR/duplicates_docs.report" || true
else
  log "WARN: find_duplicates.sh not found at $TOOLS_DIR"
fi

# 3. Determine archival candidates
TOP_LEVEL_PATTERNS=(
  'GITHUB_ACTIONS_*.md'
  'GITHUB_SECRETS_*.md'
  'GITHUB_SECRETS*.md'
  'SSL_*SUMMARY.md'
  'WORKFLOW_*SUMMARY.md'
)

PROTECTED_FILES=(ARCHITECTURE_OVERVIEW.md README.md INDEX.md SECURITY_IMPLEMENTATION_GUIDE.md SECURITY_OPTIMIZATION_STRATEGY.md)

should_protect() {
  local f=$1; for p in "${PROTECTED_FILES[@]}"; do [ "$p" = "$f" ] && return 0; done; return 1;
}

declare -a MOVES=()
for pattern in "${TOP_LEVEL_PATTERNS[@]}"; do
  while IFS= read -r -d '' f; do
    base=$(basename "$f")
    should_protect "$base" && continue
    # Skip if already in any archived subdir
    [[ "$f" == *"/archived/"* ]] && continue
    # Skip if identical name already exists inside archived bucket
    if [ -f "$ARCHIVE_BUCKET/$base" ]; then
      vlog "Skip (already archived): $base"
      continue
    fi
    MOVES+=("$f")
  done < <(find "$DOCS_DIR" -maxdepth 1 -type f -name "$pattern" -print0 2>/dev/null || true)
done

# 4. Execute moves
for src in "${MOVES[@]:-}"; do
  [ -n "$src" ] || continue
  dest="$ARCHIVE_BUCKET/$(basename "$src")"
  if $DRY_RUN; then
    echo "DRY-RUN: mv '$src' '$dest'"
  else
    mv "$src" "$dest"
    log "Archived: $(basename "$src")"
  fi
done

# 5. Capture post structure (reflects actual move or theoretical if dry run)
POST_STRUCT="$REPORT_DIR/file_structure_post.txt"
if $DRY_RUN; then
  # Simulated: copy pre + appended archive listing markers
  cp "$PRE_STRUCT" "$POST_STRUCT"
  for src in "${MOVES[@]:-}"; do
    base=$(basename "$src")
    # Replace line path with archived path notation
    sed -i "s#^${base}$#archived/github_actions_auto/${base} (WOULD MOVE)#" "$POST_STRUCT" || true
  done
else
  if command -v git >/dev/null 2>&1; then
    (cd "$ROOT_DIR" && git ls-files docs | sort > "$POST_STRUCT") || true
  fi
  if [ ! -s "$POST_STRUCT" ]; then
    (cd "$DOCS_DIR" && find . -type f | sed 's#^./##' | sort > "$POST_STRUCT")
  fi
fi

# 6. Summarize
SUMMARY="$REPORT_DIR/summary_$(date -u +%Y%m%dT%H%M%SZ).md"
{
  echo "# Docs Cleanup Summary ($(timestamp))"
  echo
  echo "Dry run: $DRY_RUN"
  echo "Moved files: ${#MOVES[@]}"
  if [ ${#MOVES[@]} -gt 0 ]; then
    echo "\n## Archived Files"; for f in "${MOVES[@]}"; do echo "- $(basename "$f")"; done
  fi
  if [ -f "$REPORT_DIR/duplicates_docs.report" ]; then
    echo "\n## Duplicate Groups Detected"
    grep '^HASH ' "$REPORT_DIR/duplicates_docs.report" | wc -l | awk '{print "Groups: "$1}'
  fi
  echo "\n## Recommendations"
  echo "- Review archived/github_actions_auto/ for any docs that should remain top-level."
  echo "- Consider merging similar GitHub Actions docs into a single CHANGELOG style history file."
  echo "- Convert static secrets docs into a single redacted SECRETS_REFERENCE.md if appropriate."
} > "$SUMMARY"

log "Complete. Summary: $SUMMARY"
${DRY_RUN} && log "(dry-run mode: no files moved)"
