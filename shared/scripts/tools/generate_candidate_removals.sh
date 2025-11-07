#!/usr/bin/env bash
set -euo pipefail
# Generate a list of files safe to remove (empty + tiny) excluding a keep whitelist.
# Run from repo root AFTER running scan_empty_files.sh and scan_small_files.sh

EMPTY_LIST=${EMPTY_LIST:-empty_files.list}
SMALL_LIST=${SMALL_LIST:-small_files.list}
OUT_LIST=candidate_removals.list
KEEP_LIST=small_files.keep

if [[ ! -f $EMPTY_LIST || ! -f $SMALL_LIST ]]; then
  echo "Run ./tools/scan_empty_files.sh and ./tools/scan_small_files.sh first." >&2
  exit 1
fi

# Default keep patterns (regex) - add to small_files.keep to extend
cat > ${KEEP_LIST}.default <<'PATTERNS'
# Python package markers
__init__\.py$
# Git sentinels
\.gitkeep$
\.gitignore$
\.gitattributes$
# Environment examples
^.*\.env(\..*)?$ 
# JS/TS config markers
.eslintrc.*$
.prettierrc.*$
# Build markers
Makefile$
# License / readme small variants
LICENSE$
README\.md$
# YAML framework placeholders
values\.ya?ml$
config\.ya?ml$
# Dist-info metadata (retain)
/dist-info/.*
# Rust fingerprint/build artifacts (retain for incremental builds)
/target/.*/fingerprint/
# Type declaration roots
\.d\.ts$
# Timestamp or log sentinel maybe keep
\.timestamp$
# Shell scripts even if small
\.sh$
PATTERNS

# Merge user keep list if exists
: > ${KEEP_LIST}.merged
if [[ -f $KEEP_LIST ]]; then
  cat ${KEEP_LIST}.default $KEEP_LIST > ${KEEP_LIST}.merged
else
  cp ${KEEP_LIST}.default ${KEEP_LIST}.merged
fi

# Build grep -E pattern joined by |, ignoring comments
KEEP_REGEX=$(grep -v '^#' ${KEEP_LIST}.merged | sed '/^$/d' | paste -sd'|' -)

# Combine empty + small (< args) lists then filter
cat "$EMPTY_LIST" "$SMALL_LIST" | sort -u | \
  grep -Ev "$KEEP_REGEX" > "$OUT_LIST" || true

TOTAL=$(wc -l < "$OUT_LIST" || echo 0)
KEPT=$(grep -Ec "$KEEP_REGEX" "$EMPTY_LIST" "$SMALL_LIST" 2>/dev/null || echo 0)

echo "Generated $OUT_LIST with $TOTAL candidate files to remove (kept patterns matched: $KEPT)."
echo "Review manually: head $OUT_LIST"
echo "Dry-run delete: xargs -a $OUT_LIST -r ls -l"
echo "Actual delete:  xargs -a $OUT_LIST -r git rm (if git) OR: xargs -a $OUT_LIST -r rm"
