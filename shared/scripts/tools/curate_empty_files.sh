#!/usr/bin/env bash
set -euo pipefail
# Filter empty_files.list to produce empty_files.curated excluding placeholder keepers.
IN=${1:-empty_files.list}
OUT=empty_files.curated
KEEP_REGEX='(__init__\.py$|\.gitkeep$|\.gitignore$|README\.md$|LICENSE$|Makefile$)'
if [[ ! -f $IN ]]; then echo "Input list not found: $IN" >&2; exit 1; fi
grep -Ev "$KEEP_REGEX" "$IN" | grep -Ev '/\.venv/|/site-packages/|/\.trash/' > "$OUT" || true
echo "Curated empty files -> $OUT (count: $(wc -l < $OUT))"
echo "Sample:"; head -n 20 "$OUT"
echo "Next: review then trash via: xargs -a $OUT -r -I{} echo {} | sed 's/^/ /'"
