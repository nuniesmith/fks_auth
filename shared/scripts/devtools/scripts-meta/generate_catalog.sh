#!/usr/bin/env bash
# Purpose: Generate a markdown catalog of scripts with Purpose lines.
# Output: devtools/scripts-meta/catalog.md
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/devtools/scripts-meta/catalog.md"

collect() {
  grep -RIl "^# Purpose:" "$ROOT" --include='*.sh' || true
}

parse() {
  local file
  while read -r file; do
    local purpose
    purpose=$(grep -m1 '^# Purpose:' "$file" | sed 's/^# Purpose:[[:space:]]*//') || purpose="(missing)"
    local rel
    rel=${file#"$ROOT/"}
    printf '| %s | %s |\n' "$rel" "$purpose"
  done
}

{
  echo '# Script Catalog'
  echo
  echo '| Path | Purpose |'
  echo '| ---- | ------- |'
  collect | parse | sort
} > "$OUT"

echo "Catalog written to $OUT" >&2
