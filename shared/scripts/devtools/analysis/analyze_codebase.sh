#!/usr/bin/env bash
# Purpose: Multi-language codebase analysis generating structure, summaries, optional contents, lint, and JSON outputs.
# Usage: analyze_codebase.sh [--full] [--lint] [--json] [--max-bytes=N] [--out=DIR] <path>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/lib/log.sh"
source "$ROOT/lib/error.sh"
source "$ROOT/lib/validate.sh"

FULL=0 LINT=0 JSON=0 MAX_BYTES=$((1024*1024)) OUT_DIR="" TARGET=""

usage(){ cat <<EOF
Usage: $0 [options] <path>
  --full             Include file content dump
  --lint             Run available linters
  --json             Emit machine-readable summary.json
  --max-bytes=N      Max single file size for content dump (default $MAX_BYTES)
  --out=DIR          Output directory (default auto timestamp)
  --help             Show help
EOF
}

for arg in "$@"; do :; done
while [[ $# -gt 0 ]]; do
  case $1 in
    --full) FULL=1;;
    --lint) LINT=1;;
    --json) JSON=1;;
    --max-bytes=*) MAX_BYTES="${1#*=}";;
    --out=*) OUT_DIR="${1#*=}";;
    --help|-h) usage; exit 0;;
    --*) die "Unknown flag: $1" 2;;
    *) TARGET="$1";;
  esac; shift || true
done

[[ -n "$TARGET" && -d "$TARGET" ]] || die "Provide a valid directory path" 1
[[ -n "$OUT_DIR" ]] || OUT_DIR="codebase_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

log_info "Analyzing: $TARGET"
log_info "Output dir: $OUT_DIR"
log_info "Full dump: $FULL | Lint: $LINT | JSON: $JSON"

# Exclusion pattern (find clauses)
EXCLUDES=(
  -not -path '*/.*' -not -path '*/__pycache__/*' -not -path '*/.pytest_cache/*'
  -not -path '*/.mypy_cache/*' -not -path '*/.tox/*' -not -path '*/venv/*'
  -not -path '*/env/*' -not -path '*/.env/*' -not -path '*/node_modules/*'
  -not -path '*/target/*' -not -path '*/bin/*' -not -path '*/obj/*'
  -not -path '*/.vs/*' -not -path '*/.idea/*' -not -path '*/.vscode/*'
  -not -path '*/coverage/*' -not -path '*/dist/*' -not -path '*/build/*'
)

find_cmd() { find "$TARGET" "${EXCLUDES[@]}" "$@" 2>/dev/null; }

STRUCTURE_FILE="$OUT_DIR/file_structure.txt"
log_info "Generating structure"; if command -v tree >/dev/null 2>&1; then
  tree -n -I "__pycache__|.git|.pytest_cache|.mypy_cache|.tox|venv|env|.env|node_modules|target|bin|obj|.vs|.idea|.vscode|coverage|dist|build" "$TARGET" > "$STRUCTURE_FILE" || true
else
  find_cmd -type f -o -type d | sort | sed 's/[^/]*\//|   /g;s/| *\([^| ]\)/+--- \1/g' > "$STRUCTURE_FILE" || true
fi

# Summary
SUMMARY="$OUT_DIR/summary.txt"
echo "CODEBASE SUMMARY" > "$SUMMARY"
echo "Target: $TARGET" >> "$SUMMARY"
echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$SUMMARY"
echo "" >> "$SUMMARY"

all_files=$(find_cmd -type f | wc -l | awk '{print $1}')
total_bytes=$(find_cmd -type f -exec stat -c%s {} + 2>/dev/null | awk '{s+=$1} END{print s+0}')
avg_bytes=0; [[ $all_files -gt 0 ]] && avg_bytes=$(( total_bytes / all_files ))
printf 'Files: %s\nTotal Bytes: %s\nAvg Bytes: %s\n' "$all_files" "$total_bytes" "$avg_bytes" >> "$SUMMARY"

echo "\nExtension counts:" >> "$SUMMARY"
find_cmd -type f | grep -E '\.[A-Za-z0-9]+$' | sed 's/.*\.//' | sort | uniq -c | sort -nr >> "$SUMMARY" || true

echo "\nEmpty files:" >> "$SUMMARY"; find_cmd -type f -size 0 | sort >> "$SUMMARY" || true
echo "\nSmall (<100B) files:" >> "$SUMMARY"; find_cmd -type f -size -100c ! -size 0 | sort >> "$SUMMARY" || true

# Language counters
count_py=$(find_cmd -name '*.py' | wc -l | awk '{print $1}')
count_rs=$(find_cmd -name '*.rs' | wc -l | awk '{print $1}')
count_cs=$(find_cmd -name '*.cs' | wc -l | awk '{print $1}')
count_js=$(find_cmd -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' | wc -l | awk '{print $1}')
count_java=$(find_cmd -name '*.java' | wc -l | awk '{print $1}')
count_go=$(find_cmd -name '*.go' | wc -l | awk '{print $1}')

printf '\nLanguage counts:\nPython: %s\nRust: %s\nC#: %s\nJS/TS: %s\nJava: %s\nGo: %s\n' \
  "$count_py" "$count_rs" "$count_cs" "$count_js" "$count_java" "$count_go" >> "$SUMMARY"

# Patterns (lightweight grep; ignore errors)
echo "\nPattern metrics:" >> "$SUMMARY"
pat() { local label=$1 expr=$2; local c; c=$(grep -ri --include='*.{py,rs,cs,java,js,ts,go}' -E "$expr" "$TARGET" 2>/dev/null | wc -l); printf '%s: %s\n' "$label" "$c" >> "$SUMMARY"; }
pat 'Design constructs' 'interface|abstract|factory|observer|singleton|builder|adapter'
pat 'Error handling' 'try|catch|except|panic|unwrap|Result|Option|error'
pat 'Async/Concurrent' 'async|await|thread|spawn|tokio|Task|Promise|goroutine|channel'
pat 'Testing refs' 'test|assert|mock|junit|pytest|jest|\[test\]|nunit|xunit'

# File contents (optional)
if (( FULL )); then
  CONTENTS="$OUT_DIR/file_contents.txt"
  echo "FILE CONTENTS (filtered)" > "$CONTENTS"
  find_cmd -type f | while read -r f; do
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    [[ $size -gt $MAX_BYTES ]] && { echo "SKIP $f ($size bytes)" >> "$CONTENTS"; continue; }
    echo "==== $f ($size bytes) ====" >> "$CONTENTS"
    [[ $size -eq 0 ]] && echo "<EMPTY>" >> "$CONTENTS"
    cat "$f" >> "$CONTENTS" 2>/dev/null || echo "<UNREADABLE>" >> "$CONTENTS"
    echo >> "$CONTENTS"
  done
fi

# Lint (best-effort)
if (( LINT )); then
  LINT_OUT="$OUT_DIR/lint_report.txt"
  echo "LINT REPORT" > "$LINT_OUT"
  if (( count_py )) && command -v ruff >/dev/null 2>&1; then
    log_info "Running ruff"; ruff check "$TARGET" >> "$LINT_OUT" 2>&1 || true
  fi
  if (( count_rs )) && command -v cargo >/dev/null 2>&1; then
    log_info "Running cargo fmt --check"; (cd "$TARGET" && cargo fmt -- --check) >> "$LINT_OUT" 2>&1 || true
  fi
  if (( count_js )) && command -v eslint >/dev/null 2>&1; then
    log_info "Running eslint"; eslint "$TARGET" >> "$LINT_OUT" 2>&1 || true
  fi
fi

# JSON summary (compact)
if (( JSON )); then
  JSON_FILE="$OUT_DIR/summary.json"
  cat > "$JSON_FILE" <<EOF
{
  "target": "${TARGET}",
  "generated_utc": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "files": ${all_files},
  "total_bytes": ${total_bytes},
  "avg_bytes": ${avg_bytes},
  "languages": {
    "python": ${count_py},
    "rust": ${count_rs},
    "csharp": ${count_cs},
    "js_ts": ${count_js},
    "java": ${count_java},
    "go": ${count_go}
  },
  "options": { "full": ${FULL}, "lint": ${LINT} }
}
EOF
fi

log_success "Analysis complete. Artifacts in $OUT_DIR"
echo "Structure: $STRUCTURE_FILE"
echo "Summary:   $SUMMARY"
(( FULL )) && echo "Contents:  $CONTENTS"
(( LINT )) && echo "Lint:      $LINT_OUT"
(( JSON )) && echo "JSON:      $JSON_FILE"
