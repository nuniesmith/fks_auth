#!/usr/bin/env bash
set -euo pipefail

# report_frontend.sh
# Build the React frontend and emit a JSON bundle metrics summary to stdout (and optionally a file).
# Designed to be CI-friendly: stable keys, deterministic ordering.
# Usage:
#   scripts/perf/report_frontend.sh [--out reports/performance/$(date +%Y%m%d-%H%M%S).json] [--cwd src/web/react]
# Env:
#   FKS_PERF_BUDGET_VENDOR_MAX (kB)
#   FKS_PERF_BUDGET_EAGER_CHUNK_MAX (kB)
#   FKS_PERF_BUDGET_VENDOR_GZIP_MAX (kB, optional)
#   FKS_PERF_BUDGET_EAGER_CHUNK_GZIP_MAX (kB, optional)
# Exits non-zero if build fails OR budgets exceeded.

OUT_FILE=""
APP_CWD="src/web/react"
VENDOR_MAX_KB="${FKS_PERF_BUDGET_VENDOR_MAX:-340}"
EAGER_MAX_KB="${FKS_PERF_BUDGET_EAGER_CHUNK_MAX:-110}"
VENDOR_GZIP_MAX_KB="${FKS_PERF_BUDGET_VENDOR_GZIP_MAX:-}"
EAGER_GZIP_MAX_KB="${FKS_PERF_BUDGET_EAGER_CHUNK_GZIP_MAX:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT_FILE="$2"; shift 2;;
    --cwd)
      APP_CWD="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ ! -d "$APP_CWD" ]]; then
  echo "ERROR: directory $APP_CWD not found" >&2
  exit 1
fi

pushd "$APP_CWD" >/dev/null

# Prefer existing install; do not auto-run npm install (CI should handle caching). Validate lockfile.
if [[ ! -f package.json ]]; then
  echo "ERROR: package.json missing in $APP_CWD" >&2
  exit 1
fi

# Build with verbose output captured.
BUILD_LOG=$(mktemp)
if ! npm run build --silent | tee "$BUILD_LOG" >/dev/null; then
  echo "ERROR: build failed" >&2
  exit 1
fi

# Attempt to locate a stats file (if configured). Fallback: parse dist file sizes.
DIST_DIR="dist"
if [[ ! -d "$DIST_DIR" ]]; then
  # Vite default is 'dist'; if different, attempt simple detection.
  ALT=$(find . -maxdepth 2 -type d -name build -o -name dist 2>/dev/null | head -n1)
  if [[ -n "$ALT" ]]; then
    DIST_DIR="$ALT"
  fi
fi

if [[ ! -d "$DIST_DIR" ]]; then
  echo "ERROR: Could not find build output directory" >&2
  exit 1
fi

# Collect JS bundles (excluding sourcemaps) and sizes (kB, 1 decimal).
mapfile -t FILES < <(find "$DIST_DIR" -type f -name '*.js' ! -name '*.map' | sort)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "ERROR: no JS bundles found" >&2
  exit 1
fi

# Determine vendor and eager heuristic: vendor = file containing 'vendor' or 'react-dom'.
# Eager chunk heuristic: all non-dynamic import chunks (approx: those without 'async' or hash-only naming). This is build-tool specific; we keep simple.
VENDOR_SIZE_KB=0
LARGEST_EAGER_KB=0
TOTAL_JS_KB=0
VENDOR_GZIP_KB=0
LARGEST_EAGER_GZIP_KB=0

# We will build a JSON array manually.
BUNDLES_JSON="["
FIRST=1
for f in "${FILES[@]}"; do
  size_bytes=$(stat -c%s "$f")
  size_kb=$(awk -v b=$size_bytes 'BEGIN { printf "%.1f", b/1024 }')
  # gzip size
  if command -v gzip >/dev/null 2>&1; then
    gzip_bytes=$(gzip -c "$f" | wc -c | awk '{print $1}')
    gzip_kb=$(awk -v b=$gzip_bytes 'BEGIN { printf "%.1f", b/1024 }')
  else
    gzip_kb="null"
  fi
  # brotli size
  if command -v brotli >/dev/null 2>&1; then
    brotli_bytes=$(brotli -c "$f" | wc -c | awk '{print $1}')
    brotli_kb=$(awk -v b=$brotli_bytes 'BEGIN { printf "%.1f", b/1024 }')
  else
    brotli_kb="null"
  fi
  TOTAL_JS_KB=$(awk -v t=$TOTAL_JS_KB -v s=$size_kb 'BEGIN { printf "%.1f", t + s }')
  base=$(basename "$f")
  # vendor detection
  if [[ "$base" == *vendor* || "$base" == *react-dom* ]]; then
    VENDOR_SIZE_KB=$(awk -v v=$VENDOR_SIZE_KB -v s=$size_kb 'BEGIN { printf "%.1f", v + s }')
    if [[ "$gzip_kb" != "null" ]]; then
      VENDOR_GZIP_KB=$(awk -v v=$VENDOR_GZIP_KB -v s=$gzip_kb 'BEGIN { printf "%.1f", v + s }')
    fi
  fi
  # naive eager detection: treat files without 'lazy' or 'async' in name as eager
  if [[ "$base" != *lazy* && "$base" != *async* ]]; then
    awk_comp=$(awk -v cur=$LARGEST_EAGER_KB -v s=$size_kb 'BEGIN { if (s>cur) printf "%.1f", s; else printf "%.1f", cur }')
    LARGEST_EAGER_KB=$awk_comp
    if [[ "$gzip_kb" != "null" ]]; then
      awk_comp_gzip=$(awk -v cur=$LARGEST_EAGER_GZIP_KB -v s=$gzip_kb 'BEGIN { if (s>cur) printf "%.1f", s; else printf "%.1f", cur }')
      LARGEST_EAGER_GZIP_KB=$awk_comp_gzip
    fi
  fi
  # append to JSON
  escaped_name=$(printf '%s' "$base" | sed 's/"/\\"/g')
  if [[ $FIRST -eq 1 ]]; then
    FIRST=0
  else
    BUNDLES_JSON+=" ,"
  fi
  # embed gzip/brotli if numeric, else null
  if [[ "$gzip_kb" == "null" ]]; then
    gzip_field="null"
  else
    gzip_field=$gzip_kb
  fi
  if [[ "$brotli_kb" == "null" ]]; then
    brotli_field="null"
  else
    brotli_field=$brotli_kb
  fi
  BUNDLES_JSON+="{\"file\":\"$escaped_name\",\"kb\":$size_kb,\"gzip_kb\":$gzip_field,\"brotli_kb\":$brotli_field}"
done
BUNDLES_JSON+="]"

TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

read -r -d '' SUMMARY_JSON <<EOF || true
{
  "timestamp": "$TIMESTAMP",
  "vendor_kb": $VENDOR_SIZE_KB,
  "largest_eager_chunk_kb": $LARGEST_EAGER_KB,
  "total_js_kb": $TOTAL_JS_KB,
  "vendor_budget_kb": $VENDOR_MAX_KB,
  "eager_chunk_budget_kb": $EAGER_MAX_KB,
  "vendor_gzip_kb": $VENDOR_GZIP_KB,
  "largest_eager_chunk_gzip_kb": $LARGEST_EAGER_GZIP_KB,
  "vendor_gzip_budget_kb": ${VENDOR_GZIP_MAX_KB:-null},
  "eager_chunk_gzip_budget_kb": ${EAGER_GZIP_MAX_KB:-null},
  "bundles": $BUNDLES_JSON
}
EOF

# Output
if [[ -n "$OUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUT_FILE")"
  printf '%s\n' "$SUMMARY_JSON" > "$OUT_FILE"
fi

printf '%s\n' "$SUMMARY_JSON"

# Budget enforcement
FAIL=0
awk_cmp_vendor=$(awk -v a=$VENDOR_SIZE_KB -v b=$VENDOR_MAX_KB 'BEGIN { if (a>b) print 1; else print 0 }')
awk_cmp_eager=$(awk -v a=$LARGEST_EAGER_KB -v b=$EAGER_MAX_KB 'BEGIN { if (a>b) print 1; else print 0 }')
if [[ $awk_cmp_vendor -eq 1 ]]; then
  echo "BUDGET FAIL: vendor_kb $VENDOR_SIZE_KB > budget $VENDOR_MAX_KB" >&2
  FAIL=1
fi
if [[ $awk_cmp_eager -eq 1 ]]; then
  echo "BUDGET FAIL: largest_eager_chunk_kb $LARGEST_EAGER_KB > budget $EAGER_MAX_KB" >&2
  FAIL=1
fi

# Optional gzip budgets
if [[ -n "$VENDOR_GZIP_MAX_KB" ]]; then
  awk_cmp_vendor_gzip=$(awk -v a=$VENDOR_GZIP_KB -v b=$VENDOR_GZIP_MAX_KB 'BEGIN { if (a>b) print 1; else print 0 }')
  if [[ $awk_cmp_vendor_gzip -eq 1 ]]; then
    echo "BUDGET FAIL: vendor_gzip_kb $VENDOR_GZIP_KB > budget $VENDOR_GZIP_MAX_KB" >&2
    FAIL=1
  fi
fi
if [[ -n "$EAGER_GZIP_MAX_KB" ]]; then
  awk_cmp_eager_gzip=$(awk -v a=$LARGEST_EAGER_GZIP_KB -v b=$EAGER_GZIP_MAX_KB 'BEGIN { if (a>b) print 1; else print 0 }')
  if [[ $awk_cmp_eager_gzip -eq 1 ]]; then
    echo "BUDGET FAIL: largest_eager_chunk_gzip_kb $LARGEST_EAGER_GZIP_KB > budget $EAGER_GZIP_MAX_KB" >&2
    FAIL=1
  fi
fi

popd >/dev/null
exit $FAIL
