#!/usr/bin/env bash
# Verify each extracted repo: build, test, schema, submodule, security, size metrics.
# Features: parallelism, thresholds, exit code control.
# Usage: ./migration/verify-split.sh /output/base/dir [--table] [--parallel 4] [--fail-on-fail] [--max-files N] [--json-out file] [--skip-security] [--fail-list file] [--ignore repo1,repo2]
set -euo pipefail

BASE=""
FORMAT="json"
PARALLEL=1
FAIL_ON_FAIL=0
MAX_FILES=0
JSON_OUT=""
CSV_OUT=""
SKIP_SECURITY=0
FAIL_LIST=""
IGNORE_SET=""
SKIP_TESTS=0
SKIP_BUILD=0
FAIL_ON_OUTDATED_SUBMODULES=0
SUMMARY_OUT=""
MARKDOWN_OUT=""
WARN_FAILURE_RATE=""
FAIL_FAILURE_RATE=""
WARN_OUTDATED_RATE=""
FAIL_OUTDATED_RATE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --table) FORMAT="table"; shift;;
    --json) FORMAT="json"; shift;;
    --parallel) PARALLEL=${2:-1}; shift 2;;
    --fail-on-fail) FAIL_ON_FAIL=1; shift;;
    --max-files) MAX_FILES=${2:-0}; shift 2;;
    --json-out) JSON_OUT=${2:-}; shift 2;;
    --csv-out) CSV_OUT=${2:-}; shift 2;;
    --skip-security) SKIP_SECURITY=1; shift;;
    --fail-list) FAIL_LIST=${2:-}; shift 2;;
    --ignore) IGNORE_SET=${2:-}; shift 2;;
    --skip-tests) SKIP_TESTS=1; shift;;
    --skip-build) SKIP_BUILD=1; shift;;
  --fail-on-outdated-submodules) FAIL_ON_OUTDATED_SUBMODULES=1; shift;;
  --summary-out) SUMMARY_OUT=${2:-}; shift 2;;
  --markdown-out) MARKDOWN_OUT=${2:-}; shift 2;;
  --warn-failure-rate) WARN_FAILURE_RATE=${2:-}; shift 2;;
  --fail-failure-rate) FAIL_FAILURE_RATE=${2:-}; shift 2;;
  --warn-outdated-submodules-rate) WARN_OUTDATED_RATE=${2:-}; shift 2;;
  --fail-outdated-submodules-rate) FAIL_OUTDATED_RATE=${2:-}; shift 2;;
    -h|--help)
      cat <<EOF
Usage: $0 <base-dir> [options]
Options:
  --table | --json          Output format (default json)
  --parallel N              Parallel workers (default 1)
  --fail-on-fail            Exit non-zero if any repo fails
  --max-files N             Mark overall=warn if file count exceeds N
  --json-out FILE           Write JSON summary to FILE
  --csv-out FILE            Write CSV summary to FILE
  --fail-list FILE          Write failing repo names to FILE
  --ignore a,b,c            Comma list of repo names to skip
  --skip-security           Skip security audit step
  --skip-tests              Skip running tests
  --skip-build              Skip build phase (still counts files/LOC)
    --fail-on-outdated-submodules  Treat any outdated submodule as failure for that repo
    --summary-out FILE        Write aggregate metrics (JSON) to FILE
  --markdown-out FILE       Write markdown report (table + aggregate) to FILE
  --warn-failure-rate F     Warn (non-fatal) if repo failure rate >= F (0-1)
  --fail-failure-rate F     Fail (exit) if repo failure rate >= F (0-1)
  --warn-outdated-submodules-rate F Warn if outdated submodule repo rate >= F
  --fail-outdated-submodules-rate F Fail if outdated submodule repo rate >= F
  -h|--help                 Show this help
EOF
      exit 0;;
    *) if [[ -z $BASE ]]; then BASE=$1; else echo "Unknown arg: $1" >&2; exit 1; fi; shift;;
  esac
done

declare -A IGNORE
if [[ -n $IGNORE_SET ]]; then
  IFS=',' read -r -a _ign <<< "$IGNORE_SET"
  for i in "${_ign[@]}"; do [[ -n $i ]] && IGNORE[$i]=1; done
fi

[[ -z $BASE ]] && echo "Need base dir" >&2 && exit 1
[[ ! -d $BASE ]] && echo "Dir $BASE not found" >&2 && exit 1

have_cmd() { command -v "$1" >/dev/null 2>&1; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

process_repo() {
  local repo=$1
  local name=$(basename "$repo")
  echo "[CHECK] $name" >&2
  pushd "$repo" >/dev/null || return 0
  local build_status="skip" test_status="skip" schema_status="skip" sub_status="ok" sec_status="skip" overall="ok" time_build=0 time_test=0 loc=0
  local assembly_count=0 assembly_bytes=0
  local sub_total=0 sub_outdated=0
  local start end
  local file_count=$(find . -type f | wc -l | tr -d ' ')
  local dir_size=$(du -sh . 2>/dev/null | cut -f1)

  if (( MAX_FILES > 0 )) && (( file_count > MAX_FILES )); then overall="warn"; fi

  # Build
  if (( ! SKIP_BUILD )); then
    if [[ -f Cargo.toml ]] && have_cmd cargo; then
      start=$(date +%s); if cargo check --quiet 2>build.err; then build_status="ok"; else build_status="fail"; fi; end=$(date +%s); time_build=$((end-start))
    elif [[ -f pyproject.toml ]] && have_cmd python; then
      start=$(date +%s); if (python -m pyproject_hooks.build_sdist >/dev/null 2>&1 || python -m build --sdist >/dev/null 2>&1); then build_status="ok"; else build_status="warn"; fi; end=$(date +%s); time_build=$((end-start))
    elif [[ -f package.json ]] && have_cmd npm; then
      start=$(date +%s); if (npm install --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1); then build_status="ok"; else build_status="warn"; fi; end=$(date +%s); time_build=$((end-start))
    elif compgen -G '*.csproj' >/dev/null && have_cmd dotnet; then
      csproj=$(ls *.csproj | head -n1)
      target_fw=""
      if grep -q '<TargetFramework>' "$csproj"; then
        target_fw=$(grep -o '<TargetFramework>[^<]*' "$csproj" | sed 's/<TargetFramework>//' | head -n1)
      fi
      if [[ "$target_fw" == net48* ]] && [[ "$(uname -s)" != *"NT"* ]]; then
        echo "[DOTNET] Skip build ($target_fw on non-Windows)" >&2
        build_status="skip"
      else
        start=$(date +%s)
        if compgen -G '*.sln' >/dev/null; then
          sln=$(ls *.sln | head -n1)
          if dotnet restore "$sln" >/dev/null 2>&1 && dotnet build "$sln" -c Release --nologo >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; fi
        else
          if dotnet restore "$csproj" >/dev/null 2>&1 && dotnet build "$csproj" -c Release --nologo >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; fi
        fi
        end=$(date +%s); time_build=$((end-start))
        # Collect assembly metrics (exclude common runtime & test host DLLs)
        while IFS= read -r dll; do
          (( assembly_count++ ))
          sz=$(stat -c%s "$dll" 2>/dev/null || echo 0)
          assembly_bytes=$((assembly_bytes + sz))
        done < <(find . -maxdepth 8 -type f -name '*.dll' \( -path '*/bin/*' -o -path '*/out/*' \) \
          ! -iname 'Microsoft.*.dll' ! -iname 'System.*.dll' ! -iname 'testhost.dll' 2>/dev/null || true)
      fi
    fi
  else
    build_status="skip"
  fi

  # Test
  if (( ! SKIP_TESTS )); then
    if [[ -f Cargo.toml ]] && have_cmd cargo; then
      start=$(date +%s); if cargo test --all --quiet 2>test.err; then test_status="ok"; else test_status="fail"; fi; end=$(date +%s); time_test=$((end-start))
    elif [[ -f pyproject.toml ]] && have_cmd pytest; then
      start=$(date +%s); if pytest -q 2>test.err; then test_status="ok"; else test_status="fail"; fi; end=$(date +%s); time_test=$((end-start))
    elif [[ -f package.json ]] && have_cmd npm && jq -e '.scripts.test' package.json >/dev/null; then
      start=$(date +%s); if npm run test:run >/dev/null 2>&1; then test_status="ok"; else test_status="fail"; fi; end=$(date +%s); time_test=$((end-start))
    elif compgen -G '*.csproj' >/dev/null && have_cmd dotnet; then
      csproj=$(ls *.csproj | head -n1)
      target_fw=""
      if grep -q '<TargetFramework>' "$csproj"; then
        target_fw=$(grep -o '<TargetFramework>[^<]*' "$csproj" | sed 's/<TargetFramework>//' | head -n1)
      fi
      if [[ "$target_fw" == net48* ]] && [[ "$(uname -s)" != *"NT"* ]]; then
        echo "[DOTNET] Skip tests ($target_fw on non-Windows)" >&2
        test_status="skip"
      else
        start=$(date +%s)
        # Only run tests if any test project exists; fallback skip
        if find . -maxdepth 4 -name '*Tests.csproj' | grep -q .; then
          if dotnet test -c Release --nologo --no-build >/dev/null 2>&1; then test_status="ok"; else test_status="fail"; fi
        else
          test_status="skip"
        fi
        end=$(date +%s); time_test=$((end-start))
      fi
    fi
  else
    test_status="skip"
  fi

  # Schema
  if [[ -f schema_assert.py ]] && have_cmd python3; then
    # If shared/schema path missing treat as skip (likely fallback copy mode)
    if [[ ! -d shared/schema ]]; then
      schema_status="skip"
    else
      if python3 schema_assert.py >/dev/null 2>&1; then schema_status="ok"; else schema_status="fail"; fi
    fi
  fi
  # Submodules
  if [[ -f .gitmodules ]]; then
    # Count total and outdated submodules (lines starting with '+')
    while IFS= read -r line; do
      [[ -z $line ]] && continue
      # lines look like: " 1a2b3c4d5e path (branch)"; '+' indicates commit not checked out / needs update
      sub_total=$((sub_total+1))
      if [[ $line == +* ]]; then
        sub_outdated=$((sub_outdated+1))
      fi
    done < <(git submodule status 2>/dev/null || true)
    if (( sub_outdated > 0 )); then sub_status="outdated"; fi
  else
    sub_status="none"
  fi
  # Security
  if (( ! SKIP_SECURITY )) && [[ -f security-audit.sh ]]; then
    if ./security-audit.sh >/dev/null 2>&1; then sec_status="ok"; else sec_status="warn"; fi
  fi
  # LOC metric
  if have_cmd cloc; then
    loc=$(cloc --quiet --json . 2>/dev/null | jq '(.SUM.code)//0' 2>/dev/null || echo 0)
  else
    loc=$(git ls-files '*.*' | xargs -r cat | wc -l | tr -d ' ')
  fi
  if [[ $build_status == fail || $test_status == fail || $schema_status == fail ]]; then overall="fail"; fi
  # If everything skipped and no failures, mark overall warn instead of ok (signals incomplete env)
  if [[ $build_status == skip && $test_status == skip && $schema_status == skip ]] && [[ $overall == ok ]]; then overall="warn"; fi
  if (( FAIL_ON_OUTDATED_SUBMODULES )) && [[ $sub_status == outdated ]]; then overall="fail"; fi
  popd >/dev/null
  jq -n \
    --arg repo "$name" \
    --arg status "$overall" \
    --arg build "$build_status" \
    --arg test "$test_status" \
    --arg schema "$schema_status" \
    --arg sub "$sub_status" \
    --arg sec "$sec_status" \
    --arg files "$file_count" \
    --arg size "$dir_size" \
    --arg tb "$time_build" \
  --arg tt "$time_test" \
  --arg loc "$loc" \
  --arg ac "$assembly_count" \
  --arg ab "$assembly_bytes" \
  --arg st "$sub_total" \
  --arg so "$sub_outdated" \
  '{repo:$repo,status:$status,build:$build,test:$test,schema:$schema,submodules:$sub,submodules_total:($st|tonumber),submodules_outdated:($so|tonumber),security:$sec,files:($files|tonumber),size:$size,loc:($loc|tonumber),assemblies:($ac|tonumber),assemblies_bytes:($ab|tonumber),time_build:($tb|tonumber),time_test:($tt|tonumber)}' > "$tmpdir/$name.json"
}

export -f process_repo have_cmd
export tmpdir

repos=("$BASE"/*)
to_process=()
for r in "${repos[@]}"; do
  [[ -d $r/.git ]] || continue
  name=$(basename "$r")
  [[ -n ${IGNORE[$name]:-} ]] && continue
  to_process+=("$r")
done

if (( PARALLEL > 1 )); then
  # naive parallelization using background jobs
  semaphore=$PARALLEL
  for r in "${to_process[@]}"; do
    while (( $(jobs -rp | wc -l) >= semaphore )); do sleep 0.2; done
    process_repo "$r" &
  done
  wait
else
  for r in "${to_process[@]}"; do process_repo "$r"; done
fi

summary=$(jq -s '.' "$tmpdir"/*.json)

# Accumulated exit status (0=success,2=repo failures,3=outdated submodules,4=failure rate threshold,5=outdated rate threshold)
status_exit=0

if [[ $FORMAT == table ]]; then
  echo "Repo | Status | Build | Test | Schema | Submods | Outdated | Sec | Files | LOC | Size | Assemblies | Assemblies(bytes) | t_build(s) | t_test(s)"
  echo "-----|--------|-------|------|--------|---------|---------|-----|-------|-----|------|-----------|------------------|-----------|----------"
  echo "$summary" | jq -r '.[] | "\(.repo) | \(.status) | \(.build) | \(.test) | \(.schema) | \(.submodules_total) | \(.submodules_outdated) | \(.security) | \(.files) | \(.loc) | \(.size) | \(.assemblies) | \(.assemblies_bytes) | \(.time_build) | \(.time_test)"'
else
  echo "$summary" | jq '.'
fi

[[ -n $JSON_OUT ]] && echo "$summary" | jq '.' > "$JSON_OUT"

if [[ -n $CSV_OUT ]]; then
  echo "repo,status,build,test,schema,submodules_status,submodules_total,submodules_outdated,security,files,loc,size,time_build,time_test" > "$CSV_OUT"
  echo "$summary" | jq -r '.[] | [ .repo, .status, .build, .test, .schema, .submodules, .submodules_total, .submodules_outdated, .security, .files, .loc, .size, .time_build, .time_test ] | @csv' >> "$CSV_OUT"
fi

if echo "$summary" | jq -e '.[] | select(.status=="fail")' >/dev/null; then
  if [[ -n $FAIL_LIST ]]; then
    echo "$summary" | jq -r '.[] | select(.status=="fail") | .repo' > "$FAIL_LIST"
  fi
  if (( FAIL_ON_FAIL )); then
    echo "One or more repositories failed" >&2
    (( status_exit==0 )) && status_exit=2
  fi
else
  [[ -n $FAIL_LIST ]] && : > "$FAIL_LIST"
fi

# Aggregate metrics summary (always compute; optionally write to file)
agg=$(echo "$summary" | jq 'reduce .[] as $r ({total:0,fail:0,warn:0,ok:0,submodules_outdated_repos:0,submodules_total:0,submodules_outdated:0,files:0,loc:0,time_build:0,time_test:0,assemblies:0,assemblies_bytes:0}; .total+=1 | .files+=($r.files//0) | .loc+=($r.loc//0) | .time_build+=($r.time_build//0) | .time_test+=($r.time_test//0) | .submodules_total+=($r.submodules_total//0) | .submodules_outdated+=($r.submodules_outdated//0) | .assemblies+=($r.assemblies//0) | .assemblies_bytes+=($r.assemblies_bytes//0) | (if $r.status=="fail" then .fail+=1 elif $r.status=="warn" then .warn+=1 elif $r.status=="ok" then .ok+=1 end) | (if ($r.submodules_outdated//0) > 0 then .submodules_outdated_repos+=1 else . end)) | .failure_rate=(if .total>0 then (.fail / .total) else 0 end) | .outdated_submodule_repo_rate=(if .total>0 then (.submodules_outdated_repos / .total) else 0 end)')

if [[ -n $SUMMARY_OUT ]]; then
  echo "$agg" | jq '.' > "$SUMMARY_OUT"
fi

if (( FAIL_ON_OUTDATED_SUBMODULES )); then
  outdated_repo_count=$(echo "$agg" | jq -r '.submodules_outdated_repos')
  if (( outdated_repo_count > 0 )); then
    echo "Outdated submodules detected in $outdated_repo_count repositories" >&2
    (( status_exit==0 )) && status_exit=3
  fi
fi

# Threshold gating (failure/outdated rates)
failure_rate=$(echo "$agg" | jq -r '.failure_rate')
outdated_rate=$(echo "$agg" | jq -r '.outdated_submodule_repo_rate')
# status_exit may already be set (2 or 3) from earlier gating
if [[ -n $WARN_FAILURE_RATE ]] && awk -v a="$failure_rate" -v b="$WARN_FAILURE_RATE" 'BEGIN{exit !(a>=b)}'; then
  echo "WARNING: Failure rate $failure_rate >= $WARN_FAILURE_RATE" >&2
fi
if [[ -n $FAIL_FAILURE_RATE ]] && awk -v a="$failure_rate" -v b="$FAIL_FAILURE_RATE" 'BEGIN{exit !(a>=b)}'; then
  echo "ERROR: Failure rate $failure_rate >= $FAIL_FAILURE_RATE" >&2
  status_exit=4
fi
if [[ -n $WARN_OUTDATED_RATE ]] && awk -v a="$outdated_rate" -v b="$WARN_OUTDATED_RATE" 'BEGIN{exit !(a>=b)}'; then
  echo "WARNING: Outdated submodule repo rate $outdated_rate >= $WARN_OUTDATED_RATE" >&2
fi
if [[ -n $FAIL_OUTDATED_RATE ]] && awk -v a="$outdated_rate" -v b="$FAIL_OUTDATED_RATE" 'BEGIN{exit !(a>=b)}'; then
  echo "ERROR: Outdated submodule repo rate $outdated_rate >= $FAIL_OUTDATED_RATE" >&2
  status_exit=5
fi

# Markdown report
if [[ -n $MARKDOWN_OUT ]]; then
  {
    echo "# Verification Report"
    echo
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## Aggregate Metrics"
    echo '\n```json'
    echo "$agg" | jq '.'
    echo '```'
    echo
    echo "## Repository Summary"
    echo
  echo "| Repo | Status | Build | Test | Schema | Submods | Outdated | Sec | Files | LOC | Size | Assemblies | Assemblies(bytes) | t_build(s) | t_test(s) |"
  echo "|------|--------|-------|------|--------|---------|---------|-----|-------|-----|------|-----------|------------------|-----------|----------|"
  echo "$summary" | jq -r '.[] | "| \(.repo) | \(.status) | \(.build) | \(.test) | \(.schema) | \(.submodules_total) | \(.submodules_outdated) | \(.security) | \(.files) | \(.loc) | \(.size) | \(.assemblies) | \(.assemblies_bytes) | \(.time_build) | \(.time_test) |"'
  } > "$MARKDOWN_OUT"
fi

# Always emit single-line machine-readable SUMMARY (stdout)
summary_line=$(echo "$agg" | jq -r '"SUMMARY: total=\(.total) fail=\(.fail) warn=\(.warn) ok=\(.ok) failure_rate=\(.failure_rate) submods_total=\(.submodules_total) submods_outdated=\(.submodules_outdated) outdated_repo_rate=\(.outdated_submodule_repo_rate) files=\(.files) loc=\(.loc) assemblies=\(.assemblies) assemblies_bytes=\(.assemblies_bytes)"')
echo "$summary_line"

exit $status_exit
