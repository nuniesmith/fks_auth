#!/usr/bin/env bash
# Quick validation: run build/test/security summary inside a service repo.
# Usage: ./migration/validate-service.sh <service-dir> [--json-out file]
set -euo pipefail

JSON_OUT=""
ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --json-out) JSON_OUT=$2; shift 2;;
    -h|--help) sed -n '1,40p' "$0"; exit 0;;
    *) ARGS+=("$1"); shift;;
  esac
done
DIR=${ARGS[0]:-}
[[ -z $DIR ]] && echo "Need service dir" >&2 && exit 1
[[ ! -d $DIR ]] && echo "Dir $DIR missing" >&2 && exit 1

pushd "$DIR" >/dev/null
repo_name=$(basename "$DIR")
echo "[VALIDATE] Repo: $repo_name"

overall=0
build_status="skip"
test_status="skip"
security_status="skip"
lint_status="skip"
lang="unknown"

time_build=0
time_test=0

ts() { date +%s; }

if [[ -f pyproject.toml ]]; then
  lang="python"
  echo "[PY] Installing (poetry if available else pip)";
  start=$(ts)
  if command -v poetry >/dev/null; then
    if poetry install --no-root >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
  else
    if pip install -e . >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
  fi
  time_build=$(( $(ts) - start ))
  if command -v pytest >/dev/null; then
    start=$(ts)
    if pytest -q >/dev/null 2>&1; then test_status="ok"; else test_status="fail"; overall=1; fi
    time_test=$(( $(ts) - start ))
  fi
  # Functional smoke for fks_data: ensure we can add/list an ActiveAsset without external providers
  if [[ $repo_name == fks_data ]]; then
    if python - <<'PY' >/dev/null 2>&1; then
from fks_data.active_assets import ActiveAssetStore, ActiveAsset
store = ActiveAssetStore(db_path="data/func_test.db")
asset_id = store.add_asset(ActiveAsset(id=None, source="alpha", symbol="AAPL", intervals=["1d"], years=1))
assets = store.list_assets()
assert any(a.get('symbol')=='AAPL' for a in assets), 'Inserted asset not found'
print('ok')
PY
      then
        if [[ $test_status == skip ]]; then test_status="ok"; fi
      else
        echo "[fks_data] functional active_assets smoke test failed" >&2
        test_status="fail"; overall=1
      fi
    fi
  fi
  # Functional smoke for fks_engine: import and inspect service URLs
  if [[ $repo_name == fks_engine ]]; then
    if python - <<'PY' >/dev/null 2>&1; then
import importlib
m = importlib.import_module('fks_engine.main')
urls = m._service_urls() if hasattr(m, '_service_urls') else {}
assert 'data' in urls and 'transformer' in urls
print('ok')
PY
      then
        if [[ $test_status == skip ]]; then test_status="ok"; fi
      else
        echo "[fks_engine] functional smoke failed" >&2
        test_status="fail"; overall=1
      fi
    fi
  fi
  # Functional smoke for fks_worker: ensure main importable
  if [[ $repo_name == fks_worker ]]; then
    if python - <<'PY' >/dev/null 2>&1; then
import importlib
m = importlib.import_module('fks_worker.main')
assert hasattr(m, 'main')
print('ok')
PY
      then
        if [[ $test_status == skip ]]; then test_status="ok"; fi
      else
        echo "[fks_worker] functional smoke failed" >&2
        test_status="fail"; overall=1
      fi
    fi
  fi
fi

if [[ -f Cargo.toml ]]; then
  lang="rust"
  start=$(ts)
  if cargo check >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
  time_build=$(( $(ts) - start ))
  start=$(ts)
  if cargo test --quiet >/dev/null 2>&1; then test_status="ok"; else test_status="fail"; overall=1; fi
  time_test=$(( $(ts) - start ))
  # Rust lint (fmt + clippy) best-effort
  if command -v cargo >/dev/null 2>&1; then
    if cargo fmt -- --check >/dev/null 2>&1; then fmt_result=ok; else fmt_result=fail; fi
    if cargo clippy --quiet -- -D warnings >/dev/null 2>&1; then clippy_result=ok; else clippy_result=fail; fi
    if [[ $fmt_result == ok && $clippy_result == ok ]]; then lint_status="ok"; else lint_status="fail"; overall=1; fi
  fi
  # Additional functional check for fks_config service
  if [[ $repo_name == fks_config ]]; then
    sample_cfg=config/sample.yaml
    if [[ ! -f $sample_cfg ]]; then
      mkdir -p config
      cat > $sample_cfg <<'YML'
account:
  size: 10000
  risk_per_trade: 0.01
network:
  master_port: 5001
runtimes: [python, rust]
YML
    fi
    if cargo run --quiet -- generate --input "$sample_cfg" --output .env.generated >/dev/null 2>&1; then
      if [[ ! -s .env.generated ]]; then
        echo "[fks_config] .env.generated missing or empty" >&2; overall=1; test_status="fail"
      fi
    else
      echo "[fks_config] cargo run generate failed" >&2; overall=1; test_status="fail"
    fi
    # Generate schema and ensure file produced
    if cargo run --quiet -- schema --output config.schema.json >/dev/null 2>&1; then
      if [[ ! -s config.schema.json ]]; then
        echo "[fks_config] config.schema.json missing or empty" >&2; overall=1; test_status="fail"
      fi
    else
      echo "[fks_config] schema generation failed" >&2; overall=1; test_status="fail"
    fi
  fi
fi

if [[ -f package.json ]]; then
  lang="web"
  start=$(ts)
  if npm install --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
  time_build=$(( $(ts) - start ))
  if grep -q '"test"' package.json; then
    start=$(ts)
    if npm test --silent >/dev/null 2>&1; then test_status="ok"; else test_status="fail"; overall=1; fi
    time_test=$(( $(ts) - start ))
  fi
  # Functional smoke for fks_web: type-check & ensure key entrypoints exist
  if [[ $repo_name == fks_web ]]; then
    if [[ -f tsconfig.json ]]; then
      if npx tsc --noEmit >/dev/null 2>&1; then :; else echo "[fks_web] type-check failed" >&2; test_status="fail"; overall=1; fi
    fi
    if [[ ! -f index.html || ! -d src ]]; then
      echo "[fks_web] missing index.html or src directory" >&2; test_status="fail"; overall=1
    else
      if [[ $test_status == skip ]]; then test_status="ok"; fi
    fi
    # Attempt short dev server startup (2s) to catch obvious runtime config issues
    if grep -q '"dev"' package.json; then
      (npm run dev >/dev/null 2>&1 &) ; DEV_PID=$!
      sleep 2
      if ps -p $DEV_PID >/dev/null 2>&1; then kill $DEV_PID || true; else echo "[fks_web] dev server failed to start" >&2; test_status="fail"; overall=1; fi
    fi
  fi
fi

# .NET / C# (Ninja) validation (best-effort; skip net48 build on non-Windows)
if compgen -G '*.sln' >/dev/null || compgen -G '*.csproj' >/dev/null; then
  lang="dotnet"
  csproj=$(ls *.csproj 2>/dev/null | head -n1 || true)
  target_fw=""
  if [[ -n $csproj ]] && grep -q '<TargetFramework>' "$csproj"; then
    target_fw=$(grep -o '<TargetFramework>[^<]*' "$csproj" | sed 's/<TargetFramework>//' | head -n1)
  fi
  if [[ "$target_fw" == net48* ]] && [[ "$(uname -s)" != *"NT"* ]]; then
    echo "[DOTNET] Skipping build of $target_fw on non-Windows host" >&2
    build_status="skip"; test_status="skip"
  else
    if command -v dotnet >/dev/null 2>&1; then
      start=$(ts)
      if compgen -G '*.sln' >/dev/null; then
        sln=$(ls *.sln | head -n1)
        if dotnet restore "$sln" >/dev/null 2>&1 && dotnet build "$sln" -c Release --nologo >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
      else
        if dotnet build -c Release --nologo >/dev/null 2>&1; then build_status="ok"; else build_status="fail"; overall=1; fi
      fi
      time_build=$(( $(ts) - start ))
      # Smoke: ensure DLL produced (if project name known)
      if [[ -n $csproj ]]; then
        asm=${csproj%.csproj}.dll
        found=$(find . -maxdepth 4 -type f -name "$asm" | head -n1 || true)
        if [[ -z $found && $build_status == ok ]]; then
          echo "[DOTNET] Expected assembly $asm not found" >&2
          build_status="fail"; overall=1
        fi
      fi
    else
      echo "[DOTNET] dotnet CLI not installed; skipping build" >&2
      build_status="skip"; test_status="skip"
    fi
  fi
fi

if [[ -f security-audit.sh ]]; then
  if ./security-audit.sh >/dev/null 2>&1; then security_status="ok"; else security_status="warn"; fi
fi

echo "[RESULT] build=$build_status test=$test_status lint=$lint_status security=$security_status overall=$overall"
popd >/dev/null

if [[ -n $JSON_OUT ]]; then
  jq -n \
    --arg repo "$repo_name" \
    --arg lang "$lang" \
    --arg build "$build_status" \
    --arg test "$test_status" \
  --arg security "$security_status" \
  --arg lint "$lint_status" \
    --arg tb "$time_build" \
    --arg tt "$time_test" \
    --arg overall "$overall" \
    '{repo:$repo,lang:$lang,build:$build,test:$test,lint:$lint,security:$security,time_build:($tb|tonumber),time_test:($tt|tonumber),overall:($overall|tonumber)}' > "$JSON_OUT"
fi

exit $overall