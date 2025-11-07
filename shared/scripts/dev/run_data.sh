#!/usr/bin/env bash
set -euo pipefail

# Simple dev runner for fks_data
# - Installs minimal Python deps if missing
# - Runs the data service on port 9001

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[fks_data] Using repo at: $ROOT_DIR"

: "${APP_ENV:=development}"
: "${APP_LOG_LEVEL:=INFO}"
: "${DATA_SERVICE_NAME:=data}"
: "${DATA_SERVICE_PORT:=9001}"

export APP_ENV APP_LOG_LEVEL DATA_SERVICE_NAME DATA_SERVICE_PORT

# Prefer an activated venv/conda if present; otherwise just use system python
PYTHON_BIN="${PYTHON_BIN:-python}"
if command -v conda >/dev/null 2>&1 && conda info --envs >/dev/null 2>&1; then
  # Use current conda python if active
  if [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
    PYTHON_BIN="python"
  fi
fi

echo "[fks_data] Using python: $(command -v "$PYTHON_BIN")"

echo "[fks_data] Ensuring minimal deps are available..."
"$PYTHON_BIN" - <<'PY' || true

import importlib, sys
pkgs = [
    ("flask", "flask"),
    ("yfinance", "yfinance"),
    ("pandas", "pandas"),
    ("requests", "requests"),
    ("loguru", "loguru"),
    ("werkzeug", "werkzeug"),
]
missing = []
for mod, pipname in pkgs:
    try:
        importlib.import_module(mod)
    except Exception:
        missing.append(pipname)
if missing:
    print("Installing:", missing)
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", *missing])
else:
    print("All minimal deps present")
PY

echo "[fks_data] Starting service on port ${DATA_SERVICE_PORT}..."
export PYTHONPATH="$ROOT_DIR/src/python:${PYTHONPATH:-}"
exec "$PYTHON_BIN" "$ROOT_DIR/src/python/main.py" service data
