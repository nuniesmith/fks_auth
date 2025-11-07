#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
REPO_DIR="$ROOT_DIR/repo"
PY_SERVICES=(fks_api fks_data fks_engine fks_worker fks_training fks_transformer)

python_bin=${PYTHON:-python3}

for svc in "${PY_SERVICES[@]}"; do
  echo "==== [$svc] Installing (editable) and running tests ===="
  pushd "$REPO_DIR/$svc" >/dev/null
  if [ -f pyproject.toml ]; then
    $python_bin -m pip install -q .[websocket,security,ml,postgres,redis,gpu] || $python_bin -m pip install -q . || true
  fi
  if [ -d tests ]; then
    $python_bin -m pytest -q || { echo "[WARN] tests failed for $svc"; };
  else
    echo "[INFO] no tests for $svc"
  fi
  popd >/dev/null
  echo
done

echo "All python repo smoke tests attempted."
