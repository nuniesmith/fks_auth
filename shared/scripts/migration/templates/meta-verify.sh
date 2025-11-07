#!/usr/bin/env bash
# Run unified meta verification in a repo: submodules, schema, dep graph (if root map present)
set -euo pipefail

if [[ -f update-submodules.sh ]]; then
  echo "[META] Submodule status:"; ./update-submodules.sh list || true
fi
if [[ -f schema_assert.py ]]; then
  echo "[META] Schema check:"; python3 schema_assert.py || true
fi
if [[ -f extraction-map.yml ]]; then
  echo "[META] Generating dependency graph"; python3 dep-graph.py --map extraction-map.yml --out dependency-graph.md || true
fi
