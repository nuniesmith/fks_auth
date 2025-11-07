#!/usr/bin/env bash
set -euo pipefail

MANIFEST="repo-extraction-neutral.yml"
OUT_DIR="exports-neutral"

echo "[INFO] Extracting neutral shared repos -> ${OUT_DIR}" >&2
python3 scripts/extract_neutral_shared.py "${MANIFEST}" "${OUT_DIR}"

echo "[INFO] Summary:" >&2
cat "${OUT_DIR}/_summary.json" || true
