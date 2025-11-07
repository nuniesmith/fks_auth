#!/usr/bin/env bash
# Lightweight SBOM/dependency snapshot generator (language aware, no external syft dependency).
# Usage: ./migration/generate-sbom.sh <service-dir> <output-json>
set -euo pipefail
DIR=${1:-}
OUT=${2:-sbom.json}
[[ -z $DIR || -z $OUT ]] && echo "Usage: $0 <dir> <out-json>" >&2 && exit 1
[[ ! -d $DIR ]] && echo "Directory $DIR missing" >&2 && exit 1

pushd "$DIR" >/dev/null
repo=$(basename "$DIR")
license=""

py_deps=()
if [[ -f pyproject.toml ]]; then
  # Extract dependencies sections (basic)
  py_deps+=( $(grep -E '^[A-Za-z0-9_.-]+ ?=' pyproject.toml | sed -E 's/ =.*//' ) ) || true
  # Attempt license detection (PEP 621 'license' or legacy classifiers)
  license=$(grep -E '^license ?=' pyproject.toml | head -n1 | sed -E 's/.*= *"?([^"#]+)"?.*/\1/' || true)
  if [[ -z $license ]]; then
    license=$(grep -E '^classifiers' -A5 pyproject.toml | grep -E 'License ::' | head -n1 | sed -E 's/.*License :: *([^"']+).*/\1/' || true)
  fi
elif [[ -f requirements.txt ]]; then
  py_deps+=( $(grep -v '^#' requirements.txt | cut -d'=' -f1 | cut -d'<' -f1 | cut -d'>' -f1) ) || true
fi

node_deps=()
if [[ -f package.json ]]; then
  if command -v jq >/dev/null 2>&1; then
    node_deps+=( $(jq -r '.dependencies? // {} | keys[]' package.json 2>/dev/null) ) || true
    node_deps+=( $(jq -r '.devDependencies? // {} | keys[]' package.json 2>/dev/null) ) || true
    if [[ -z $license ]]; then
      license=$(jq -r '.license // empty' package.json 2>/dev/null || echo "")
    fi
  else
    node_deps+=( $(grep '".*":' package.json | cut -d'"' -f2) ) || true
  fi
fi

rust_deps=()
if [[ -f Cargo.toml ]]; then
  rust_deps+=( $(grep -E '^([A-Za-z0-9_-]+) ?=' Cargo.toml | sed -E 's/ =.*//' | grep -v '^package$' ) ) || true
  if [[ -z $license ]]; then
    license=$(grep -E '^license *= *"' Cargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
  fi
fi

python_json=$(printf '%s\n' "${py_deps[@]:-}" | awk 'NF' | sort -u | jq -R . | jq -s .)
node_json=$(printf '%s\n' "${node_deps[@]:-}" | awk 'NF' | sort -u | jq -R . | jq -s .)
rust_json=$(printf '%s\n' "${rust_deps[@]:-}" | awk 'NF' | sort -u | jq -R . | jq -s .)

jq -n \
  --arg repo "$repo" \
  --arg license "$license" \
  --argjson python "$python_json" \
  --argjson node "$node_json" \
  --argjson rust "$rust_json" \
  '{repo:$repo, license:$license, python:$python, node:$node, rust:$rust}' > "$OUT"

echo "[SBOM] Wrote $OUT" >&2
popd >/dev/null