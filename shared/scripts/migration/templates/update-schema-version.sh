#!/usr/bin/env bash
# Populate schema_version.txt with current schema submodule tag (if present)
set -euo pipefail
SCHEMA_DIR=${1:-shared/schema}
TARGET_FILE=${2:-schema_version.txt}
if [[ ! -d $SCHEMA_DIR ]]; then
  echo "Schema directory $SCHEMA_DIR not found" >&2; exit 0; fi
pushd "$SCHEMA_DIR" >/dev/null
if tag=$(git describe --tags --abbrev=0 2>/dev/null); then
  echo "$tag" > "../$TARGET_FILE"
  echo "Wrote $tag to $TARGET_FILE"
else
  echo "No tag found in schema submodule" >&2
fi
popd >/dev/null
