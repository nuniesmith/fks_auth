#!/usr/bin/env bash
set -euo pipefail

SCHEMA_DIR=$(dirname "$0")/../../schema
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$(pwd)/../../..")

echo "[typesync] (stub) Would process schemas in $SCHEMA_DIR"
# Future: invoke quicktype or other generators
exit 0
