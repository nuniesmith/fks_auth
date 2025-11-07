#!/usr/bin/env bash
set -euo pipefail
# Simple wrapper to produce deterministic codegen outputs
OUT_FILE="generated/strategy_ir.json"
EMIT_DIR="generated/codegen"
PACKAGE="src.python.strategies"
EMITTERS=(csharp)

# Clean previous emitted code (but keep prior IR for timestamp reuse)
if [[ -d "$EMIT_DIR" ]]; then
  rm -rf "$EMIT_DIR"
fi

CMD=(python -m src.python.codegen.extract --package "$PACKAGE" --out "$OUT_FILE")
for e in "${EMITTERS[@]}"; do
  CMD+=( --emit "$e" )
  CMD+=( --modules "src.python.codegen.emitters.$e" )
done

"${CMD[@]}"
