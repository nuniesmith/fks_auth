#!/usr/bin/env bash
# Run language-specific security/audit scans (best-effort)
set -euo pipefail
if command -v cargo >/dev/null 2>&1 && [ -f Cargo.toml ]; then
  cargo install --quiet cargo-audit || true
  cargo audit || true
fi
if command -v python >/dev/null 2>&1 && ls *.py >/dev/null 2>&1; then
  pip install pip-audit || true
  pip-audit -r requirements.txt || true
fi
if command -v npm >/dev/null 2>&1 && [ -f package.json ]; then
  npm audit --audit-level=high || true
fi
