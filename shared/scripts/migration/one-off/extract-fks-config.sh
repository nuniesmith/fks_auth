#!/usr/bin/env bash
# One-off extraction script for fks_config service.
# Performs history filter, adds submodules (rust,schema,scripts,actions,docker), and validates cargo run.
# Usage: ./migration/one-off/extract-fks_config.sh <mono-root> <out-base> [--org yourorg] [--remote git@github.com:org/fks_config.git]
set -euo pipefail
MONO_ROOT=${1:-}
OUT_BASE=${2:-}
shift 2 || true
ORG=yourorg
REMOTE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --org) ORG=$2; shift 2;;
    --remote) REMOTE=$2; shift 2;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done
[[ -z $MONO_ROOT || -z $OUT_BASE ]] && echo "Usage: $0 <mono-root> <out-base> [--org org] [--remote url]" >&2 && exit 1
[[ ! -d $MONO_ROOT/.git ]] && echo "Monorepo root invalid" >&2 && exit 1
command -v git-filter-repo >/dev/null || { echo "git-filter-repo not installed" >&2; exit 1; }
SERVICE=fks_config
WORK="$OUT_BASE/$SERVICE"
rm -rf "$WORK"
mkdir -p "$OUT_BASE"

echo "[STEP] Clone"
git clone "$MONO_ROOT" "$WORK" --no-hardlinks --quiet
pushd "$WORK" >/dev/null

echo "[STEP] Filter history to fks_config/"
 git filter-repo --path fks_config --force

# Flatten directory if nested
if [[ -d fks_config ]]; then
  rsync -a fks_config/ ./
  rm -rf fks_config
fi

# Ensure src/ structure (already present)
mkdir -p src tests

# Restructure: model.rs -> config.rs (if not already renamed)
if [[ -f src/model.rs && ! -f src/config.rs ]]; then
  mv src/model.rs src/config.rs
  # Update lib.rs to reference config instead of model
  if grep -q 'pub mod model;' src/lib.rs; then
    sed -i 's/pub mod model;/pub mod config;/' src/lib.rs || true
  fi
  # Update generator import
  if grep -q 'crate::model::AppConfig' src/generator.rs; then
    sed -i 's/crate::model::AppConfig/crate::config::AppConfig/' src/generator.rs || true
  fi
  # Preserve backwards compatibility: add re-export in lib if not already
  if ! grep -q 'pub use config::' src/lib.rs; then
    echo 'pub use config::{AppConfig, RuntimeKind, AccountConfig, NetworkConfig};' >> src/lib.rs
  fi
fi

# Add submodules
declare -A MAPSUB=( [rust]=shared_rust [schema]=shared_schema [scripts]=shared_scripts [actions]=shared_actions [docker]=shared_docker )
for s in rust schema scripts actions docker; do
  repo="${MAPSUB[$s]}"
  url="git@github.com:$ORG/$repo.git"
  git submodule add -f "$url" "shared/$s" || true
done

# Scaffolding additions
TEMPLATES="$MONO_ROOT/migration/templates"
mkdir -p .github/workflows docs
cp "$TEMPLATES/ci-rust.yml" .github/workflows/ci.yml
cp "$TEMPLATES/update-submodules.sh" ./update-submodules.sh; chmod +x update-submodules.sh
cp "$TEMPLATES/schema_assert.py" ./schema_assert.py; echo "v0.0.0" > schema_version.txt
cp "$TEMPLATES/update-schema-version.sh" ./update-schema-version.sh; chmod +x update-schema-version.sh
cp "$TEMPLATES/dep-graph.py" ./dep-graph.py
cp "$TEMPLATES/meta-verify.sh" ./meta-verify.sh; chmod +x meta-verify.sh
cp "$TEMPLATES/security-audit.sh" ./security-audit.sh; chmod +x security-audit.sh
cp "$TEMPLATES/release-please-config.json" ./release-please-config.json
cp "$TEMPLATES/release-please-workflow.yml" .github/workflows/release-please.yml
if [[ ! -f README.md ]]; then
  sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/Rust config management & generation utility/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md
  cat >> README.md <<'EOF'

## Usage

Generate an environment file from a YAML config:

```bash
cargo run -- generate --input config/sample.yaml --output .env.generated --runtime python
```

Example YAML (`config/sample.yaml`):

```yaml
account:
  size: 10000
  risk_per_trade: 0.01
network:
  master_port: 5001
runtimes: [python, rust]
```

Output `.env.generated` will contain derived MAX_LOSS_PER_TRADE and other fields.
EOF
fi
if [[ ! -f docs/architecture.md ]]; then
  sed -e "s/{{INTERNAL_DEPS}}/TBD/" -e "s/{{SHARED_MODULES}}/rust schema scripts actions docker/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md
fi
sed -e "s/{{REPO_NAME}}/$SERVICE/g" "$TEMPLATES/Makefile.tpl" > Makefile

# Sample config for validation
mkdir -p config
cat > config/sample.yaml <<'YML'
account:
  size: 10000
  risk_per_trade: 0.01
network:
  master_port: 5001
  sim_latency_ms: 50
runtimes: [python, rust]
YML

# Validation run
if command -v cargo >/dev/null 2>&1; then
  # Pin workspace deps before build if needed
  if grep -q 'workspace = true' Cargo.toml; then bash "$MONO_ROOT/migration/normalize-rust-standalone.sh" . || true; fi
  echo "[STEP] Cargo build"
  cargo build --quiet || echo "Build issues (non-fatal)" >&2
  echo "[STEP] Generate test"
  cargo run --quiet -- generate --input config/sample.yaml --output .env.generated || echo "Run failed" >&2
  echo "[STEP] Generate schema"
  cargo run --quiet -- schema --output config.schema.json || echo "Schema generation failed" >&2
fi

# SBOM snapshot
if [[ -f "$MONO_ROOT/migration/generate-sbom.sh" ]]; then
  echo "[STEP] SBOM snapshot"
  bash "$MONO_ROOT/migration/generate-sbom.sh" . sbom.json || true
  git add sbom.json || true
fi
git add config.schema.json 2>/dev/null || true

git add .
git commit -m "chore: initial extraction for $SERVICE" || true
if [[ -n $REMOTE ]]; then
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE"
  git push -u origin main || true
fi

echo "[DONE] Extracted $SERVICE at $WORK"
popd >/dev/null
