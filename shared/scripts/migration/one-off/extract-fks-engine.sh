#!/usr/bin/env bash
# One-off extraction script for fks_engine service.
# Usage: ./migration/one-off/extract-fks_engine.sh <mono-root> <out-base> [--org yourorg] [--remote git@github.com:org/fks_engine.git]
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
SERVICE=fks_engine
WORK="$OUT_BASE/$SERVICE"
rm -rf "$WORK"; mkdir -p "$OUT_BASE"
echo "[STEP] Clone" >&2
git clone "$MONO_ROOT" "$WORK" --no-hardlinks --quiet
pushd "$WORK" >/dev/null
echo "[STEP] Filter history" >&2
git filter-repo --path fks_engine --force
if [[ -d fks_engine ]]; then rsync -a fks_engine/ ./; rm -rf fks_engine; fi
mkdir -p src tests
# Submodules (python, schema, scripts, docker, actions, rust)
declare -A MAPSUB=( [python]=shared_python [schema]=shared_schema [scripts]=shared_scripts [docker]=shared_docker [actions]=shared_actions [rust]=shared_rust )
for s in python schema scripts docker actions rust; do
  repo="${MAPSUB[$s]}"; url="git@github.com:$ORG/$repo.git"; git submodule add -f "$url" "shared/$s" || true; done
# Import rewrites
if grep -RIl '^from fks_shared\.' src >/dev/null 2>&1; then
  grep -RIl '^from fks_shared\.' src | while read -r f; do sed -i "s/^from fks_shared\./from shared_python./" "$f" || true; done
fi
TEMPLATES="$MONO_ROOT/migration/templates"
mkdir -p .github/workflows docs
cp "$TEMPLATES/ci-python.yml" .github/workflows/ci.yml
if [[ ! -f README.md ]]; then
  sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/Python engine & backtesting service/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md
fi
if [[ ! -f docs/architecture.md ]]; then
  sed -e "s/{{INTERNAL_DEPS}}/shared_python shared_rust/" -e "s/{{SHARED_MODULES}}/python schema scripts docker actions rust/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md
fi
sed -e "s/{{REPO_NAME}}/$SERVICE/g" "$TEMPLATES/Makefile.tpl" > Makefile
cp "$TEMPLATES/update-submodules.sh" ./update-submodules.sh; chmod +x update-submodules.sh
cp "$TEMPLATES/schema_assert.py" ./schema_assert.py; echo "v0.0.0" > schema_version.txt
cp "$TEMPLATES/update-schema-version.sh" ./update-schema-version.sh; chmod +x update-schema-version.sh
cp "$TEMPLATES/dep-graph.py" ./dep-graph.py
cp "$TEMPLATES/meta-verify.sh" ./meta-verify.sh; chmod +x meta-verify.sh
cp "$TEMPLATES/security-audit.sh" ./security-audit.sh; chmod +x security-audit.sh
cp "$TEMPLATES/release-please-config.json" ./release-please-config.json
cp "$TEMPLATES/release-please-workflow.yml" .github/workflows/release-please.yml
git add .; git commit -m "chore: initial extraction for $SERVICE" || true
# Functional smoke: ensure _service_urls present
python - <<'PY' || echo '[WARN] engine smoke failed' >&2
import importlib
m = importlib.import_module('main') if importlib.util.find_spec('main') else importlib.import_module('fks_engine.main')
assert hasattr(m,'_service_urls') and isinstance(m._service_urls(), dict)
print('engine smoke ok')
PY
if [[ -f "$MONO_ROOT/migration/generate-sbom.sh" ]]; then bash "$MONO_ROOT/migration/generate-sbom.sh" . sbom.json || true; git add sbom.json || true; git commit -m 'chore: sbom snapshot' || true; fi
if [[ -n $REMOTE ]]; then git remote remove origin 2>/dev/null || true; git remote add origin "$REMOTE"; git push -u origin main || true; fi
echo "[DONE] Extracted $SERVICE at $WORK"; popd >/dev/null