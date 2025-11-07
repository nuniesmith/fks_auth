#!/usr/bin/env bash
# One-off extraction for fks_web (React/TS frontend)
# Usage: ./migration/one-off/extract-fks_web.sh <mono-root> <out-base> [--org yourorg] [--remote git@github.com:org/fks_web.git]
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
SERVICE=fks_web
WORK="$OUT_BASE/$SERVICE"
rm -rf "$WORK"; mkdir -p "$OUT_BASE"

echo "[STEP] Clone" >&2
git clone "$MONO_ROOT" "$WORK" --no-hardlinks --quiet
pushd "$WORK" >/dev/null

echo "[STEP] Filter history" >&2
# Use fks_web directory; adjust if future consolidation
git filter-repo --path fks_web --force
if [[ -d fks_web ]]; then rsync -a fks_web/ ./; rm -rf fks_web; fi

# Ensure src & public exist (already present if original project structured)
mkdir -p src public .github/workflows docs

# Add submodules (react, nginx, docker, actions, scripts)
declare -A MAPSUB=( [react]=shared_react [nginx]=shared_nginx [docker]=shared_docker [actions]=shared_actions [scripts]=shared_scripts )
for s in react nginx docker actions scripts; do
  url="git@github.com:$ORG/${MAPSUB[$s]}.git"
  git submodule add -f "$url" "shared/$s" || true
done

TEMPLATES="$MONO_ROOT/migration/templates"
# CI workflow (web)
if [[ -d shared/actions ]]; then
  cp "$TEMPLATES/ci-web.yml" .github/workflows/ci.yml 2>/dev/null || true
else
  cp "$TEMPLATES/ci-web.yml" .github/workflows/ci.yml 2>/dev/null || true
fi

# README + docs
if [[ ! -f README.md ]]; then
  sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/React UI frontend/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md
fi
if [[ ! -f docs/architecture.md ]]; then
  sed -e "s/{{INTERNAL_DEPS}}/shared_react/" -e "s/{{SHARED_MODULES}}/react nginx docker actions scripts/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md
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

git add .
git commit -m "chore: initial extraction for $SERVICE" || true

# Functional smoke: install minimal and build (skip heavy dev server run here)
if command -v npm >/dev/null 2>&1; then
  if npm install --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1; then
    echo "[SMOKE] build ok"
  else
    echo "[SMOKE] build failed" >&2
  fi
fi

# Add tsconfig path alias for shared react hooks if not present
if [[ -f tsconfig.json ]] && ! grep -q '"@shared/*"' tsconfig.json; then
  tmp=$(mktemp)
  node - <<'JS' > $tmp || cat tsconfig.json > $tmp
const fs=require('fs');
try { const j=JSON.parse(fs.readFileSync('tsconfig.json','utf8')); j.compilerOptions=j.compilerOptions||{}; j.compilerOptions.baseUrl=j.compilerOptions.baseUrl||'.'; j.compilerOptions.paths=j.compilerOptions.paths||{}; j.compilerOptions.paths['@shared/*']=['shared/react/src/*']; fs.writeFileSync('tsconfig.json', JSON.stringify(j,null,2)); } catch(e){ process.stderr.write('tsconfig alias inject failed '+e+'\n'); }
JS
  mv $tmp tsconfig.json
  git add tsconfig.json || true
  git commit -m 'chore: add @shared/* path alias' || true
fi

if [[ -f "$MONO_ROOT/migration/generate-sbom.sh" ]]; then
  bash "$MONO_ROOT/migration/generate-sbom.sh" . sbom.json || true
  git add sbom.json || true
  git commit -m 'chore: sbom snapshot' || true
fi

if [[ -n $REMOTE ]]; then
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE"
  git push -u origin main || true
fi

echo "[DONE] Extracted $SERVICE at $WORK"
popd >/dev/null
