#!/usr/bin/env bash
# One-off extraction script for fks_ninja (C# / NinjaTrader integration)
# Usage: ./migration/one-off/extract-fks_ninja.sh <mono-root> <out-base> [--org yourorg] [--remote git@github.com:org/fks_ninja.git]
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
SERVICE=fks_ninja
WORK="$OUT_BASE/$SERVICE"
rm -rf "$WORK"; mkdir -p "$OUT_BASE"
echo "[STEP] Clone" >&2
git clone "$MONO_ROOT" "$WORK" --no-hardlinks --quiet
pushd "$WORK" >/dev/null
echo "[STEP] Filter history" >&2
git filter-repo --path fks_ninja --force
if [[ -d fks_ninja ]]; then rsync -a fks_ninja/ ./; rm -rf fks_ninja; fi
mkdir -p src tests .github/workflows docs

# Add submodules (schema, scripts, actions, docker)
declare -A MAPSUB=( [schema]=shared_schema [scripts]=shared_scripts [actions]=shared_actions [docker]=shared_docker )
for s in schema scripts actions docker; do
  url="git@github.com:$ORG/${MAPSUB[$s]}.git"; git submodule add -f "$url" "shared/$s" || true
done

TEMPLATES="$MONO_ROOT/migration/templates"
cp "$TEMPLATES/ci-dotnet.yml" .github/workflows/ci.yml
if [[ ! -f README.md ]]; then
  sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/NinjaTrader integration & indicators/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md
fi
if [[ ! -f docs/architecture.md ]]; then
  sed -e "s/{{INTERNAL_DEPS}}/shared_schema shared_scripts/" -e "s/{{SHARED_MODULES}}/schema scripts actions docker/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md
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

# Build smoke (skip net48 on non-Windows)
if command -v dotnet >/dev/null 2>&1 && grep -q '<TargetFramework>net48' src/*.csproj 2>/dev/null; then
  if [[ "$(uname -s)" == *NT* || "$(uname -s)" == *Windows* ]]; then
    dotnet build -c Release --nologo || echo "[WARN] dotnet build failed" >&2
  else
    echo "[SMOKE] Skipping net48 build on non-Windows" >&2
  fi
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