#!/usr/bin/env bash
# One-off focused extraction for fks_api main service.
# Creates a clean working directory with history limited to service paths,
# adds declared shared submodules, applies basic import rewrites, and prepares initial commit.
# Prereqs: git-filter-repo installed, upstream empty GitHub repo already created.

set -euo pipefail

if ! command -v git-filter-repo >/dev/null 2>&1; then
  echo "git-filter-repo not installed" >&2; exit 1; fi

MONO_ROOT=${1:-.}
TARGET_DIR=${2:-./_extracted-fks_api}
REMOTE_URL=${3:-}
ORG=${ORG:-yourorg}
SERVICE=fks_api
SERVICE_PATH=fks_api/src/fks_api

echo "[STEP] Clone shallow working copy" >&2
rm -rf "$TARGET_DIR"
git clone "$MONO_ROOT" "$TARGET_DIR" --no-hardlinks --quiet
pushd "$TARGET_DIR" >/dev/null

echo "[STEP] Filter history for $SERVICE_PATH" >&2
git filter-repo --path "$SERVICE_PATH" --path-rename "$SERVICE_PATH/:" --force

# Remove residual empty dirs
find . -type d -empty -delete || true

echo "[STEP] Create src/ structure if needed" >&2
mkdir -p src
if [[ -d fks_api ]]; then
  rsync -a fks_api/ src/
  rm -rf fks_api/
fi

echo "[STEP] Extract tests (best-effort)" >&2
if [[ -d "$MONO_ROOT/fks_api/tests" ]]; then
  rsync -a "$MONO_ROOT/fks_api/tests" ./tests
elif [[ -d "$MONO_ROOT/fks_api/src/tests" ]]; then
  rsync -a "$MONO_ROOT/fks_api/src/tests" ./tests
fi

echo "[STEP] Initialize new git (optional re-root)" >&2
git checkout -b main || true

echo "[STEP] Add submodules" >&2
declare -A SUBS=(
  [python]=git@github.com:$ORG/shared_python.git
  [schema]=git@github.com:$ORG/shared_schema.git
  [scripts]=git@github.com:$ORG/shared_scripts.git
  [docker]=git@github.com:$ORG/shared_docker.git
  [actions]=git@github.com:$ORG/shared_actions.git
  [nginx]=git@github.com:$ORG/shared_nginx.git
)
for name url in "${!SUBS[@]}"; do
  git submodule add -f "${SUBS[$name]}" "shared/$name" || true
done

echo "[STEP] Basic Python import rewrites" >&2
if command -v grep >/dev/null; then
  grep -Rl '^from fks_shared\.' src | while read -r file; do
    sed -i "s/^from fks_shared\./from shared_python./" "$file" || true
  done
fi

echo "[STEP] Seed scaffolding (reuse generic script)" >&2
ROOT_ABS=$(cd "$MONO_ROOT"; pwd)
TEMPLATES="$ROOT_ABS/migration/templates"
mkdir -p .github/workflows docs
[[ -f pyproject.toml ]] && cp "$TEMPLATES/ci-python.yml" .github/workflows/ci.yml || true
if [[ ! -f README.md ]]; then
  sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/API Service/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md
fi
if [[ ! -f docs/architecture.md ]]; then
  sed -e "s/{{INTERNAL_DEPS}}/shared_python, shared_schema/" -e "s/{{SHARED_MODULES}}/python,schema,scripts,docker,actions,nginx/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md
fi
sed -e "s/{{REPO_NAME}}/$SERVICE/g" "$TEMPLATES/Makefile.tpl" > Makefile
cp "$TEMPLATES/update-submodules.sh" ./update-submodules.sh; chmod +x update-submodules.sh
cp "$TEMPLATES/schema_assert.py" ./schema_assert.py
echo "v0.0.0" > schema_version.txt
cp "$TEMPLATES/update-schema-version.sh" ./update-schema-version.sh; chmod +x update-schema-version.sh
cp "$TEMPLATES/dep-graph.py" ./dep-graph.py
cp "$TEMPLATES/meta-verify.sh" ./meta-verify.sh; chmod +x meta-verify.sh
cp "$TEMPLATES/security-audit.sh" ./security-audit.sh; chmod +x security-audit.sh
cp "$TEMPLATES/release-please-config.json" ./release-please-config.json
cp "$TEMPLATES/release-please-workflow.yml" .github/workflows/release-please.yml

git add .
git commit -m "chore: initial extraction of fks_api service" || true

if [[ -n $REMOTE_URL ]]; then
  echo "[STEP] Setting remote origin -> $REMOTE_URL" >&2
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE_URL"
  git push -u origin main || true
fi

echo "[DONE] fks_api extraction prepared at $TARGET_DIR"
popd >/dev/null