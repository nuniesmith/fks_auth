#!/usr/bin/env bash
# Generic single-service extractor driven by extraction-map.yml
# Preserves history only for the service paths, seeds scaffolding & submodules.
# Usage: ./migration/extract-service.sh <service-name> <mono-root> <out-dir> [--org yourorg] [--remote git@github.com:org/repo.git]
# Example: ./migration/extract-service.sh fks_api . ./_out --org yourorg --remote git@github.com:yourorg/fks_api.git
set -euo pipefail

SERVICE=${1:-}
MONO_ROOT=${2:-}
OUT_BASE=${3:-}
shift 3 || true
ORG=yourorg
REMOTE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --org) ORG=$2; shift 2;;
    --remote) REMOTE=$2; shift 2;;
    --help|-h)
      sed -n '1,40p' "$0"; exit 0;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done

[[ -z $SERVICE || -z $MONO_ROOT || -z $OUT_BASE ]] && echo "Missing args" >&2 && exit 1
[[ ! -d $MONO_ROOT/.git ]] && echo "Monorepo root invalid" >&2 && exit 1
[[ ! -f $MONO_ROOT/extraction-map.yml ]] && echo "extraction-map.yml missing" >&2 && exit 1
command -v git-filter-repo >/dev/null || { echo "git-filter-repo not installed" >&2; exit 1; }

MAP=$MONO_ROOT/extraction-map.yml

echo "[INFO] Parsing mapping for $SERVICE" >&2
block=$(awk -v s="  $SERVICE:" '$0==s{f=1} f && NF==$1 && $1!~"^  " && NR>1{f=0} f{print}' "$MAP" ) || true
if [[ -z $block ]]; then
  # fallback simple grep region until blank line
  block=$(awk -v s="  $SERVICE:" 'index($0,s){f=1} f{if(/^$/){exit} print}' "$MAP") || true
fi
paths=()
while IFS= read -r line; do
  [[ $line =~ paths: ]] && mode=paths && continue
  if [[ $mode == paths && $line =~ ^[[:space:]]{6}-[[:space:]]([^#]+) ]]; then
    p=$(echo "$line" | sed -E 's/^[[:space:]]{6}-[[:space:]]//; s/[[:space:]]+#.*$//')
    paths+=("$p")
  fi
  if [[ $line =~ submodules: ]]; then
    subs_line=$(echo "$line" | sed -E 's/.*submodules:[[:space:]]*\[(.*)\].*/\1/')
    IFS=',' read -r -a subs <<< "$subs_line"
    for i in "${!subs[@]}"; do subs[$i]=$(echo "${subs[$i]}" | tr -d ' '); done
  fi
done < <(printf '%s\n' "$block")

[[ ${#paths[@]} -eq 0 ]] && echo "No paths resolved for $SERVICE" >&2 && exit 1
echo "[INFO] Paths: ${paths[*]}" >&2
echo "[INFO] Submodules: ${subs[*]:-<none>}" >&2

WORK="$OUT_BASE/$SERVICE"
rm -rf "$WORK"
mkdir -p "$OUT_BASE"
echo "[STEP] Clone working copy" >&2
git clone "$MONO_ROOT" "$WORK" --no-hardlinks --quiet
pushd "$WORK" >/dev/null

echo "[STEP] Filter history" >&2
git filter-repo $(printf ' --path %q' "${paths[@]}") --force

echo "[STEP] Flatten top-level service dir(s)" >&2
for d in fks_*; do
  [[ -d $d ]] || continue
  rsync -a "$d/" ./
  rm -rf "$d"
done

echo "[STEP] Normalize Python src layout" >&2
if compgen -G 'src/*' >/dev/null; then :; else
  if ls -d */ 2>/dev/null | grep -q fks_ ; then
    first=$(ls -d fks_*/ | head -n1 | tr -d '/')
    mkdir -p src
    rsync -a "$first/" src/
    rm -rf "$first"
  fi
fi

echo "[STEP] Collect tests from monorepo (best-effort)" >&2
for p in "${paths[@]}"; do
  base=${p%%/*}
  test_root="$MONO_ROOT/$base/tests"
  if [[ -d $test_root ]]; then
    rsync -a "$test_root/" tests/ 2>/dev/null || true
  fi
done

echo "[STEP] Add submodules" >&2
declare -A MAPSUB=( [python]=shared_python [schema]=shared_schema [scripts]=shared_scripts [docker]=shared_docker [nginx]=shared_nginx [react]=shared_react [rust]=shared_rust [actions]=shared_actions )
for s in "${subs[@]:-}"; do
  [[ -z $s ]] && continue
  repo="${MAPSUB[$s]:-}"
  [[ -z $repo ]] && continue
  url="git@github.com:$ORG/$repo.git"
  git submodule add -f "$url" "shared/$s" || true
done

echo "[STEP] Apply Python import rewrite" >&2
if grep -RIl '^from fks_shared\.' src >/dev/null 2>&1; then
  grep -RIl '^from fks_shared\.' src | while read -r f; do
    sed -i "s/^from fks_shared\./from shared_python./" "$f" || true
  done
fi

echo "[STEP] Scaffolding" >&2
TEMPLATES="$MONO_ROOT/migration/templates"
mkdir -p .github/workflows docs
if [[ -f pyproject.toml ]]; then cp "$TEMPLATES/ci-python.yml" .github/workflows/ci.yml; fi
if [[ -f Cargo.toml ]]; then cp "$TEMPLATES/ci-rust.yml" .github/workflows/ci.yml; fi
if [[ -f package.json ]]; then cp "$TEMPLATES/ci-web.yml" .github/workflows/ci.yml; fi
# .NET (C#) detection: any .csproj within top 3 levels after flatten
if find . -maxdepth 3 -name '*.csproj' | grep -q .; then
  cp "$TEMPLATES/ci-dotnet.yml" .github/workflows/ci.yml
fi
if [[ ! -f README.md ]]; then sed -e "s/{{REPO_NAME}}/$SERVICE/g" -e "s/{{DESCRIPTION}}/Service extracted from monorepo/" -e "s/{{ORG}}/$ORG/" "$TEMPLATES/README.md.tpl" > README.md; fi
if [[ ! -f docs/architecture.md ]]; then sed -e "s/{{INTERNAL_DEPS}}/TBD/" -e "s/{{SHARED_MODULES}}/${subs[*]}/" "$TEMPLATES/architecture.md.tpl" > docs/architecture.md; fi
sed -e "s/{{REPO_NAME}}/$SERVICE/g" "$TEMPLATES/Makefile.tpl" > Makefile
cp "$TEMPLATES/update-submodules.sh" ./update-submodules.sh; chmod +x update-submodules.sh
cp "$TEMPLATES/schema_assert.py" ./schema_assert.py; echo "v0.0.0" > schema_version.txt
cp "$TEMPLATES/update-schema-version.sh" ./update-schema-version.sh; chmod +x update-schema-version.sh
cp "$TEMPLATES/dep-graph.py" ./dep-graph.py
cp "$TEMPLATES/meta-verify.sh" ./meta-verify.sh; chmod +x meta-verify.sh
cp "$TEMPLATES/security-audit.sh" ./security-audit.sh; chmod +x security-audit.sh
cp "$TEMPLATES/release-please-config.json" ./release-please-config.json
cp "$TEMPLATES/release-please-workflow.yml" .github/workflows/release-please.yml

if [[ -f Cargo.toml ]] && grep -q 'workspace = true' Cargo.toml; then bash "$MONO_ROOT/migration/normalize-rust-standalone.sh" . || true; fi

git add .
git commit -m "chore: initial extraction for $SERVICE" || true

if [[ -n $REMOTE ]]; then
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE"
  git push -u origin main || true
fi

echo "[DONE] Service $SERVICE prepared at $WORK"
popd >/dev/null