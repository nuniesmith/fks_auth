#!/usr/bin/env bash
# Orchestrate extraction of services & shared components into new repos.
# REQUIREMENTS: git-filter-repo installed (pip install git-filter-repo)
# USAGE: ./migration/run-extraction.sh [--only repo1,repo2] [--skip-shared] /path/to/mono-root /output/base/dir org-name
set -euo pipefail

ONLY_LIST=""
SKIP_SHARED=0
POSITIONALS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --only)
      ONLY_LIST=$2; shift 2;;
    --skip-shared)
      SKIP_SHARED=1; shift;;
    --help|-h)
      echo "Usage: $0 [--only repoA,repoB] [--skip-shared] <monorepo-root> <output-base> [org]"; exit 0;;
    *) POSITIONALS+=("$1"); shift;;
  esac
done
set -- "${POSITIONALS[@]}"
MONO_ROOT=${1:-}
OUT_BASE=${2:-}
ORG=${3:-yourorg}
MAP_FILE="${MONO_ROOT}/extraction-map.yml"

if [[ -z "$MONO_ROOT" || -z "$OUT_BASE" ]]; then
  echo "Usage: $0 <monorepo-root> <output-base-dir> [org]" >&2
  exit 1
fi
FALLBACK_COPY=0
if [[ ! -d "$MONO_ROOT/.git" ]]; then
  echo "[WARN] Monorepo root $MONO_ROOT missing .git; falling back to copy mode (no history)" >&2
  FALLBACK_COPY=1
fi
if (( ! FALLBACK_COPY )); then
  if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "git-filter-repo not installed" >&2; exit 1;
  fi
fi
if [[ ! -f "$MAP_FILE" ]]; then
  echo "Mapping file $MAP_FILE not found" >&2; exit 1; fi

mkdir -p "$OUT_BASE"

extract_repo() {
  local target=$1; shift
  local paths=("$@")
  local workdir="$OUT_BASE/$target"
  echo "[INFO] Extracting $target (paths: ${paths[*]})"
  rm -rf "$workdir"
  if (( FALLBACK_COPY )); then
    mkdir -p "$workdir"
    pushd "$workdir" >/dev/null
    for p in "${paths[@]}"; do
      src="$MONO_ROOT/$p"
      if [[ -d $src ]]; then
        rsync -a "$src/" ./ 2>/dev/null || rsync -a "$src" ./ || true
      elif [[ -f $src ]]; then
        rsync -a "$src" ./ || true
      fi
    done
    # Flatten any fks_* dirs
    shopt -s nullglob
    if compgen -G "fks_*" > /dev/null; then
      for d in fks_*; do
        [[ -d $d ]] || continue
        rsync -a "$d/" ./
        rm -rf "$d"
      done
    fi
    git init -q
    git add . || true
    git commit -m "chore: initial copy extraction (no history)" >/dev/null || true
  else
    git clone "$MONO_ROOT" "$workdir" --no-hardlinks --quiet
    pushd "$workdir" >/dev/null
    git filter-repo $(printf ' --path %q' "${paths[@]}") --force
    # Move contents if nested under fks_* directory
    shopt -s nullglob
    if compgen -G "fks_*" > /dev/null; then
      first_dir=$(ls -d fks_* | head -n1)
      rsync -a "$first_dir/" ./
      rm -rf fks_*/
    fi
  fi
  # Inject scaffolding templates
  mkdir -p .github/workflows docs
  local tmpl_dir="${MONO_ROOT}/migration/templates"
  local desc="Service extracted from monorepo"
  if [[ $target == shared_* ]]; then
    desc="Shared component library"
  fi
  if [[ $target == shared_actions ]]; then
    # Seed composite actions
    rsync -a "$tmpl_dir/shared_actions/" ./
    git add actions || true
  fi
  # Detect language
  if [[ -f pyproject.toml ]]; then
    cp "$tmpl_dir/ci-python.yml" .github/workflows/ci.yml
  elif [[ -f Cargo.toml ]]; then
    cp "$tmpl_dir/ci-rust.yml" .github/workflows/ci.yml
  elif [[ -f package.json ]]; then
    cp "$tmpl_dir/ci-web.yml" .github/workflows/ci.yml
  elif compgen -G '*.csproj' >/dev/null; then
    cp "$tmpl_dir/ci-dotnet.yml" .github/workflows/ci.yml
  fi
  # README
  if [[ ! -f README.md ]]; then
    sed -e "s/{{REPO_NAME}}/$target/g" -e "s/{{DESCRIPTION}}/$desc/" -e "s/{{ORG}}/$ORG/" "$tmpl_dir/README.md.tpl" > README.md
  fi
  # Architecture doc
  if [[ ! -f docs/architecture.md ]]; then
    sed -e "s/{{INTERNAL_DEPS}}/TBD/" -e "s/{{SHARED_MODULES}}/TBD/" "$tmpl_dir/architecture.md.tpl" > docs/architecture.md
  fi
  # Makefile
  if [[ ! -f Makefile ]]; then
    sed -e "s/{{REPO_NAME}}/$target/g" "$tmpl_dir/Makefile.tpl" > Makefile
  fi
  # Add submodule management script if this repo will consume submodules (heuristic: not shared repo itself)
  if [[ $target != shared_* ]]; then
    cp "$tmpl_dir/update-submodules.sh" ./update-submodules.sh
    chmod +x update-submodules.sh
    # Schema assert support
    cp "$tmpl_dir/schema_assert.py" ./schema_assert.py
    if [[ ! -f schema_version.txt ]]; then echo "v0.0.0" > schema_version.txt; fi
    cp "$tmpl_dir/update-schema-version.sh" ./update-schema-version.sh
    chmod +x update-schema-version.sh
    # Meta tools
    cp "$tmpl_dir/dep-graph.py" ./dep-graph.py
    cp "$tmpl_dir/meta-verify.sh" ./meta-verify.sh
    chmod +x meta-verify.sh
    cp "$tmpl_dir/security-audit.sh" ./security-audit.sh
    chmod +x security-audit.sh
  fi
  # Release automation (skip for infra if desired later)
  if [[ ! -f release-please-config.json ]]; then
    cp "$tmpl_dir/release-please-config.json" ./release-please-config.json
    cp "$tmpl_dir/release-please-workflow.yml" .github/workflows/release-please.yml
  fi
  # Fallback stub shared submodules (schema, scripts, etc.)
  if (( FALLBACK_COPY )) && [[ -n ${SUBMODULES[$target]:-} ]]; then
    mkdir -p shared
    for sm in ${SUBMODULES[$target]}; do
      [[ -z $sm ]] && continue
      mkdir -p "shared/$sm"
      [[ -f shared/$sm/README.md ]] || echo "# Stub $sm (fallback mode)" > "shared/$sm/README.md"
      if [[ $sm == schema ]]; then
        echo "v0.0.0" > shared/schema/VERSION 2>/dev/null || true
        [[ -f schema_version.txt ]] || echo "v0.0.0" > schema_version.txt
      fi
    done
    git add shared 2>/dev/null || true
  fi
  git add update-submodules.sh schema_assert.py dep-graph.py meta-verify.sh security-audit.sh update-schema-version.sh schema_version.txt release-please-config.json .github/workflows/release-please.yml 2>/dev/null || true
  git add .github/workflows/ci.yml README.md Makefile docs/architecture.md 2>/dev/null || true
  git commit --allow-empty -m "chore: scaffolding placeholder" >/dev/null || true

  # Normalize Rust workspace dependencies to standalone (if needed)
  if [[ -f Cargo.toml ]] && grep -q 'workspace = true' Cargo.toml; then
    if [[ -f "$MONO_ROOT/migration/normalize-rust-standalone.sh" ]]; then
      bash "$MONO_ROOT/migration/normalize-rust-standalone.sh" . || true
      git add pinned-deps.json Cargo.toml Cargo.toml.orig 2>/dev/null || true
      git commit -m "chore: pin workspace deps for standalone build" >/dev/null || true
    fi
  fi
  popd >/dev/null
}

# Parse extraction-map.yml (very light parser; expects simple structure)
current_section=""
current_repo=""
collect_paths=0
declare -A PATHS
declare -A SUBMODULES

while IFS='' read -r line; do
  l=${line%%#*}; l=$(echo "$l" | sed -e 's/[[:space:]]*$//')
  [[ -z $l ]] && continue
  if [[ $l =~ ^shared: ]]; then current_section="shared"; continue; fi
  if [[ $l =~ ^services: ]]; then current_section="services"; continue; fi
  if [[ $l =~ ^[[:space:]]{2}[a-z0-9_-]+: ]]; then
    current_repo=$(echo "$l" | sed -E 's/^[[:space:]]{2}([a-z0-9_-]+):.*/\1/')
    collect_paths=0
    continue
  fi
  if [[ $l =~ paths: ]]; then collect_paths=1; continue; fi
  if [[ $l =~ submodules: ]]; then
    subs_line=$(echo "$l" | sed -E 's/.*submodules:[[:space:]]*\[(.*)\].*/\1/')
    subs_line=$(echo "$subs_line" | tr -d ' ')
    IFS=',' read -r -a subs_arr <<< "$subs_line"
    SUBMODULES[$current_repo]="${subs_arr[*]}"
    continue
  fi
  if (( collect_paths )); then
    if [[ $l =~ ^[[:space:]]{6}-[[:space:]]([^[:space:]].*) ]]; then
      path=$(echo "$l" | sed -E 's/^[[:space:]]{6}-[[:space:]]//')
      path=${path%% #*}
      existing="${PATHS[$current_repo]-}"
      PATHS[$current_repo]="${existing}$path\n"
    else
      collect_paths=0
    fi
  fi
done < "$MAP_FILE"

declare -A ONLY
if [[ -n $ONLY_LIST ]]; then
  IFS=',' read -r -a only_arr <<< "$ONLY_LIST"
  for o in "${only_arr[@]}"; do ONLY[$o]=1; done
fi

summary='[]'
summary_add() { local repo=$1; local count=$2; summary=$(echo "$summary" | jq --arg r "$repo" --arg c "$count" '. + [{repo:$r, files:($c|tonumber)}]'); }

for TARGET in "${!PATHS[@]}"; do
  if (( SKIP_SHARED )) && [[ $TARGET == shared_* ]]; then continue; fi
  if [[ -n $ONLY_LIST ]] && [[ -z ${ONLY[$TARGET]:-} ]]; then continue; fi
  mapfile -t ARR < <(printf "%s" "${PATHS[$TARGET]}" | sed '/^$/d')
  extract_repo "$TARGET" "${ARR[@]}"
  count=$(find "$OUT_BASE/$TARGET" -type f | wc -l | tr -d ' ' || echo 0)
  summary_add "$TARGET" "$count"
done

echo "$summary" | jq '.' > "$OUT_BASE/extraction-summary.json"
echo "[DONE] Extraction complete. Summary written to $OUT_BASE/extraction-summary.json"
