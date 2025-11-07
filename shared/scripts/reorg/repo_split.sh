#!/usr/bin/env bash
set -euo pipefail

# Repository Split Automation Script
# Uses git filter-repo (must be installed) to extract components into new repos.
# Dry-run friendly: set DRY_RUN=1 to preview commands.

COMPONENTS=(
  "fks_actions:repo/fks_actions"
  "fks_scripts:scripts"
  "fks_shared:repo/fks_shared"
  "fks_config:repo/fks_config"
  "fks_docker_builder:repo/fks_docker_builder"
  "fks_nodes:repo/fks_nodes"
  "fks_execution:repo/fks_execution"
  "fks_data:repo/fks_data"
  "fks_engine:repo/fks_engine"
  "fks_worker:repo/fks_worker"
  "fks_api:repo/fks_api"
  "fks_training:repo/fks_training"
  "fks_transformer:repo/fks_transformer"
  "fks_ninja:repo/fks_ninja"
)

OUT_DIR="_splits"
mkdir -p "$OUT_DIR"

command_exists() { command -v "$1" >/dev/null 2>&1; }

if ! command_exists git-filter-repo && ! command_exists git-filter-repo.py; then
  echo "git-filter-repo not found. Install via: pip install git-filter-repo" >&2
  exit 1
fi

run_filter_repo() {
  local name="$1"; shift
  local path="$1"; shift
  echo "=== Splitting $name ($path) ==="
  local target="$OUT_DIR/$name"
  rm -rf "$target" && mkdir -p "$target"
  git clone --no-local . "$target" >/dev/null 2>&1
  pushd "$target" >/dev/null
  if [ "${DRY_RUN:-}" = "1" ]; then
    echo "DRY_RUN: would run filter-repo for path $path";
  else
    git filter-repo --quiet --path "$path/" --path-rename "$path/:" || {
      echo "WARN: filter-repo failed for $name (maybe empty)";
    }
  fi
  popd >/dev/null
}

for comp in "${COMPONENTS[@]}"; do
  IFS=":" read -r repo path <<<"$comp"
  if [ -d "$path" ]; then
    run_filter_repo "$repo" "$path"
  else
    echo "Skip $repo (missing path $path)"
  fi
done

echo "All splits staged under $OUT_DIR. Next steps:";
echo "  1. Create remote empty repos (GitHub org).";
echo "  2. For each dir: push: (cd _splits/<name> && git remote add origin <url> && git push -u origin HEAD:main)";
echo "  3. Replace directories with submodules: git rm -r repo/fks_config && git submodule add <url> repo/fks_config";
echo "  4. Commit and push submodule references.";
