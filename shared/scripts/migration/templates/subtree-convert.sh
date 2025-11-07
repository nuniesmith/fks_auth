#!/usr/bin/env bash
# Convert existing submodules to subtree copies for a repo (fallback strategy).
# Usage: ./subtree-convert.sh <remote-prefix>
# remote-prefix: e.g., git@github.com:yourorg
set -euo pipefail
PREFIX=${1:-git@github.com:yourorg}

git config --file .gitmodules --get-regexp path | while read -r key path; do
  name=${path##*/}
  url=$(git config --file .gitmodules submodule."$path".url)
  branch=main
  echo "[CONVERT] $name ($path)"
  git submodule deinit -f "$path" || true
  rm -rf "$path" .git/modules/"$path"
  git rm -f "$path" || true
  git commit -m "chore: remove submodule $name" || true
  git remote add "$name" "$url" || true
  git fetch "$name" $branch
  git subtree add --prefix "$path" "$name" $branch --squash
  git commit -m "chore: subtree add $name" || true
 done
