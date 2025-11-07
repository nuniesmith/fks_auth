#!/usr/bin/env bash
set -euo pipefail

# submodules_push.sh
# Ensures every submodule is initialized, commits any local changes in submodules,
# pushes them (setting upstream if needed), then updates and pushes the root repo
# if submodule SHAs changed.

commit_msg_sub=${1:-"chore: submodule sync $(date -u +%Y-%m-%dT%H:%M:%SZ)"}
root_commit_msg=${2:-"chore: update submodule refs"}

echo "== Initialize/Update submodules =="
git submodule update --init --recursive

echo "== Processing submodules =="
changed=false
while IFS= read -r line; do
  path=$(echo "$line" | awk '{print $2}')
  [ -z "$path" ] && continue
  echo "\n-- $path --"
  if ! git -C "$path" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Skipping (not a work tree)"
    continue
  fi
  branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || echo UNKNOWN)
  echo "Branch: $branch"
  changes=$(git -C "$path" status --porcelain || true)
  if [ -n "$changes" ]; then
    echo "Changes detected:"; echo "$changes"
    git -C "$path" add -A
    if git -C "$path" diff --cached --quiet; then
      echo "Nothing staged after add."
    else
      git -C "$path" commit -m "$commit_msg_sub" || echo "Commit skipped." 
      changed=true
    fi
  else
    echo "No changes."
  fi
  if git -C "$path" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
    git -C "$path" push || echo "Push failed ($path)"
  else
    if git -C "$path" remote get-url origin >/dev/null 2>&1; then
      git -C "$path" push -u origin "$branch" || echo "Initial push failed ($path)"
    else
      echo "No origin remote ($path)"
    fi
  fi
done < <(git config --file .gitmodules --get-regexp path 2>/dev/null)

echo "\n== Update root refs if needed =="
if git diff --quiet HEAD -- .gitmodules; then :; fi
if ! git diff --quiet --submodule=diff; then
  echo "Submodule SHA changes detected; committing root update."
  git add .
  git -c commit.gpgsign=false commit -m "$root_commit_msg" || echo "Root commit skipped."
else
  echo "No submodule SHA changes to commit in root."
fi

echo "== Pushing root repo =="
if git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
  git push || echo "Root push failed"
else
  if git remote get-url origin >/dev/null 2>&1; then
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    git push -u origin "$current_branch" || echo "Initial root push failed"
  else
    echo "No origin remote for root repo."
  fi
fi

echo "\nAll submodules processed and root attempted."
