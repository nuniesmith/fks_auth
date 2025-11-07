#!/usr/bin/env bash
set -euo pipefail

# push_all.sh
# Stages, commits (if needed), and pushes every git repository nested under the current project root.
# Usage:
#   ./scripts/push_all.sh                # uses default commit message with UTC timestamp
#   ./scripts/push_all.sh "chore: sync"   # custom commit message

commit_msg=${1:-"chore: sync $(date -u +%Y-%m-%dT%H:%M:%SZ)"}

# Find all git repos (directories containing a .git folder)
mapfile -t repos < <(find . -type d -name .git -print 2>/dev/null | sed 's|/\.git$||' | sort)

if [ ${#repos[@]} -eq 0 ]; then
  echo "No git repositories found." >&2
  exit 1
fi

echo "Discovered ${#repos[@]} repositories." 

for repo in "${repos[@]}"; do
  echo "\n==== $repo ===="
  (
    cd "$repo"
    branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "UNKNOWN")
    echo "Branch: $branch"

    changes=$(git status --porcelain || true)
    if [ -n "$changes" ]; then
      echo "Staging & committing changes:"; echo "$changes"
      git add -A
      if git diff --cached --quiet; then
        echo "Nothing to commit after add (possibly only ignored files)."
      else
        git commit -m "$commit_msg" || echo "Commit skipped (hook or race)."
      fi
    else
      echo "No changes to commit."
    fi

    # Push logic
    if git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
      echo "Pushing to existing upstream..."
      git push || echo "Push failed: $repo"
    else
      if git remote get-url origin >/dev/null 2>&1; then
        echo "Setting upstream to origin/$branch and pushing..."
        git push -u origin "$branch" || echo "Initial push failed: $repo"
      else
        echo "No remote 'origin' configured; skipping push."
      fi
    fi
  )
done

echo "\nAll repositories processed."
