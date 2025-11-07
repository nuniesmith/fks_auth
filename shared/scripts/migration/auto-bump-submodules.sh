#!/usr/bin/env bash
# Auto bump submodules across extracted repos and summarize changes.
# Usage: ./migration/auto-bump-submodules.sh <extracted-base> [--strategy tag|main|tag-first] [--json-out summary.json] [--dry-run]
# Strategy:
#   tag        : bump-all tag (latest semver-ish tag)
#   main       : bump-all main
#   tag-first  : attempt tag; if no commit changes, try main
set -euo pipefail
BASE=${1:-}
[[ -z $BASE ]] && echo "Usage: $0 <extracted-base> [--strategy ...]" >&2 && exit 1
[[ ! -d $BASE ]] && echo "Base dir $BASE not found" >&2 && exit 1
shift || true
STRATEGY=tag-first
JSON_OUT="submodule-bump-summary.json"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --strategy) STRATEGY=$2; shift 2;;
    --json-out) JSON_OUT=$2; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done

summary='[]'
add_summary() {
  local repo=$1; local before=$2; local after=$3; local updated=$4; local commits=$5
  summary=$(echo "$summary" | jq --arg r "$repo" --arg before "$before" --arg after "$after" --argjson updated "$updated" --argjson commits "$commits" '. + [{repo:$r,before:$before,after:$after,modules_updated:$updated,commits_created:$commits}]')
}

for repo in "$BASE"/*; do
  [[ -d $repo/.git ]] || continue
  [[ -f $repo/update-submodules.sh ]] || continue
  pushd "$repo" >/dev/null
  name=$(basename "$repo")
  before_hash=$(git rev-parse HEAD)
  # capture list output
  ./update-submodules.sh list >/dev/null || true
  if [[ $STRATEGY == tag ]]; then
    if (( DRY_RUN )); then echo "[DRY] $name bump-all tag"; else ./update-submodules.sh bump-all tag || true; fi
  elif [[ $STRATEGY == main ]]; then
    if (( DRY_RUN )); then echo "[DRY] $name bump-all main"; else ./update-submodules.sh bump-all main || true; fi
  else # tag-first
    if (( DRY_RUN )); then
      echo "[DRY] $name bump-all tag (then main if unchanged)"
    else
      ./update-submodules.sh bump-all tag || true
      # If still no changes, try main (some repos may have no new tag)
      if [[ -z $(git diff --name-only --cached) ]]; then
        ./update-submodules.sh bump-all main || true
      fi
    fi
  fi
  commits_created=0
  if [[ -n $(git log --oneline ${before_hash}..HEAD) ]]; then
    commits_created=$(git log --oneline ${before_hash}..HEAD | wc -l | tr -d ' ')
  fi
  modules_updated=$(git show ${before_hash}:.gitmodules 2>/dev/null | grep 'submodule' || true)
  new_hash=$(git rev-parse HEAD)
  updated_count=0
  # Heuristic: count commit messages with chore(submodule): pattern
  updated_count=$(git log --oneline ${before_hash}..HEAD | grep -c 'chore(submodule):' || true)
  add_summary "$name" "$before_hash" "$new_hash" "$updated_count" "$commits_created"
  if (( DRY_RUN )); then
    git reset --hard $before_hash >/dev/null
  fi
  popd >/dev/null
done

echo "$summary" | jq '.' > "$BASE/$JSON_OUT"
echo "[AUTO-BUMP] Summary written to $BASE/$JSON_OUT" >&2
