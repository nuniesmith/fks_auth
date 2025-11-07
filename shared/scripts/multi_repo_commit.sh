#!/usr/bin/env bash
# Bulk commit & push helper for all fks service repositories.
# Usage:
#   ./multi_repo_commit.sh -m "commit message"        # real run
#   ./multi_repo_commit.sh -m "commit message" -a      # add untracked files too
#   ./multi_repo_commit.sh -m "commit message" -r api,engine # only selected repos
#   ./multi_repo_commit.sh                              # dry run (shows status)
# Flags:
#   -m  Commit message (required for non-dry run)
#   -a  Add untracked files (git add -A). Default: tracked modifications only.
#   -r  Comma separated subset of repo dir names.
#   -y  Do not prompt, assume yes.
#   -h  Help
#   --no-push  Skip pushing (just commit)
#
# Safety:
#   Without -m it will never create commits (dry run).
#   Shows per repo status before acting.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALL_REPOS=(analyze api auth config data docs engine execution master nginx nodes ninja training transformer web worker)
ADD_UNTRACKED=false
COMMIT_MSG=""
SUBSET=()
ASSUME_YES=false
DO_PUSH=true

color() { local c=$1; shift; printf "\033[%sm%s\033[0m" "$c" "$*"; }
status_line() { printf "[%s] %s\n" "$(color 36 INFO)" "$*"; }
warn() { printf "[%s] %s\n" "$(color 33 WARN)" "$*"; }
err() { printf "[%s] %s\n" "$(color 31 ERROR)" "$*" >&2; }

usage() { grep '^# ' "$0" | sed 's/^# //'; exit 0; }

while (( "$#" )); do
  case "$1" in
    -m) shift; COMMIT_MSG=${1:-}; [[ -n "$COMMIT_MSG" ]] || { err "-m requires a message"; exit 1; } ;;
    -a) ADD_UNTRACKED=true ;;
    -r) shift; IFS=',' read -r -a SUBSET <<< "${1:-}" ;;
    -y) ASSUME_YES=true ;;
    --no-push) DO_PUSH=false ;;
    -h|--help) usage ;;
    *) err "Unknown arg: $1"; usage ;;
  esac
  shift
done

TARGET_REPOS=()
if ((${#SUBSET[@]})); then
  for r in "${SUBSET[@]}"; do
    if [[ ! -d "$ROOT_DIR/$r/.git" ]]; then
      warn "Skipping unknown repo '$r'"
      continue
    fi
    TARGET_REPOS+=("$r")
  done
else
  TARGET_REPOS=("${ALL_REPOS[@]}")
fi

if [[ -z "$COMMIT_MSG" ]]; then
  warn "No commit message provided: dry run mode (no commits or pushes)."
fi

DRY_RUN=true
[[ -n "$COMMIT_MSG" ]] && DRY_RUN=false

overall_result=0

for repo in "${TARGET_REPOS[@]}"; do
  REPO_PATH="$ROOT_DIR/$repo"
  if [[ ! -d "$REPO_PATH/.git" ]]; then
    warn "$repo: not a git repository (skipping)"
    continue
  fi
  pushd "$REPO_PATH" >/dev/null
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'UNKNOWN')
  REMOTE="origin/$BRANCH"
  git fetch --quiet origin || true
  AHEAD=$(git rev-list --left-right --count "$BRANCH"..."$REMOTE" 2>/dev/null | awk '{print $1}') || AHEAD=0
  BEHIND=$(git rev-list --left-right --count "$BRANCH"..."$REMOTE" 2>/dev/null | awk '{print $2}') || BEHIND=0
  MODS=$(git status --porcelain)
  if [[ -z "$MODS" && $AHEAD -eq 0 && $BEHIND -eq 0 ]]; then
    status_line "$repo ($BRANCH): clean"
    popd >/dev/null
    continue
  fi
  status_line "$repo ($BRANCH): changes present | ahead=$AHEAD behind=$BEHIND"
  if [[ -n "$MODS" ]]; then
    git --no-pager status -sb
  fi
  if $DRY_RUN; then
    popd >/dev/null
    continue
  fi
  if ! $ASSUME_YES; then
    read -rp "Commit changes in $repo? [y/N] " ans
    [[ $ans =~ ^[Yy]$ ]] || { warn "Skipped $repo"; popd >/dev/null; continue; }
  fi
  if $ADD_UNTRACKED; then
    git add -A
  else
    # add modified & deleted only
    git diff --name-only | xargs -r git add
    git diff --name-only --cached | xargs -r echo >/dev/null
  fi
  if git diff --cached --quiet; then
    warn "$repo: nothing staged after add (maybe only untracked and -a not used)"
  else
    git commit -m "$COMMIT_MSG" || warn "$repo: commit failed"
  fi
  if $DO_PUSH; then
    git push origin "$BRANCH" || { err "$repo: push failed"; overall_result=1; }
  else
    status_line "$repo: push skipped (--no-push)"
  fi
  popd >/dev/null
done

if $DRY_RUN; then
  status_line "Dry run complete. Provide -m 'message' to create commits."
fi
exit $overall_result
