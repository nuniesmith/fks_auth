#!/usr/bin/env bash
# Bulk updater for a specific shared/* git submodule across every service repo.
# Default target: shared_docker
#
# What it does (safe-by-default):
#   1. Optionally commits & pushes pending changes INSIDE one copy of the submodule
#      (only if you pass -m/--message; otherwise dry run prints what it'd do).
#   2. Fast‑forwards (pulls) the submodule in each service to the latest origin/<branch>.
#   3. Commits the updated gitlink (pointer) in each parent service repo (if changed)
#      with a standardized message including the new short SHA.
#   4. Pushes each service repo (unless --no-push provided).
#
# Usage examples:
#   ./update_shared_submodule.sh                          # dry run (no commits)
#   ./update_shared_submodule.sh -m "chore: bump shared_docker"          # commit submodule changes (if any) & update parents
#   ./update_shared_submodule.sh -s shared_docker -b main -m "chore: sync"
#   ./update_shared_submodule.sh -s shared_schema -m "chore: bump schema"
#   ./update_shared_submodule.sh -s shared_docker --no-parent --m "feat: add X"  # only commit inside submodule
#   ./update_shared_submodule.sh -s shared_docker -m "chore: bump" --no-submodule-commit  # skip committing inside submodule, just refresh pointers
#
# Flags:
#   -s, --submodule NAME     Submodule directory name under shared/ (default: shared_docker)
#   -b, --branch BRANCH      Branch inside the submodule to pull/track (default: main)
#   -m, --message MSG        Commit message to use when committing inside submodule (also base for parent commit)
#   --no-submodule-commit    Do not create a commit inside the submodule even if changes exist
#   --no-parent              Do not update/commit in parent repos (only operate inside the first submodule instance)
#   --no-push                Skip pushes (both submodule + parents)
#   -y                       Assume yes (non-interactive)
#   -r, --repos a,b,c        Limit to subset of service repos
#   -h, --help               Show help
#
# Dry-run mode: If you do not pass -m/--message AND there are staged/unstaged submodule changes, the script will NOT commit anything.
#
# Exit codes:
#   0 success, 1 failure.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALL_REPOS=(analyze api auth config data docs engine execution master nginx ninja nodes training transformer web worker)

SUBMODULE_NAME="shared_docker"   # user can pass either 'shared_docker' or 'docker' or even 'shared/docker'
SUBMODULE_BRANCH="main"
USER_MESSAGE=""
NO_SUBMODULE_COMMIT=false
NO_PARENT_UPDATES=false
NO_PUSH=false
ASSUME_YES=false
LIMIT_REPOS=()

color() { local c=$1; shift; printf "\033[%sm%s\033[0m" "$c" "$*"; }
info() { printf "[%s] %s\n" "$(color 36 INFO)" "$*"; }
warn() { printf "[%s] %s\n" "$(color 33 WARN)" "$*"; }
err() { printf "[%s] %s\n" "$(color 31 ERROR)" "$*" >&2; }

usage() { grep '^# ' "$0" | sed 's/^# //'; exit 0; }

while (( "$#" )); do
  case "$1" in
    -s|--submodule) shift; SUBMODULE_NAME=${1:-}; [[ -n "$SUBMODULE_NAME" ]] || { err "--submodule requires a name"; exit 1; } ;;
    -b|--branch) shift; SUBMODULE_BRANCH=${1:-main} ;;
    -m|--message) shift; USER_MESSAGE=${1:-}; [[ -n "$USER_MESSAGE" ]] || { err "--message requires text"; exit 1; } ;;
    --no-submodule-commit) NO_SUBMODULE_COMMIT=true ;;
    --no-parent) NO_PARENT_UPDATES=true ;;
    --no-push) NO_PUSH=true ;;
    -y) ASSUME_YES=true ;;
    -r|--repos) shift; IFS=',' read -r -a LIMIT_REPOS <<< "${1:-}" ;;
    -h|--help) usage ;;
    *) err "Unknown arg: $1"; usage ;;
  esac
  shift
done

# Resolve layout: accept inputs
ORIG_INPUT="$SUBMODULE_NAME"
if [[ "$SUBMODULE_NAME" == */* ]]; then
  # If user passed a path like shared/docker just strip leading shared/
  SUBMODULE_NAME="${SUBMODULE_NAME#shared/}"
fi
if [[ "$SUBMODULE_NAME" == shared_* ]]; then
  SHORT_NAME="${SUBMODULE_NAME#shared_}"
else
  SHORT_NAME="$SUBMODULE_NAME"
fi

# Candidate paths (prefer new short layout if both exist somewhere)
LEGACY_PATH="shared/${SHORT_NAME}"
SHORT_PATH="shared/${SHORT_NAME}"

detect_chosen_path() {
  local found_short=0 found_legacy=0
  for r in "${TARGET_REPOS[@]}"; do
    [[ -e "$ROOT_DIR/$r/$SHORT_PATH/.git" || -f "$ROOT_DIR/$r/$SHORT_PATH/.git" ]] && found_short=1
    [[ -e "$ROOT_DIR/$r/$LEGACY_PATH/.git" || -f "$ROOT_DIR/$r/$LEGACY_PATH/.git" ]] && found_legacy=1
  done
  if (( found_short )); then
    echo "$SHORT_PATH"; return 0
  elif (( found_legacy )); then
    echo "$LEGACY_PATH"; return 0
  else
    echo ""; return 1
  fi
}

SUB_PATH=$(detect_chosen_path || true)
if [[ -z "$SUB_PATH" ]]; then
  # We'll continue; later presence detection logic will emit a clearer hint.
  SUB_PATH="$SHORT_PATH"  # default preference
fi

TARGET_REPOS=()
if ((${#LIMIT_REPOS[@]})); then
  for r in "${LIMIT_REPOS[@]}"; do
    [[ -d "$ROOT_DIR/$r" ]] && TARGET_REPOS+=("$r") || warn "Skipping unknown repo $r"
  done
else
  TARGET_REPOS=("${ALL_REPOS[@]}")
fi

if $NO_PARENT_UPDATES && ! $NO_SUBMODULE_COMMIT && [[ -z "$USER_MESSAGE" ]]; then
  warn "No commit message: will still be dry-run inside first submodule copy." 
fi

# --- Step 1: Find a canonical working copy of the submodule to commit (if needed) ---
PRIMARY_REPO=""
MODIFIED_REPOS=()
submodule_exists() {
  local path="$1"
  # In modern git, submodule has a .git file (gitdir: ../..). Older may have directory.
  [[ -e "$path/.git" ]] && return 0
  return 1
}

reinit_submodule() {
  local repo_path="$1" rel_path="$2"
  if [[ ! -d "$repo_path/.git" ]]; then return 1; fi
  ( cd "$repo_path" && git submodule sync --quiet "$rel_path" 2>/dev/null || true; git submodule update --init --recursive "$rel_path" 2>/dev/null || true )
}

repair_full_clone_to_submodule() {
  # Handle case where directory contains a full clone (.git dir) instead of a gitlink index entry.
  local repo_path="$1" rel_path="$2" url="$3"
  ( cd "$repo_path" && {
      # capture commit from actual clone if possible
      local sha
      sha=$(git -C "$rel_path" rev-parse HEAD 2>/dev/null || echo "")
      git rm -f "$rel_path" >/dev/null 2>&1 || true
      git submodule add -f "$url" "$rel_path" >/dev/null 2>&1 || return 1
      git submodule update --init --recursive "$rel_path" >/dev/null 2>&1 || true
      if [[ -n "$sha" ]]; then
        ( cd "$rel_path" && git fetch --quiet && git checkout -q "$sha" 2>/dev/null ) || true
      fi
    } )
}

for repo in "${TARGET_REPOS[@]}"; do
  if submodule_exists "$ROOT_DIR/$repo/$SUB_PATH"; then
    if git -C "$ROOT_DIR/$repo/$SUB_PATH" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      # Detect uncommitted changes inside submodule
      if [[ -n "$(git -C "$ROOT_DIR/$repo/$SUB_PATH" status --porcelain 2>/dev/null || true)" ]]; then
        MODIFIED_REPOS+=("$repo")
      fi
      [[ -z "$PRIMARY_REPO" ]] && PRIMARY_REPO="$repo"
    fi
  fi
done

if [[ -z "$PRIMARY_REPO" ]]; then
  err "Submodule path for name '$ORIG_INPUT' not located. Tried: '$SHORT_PATH' and legacy '$LEGACY_PATH'."
  err "Hint: Run migration (./migrate_shared_submodules.sh --apply) or init legacy: ./verify_shared_repos.sh --modules=shared_${SHORT_NAME} --init"
  exit 1
fi

if ((${#MODIFIED_REPOS[@]} > 1)); then
  err "Detected local uncommitted submodule changes in multiple repos: ${MODIFIED_REPOS[*]}. Please consolidate (commit or reset) so only one working copy holds changes."; exit 1
fi

if ((${#MODIFIED_REPOS[@]} == 1)); then
  info "Changes detected inside $SUB_PATH in repo ${MODIFIED_REPOS[0]}"
  if [[ -z "$USER_MESSAGE" ]]; then
    warn "No -m message -> dry run (showing diff, no commit)."
    git -C "$ROOT_DIR/${MODIFIED_REPOS[0]}/$SUB_PATH" --no-pager diff --stat || true
  elif $NO_SUBMODULE_COMMIT; then
    warn "--no-submodule-commit specified: WILL NOT commit changes inside submodule even though changes exist." 
  else
    if ! $ASSUME_YES; then
      read -rp "Commit & push these submodule changes? [y/N] " ans
      [[ $ans =~ ^[Yy]$ ]] || { warn "User declined commit."; USER_MESSAGE=""; }
    fi
    if [[ -n "$USER_MESSAGE" ]]; then
      ( cd "$ROOT_DIR/${MODIFIED_REPOS[0]}/$SUB_PATH" && git add -A && git commit -m "$USER_MESSAGE" ) || { err "Submodule commit failed"; exit 1; }
      if ! $NO_PUSH; then
        ( cd "$ROOT_DIR/${MODIFIED_REPOS[0]}/$SUB_PATH" && git push origin "$SUBMODULE_BRANCH" ) || { err "Submodule push failed"; exit 1; }
      else
        info "Skipped submodule push (--no-push)."
      fi
    fi
  fi
fi

# Always ensure submodule branch is up to date in PRIMARY_REPO (fetch & fast-forward)
info "Ensuring latest $SUBMODULE_BRANCH for $SUB_PATH in $PRIMARY_REPO"
( cd "$ROOT_DIR/$PRIMARY_REPO/$SUB_PATH" && git fetch origin "$SUBMODULE_BRANCH" --quiet && git checkout "$SUBMODULE_BRANCH" >/dev/null 2>&1 || true && git pull --ff-only origin "$SUBMODULE_BRANCH" || true )

NEW_SHA=$(git -C "$ROOT_DIR/$PRIMARY_REPO/$SUB_PATH" rev-parse --short HEAD 2>/dev/null || echo unknown)
PARENT_MSG_BASE=${USER_MESSAGE:-"chore($SUBMODULE_NAME): update submodule"}
PARENT_COMMIT_MSG="$PARENT_MSG_BASE @ $NEW_SHA"

if $NO_PARENT_UPDATES; then
  info "--no-parent specified: skipping parent repo pointer updates."; exit 0
fi

DRY_PARENT=false
[[ -z "$USER_MESSAGE" ]] && DRY_PARENT=true
[[ "$PARENT_COMMIT_MSG" == *"unknown"* ]] && DRY_PARENT=true

info "Updating parent repo gitlinks for $SUB_PATH (target SHA $NEW_SHA)"

overall=0
for repo in "${TARGET_REPOS[@]}"; do
  REPO_PATH="$ROOT_DIR/$repo"
  [[ -d "$REPO_PATH/.git" ]] || { warn "$repo: not a git repository"; continue; }
  if ! submodule_exists "$REPO_PATH/$SUB_PATH"; then
    warn "$repo: submodule $SUB_PATH absent (skip)"; continue
  fi
  pushd "$REPO_PATH/$SUB_PATH" >/dev/null || continue
  # Sync & fast-forward submodule working copy
  if ! git fetch origin "$SUBMODULE_BRANCH" --quiet 2>/dev/null; then
    warn "$repo: fetch failed; will attempt re-init"; popd >/dev/null; reinit_submodule "$REPO_PATH" "$SUB_PATH"; pushd "$REPO_PATH/$SUB_PATH" >/dev/null || continue
  fi
  git checkout "$SUBMODULE_BRANCH" >/dev/null 2>&1 || true
  if ! git pull --ff-only origin "$SUBMODULE_BRANCH" >/dev/null 2>&1; then
    warn "$repo: fast-forward pull failed (divergence or uninit). Attempting re-init."; popd >/dev/null; reinit_submodule "$REPO_PATH" "$SUB_PATH"; pushd "$REPO_PATH/$SUB_PATH" >/dev/null || continue
  fi
  CURRENT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo none)
  popd >/dev/null
  pushd "$REPO_PATH" >/dev/null || continue
  # Detect uninitialized marker '-' in submodule status -> reinit
  if git submodule status "$SUB_PATH" 2>/dev/null | grep -q '^-' ; then
    info "$repo: submodule appears uninitialized; re-initializing $SUB_PATH";
    reinit_submodule "$REPO_PATH" "$SUB_PATH"
  fi
  # If directory has a full .git dir (not file) AND index entry not a gitlink, repair
  if [[ -d "$REPO_PATH/$SUB_PATH/.git" ]]; then
    if ! git ls-files --stage "$SUB_PATH" 2>/dev/null | grep -q '160000'; then
      warn "$repo: $SUB_PATH is a full clone not a gitlink; repairing to submodule"
      repair_full_clone_to_submodule "$REPO_PATH" "$SUB_PATH" "$(awk -v p="$SUB_PATH" 'found&&/url =/ {print $3; exit} /path = '"$SUB_PATH"'/ {found=1}' "$REPO_PATH/.gitmodules" 2>/dev/null)"
    fi
  fi
  if git diff --quiet "$SUB_PATH"; then
    info "$repo: already at $CURRENT_SHA (no parent commit needed)"
    popd >/dev/null; continue
  fi
  if $DRY_PARENT; then
    info "$repo: would commit pointer to $CURRENT_SHA (dry run)"
    git diff --shortstat "$SUB_PATH" || true
    popd >/dev/null; continue
  fi
  git add "$SUB_PATH"
  if git diff --cached --quiet; then
    info "$repo: nothing staged after add (skip)"
    popd >/dev/null; continue
  fi
  git commit -m "$PARENT_COMMIT_MSG" || { warn "$repo: parent commit failed"; overall=1; popd >/dev/null; continue; }
  if ! $NO_PUSH; then
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    git push origin "$BRANCH" || { warn "$repo: push failed"; overall=1; }
  else
    info "$repo: push skipped (--no-push)"
  fi
  popd >/dev/null
done

if $DRY_PARENT; then
  warn "Dry run complete (no parent commits made). Add -m <msg> to create commits."
fi
exit $overall
