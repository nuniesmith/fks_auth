#!/usr/bin/env bash
set -euo pipefail
log(){ echo -e "[update-submodules] $1"; }
err(){ echo -e "[update-submodules][err] $1" >&2; }

PUSH=false
REMOTE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --push) PUSH=true; shift;;
    --remote|--remote-update) REMOTE=true; shift;;
    -h|--help)
      cat <<USAGE
Usage: $0 [--remote] [--push]
  --remote         Update submodules to latest remote (git submodule update --remote)
  --push           Commit and push submodule reference changes if any
Examples:
  $0 --remote
  $0 --remote --push
USAGE
      exit 0;;
    *) err "Unknown arg $1"; exit 1;;
  esac
done

log "Syncing submodule URLs"
git submodule sync --recursive

if $REMOTE; then
  log "Updating submodules to latest remote commits"
  git submodule update --init --recursive --remote --jobs 8
else
  log "Initializing/updating submodules at recorded SHAs"
  git submodule update --init --recursive --jobs 8
fi

log "Fetching all remotes inside each submodule (for info)"
while read -r path; do
  if [[ -d "$path/.git" ]]; then
    (cd "$path" && git fetch --all --prune && log "Fetched $path") || true
  fi
done < <(git config --file .gitmodules --get-regexp path | awk '{print $2}')

if $REMOTE; then
  # Stage updated submodule pointers
  if ! git diff --quiet || ! git diff --cached --quiet; then
    log "Recording updated submodule SHAs"
    git add .gitmodules || true
    git add $(git config --file .gitmodules --get-regexp path | awk '{print $2}') || true
    if ! git diff --cached --quiet; then
      git commit -m "chore(submodules): update submodule references"
      if $PUSH; then
        if git push; then
          log "Pushed submodule reference update commit"
        else
          err "Failed to push changes"
        fi
      fi
    else
      log "No staged changes after add."
    fi
  else
    log "No submodule pointer changes detected."
  fi
fi

log "Done"
