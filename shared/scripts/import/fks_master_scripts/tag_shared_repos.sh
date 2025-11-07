#!/usr/bin/env bash
set -euo pipefail
# Tag shared repositories using provided version or auto-bumped semantic version.
# Usage: tag_shared_repos.sh [<version>|--auto [--part major|minor|patch] [--prerelease rc]]

# Dynamically discover shared paths. Prefer submodules; fallback to known local shared repo(s).
if [[ -f .gitmodules ]]; then
  mapfile -t SHARED < <(git config --file .gitmodules --get-regexp path | awk '{print $2}')
else
  SHARED=(fks_shared)
fi
PART=patch
PRERELEASE=""
MODE=manual
MANUAL_VERSION=""

log(){ echo -e "[tag] $1"; }
err(){ echo -e "[tag][err] $1" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto) MODE=auto; shift;;
    --part) PART=$2; shift 2;;
    --prerelease) PRERELEASE=$2; shift 2;;
    v*|[0-9]*.[0-9]*.[0-9]*) MANUAL_VERSION=$1; shift;;
    -h|--help)
      cat <<USAGE
Usage: $0 [version]|[--auto --part patch|minor|major [--prerelease rc]]
Examples:
  $0 v1.2.3
  $0 --auto --part minor
  $0 --auto --part patch --prerelease rc1
USAGE
      exit 0;;
    *) err "Unknown arg $1"; exit 1;;
  esac
done

if [[ $MODE = manual && -z $MANUAL_VERSION ]]; then
  MANUAL_VERSION=v1.0.0
fi

derive_next_version(){
  local repo_dir=$1
  pushd "$repo_dir" >/dev/null
  local last_tag
  last_tag=$(git tag --list 'v*' --sort=-v:refname | head -1 || true)
  [[ -z $last_tag ]] && last_tag=v0.0.0
  local core=${last_tag#v}
  IFS=. read -r MAJ MIN PAT <<<"$core"
  case $PART in
    major) ((MAJ++)); MIN=0; PAT=0;;
    minor) ((MIN++)); PAT=0;;
    patch) ((PAT++));;
    *) err "Invalid part $PART"; popd >/dev/null; return 1;;
  esac
  local next=v${MAJ}.${MIN}.${PAT}
  if [[ -n $PRERELEASE ]]; then
    next+="-${PRERELEASE}"
  fi
  echo $next
  popd >/dev/null || true
}

for path in "${SHARED[@]}"; do
  if [ -d "$path/.git" ]; then
    pushd "$path" >/dev/null
    if ! git diff --quiet || ! git diff --cached --quiet; then
      log "Skipping $path (uncommitted changes)"
      popd >/dev/null; continue
    fi
    VERSION=$MANUAL_VERSION
    if [[ $MODE = auto ]]; then
      VERSION=$(derive_next_version .) || { popd >/dev/null; continue; }
    fi
    if git rev-parse "$VERSION" >/dev/null 2>&1; then
      log "$path already has tag $VERSION"
    else
      git tag "$VERSION"
      if git push origin "$VERSION"; then
        log "Tagged $path with $VERSION"
      else
        err "Push failed for $path (tag still created locally)"
      fi
    fi
    popd >/dev/null
  fi
done
