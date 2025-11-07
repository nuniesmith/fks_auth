#!/usr/bin/env bash
# Manage and update submodules: list status, bump to latest tag or main.
# Usage:
#   ./update-submodules.sh list
#   ./update-submodules.sh bump <name> [tag|main]
#   ./update-submodules.sh bump-all [tag|main]
set -euo pipefail

mode=${1:-list}
which=${2:-}
refspec=${3:-tag}

color() { local c=$1; shift; echo -e "\033[${c}m$*\033[0m"; }
header() { color 36 "$*"; }
err() { color 31 "$*" >&2; }

require_clean() {
  if [[ -n $(git status --porcelain) ]]; then
    err "Working tree not clean. Commit or stash first."; exit 1; fi
}

list_status() {
  git submodule status || true
  echo
  printf '%-25s %-12s %-12s %-10s %s\n' NAME LOCAL_TAG REMOTE_TAG UPDATE? URL
  git config --file .gitmodules --get-regexp path | while read -r key path; do
    name=${path##*/}
    url=$(git config --file .gitmodules submodule."$path".url)
    commit=$(git rev-parse HEAD:"$path" 2>/dev/null || echo '-')
    pushd "$path" >/dev/null || continue
    fetch_output=$(git fetch --tags origin 2>&1 || true)
    local_tag=$(git describe --tags --abbrev=0 --match 'v*' --always 2>/dev/null || echo '-')
    remote_tag=$(git tag -l 'v*' --sort=-v:refname | head -n1 || echo '-')
    update="no"
    if [[ "$remote_tag" != '-' && "$remote_tag" != "$local_tag" ]]; then update="yes"; fi
    printf '%-25s %-12s %-12s %-10s %s\n' "$name" "$local_tag" "$remote_tag" "$update" "$url"
    popd >/dev/null
  done
}

bump_one() {
  local name=$1 refspec=$2
  require_clean
  local path="$(git config --file .gitmodules --get-regexp path | awk -v n=$name '$0~n"$"{print $2}')"
  if [[ -z $path ]]; then err "Submodule $name not found"; exit 1; fi
  pushd "$path" >/dev/null
  git fetch --tags origin
  if [[ $refspec == tag ]]; then
    target=$(git tag -l 'v*' --sort=-v:refname | head -n1)
  else
    target=origin/main
  fi
  [[ -z $target ]] && err "No target ref found for $name" && exit 1
  echo "Updating $name -> $target"
  git checkout --quiet $target
  new_commit=$(git rev-parse HEAD)
  popd >/dev/null
  git add "$path"
  git commit -m "chore(submodule): bump $name to ${target##*/} ($new_commit)" || true
}

case $mode in
  list) list_status ;;
  bump)
    [[ -z $which ]] && err "Specify submodule name" && exit 1
    bump_one "$which" "$refspec" ;;
  bump-all)
    require_clean
    for path in $(git config --file .gitmodules --get-regexp path | awk '{print $2}'); do
      name=${path##*/}
      $0 bump "$name" "$refspec"
    done ;;
  *) err "Unknown mode $mode"; exit 1 ;;
 esac
