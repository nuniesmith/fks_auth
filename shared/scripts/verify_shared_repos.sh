#!/usr/bin/env bash
# Unified verifier for all shared submodule repos across every service.
# Extends previous script (kept same filename for continuity) to cover:
#   shared_actions  shared_docker  shared_python  shared_schema  shared_scripts
#   shared_rust     shared_nginx   shared_react
#
# Features:
#   - Detect missing submodule declarations in .gitmodules
#   - (Optional) add them ( --fix-missing )
#   - Detect URL mismatches ( --fix-url to auto-correct )
#   - Initialize / update recursively ( --init )
#   - Detect empty / partially checked-out submodule working trees and reinitialize
#   - Force reclone of a problematic submodule ( --force-reclone )
#   - Parallel execution ( --parallel )
#   - Limit to subset of modules ( --modules=mod1,mod2 )
#   - Enforce that ALL listed modules exist in every service ( --enforce )
#
# Usage examples:
#   ./verify_shared_repos.sh                                 # report only (auto-detect present modules per service)
#   ./verify_shared_repos.sh --init                          # ensure all existing declared submodules are fetched
#   ./verify_shared_repos.sh --fix-missing --init            # add any missing declarations and fetch
#   ./verify_shared_repos.sh --fix-url --init                # normalize URLs & update
#   ./verify_shared_repos.sh --modules=shared_docker,shared_schema --init
#   ./verify_shared_repos.sh --force-reclone --modules=shared_docker
#   ./verify_shared_repos.sh --enforce --fix-missing --init
#   ./verify_shared_repos.sh --auto-commit --fix-missing --fix-url --init  # also commits changes per service
#   ./verify_shared_repos.sh --auto-commit --commit-msg="chore: sync shared submodules" --fix-missing --fix-url --init

set -euo pipefail

SERVICES=(analyze api auth config data docs engine execution master nginx ninja nodes training transformer web worker)

# Canonical module -> URL map (underscore form only)
# Canonical module list (order preserved here for normalized output)
MODULE_ORDER=(
  shared_scripts
  shared_schema
  shared_docker
  shared_rust
  shared_actions
  shared_nginx
  shared_python
  shared_react
)

declare -A MODULE_URLS=(
  [shared_actions]="https://github.com/nuniesmith/shared_actions.git"
  [shared_docker]="https://github.com/nuniesmith/shared_docker.git"
  [shared_python]="https://github.com/nuniesmith/shared_python.git"
  [shared_schema]="https://github.com/nuniesmith/shared_schema.git"
  [shared_scripts]="https://github.com/nuniesmith/shared_scripts.git"
  [shared_rust]="https://github.com/nuniesmith/shared_rust.git"
  [shared_nginx]="https://github.com/nuniesmith/shared_nginx.git"
  [shared_react]="https://github.com/nuniesmith/shared_react.git"
)

DO_INIT=false
DO_FIX=false            # add missing submodule declaration
DO_FIX_URL=false        # correct URL mismatches
PARALLEL=false
ENFORCE=false           # treat missing submodule as error even if not typical for service
FORCE_RECLONE=false     # remove & re-add if working tree looks broken
LIMIT_MODULES=()        # optional subset
AUTO_COMMIT=false       # automatically commit changes inside each service repo
COMMIT_MSG="chore: sync shared submodules"
NORMALIZE=false         # rewrite .gitmodules into canonical ordered deduplicated form
declare -A FAILS        # svc:module -> reason
declare -A SERVICE_CHANGED_MODULES  # svc -> space separated modules changed

# --- Normalization logic function (defined early so it is available) ---
normalize_gitmodules() {
  local svc=$1 gm="$svc/.gitmodules" tmp
  [ -f "$gm" ] || return 0
  tmp=$(mktemp)

  # Build associative maps of existing, capturing last occurrence (duplicates collapsed)
  declare -A existing_urls existing_paths
  local current_module="" line
  while IFS= read -r line; do
    if [[ $line =~ ^\[submodule\ "(.+)"\] ]]; then
      current_module="${BASH_REMATCH[1]}"
    elif [[ $line =~ path\ =\ (.+)$ ]] && [ -n "$current_module" ]; then
      existing_paths[$current_module]="${BASH_REMATCH[1]}"
    elif [[ $line =~ url\ =\ (.+)$ ]] && [ -n "$current_module" ]; then
      existing_urls[$current_module]="${BASH_REMATCH[1]}"
    fi
  done < "$gm"

  : > "$tmp"
  local m expected_url canonical_path actual_url
  for m in "${MODULE_ORDER[@]}"; do
    expected_url="${MODULE_URLS[$m]}"
    actual_url=""
    # Attempt to find matching existing submodule names in several forms
    local k
    for k in "${!existing_urls[@]}"; do
      if [[ $k == "shared/$m" || $k == "$m" ]]; then
        actual_url="${existing_urls[$k]}"; break
      fi
    done
    [ -z "$actual_url" ] && actual_url="$expected_url"
    canonical_path="shared/$m"
    printf '[submodule "%s"]\n\tpath = %s\n\turl = %s\n' "shared/$m" "$canonical_path" "$expected_url" >> "$tmp"
  done

  if ! diff -q "$gm" "$tmp" >/dev/null 2>&1; then
    mv "$tmp" "$gm"
    report_line OK "$svc" ".gitmodules normalized"
    SERVICE_CHANGED_MODULES[$svc]="${SERVICE_CHANGED_MODULES[$svc]:-} normalized"
  else
    rm -f "$tmp"
  fi
}

parse_modules_arg() {
  local raw="$1"; IFS=',' read -r -a LIMIT_MODULES <<< "$raw"; unset IFS
}

for arg in "$@"; do
  case "$arg" in
    --init) DO_INIT=true ;;
    --fix-missing) DO_FIX=true ; DO_INIT=true ;;
  --repair) DO_FIX=true ; DO_INIT=true ;;  # alias
    --fix-url) DO_FIX_URL=true ;;
    --parallel) PARALLEL=true ;;
    --enforce) ENFORCE=true ;;
  --force-reclone) FORCE_RECLONE=true ; DO_INIT=true ;;
  --normalize) NORMALIZE=true ; DO_FIX_URL=true ;;
    --modules=*) parse_modules_arg "${arg#*=}" ;;
    --auto-commit) AUTO_COMMIT=true ;;
    --commit-msg=*) COMMIT_MSG="${arg#*=}" ;;
    -h|--help) sed -n '1,40p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if $AUTO_COMMIT && $PARALLEL; then
  echo "[warn] Disabling --parallel because --auto-commit is enabled (to ensure safe commits)." >&2
  PARALLEL=false
fi

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'

report_line() { # status message
  local status=$1 svc=$2 msg=$3
  local color="$NC"
  case "$status" in
    OK) color=$GREEN ;;
    WARN) color=$YELLOW ;;
    ERR) color=$RED ;;
  esac
  printf "%b%-8s%b %-12s %s\n" "$color" "$status" "$NC" "$svc" "$msg"
}

add_submodule() {
  local svc=$1 module=$2 url=$3 path="shared/$2"
  ( cd "$svc" && git submodule add -f "$url" "$path" >/dev/null 2>&1 ) || return 1
  SERVICE_CHANGED_MODULES[$svc]="${SERVICE_CHANGED_MODULES[$svc]:-} $module"
}

init_submodule() {
  local svc=$1 module=$2 path="shared/$2"
  ( cd "$svc" && git submodule sync --quiet && git submodule update --init --recursive "$path" >/dev/null 2>&1 ) || return 1
}

reclone_submodule() {
  local svc=$1 module=$2 url=$3 path="shared/$2"
  ( cd "$svc" && rm -rf "$path" && git submodule add -f "$url" "$path" >/dev/null 2>&1 ) || return 1
}

module_list_for_service() {
  # If explicit modules provided, use them. Else discover from .gitmodules (present) + canonical set.
  local svc=$1
  if [ ${#LIMIT_MODULES[@]} -gt 0 ]; then
    printf '%s\n' "${LIMIT_MODULES[@]}"; return 0
  fi
  local gm="$svc/.gitmodules"
  if [ -f "$gm" ]; then
    awk -F '"' '/^\[submodule/ {print $2}' "$gm" | sed -E 's#^shared/##' | sort -u
  else
    # No .gitmodules yet; return canonical modules (we'll mark missing)
    printf '%s\n' "${!MODULE_URLS[@]}"
  fi
}

check_single_module() {
  local svc=$1 module=$2 url path="shared/$2" gm="$svc/.gitmodules" expected_url
  expected_url=${MODULE_URLS[$module]:-}
  if [ -z "$expected_url" ]; then
    # Unknown module; skip
    return 0
  fi

  # Determine if declaration exists
  local declared=false
  if grep -q "path = $path" "$gm" 2>/dev/null; then
    declared=true
  fi

  if ! $declared; then
    if $DO_FIX; then
      if add_submodule "$svc" "$module" "$expected_url"; then
        report_line OK "$svc" "$module: added"
      else
  report_line ERR "$svc" "$module: add failed"
  FAILS["$svc:$module"]="add failed"
        return 0
      fi
    else
      if $ENFORCE; then
        report_line ERR "$svc" "$module: missing declaration"
      else
        report_line WARN "$svc" "$module: missing declaration"
      fi
      return 0
    fi
  fi

  # If declared but not present in index (no gitlink) and directory missing, attempt add when --fix-missing/--repair provided
  if $DO_FIX && ! git -C "$svc" ls-files --stage | grep -q " $path$" && [ ! -d "$svc/$path/.git" ]; then
    if add_submodule "$svc" "$module" "$expected_url"; then
      report_line OK "$svc" "$module: added (repair)"
    else
      report_line ERR "$svc" "$module: repair add failed"
      FAILS["$svc:$module"]="repair add failed"
    fi
  fi

  # URL validation
  local actual_url
  actual_url=$(awk -v p="$path" 'found&&/^\turl/ {print $3; exit} /path = '"$path"'/ {found=1}' "$gm" 2>/dev/null || true)
  if [ -n "$actual_url" ] && [ "$actual_url" != "$expected_url" ]; then
    if $DO_FIX_URL; then
      sed -i "s#url = ${actual_url}#url = ${expected_url}#" "$gm" || true
      ( cd "$svc" && git submodule sync >/dev/null 2>&1 || true )
      report_line OK "$svc" "$module: url corrected"
      SERVICE_CHANGED_MODULES[$svc]="${SERVICE_CHANGED_MODULES[$svc]:-} $module"
    else
      report_line WARN "$svc" "$module: url mismatch (got $actual_url)"
      FAILS["$svc:$module"]="url mismatch"
    fi
  fi

  # Initialize / verify working tree
  if $DO_INIT; then
    if init_submodule "$svc" "$module"; then
      :
    else
  report_line ERR "$svc" "$module: init failed"
  FAILS["$svc:$module"]="init failed"
      return 0
    fi
  fi

  # Detect empty or broken checkout
  if [ -d "$svc/$path" ]; then
    local non_git_count
    non_git_count=$(find "$svc/$path" -mindepth 1 -maxdepth 1 ! -name '.git' | wc -l | tr -d ' ')
    if [ "$non_git_count" = "0" ]; then
      if $FORCE_RECLONE; then
        if reclone_submodule "$svc" "$module" "$expected_url" && init_submodule "$svc" "$module"; then
          report_line OK "$svc" "$module: recloned"
          SERVICE_CHANGED_MODULES[$svc]="${SERVICE_CHANGED_MODULES[$svc]:-} $module"
        else
          report_line ERR "$svc" "$module: reclone failed"
          FAILS["$svc:$module"]="reclone failed"
        fi
      else
        report_line WARN "$svc" "$module: empty working tree (use --force-reclone)"
        FAILS["$svc:$module"]="empty working tree"
      fi
    else
      report_line OK "$svc" "$module: ready"
    fi
  else
    report_line WARN "$svc" "$module: directory absent"
    FAILS["$svc:$module"]="directory absent"
  fi
}

check_service() {
  local svc=$1
  if [ ! -d "$svc/.git" ]; then
    report_line WARN "$svc" ".git not found (skipping)"
    return 0
  fi

  if $NORMALIZE; then
    normalize_gitmodules "$svc"
  fi

  local modules_to_check
  mapfile -t modules_to_check < <(module_list_for_service "$svc")
  # If limiting modules, we already use that set; else ensure canonical modules also evaluated
  if [ ${#LIMIT_MODULES[@]} -eq 0 ]; then
    # Merge canonical set with discovered (ensuring uniqueness)
    for m in "${!MODULE_URLS[@]}"; do
      if ! printf '%s\n' "${modules_to_check[@]}" | grep -qx "$m"; then
        modules_to_check+=("$m")
      fi
    done
  fi
  for module in "${modules_to_check[@]}"; do
    check_single_module "$svc" "$module"
  done
}

run_all() {
  if $PARALLEL; then
    pids=()
    for svc in "${SERVICES[@]}"; do
      check_service "$svc" &
      pids+=("$!")
    done
    for p in "${pids[@]}"; do wait "$p" || true; done
  else
    for svc in "${SERVICES[@]}"; do
      check_service "$svc"
    done
  fi
}

run_all

echo
echo "Complete. Flags used: init=$DO_INIT fix-missing=$DO_FIX fix-url=$DO_FIX_URL force-reclone=$FORCE_RECLONE enforce=$ENFORCE" 
echo "Tip: commit .gitmodules changes inside each service repo after --fix-* operations." 

if $AUTO_COMMIT; then
  echo
  echo "Auto-commit phase (message: $COMMIT_MSG)" 
  for svc in "${!SERVICE_CHANGED_MODULES[@]}"; do
    if [ ! -d "$svc/.git" ]; then
      continue
    fi
    # Build list of paths to add
    changed_mods=${SERVICE_CHANGED_MODULES[$svc]}
    add_paths=".gitmodules"
    for m in $changed_mods; do
      add_paths+=" shared/$m"
    done
    ( cd "$svc" && git add $add_paths >/dev/null 2>&1 || true )
    if ( cd "$svc" && ! git diff --cached --quiet ); then
      ( cd "$svc" && git commit -m "$COMMIT_MSG" >/dev/null 2>&1 && echo "Committed in $svc: $changed_mods" || echo "No commit (perhaps hooks blocked) in $svc" )
    else
      echo "No staged changes to commit in $svc"
    fi
  done
fi


if [ ${#FAILS[@]} -gt 0 ]; then
  echo
  echo "Failures / Warnings summary:" >&2
  for key in "${!FAILS[@]}"; do
    svc=${key%%:*}; module=${key##*:}
    printf ' - %s / %s : %s\n' "$svc" "$module" "${FAILS[$key]}" >&2
  done | sort
  echo
  echo "Re-run for only failing modules (example):" >&2
  # Build unique module list from failures
  fail_mods=$(printf '%s\n' "${!FAILS[@]}" | awk -F: '{print $2}' | sort -u | paste -sd, -)
  echo "  ./verify_shared_repos.sh --modules=$fail_mods --init --force-reclone --fix-url" >&2
fi
