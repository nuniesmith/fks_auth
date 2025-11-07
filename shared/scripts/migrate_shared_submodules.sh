#!/usr/bin/env bash
# Migration utility: convert legacy submodule paths
#   shared/actions  -> shared/actions
#   shared/docker   -> shared/docker
#   ... etc ...
# while keeping the SAME remote URLs (which still point to repos named shared_<name>.git).
#
# Safe features:
#   - Dry run by default unless -y or --apply is supplied.
#   - Detects uncommitted changes inside old submodule paths and skips unless --force.
#   - Preserves the exact commit SHA of each submodule pointer (captures before removal and checks out after re-adding).
#   - Backs up the original .gitmodules as .gitmodules.bak.<timestamp> once per repo when first change occurs.
#
# Usage:
#   ./migrate_shared_submodules.sh                 # dry run summary
#   ./migrate_shared_submodules.sh --apply -y      # perform migration non-interactively
#   ./migrate_shared_submodules.sh --repos api,engine --apply
#   ./migrate_shared_submodules.sh --force --apply # force even if local changes present (USE WITH CAUTION)
#
# After migration you can remove the old script references and use new short names
# with ./update_shared_submodule.sh (it auto-detects either form).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICES=(analyze api auth config data docs engine execution master nginx ninja nodes training transformer web worker)

# Mapping short name -> legacy full repo name + URL
SHORT_NAMES=(actions docker python schema scripts rust nginx react)
declare -A REMOTE_REPO
for n in "${SHORT_NAMES[@]}"; do REMOTE_REPO[$n]="shared_${n}"; done
declare -A REMOTE_URL
REMOTE_URL[actions]="https://github.com/nuniesmith/shared_actions.git"
REMOTE_URL[docker]="https://github.com/nuniesmith/shared_docker.git"
REMOTE_URL[python]="https://github.com/nuniesmith/shared_python.git"
REMOTE_URL[schema]="https://github.com/nuniesmith/shared_schema.git"
REMOTE_URL[scripts]="https://github.com/nuniesmith/shared_scripts.git"
REMOTE_URL[rust]="https://github.com/nuniesmith/shared_rust.git"
REMOTE_URL[nginx]="https://github.com/nuniesmith/shared_nginx.git"
REMOTE_URL[react]="https://github.com/nuniesmith/shared_react.git"

APPLY=false
ASSUME_YES=false
FORCE=false
LIMIT=()

color(){ printf "\033[%sm%s\033[0m" "$1" "$2"; }
info(){ printf "[%s] %s\n" "$(color 36 INFO)" "$*"; }
warn(){ printf "[%s] %s\n" "$(color 33 WARN)" "$*"; }
err(){ printf "[%s] %s\n" "$(color 31 ERROR)" "$*" >&2; }

usage(){ grep '^# ' "$0" | sed 's/^# //'; exit 0; }

while (( "$#" )); do
  case "$1" in
    --apply) APPLY=true ;;
    -y) ASSUME_YES=true ;;
    --force) FORCE=true ;;
    --repos) shift; IFS=',' read -r -a LIMIT <<< "${1:-}" ;;
    -h|--help) usage ;;
    *) err "Unknown arg: $1"; usage ;;
  esac; shift
done

TARGET=()
if ((${#LIMIT[@]})); then
  for r in "${LIMIT[@]}"; do [[ -d "$ROOT_DIR/$r/.git" ]] && TARGET+=("$r") || warn "Skip unknown repo $r"; done
else
  TARGET=("${SERVICES[@]}")
fi

legacy_present=false
declare -A ACTIONS_TODO  # svc -> list

detect_legacy(){
  local svc=$1 short=$2 legacy_dir="shared/${short}" new_dir="shared/${short}" svc_path="$ROOT_DIR/$svc"
  [[ -d "$svc_path/$legacy_dir" ]] || return 1
  legacy_present=true
  ACTIONS_TODO[$svc]="${ACTIONS_TODO[$svc]:-} $short"
  return 0
}

for svc in "${TARGET[@]}"; do
  for short in "${SHORT_NAMES[@]}"; do
    detect_legacy "$svc" "$short" || true
  done
done

if ! $legacy_present; then
  info "No legacy shared_ submodule directories found. Nothing to migrate."; exit 0
fi

info "Planned migrations (legacy -> new):"
for svc in "${!ACTIONS_TODO[@]}"; do
  printf "  %s:%s\n" "$svc" "${ACTIONS_TODO[$svc]}"
done | sort

if ! $APPLY; then
  warn "Dry run only. Re-run with --apply to perform migration."; exit 0
fi

if ! $ASSUME_YES; then
  read -rp "Proceed with migration? This will modify repositories. [y/N] " ans
  [[ $ans =~ ^[Yy]$ ]] || { warn "Aborted by user."; exit 1; }
fi

overall=0
ts=$(date +%s)

migrate_one(){
  local svc=$1 short=$2 svc_path="$ROOT_DIR/$svc" legacy_path="shared/${short}" new_path="shared/${short}" url=${REMOTE_URL[$short]}
  [[ -d "$svc_path/$legacy_path" ]] || { warn "$svc: missing expected $legacy_path (skip)"; return 0; }
  if [[ -d "$svc_path/$new_path" ]]; then
    warn "$svc: $new_path already exists; skipping $short"; return 0
  fi
  # Check for local changes
  if [[ -n "$(git -C "$svc_path/$legacy_path" status --porcelain 2>/dev/null || true)" ]] && ! $FORCE; then
    warn "$svc: uncommitted changes in $legacy_path; skip (use --force to override)"
    return 0
  fi
  local sha
  sha=$(git -C "$svc_path/$legacy_path" rev-parse HEAD 2>/dev/null || echo "")
  info "$svc: migrating $legacy_path -> $new_path (SHA ${sha:-none})"
  pushd "$svc_path" >/dev/null || return 1
  # backup .gitmodules once
  if [[ -f .gitmodules && ! -f .gitmodules.bak.$ts ]]; then cp .gitmodules .gitmodules.bak.$ts; fi
  git submodule deinit -f "$legacy_path" >/dev/null 2>&1 || true
  git rm -f "$legacy_path" >/dev/null 2>&1 || { err "$svc: git rm failed for $legacy_path"; popd >/dev/null; overall=1; return 1; }
  git submodule add -f "$url" "$new_path" >/dev/null 2>&1 || { err "$svc: submodule add failed for $short"; popd >/dev/null; overall=1; return 1; }
  if [[ -n "$sha" ]]; then
    ( cd "$new_path" && git fetch --quiet && git checkout -q "$sha" 2>/dev/null ) || warn "$svc: could not checkout preserved SHA $sha for $short"
  fi
  # Stage new submodule
  git add "$new_path" .gitmodules >/dev/null 2>&1 || true
  popd >/dev/null || true
}

for svc in "${!ACTIONS_TODO[@]}"; do
  for short in ${ACTIONS_TODO[$svc]}; do
    migrate_one "$svc" "$short"
  done
  # Commit if there are staged changes
  if ( cd "$ROOT_DIR/$svc" && ! git diff --cached --quiet ); then
    ( cd "$ROOT_DIR/$svc" && git commit -m "chore(submodules): migrate legacy shared_ paths to short names" >/dev/null 2>&1 && info "$svc: committed migration" || warn "$svc: commit failed" )
  else
    info "$svc: no staged migration changes"
  fi
done

info "Migration phase complete. Review commits then push (or run multi_repo_commit.sh)."
exit $overall
