#!/usr/bin/env bash
# Lightweight verifier for new short shared submodule layout (shared/<name>).
# Co-exists with existing verify_shared_repos.sh (which still handles legacy names).
# Reports which services still have legacy paths and optionally normalizes .gitmodules.
# Usage:
#   ./verify_shared_repos_short.sh                     # report only
#   ./verify_shared_repos_short.sh --normalize         # rewrite .gitmodules to only short entries
#   ./verify_shared_repos_short.sh --migrate-hint      # show commands to migrate legacy paths
#   ./verify_shared_repos_short.sh --json              # machine readable output
#
set -euo pipefail
SERVICES=(analyze api auth config data docs engine execution master nginx ninja nodes training transformer web worker)
SHORT_NAMES=(actions docker python schema scripts rust nginx react)

DO_NORMALIZE=false
SHOW_MIGRATE_HINT=false
OUTPUT_JSON=false

while (( "$#" )); do
  case "$1" in
    --normalize) DO_NORMALIZE=true ;;
    --migrate-hint) SHOW_MIGRATE_HINT=true ;;
    --json) OUTPUT_JSON=true ;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac; shift
done

json_escape(){ echo -n "$1" | sed 's/"/\\"/g'; }

report_rows=()

normalize_gitmodules(){
  local svc=$1 gm="$svc/.gitmodules" tmp
  [ -f "$gm" ] || return 0
  tmp=$(mktemp)
  for n in "${SHORT_NAMES[@]}"; do
    local url name_legacy="shared_${n}" url_guess
    case $n in
      actions) url_guess="https://github.com/nuniesmith/shared_actions.git" ;;
      docker) url_guess="https://github.com/nuniesmith/shared_docker.git" ;;
      python) url_guess="https://github.com/nuniesmith/shared_python.git" ;;
      schema) url_guess="https://github.com/nuniesmith/shared_schema.git" ;;
      scripts) url_guess="https://github.com/nuniesmith/shared_scripts.git" ;;
      rust) url_guess="https://github.com/nuniesmith/shared_rust.git" ;;
      nginx) url_guess="https://github.com/nuniesmith/shared_nginx.git" ;;
      react) url_guess="https://github.com/nuniesmith/shared_react.git" ;;
    esac
    printf '[submodule "shared/%s"]\n\tpath = shared/%s\n\turl = %s\n' "$n" "$n" "$url_guess" >> "$tmp"
  done
  if ! diff -q "$gm" "$tmp" >/dev/null 2>&1; then
    cp "$gm" "$gm.bak.short.$(date +%s)"
    mv "$tmp" "$gm"
  else
    rm -f "$tmp"
  fi
}

for svc in "${SERVICES[@]}"; do
  [ -d "$svc/.git" ] || continue
  legacy=0; short=0
  for n in "${SHORT_NAMES[@]}"; do
    [[ -e "$svc/shared/${n}/.git" || -f "$svc/shared/${n}/.git" ]] && legacy=$((legacy+1))
    [[ -e "$svc/shared/${n}/.git" || -f "$svc/shared/${n}/.git" ]] && short=$((short+1))
  done
  status="mixed"
  (( legacy>0 && short==0 )) && status="legacy_only"
  (( short>0 && legacy==0 )) && status="short_only"
  (( legacy==0 && short==0 )) && status="none"
  if $DO_NORMALIZE && [[ $status != none ]]; then
    normalize_gitmodules "$svc"
  fi
  if $OUTPUT_JSON; then
    report_rows+=("{\"service\":\"$svc\",\"legacy\":$legacy,\"short\":$short,\"status\":\"$status\"}")
  else
    printf '%-12s legacy=%-2d short=%-2d status=%s\n' "$svc" "$legacy" "$short" "$status"
  fi
  if $SHOW_MIGRATE_HINT && [[ $status == legacy_only || $status == mixed ]]; then
    echo "  hint: ./migrate_shared_submodules.sh --repos $svc --apply -y" 
  fi
done

if $OUTPUT_JSON; then
  printf '[%s]\n' "$(IFS=,; echo "${report_rows[*]}")"
fi

if $DO_NORMALIZE; then
  echo "Normalization complete (backups saved as .gitmodules.bak.short.<ts>)."
fi
