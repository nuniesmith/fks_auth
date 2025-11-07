#!/usr/bin/env bash
# Initialize & optionally fast-forward all shared submodules across extracted microrepos.
# Usage: ./migration/init-all-submodules.sh --micro-root ./_out [--parallel 4] [--pull] [--update-script]
#   --pull           : after init, run `git submodule update --remote --merge` to fast-forward
#   --update-script  : also invoke repo-local ./update-submodules.sh if present
#   --parallel N     : process repositories in parallel
# Exits non-zero if any repo submodule init fails.
set -euo pipefail
MICRO_ROOT=""; PAR=1; DO_PULL=0; DO_SCRIPT=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --micro-root) MICRO_ROOT=$2; shift 2;;
    --parallel) PAR=$2; shift 2;;
    --pull) DO_PULL=1; shift;;
    --update-script) DO_SCRIPT=1; shift;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "Unknown arg $1" >&2; exit 1;;
  esac
done
[[ -z $MICRO_ROOT ]] && { echo "--micro-root required" >&2; exit 1; }
[[ ! -d $MICRO_ROOT ]] && { echo "micro-root $MICRO_ROOT not found" >&2; exit 1; }

todo=()
for r in "$MICRO_ROOT"/*; do
  [[ -d $r/.git && -f $r/.gitmodules ]] && todo+=("$r")
done
[[ ${#todo[@]} -eq 0 ]] && { echo "No repos with submodules found" >&2; exit 0; }

echo "[INFO] Processing ${#todo[@]} repositories (parallel=$PAR pull=$DO_PULL script=$DO_SCRIPT)" >&2

process() {
  local repo="$1"; local name=$(basename "$repo")
  pushd "$repo" >/dev/null || return 0
  echo "[SUBMOD] $name init" >&2
  if ! git submodule update --init --recursive >/dev/null 2>&1; then
    echo "[ERROR] $name submodule init failed" >&2; echo FAIL > "/tmp/submod_$name"; popd >/dev/null; return 0
  fi
  if (( DO_PULL )); then
    git submodule update --remote --merge || true
  fi
  if (( DO_SCRIPT )) && [[ -x ./update-submodules.sh ]]; then
    ./update-submodules.sh || true
  fi
  git submodule status > "/tmp/submod_$name" 2>/dev/null || true
  popd >/dev/null
}
export -f process

if (( PAR > 1 )); then
  semaphore=$PAR
  for r in "${todo[@]}"; do
    while (( $(jobs -rp | wc -l) >= semaphore )); do sleep 0.2; done
    process "$r" &
  done
  wait
else
  for r in "${todo[@]}"; do process "$r"; done
fi

fail=0
for r in "${todo[@]}"; do name=$(basename "$r"); if grep -q '^FAIL' "/tmp/submod_$name" 2>/dev/null; then fail=1; fi; done
rm -f /tmp/submod_*
[[ $fail -eq 1 ]] && { echo "[RESULT] failures occurred" >&2; exit 2; } || echo "[RESULT] all submodules initialized" >&2
