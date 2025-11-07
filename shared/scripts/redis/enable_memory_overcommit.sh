#!/usr/bin/env bash
set -euo pipefail

#=============================================================
# Enable Linux memory overcommit for Redis reliability.
# Provides idempotent apply, status, dry-run, and revert modes.
#=============================================================

set -o pipefail

TARGET_DROPIN=/etc/sysctl.d/99-redis-overcommit.conf
TARGET_KEY=vm.overcommit_memory
DESIRED_VALUE=1
BACKUP_FILE=/etc/sysctl.conf.bak.pre_redis_overcommit
DEBUG=0

log() { echo "$(date +'%Y-%m-%d %H:%M:%S') [$1] ${2:-}"; }
die() { log ERROR "$1" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [--apply|--revert|--status] [--dry-run] [--debug]

  --apply    Default. Write $TARGET_KEY=$DESIRED_VALUE via drop-in & apply at runtime.
  --revert   Remove drop-in and set runtime value to 0 (no overcommit) unless another config overrides.
  --status   Show current runtime value and config sources.
  --dry-run  Show actions without changing anything.
  --debug    Verbose diagnostics (prints detection steps / conflicting values).

Notes:
  * Uses $TARGET_DROPIN instead of editing /etc/sysctl.conf directly.
  * Creates a one-time backup of /etc/sysctl.conf if it contains the target key.
  * Runtime check reads /proc/sys/$TARGET_KEY.
EOF
}

ACTION=apply
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
  --apply) ACTION=apply ;;
  --revert) ACTION=revert ;;
  --status) ACTION=status ;;
  --dry-run) DRY_RUN=1 ;;
  --debug) DEBUG=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# Require root (re-exec with sudo if needed)
if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

current_runtime() {
  local val=""
  # Prefer sysctl -n (more portable) then fallback to /proc
  if val=$(sysctl -n "${TARGET_KEY}" 2>/dev/null); then
    [[ -n "$val" ]] && { [[ $DEBUG -eq 1 ]] && log DEBUG "Runtime via sysctl: $val"; echo "$val"; return; }
  fi
  if [[ -r "/proc/sys/${TARGET_KEY//./\/}" ]]; then
    val=$(cat "/proc/sys/${TARGET_KEY//./\/}" 2>/dev/null || true)
    [[ -n "$val" ]] && { [[ $DEBUG -eq 1 ]] && log DEBUG "Runtime via /proc: $val"; echo "$val"; return; }
  fi
  [[ $DEBUG -eq 1 ]] && log DEBUG "Unable to read runtime value (sysctl + /proc failed)."
  echo "?"
}

print_status() {
  local rt; rt=$(current_runtime)
  log INFO "Runtime ${TARGET_KEY}=${rt} (desired=${DESIRED_VALUE})"
  if [[ -f "$TARGET_DROPIN" ]]; then
    log INFO "Drop-in present: $TARGET_DROPIN"
    grep -E "^${TARGET_KEY}" "$TARGET_DROPIN" || true
  else
    log INFO "Drop-in not present: $TARGET_DROPIN"
  fi
  if grep -q "^${TARGET_KEY}" /etc/sysctl.conf; then
    log INFO "Base file /etc/sysctl.conf also defines ${TARGET_KEY}:"
    grep -E "^${TARGET_KEY}" /etc/sysctl.conf || true
  fi
}

apply_overcommit() {
  local rt; rt=$(current_runtime)
  if [[ -f /etc/sysctl.conf && ! -f $BACKUP_FILE && $(grep -c "^${TARGET_KEY}" /etc/sysctl.conf || true) -gt 0 ]]; then
    log INFO "Backing up /etc/sysctl.conf to $BACKUP_FILE (one-time)."
    [[ $DRY_RUN -eq 1 ]] || cp /etc/sysctl.conf "$BACKUP_FILE"
  fi

  log INFO "Writing drop-in $TARGET_DROPIN (${TARGET_KEY}=${DESIRED_VALUE})."
  if [[ $DRY_RUN -eq 0 ]]; then
    printf '%s = %s\n' "$TARGET_KEY" "$DESIRED_VALUE" > "$TARGET_DROPIN"
  fi

  log INFO "Reloading sysctl settings."
  if [[ $DRY_RUN -eq 0 ]]; then
    # Apply only the drop-in to avoid noise; fallback to sysctl --system if needed
    if ! sysctl -p "$TARGET_DROPIN" >/dev/null 2>&1; then
      [[ $DEBUG -eq 1 ]] && log DEBUG "Direct load failed, trying sysctl --system"
      sysctl --system >/dev/null 2>&1 || true
    fi
    if ! sysctl -w ${TARGET_KEY}=${DESIRED_VALUE} >/dev/null 2>&1; then
      [[ $DEBUG -eq 1 ]] && log DEBUG "Direct write failed, will re-check value anyway"
    fi
  fi

  rt=$(current_runtime)
  if [[ "$rt" != "$DESIRED_VALUE" ]]; then
    if [[ "$rt" == "?" ]]; then
      [[ $DRY_RUN -eq 1 ]] && log WARN "(dry-run) Could not detect runtime value." || log WARN "Could not detect runtime value (permissions / kernel?). Verify manually: sysctl ${TARGET_KEY}";
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        log WARN "(dry-run) Would expect runtime ${TARGET_KEY}=${DESIRED_VALUE}, currently ${rt}."
      else
        log WARN "Runtime value is ${rt}, expected ${DESIRED_VALUE}. Another config may override it."
        # Show potential overriding lines
        if [[ $DEBUG -eq 1 ]]; then
          grep -R "${TARGET_KEY}" /etc/sysctl* 2>/dev/null || true
        fi
      fi
    fi
  else
    log SUCCESS "${TARGET_KEY}=${DESIRED_VALUE} active (runtime)."
  fi
}

revert_overcommit() {
  log INFO "Reverting overcommit configuration."
  if [[ -f "$TARGET_DROPIN" ]]; then
    log INFO "Removing $TARGET_DROPIN"
    [[ $DRY_RUN -eq 1 ]] || rm -f "$TARGET_DROPIN"
  else
    log INFO "No drop-in file to remove."
  fi
  if grep -q "^${TARGET_KEY}" /etc/sysctl.conf; then
    log INFO "NOTE: /etc/sysctl.conf defines ${TARGET_KEY}; not modifying base file. Manual edit required if you want full revert."
  fi
  if [[ $DRY_RUN -eq 0 ]]; then
    sysctl -w ${TARGET_KEY}=0 >/dev/null || true
  fi
  log SUCCESS "Revert attempted. Current runtime ${TARGET_KEY}=$(current_runtime)."
}

case "$ACTION" in
  status)
    print_status
    ;;
  apply)
    apply_overcommit
    ;;
  revert)
    revert_overcommit
    ;;
esac

if [[ $DRY_RUN -eq 1 ]]; then
  log INFO "Dry-run mode: no changes were applied."
fi
