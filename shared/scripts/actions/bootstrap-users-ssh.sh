#!/usr/bin/env bash

# Bootstrap users, groups, and SSH settings; generate passwords and print for GitHub Secrets.
#
# What it does:
# - Creates/updates users (actions, jordan, service user, plus optional extras)
# - Adds users to admin group (wheel/sudo auto-detected) and docker (if present)
# - Optionally writes authorized_keys if provided
# - Enables PermitRootLogin in sshd_config (and optionally PasswordAuthentication)
# - Generates strong passwords for each user (and root), sets them, and prints
#   them as SECRET_NAME=value lines you can paste into GitHub Secrets
#
# Usage (as root):
#   ./bootstrap-users-ssh.sh \
#     --service-user freddy_user \
#     --extra-user deploy \
#     --allow-root-login true \
#     --password-auth true
#
# Options (all optional, sane defaults provided):
#   --service-user NAME         Service user name (default: service)
#   --actions-user NAME         Actions user name (default: actions)
#   --jordan-user NAME          Jordan user name (default: jordan)
#   --extra-user NAME           Additional user(s); may be repeated
#   --no-docker                 Do not add users to docker group
#   --admin-group GROUP         Force admin group (sudo|wheel). Auto-detect by default
#   --allow-root-login BOOL     Enable PermitRootLogin (default: true)
#   --password-auth BOOL        Enable PasswordAuthentication (default: true)
#   --rotate-existing BOOL      Rotate passwords of existing users (default: true)
#   --authorized-keys FILE      Path to a file of SSH public keys to add for all created users
#   --quiet                     Less output (still prints secrets at the end)
#
set -euo pipefail

QUIET=false
log() { "$QUIET" && return 0 || echo -e "$@"; }

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

# Defaults
SERVICE_USER="${SERVICE_USER:-service}"
ACTIONS_USER="${ACTIONS_USER:-actions}"
JORDAN_USER="${JORDAN_USER:-jordan}"
EXTRA_USERS=()
ADD_DOCKER=true
ADMIN_GROUP="auto"
ALLOW_ROOT_LOGIN=true
PASSWORD_AUTH=true
ROTATE_EXISTING=true
AUTHORIZED_KEYS_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-user) SERVICE_USER="$2"; shift 2;;
    --actions-user) ACTIONS_USER="$2"; shift 2;;
    --jordan-user)  JORDAN_USER="$2"; shift 2;;
    --extra-user)   EXTRA_USERS+=("$2"); shift 2;;
    --no-docker)    ADD_DOCKER=false; shift 1;;
    --admin-group)  ADMIN_GROUP="$2"; shift 2;;
    --allow-root-login) ALLOW_ROOT_LOGIN=${2,,}; shift 2;;
    --password-auth)    PASSWORD_AUTH=${2,,}; shift 2;;
    --rotate-existing)  ROTATE_EXISTING=${2,,}; shift 2;;
    --authorized-keys)  AUTHORIZED_KEYS_FILE="$2"; shift 2;;
    --quiet)        QUIET=true; shift 1;;
    -h|--help)
      sed -n '1,80p' "$0"; exit 0;;
    *)
      echo "Unknown option: $1" >&2; exit 2;;
  esac
done

require_root

# Detect admin group if not forced
detect_admin_group() {
  if [[ "$ADMIN_GROUP" != "auto" ]]; then
    echo "$ADMIN_GROUP"; return 0
  fi
  if getent group sudo >/dev/null 2>&1; then echo sudo; return 0; fi
  if getent group wheel >/dev/null 2>&1; then echo wheel; return 0; fi
  # Fallback to sudo
  echo sudo
}

ADMIN_GROUP_RESOLVED=$(detect_admin_group)
log "Admin group: $ADMIN_GROUP_RESOLVED"

DOCKER_GROUP=""
if "$ADD_DOCKER" && getent group docker >/dev/null 2>&1; then
  DOCKER_GROUP=docker
fi

# Create or update a user, add to groups, install authorized_keys
ensure_user() {
  local user="$1"
  local groups=("$ADMIN_GROUP_RESOLVED")
  [[ -n "$DOCKER_GROUP" ]] && groups+=("$DOCKER_GROUP")

  if id "$user" >/dev/null 2>&1; then
    log "User exists: $user (updating groups)"
    if [[ ${#groups[@]} -gt 0 ]]; then
      usermod -aG "$(IFS=,; echo "${groups[*]}")" "$user"
    fi
  else
    log "Creating user: $user"
    useradd -m -s /bin/bash "$user"
    if [[ ${#groups[@]} -gt 0 ]]; then
      usermod -aG "$(IFS=,; echo "${groups[*]}")" "$user"
    fi
  fi

  # authorized_keys if provided
  if [[ -n "$AUTHORIZED_KEYS_FILE" && -f "$AUTHORIZED_KEYS_FILE" ]]; then
    local home_dir
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    install -d -m 700 -o "$user" -g "$user" "$home_dir/.ssh"
    install -m 600 -o "$user" -g "$user" /dev/null "$home_dir/.ssh/authorized_keys"
    # Append non-empty keys
    grep -v '^\s*$' "$AUTHORIZED_KEYS_FILE" >> "$home_dir/.ssh/authorized_keys"
    chown "$user:$user" "$home_dir/.ssh/authorized_keys"
  fi
}

# Generate a strong password (URL-safe, no colon or whitespace)
gen_password() {
  if command -v openssl >/dev/null 2>&1; then
    # 24 bytes -> ~32 chars base64 url-safe
    openssl rand -base64 24 | tr -d '\n' | tr '+/' '-_' | tr -d '='
  else
    # Fallback
    tr -dc 'A-Za-z0-9_@%+-=' </dev/urandom | head -c 32
  fi
}

set_password() {
  local user="$1"; local pass="$2"
  echo "$user:$pass" | chpasswd
}

set_root_password() {
  local pass="$1"
  echo "root:$pass" | chpasswd
}

enable_sshd_settings() {
  local allow_root="$1"   # true|false
  local pw_auth="$2"      # true|false

  local sshd_cfg="/etc/ssh/sshd_config"
  local backup="/etc/ssh/sshd_config.bak-$(date +%Y%m%d%H%M%S)"
  cp "$sshd_cfg" "$backup"
  log "Backed up sshd_config -> $backup"

  # Ensure key directives exist/updated
  sed -i \
    -e "s/^#\?PermitRootLogin .*/PermitRootLogin $([[ "$allow_root" == true ]] && echo yes || echo no)/" \
    -e "s/^#\?PasswordAuthentication .*/PasswordAuthentication $([[ "$pw_auth" == true ]] && echo yes || echo no)/" \
    -e 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
    -e 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' \
    "$sshd_cfg" || true

  # If directives missing entirely, append them
  grep -q '^PermitRootLogin ' "$sshd_cfg" || echo "PermitRootLogin $([[ "$allow_root" == true ]] && echo yes || echo no)" >> "$sshd_cfg"
  grep -q '^PasswordAuthentication ' "$sshd_cfg" || echo "PasswordAuthentication $([[ "$pw_auth" == true ]] && echo yes || echo no)" >> "$sshd_cfg"
  grep -q '^PubkeyAuthentication ' "$sshd_cfg" || echo 'PubkeyAuthentication yes' >> "$sshd_cfg"
  grep -q '^ChallengeResponseAuthentication ' "$sshd_cfg" || echo 'ChallengeResponseAuthentication no' >> "$sshd_cfg"

  # Restart ssh service name differences (sshd vs ssh)
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled sshd >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
      systemctl restart sshd || true
    fi
    if systemctl is-enabled ssh >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
      systemctl restart ssh || true
    fi
  else
    # SysVinit/service fallback
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
  fi
  log "sshd settings applied and service restarted"
}

# Main
declare -A USER_TO_SECRET

# Map known names to expected GitHub Secret names
map_secret_name() {
  local u="$1"
  case "$u" in
    root) echo "SERVICE_ROOT_PASSWORD";;
    "$ACTIONS_USER") echo "ACTIONS_USER_PASSWORD";;
    "$JORDAN_USER") echo "JORDAN_PASSWORD";;
    "$SERVICE_USER") echo "SERVICE_USER_PASSWORD";;
    *) echo "${u^^}_PASSWORD";;
  esac
}

USERS=()
[[ -n "$ACTIONS_USER" ]] && USERS+=("$ACTIONS_USER")
[[ -n "$JORDAN_USER"  ]] && USERS+=("$JORDAN_USER")
[[ -n "$SERVICE_USER" ]] && USERS+=("$SERVICE_USER")
if [[ ${#EXTRA_USERS[@]} -gt 0 ]]; then USERS+=("${EXTRA_USERS[@]}"); fi

log "Configuring users: ${USERS[*]}"
for u in "${USERS[@]}"; do
  ensure_user "$u"
done

# Passwords for users
for u in "${USERS[@]}"; do
  if id "$u" >/dev/null 2>&1; then
    if "$ROTATE_EXISTING"; then
      p=$(gen_password)
      set_password "$u" "$p"
      USER_TO_SECRET["$(map_secret_name "$u")"]="$p"
      log "Password set for $u"
    else
      log "Skipping password rotation for $u"
    fi
  fi
done

# Root password
ROOT_PASS=$(gen_password)
set_root_password "$ROOT_PASS"
USER_TO_SECRET["SERVICE_ROOT_PASSWORD"]="$ROOT_PASS"

# SSHD settings
enable_sshd_settings "$ALLOW_ROOT_LOGIN" "$PASSWORD_AUTH"

echo
echo "----- Copy these into your GitHub Secrets -----"
for key in "${!USER_TO_SECRET[@]}"; do
  echo "$key=${USER_TO_SECRET[$key]}"
done | sort
echo "----------------------------------------------"

log "Done. Users configured: ${USERS[*]} | Admin group: $ADMIN_GROUP_RESOLVED ${DOCKER_GROUP:+| Docker group added}"
