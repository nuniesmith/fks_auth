#!/usr/bin/env bash
# domains/ssl/systemd-install.sh
# TODO RESTORE: Installs systemd units for SSL manager (service + timer) formerly in install-ssl-systemd.sh
set -euo pipefail

SERVICE_NAME="fks_ssl-manager"
UNIT_DIR="/etc/systemd/system"

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Must run as root (sudo)" >&2; exit 1
fi

case ${1:-apply} in
  plan)
    echo "Would create $UNIT_DIR/${SERVICE_NAME}.service and timer (placeholder)." ;;
  apply)
    echo "[TODO] Write systemd unit files (service, timer) and enable them." ;;
  remove)
    echo "[TODO] Remove unit files and daemon-reload." ;;
  *) echo "Usage: $0 [plan|apply|remove]"; exit 1;;
esac