#!/usr/bin/env bash
set -euo pipefail
# Wrapper to provision multiple remote servers using shared scripts.
# Expects an inventory file (servers.txt) with lines: user@host SSH_KEY=/path role=api|engine|worker

INV_FILE=${1:-servers.txt}
SHARED_SCRIPTS_DIR=shared/scripts
log(){ echo -e "[provision] $1"; }

if [ ! -f "$INV_FILE" ]; then
  log "Inventory $INV_FILE not found"; exit 1; fi

while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  userhost=$(echo "$line" | awk '{print $1}')
  role=$(echo "$line" | grep -oE 'role=[^ ]+' | cut -d= -f2 || echo generic)
  key=$(echo "$line" | grep -oE 'SSH_KEY=[^ ]+' | cut -d= -f2 || echo "$HOME/.ssh/id_rsa")
  log "Provisioning $userhost (role=$role)"
  ssh -i "$key" -o StrictHostKeyChecking=no "$userhost" 'bash -s' <<'REMOTE'
set -euo pipefail
# Placeholder: call shared_scripts provisioning once present
echo "Provision stub on $(hostname)"
REMOTE

done < "$INV_FILE"
log "Provisioning complete"
