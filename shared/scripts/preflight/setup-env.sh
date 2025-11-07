#!/bin/bash
# (Relocated) Environment setup script.
set -e
echo "[INFO] Generating .env.fks (relocated from top-level)."
ENV_FILE='.env.fks'
[[ -f $ENV_FILE ]] && { echo "Already exists: $ENV_FILE"; exit 0; }
cat > $ENV_FILE <<EOF
# Minimal placeholder. Use original script (see history) for interactive prompts.
DOMAIN_NAME=fkstrading.xyz
SERVER_REGION=ca-central
EOF
echo "Created $ENV_FILE (minimal). Fill in sensitive values manually."
