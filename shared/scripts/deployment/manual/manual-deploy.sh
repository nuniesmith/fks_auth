#!/bin/bash
# (Relocated) Manual deployment helper.
set -e
echo "[INFO] Manual deploy script moved under deployment/manual/."
echo "[INFO] Original functionality retained below (trimmed)."

# For full original logic consider referencing git history if further flags needed.
if [[ $# -lt 1 || "$1" == "--help" ]]; then
  echo "Usage: $0 --host <HOST> [--user USER]"; exit 0; fi

TARGET_HOST=""; TARGET_USER="fks_user"; REPO_DIR="/home/fks_user/fks"; FORCE_PULL=false
while [[ $# -gt 0 ]]; do case $1 in --host) TARGET_HOST=$2; shift 2;; --user) TARGET_USER=$2; shift 2;; --force-pull) FORCE_PULL=true; shift;; *) shift;; esac; done
[[ -z "$TARGET_HOST" ]] && { echo "Host required"; exit 1; }
ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "mkdir -p $REPO_DIR && cd $REPO_DIR && git fetch origin && (git diff --quiet || $FORCE_PULL) && git pull origin main || git clone https://github.com/nuniesmith/fks.git $REPO_DIR" || exit 1
ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "cd $REPO_DIR && (docker compose pull || true) && (docker compose up -d || docker-compose up -d)"
echo "[SUCCESS] Deployment triggered on $TARGET_HOST"
