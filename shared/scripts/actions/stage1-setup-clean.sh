#!/bin/bash
set -euo pipefail

echo "🏗️ Starting Stage 1 setup with external scripts..."

# Download the modular setup scripts
curl -o stage1-core-setup.sh https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/stage1-core-setup.sh
curl -o stage1-docker-setup.sh https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/stage1-docker-setup.sh
curl -o stage1-final-setup.sh https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/stage1-final-setup.sh

chmod +x stage1-*.sh

echo "🏗️ Running Stage 1 Core Setup..."
./stage1-core-setup.sh

echo "🐳 Running Stage 1 Docker Setup..."
./stage1-docker-setup.sh

echo "⚙️ Running Stage 1 Final Setup..."
# Replace placeholders in final setup
sed -i 's/SERVICE_NAME_PLACEHOLDER/nginx/g' stage1-final-setup.sh
sed -i 's/TAILSCALE_AUTH_KEY_PLACEHOLDER/$TAILSCALE_AUTH_KEY/g' stage1-final-setup.sh
sed -i 's/\$ACTIONS_USER_PASSWORD/$ACTIONS_USER_PASSWORD/g' stage1-final-setup.sh
./stage1-final-setup.sh

echo "✅ Stage 1 complete - system ready for reboot"
echo "NEEDS_REBOOT" > /tmp/stage1_status
