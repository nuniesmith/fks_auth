#!/bin/bash

# FKS Trading Systems - Fix Current Server Deployment
# This script fixes the current server's Docker deployment issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
TARGET_HOST=""
ROOT_PASSWORD=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --root-password)
            ROOT_PASSWORD="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$TARGET_HOST" ] || [ -z "$ROOT_PASSWORD" ]; then
    echo "Usage: $0 --target-host <host> --root-password <password>"
    exit 1
fi

echo -e "${GREEN}🚀 Fixing Docker deployment on $TARGET_HOST${NC}"

# Create the fix script
cat > /tmp/fix-docker-remote.sh << 'REMOTE_SCRIPT'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Fix Docker iptables
log "Fixing Docker iptables..."
systemctl restart docker
sleep 10

if iptables -L DOCKER-FORWARD -n &>/dev/null; then
    log "✅ Docker iptables chains restored"
else
    error "Failed to restore Docker iptables chains"
    exit 1
fi

# Clean up Docker
log "Cleaning up Docker..."
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm $(docker ps -aq) 2>/dev/null || true

# Remove problematic networks
for network in $(docker network ls --format '{{.Name}}' | grep -E '^fks_'); do
    log "Removing network: $network"
    docker network rm "$network" 2>/dev/null || true
done

# Deploy FKS
log "Deploying FKS..."
cd /home/fks_user/fks

# Ensure proper ownership
chown -R fks_user:fks_user /home/fks_user/fks

# Run deployment as fks_user
sudo -u fks_user bash << 'DEPLOY'
cd /home/fks_user/fks

# Ensure .env exists
if [ ! -f .env ]; then
    if [ -f .env.development ]; then
        cp .env.development .env
    elif [ -f .env.example ]; then
        cp .env.example .env
    else
        echo "No .env file found!"
        exit 1
    fi
fi

# Pull and start
docker compose pull
docker compose up -d

# Wait for services
sleep 20

# Show status
docker compose ps
DEPLOY

log "✅ Deployment completed!"

# Check services
log "Checking services..."
curl -s -o /dev/null -w "HTTP: %{http_code}\n" http://localhost:80 || echo "HTTP not ready"
curl -s -o /dev/null -w "API: %{http_code}\n" http://localhost:8000/health || echo "API not ready"
curl -s -o /dev/null -w "Web: %{http_code}\n" http://localhost:3000 || echo "Web not ready"
REMOTE_SCRIPT

# Upload and execute
echo -e "${GREEN}📤 Uploading fix script...${NC}"
sshpass -p "$ROOT_PASSWORD" scp -o StrictHostKeyChecking=no /tmp/fix-docker-remote.sh root@$TARGET_HOST:/tmp/

echo -e "${GREEN}🔧 Executing fix script...${NC}"
sshpass -p "$ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no root@$TARGET_HOST "chmod +x /tmp/fix-docker-remote.sh && /tmp/fix-docker-remote.sh"

# Cleanup
rm -f /tmp/fix-docker-remote.sh

echo -e "${GREEN}✅ Fix completed!${NC}"
echo -e "${GREEN}🌐 Check services at:${NC}"
echo -e "  - Web: http://$TARGET_HOST"
echo -e "  - API: http://$TARGET_HOST:8000"
echo -e "  - Web UI: http://$TARGET_HOST:3000"
