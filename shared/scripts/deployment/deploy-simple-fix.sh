#!/bin/bash

# FKS Trading Systems - Simple Deployment Fix
# This script simplifies the deployment to avoid nested quoting issues

set -e
set -o pipefail

# Configuration
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_TOKEN="${DOCKER_TOKEN:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
APP_ENV="${APP_ENV:-development}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ENABLE_SSL="${ENABLE_SSL:-true}"
SSL_STAGING="${SSL_STAGING:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Create deployment script on remote
create_remote_script() {
    cat << 'REMOTE_SCRIPT'
#!/bin/bash
set -e

echo "🚀 Starting FKS deployment on server..."

# Change to fks directory
cd /home/fks_user/fks

# Check if user exists
if ! id fks_user &>/dev/null; then
    echo "❌ Error: fks_user does not exist"
    exit 1
fi

echo "✅ fks_user exists"

# Docker Hub login
echo "🔐 Logging into Docker Hub..."
if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_TOKEN" ]; then
    echo "$DOCKER_TOKEN" | sudo -u fks_user docker login -u "$DOCKER_USERNAME" --password-stdin docker.io
    echo "✅ Docker Hub login successful"
else
    echo "❌ Docker credentials not provided"
    exit 1
fi

# Create .env file
echo "📝 Creating .env file..."
sudo -u fks_user tee .env > /dev/null << ENV_FILE
# FKS Trading Systems Configuration
COMPOSE_PROJECT_NAME=fks
APP_ENV=$APP_ENV
ENVIRONMENT=$APP_ENV
NODE_ENV=$APP_ENV

# Docker Configuration
DOCKER_REGISTRY=docker.io
DOCKER_NAMESPACE=$DOCKER_USERNAME
DOCKER_USERNAME=$DOCKER_USERNAME
DOCKER_TOKEN=$DOCKER_TOKEN
USE_DOCKER_HUB_IMAGES=true

# Service Ports
API_PORT=8000
WEB_PORT=3000
DATA_PORT=9001
WORKER_PORT=8001
HTTP_PORT=80
HTTPS_PORT=443
POSTGRES_PORT=5432
REDIS_PORT=6379

# Database Configuration
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=fks_postgres_$(openssl rand -hex 8)

# Redis Configuration
REDIS_PASSWORD=fks_redis_$(openssl rand -hex 8)

# Security
JWT_SECRET_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)

# Domain Configuration
DOMAIN_NAME=$DOMAIN_NAME
ENABLE_SSL=$ENABLE_SSL

# API URLs
API_URL=http://$DOMAIN_NAME:8000
WS_URL=ws://$DOMAIN_NAME:8000
REACT_APP_API_URL=http://$DOMAIN_NAME:8000

# Development settings
DEBUG_MODE=true
APP_LOG_LEVEL=DEBUG
VERBOSE_LOGGING=true

# Timezone
TZ=America/New_York
ENV_FILE

sudo -u fks_user chmod 600 .env
echo "✅ Environment file created"

# Make scripts executable
echo "🔧 Making scripts executable..."
sudo chmod +x scripts/orchestration/*.sh 2>/dev/null || true

# Create logs directory
sudo -u fks_user mkdir -p logs

# Start services
echo "🚀 Starting Docker services..."
if [ -f docker-compose.dev.yml ]; then
    echo "Using development configuration..."
    sudo -u fks_user docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
else
    echo "Using base configuration..."
    sudo -u fks_user docker compose up -d
fi

# Wait for services
echo "⏳ Waiting for services to start..."
sleep 20

# Check status
echo "📊 Checking service status..."
echo "=== Docker Containers ==="
sudo -u fks_user docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "=== Docker Compose Status ==="
sudo -u fks_user docker compose ps

echo ""
echo "✅ Deployment completed!"
echo "🌐 Application available at:"
echo "  - Web Interface: http://$DOMAIN_NAME:3000"
echo "  - API: http://$DOMAIN_NAME:8000"
echo "  - Data Service: http://$DOMAIN_NAME:9001"

REMOTE_SCRIPT
}

# Main execution
main() {
    log "🚀 Starting simplified FKS deployment..."
    log "📋 Target: $TARGET_HOST"
    
    # Test SSH connection
    log "🔐 Testing SSH connection..."
    if ! sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no actions_user@$TARGET_HOST "echo 'SSH OK'"; then
        error "Failed to connect via SSH"
        exit 1
    fi
    
    log "✅ SSH connection successful"
    
    # Create and upload the deployment script
    log "📤 Uploading deployment script..."
    create_remote_script | sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no actions_user@$TARGET_HOST "cat > /tmp/deploy.sh && chmod +x /tmp/deploy.sh"
    
    # Execute the deployment script with environment variables
    log "🚀 Executing deployment..."
    sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no actions_user@$TARGET_HOST "
        export DOCKER_USERNAME='$DOCKER_USERNAME'
        export DOCKER_TOKEN='$DOCKER_TOKEN'
        export APP_ENV='$APP_ENV'
        export DOMAIN_NAME='$DOMAIN_NAME'
        export ENABLE_SSL='$ENABLE_SSL'
        sudo -E bash /tmp/deploy.sh
    "
    
    log "✅ Deployment process completed!"
}

# Run main function
main "$@"
