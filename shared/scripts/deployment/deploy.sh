#!/bin/bash

# FKS Trading Systems - Unified Deployment Script
# This script consolidates all deployment variations into a single, maintainable solution
# Supports: SSL/HTTP, development/production, Docker Hub            sudo cp /home/fks_user/fks/.env $HOME/fks_env_backup_$(date +%Y%m%d_%H%M%S)images, and proper permissions

set -e  # Exit on any error
set -o pipefail  # Exit on pipe failures

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$HOME/deploy-fks.log"

# Environment variables with defaults
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_TOKEN="${DOCKER_TOKEN:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_REF_NAME="${GITHUB_REF_NAME:-main}"
APP_ENV="${APP_ENV:-development}"

# SSL Configuration
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
ENABLE_SSL="${ENABLE_SSL:-true}"
SSL_STAGING="${SSL_STAGING:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

# SSH execution function with proper error handling
execute_ssh() {
    local command="$1"
    local description="$2"
    local timeout="${3:-120}"
    
    log "📡 $description"
    
    if [ -z "$ACTIONS_USER_PASSWORD" ]; then
        error "No SSH password available"
        return 1
    fi
    
    if timeout "$timeout" sshpass -p "$ACTIONS_USER_PASSWORD" \
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 \
        actions_user@"$TARGET_HOST" "$command" 2>&1 | tee -a "$LOG_FILE"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description"
        return 1
    fi
}

# SCP file transfer function
execute_scp() {
    local source="$1"
    local dest="$2"
    local description="$3"
    
    log "📤 $description"
    
    if sshpass -p "$ACTIONS_USER_PASSWORD" \
        scp -o StrictHostKeyChecking=no \
        "$source" actions_user@"$TARGET_HOST":"$dest"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description"
        return 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "🔍 Checking deployment prerequisites..."
    
    local missing=()
    
    # Check required environment variables
    [ -z "$ACTIONS_USER_PASSWORD" ] && missing+=("ACTIONS_USER_PASSWORD")
    [ -z "$DOCKER_USERNAME" ] && missing+=("DOCKER_USERNAME")
    [ -z "$DOCKER_TOKEN" ] && missing+=("DOCKER_TOKEN")
    [ -z "$GITHUB_TOKEN" ] && missing+=("GITHUB_TOKEN")
    
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required environment variables:"
        for var in "${missing[@]}"; do
            error "  - $var"
        done
        return 1
    fi
    
    # Check SSL requirements if enabled
    if [ "$ENABLE_SSL" = "true" ]; then
        if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
            warn "SSL enabled but Cloudflare credentials missing. Disabling SSL."
            ENABLE_SSL="false"
        fi
    fi
    
    log "✅ All prerequisites met"
    return 0
}

# Function to test SSH connectivity
test_ssh_connection() {
    log "🔐 Testing SSH connection..."
    
    if timeout 15 sshpass -p "$ACTIONS_USER_PASSWORD" \
        ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        actions_user@"$TARGET_HOST" "echo 'SSH ready'" >/dev/null 2>&1; then
        log "✅ SSH connection successful"
        return 0
    else
        error "Unable to connect via SSH"
        return 1
    fi
}

# Function to check server status
check_server_status() {
    execute_ssh "
        echo '📊 Server Status Check'
        echo '===================='
        echo ''
        echo '🐳 Docker status:'
        docker --version || echo 'Docker not installed'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo 'No containers running'
        echo ''
        echo '📁 Directory status:'
        ls -la /home/fks_user/ 2>/dev/null || echo 'fks_user directory not accessible'
        echo ''
        echo '💾 Disk usage:'
        df -h | grep -E '(Filesystem|/dev/)'
        echo ''
        echo '👥 User groups:'
        groups
    " "Server status check"
}

# Function to setup SSL certificates
setup_ssl_certificates() {
    if [ "$ENABLE_SSL" != "true" ]; then
        warn "SSL is disabled, skipping certificate setup"
        return 0
    fi
    
    log "🔐 Setting up SSL certificates..."
    
    execute_ssh "
        echo '📋 Checking for existing SSL certificates...'
        
        if [ -f /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem ]; then
            echo '✅ Found existing SSL certificates'
            
            # Create SSL directory for Docker mount
            sudo mkdir -p /home/fks_user/ssl
            
            # Copy certificates
            sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /home/fks_user/ssl/cert.pem
            sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /home/fks_user/ssl/key.pem
            
            # Set proper permissions
            sudo chown -R fks_user:fks_user /home/fks_user/ssl
            sudo chmod 755 /home/fks_user/ssl
            sudo chmod 644 /home/fks_user/ssl/cert.pem
            sudo chmod 600 /home/fks_user/ssl/key.pem
            
            echo '✅ SSL certificates ready for Docker'
        else
            echo '⚠️ SSL certificates not found, will use HTTP'
        fi
    " "SSL certificate check"
}

# Function to backup existing data
backup_existing_data() {
    log "💾 Backing up existing data..."
    
    execute_ssh "
        # Backup .env file if exists
        if [ -f /home/fks_user/fks/.env ]; then
            sudo cp /home/fks_user/fks/.env /tmp/fks_env_backup_\$(date +%Y%m%d_%H%M%S)
            echo '✅ Backed up existing .env file'
        fi
        
        # Check Docker volumes
        echo '📊 Docker volumes:'
        docker volume ls | grep fks || echo 'No FKS volumes found'
    " "Backup data"
}

# Function to setup repository
setup_repository() {
    log "📥 Setting up repository..."
    
    execute_ssh "
        echo '📦 Repository setup'
        echo '=================='
        
        # Ensure actions_user is in fks_user group
        sudo usermod -a -G fks_user actions_user 2>/dev/null || true
        
        # Backup old directory if exists
        if [ -d /home/fks_user/fks ]; then
            sudo mv /home/fks_user/fks /home/fks_user/fks_backup_\$(date +%Y%m%d_%H%M%S)
            echo '✅ Backed up old repository'
        fi
        
        # Create directory
        sudo mkdir -p /home/fks_user/fks
        sudo chown fks_user:fks_user /home/fks_user/fks
        sudo chmod 775 /home/fks_user/fks
        
        # Clone repository
        cd /tmp
        rm -rf fks_temp
        git clone https://x-access-token:$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_temp
        
        # Get latest commit
        cd fks_temp
        LATEST_COMMIT=\$(git rev-parse --short HEAD)
        echo \"📌 Latest commit: \$LATEST_COMMIT\"
        cd ..
        
        # Move files
        sudo mv fks_temp/* /home/fks_user/fks/
        sudo mv fks_temp/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
        rm -rf fks_temp
        
        # Set permissions
        sudo chown -R fks_user:fks_user /home/fks_user/fks
        sudo chmod -R g+rw /home/fks_user/fks
        sudo chmod 755 /home/fks_user
        
        # Make scripts executable
        sudo find /home/fks_user/fks/scripts -name '*.sh' -exec chmod +x {} \\; 2>/dev/null || true
        
        echo '✅ Repository setup complete'
    " "Repository setup"
}

# Function to deploy application
deploy_application() {
    log "🚀 Deploying application..."
    
    # Clean up Docker images and containers first
    log "🧹 Cleaning up old Docker resources..."
    execute_ssh "
        echo '🐳 Stopping all containers...'
        docker stop \$(docker ps -aq) 2>/dev/null || true
        
        echo '🗑️ Removing all containers...'
        docker rm \$(docker ps -aq) 2>/dev/null || true
        
        echo '🧹 Pruning Docker system (images, volumes, networks)...'
        docker system prune -af --volumes || true
        
        echo '✅ Docker cleanup complete'
    " "Docker cleanup"
    
    # Create environment file
    log "📝 Creating environment configuration..."
    cat > $HOME/fks.env << ENVEOF
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
REDIS_PASSWORD=fks_redis_$(openssl rand -hex 8)

# Security
JWT_SECRET_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)
AUTHELIA_JWT_SECRET=${AUTHELIA_JWT_SECRET:-a6d7d8c44bb1938d41234dc7dac9b10bbdc1ad4e0c9277885c2d795ebcb6d15d}
AUTHELIA_JWT_ALGORITHM=${AUTHELIA_JWT_ALGORITHM:-HS256}

# Domain Configuration
DOMAIN_NAME=$DOMAIN_NAME
ENABLE_SSL=$ENABLE_SSL
SSL_STAGING=$SSL_STAGING

# URLs
$(if [ "$ENABLE_SSL" = "true" ]; then
    echo "API_URL=https://$DOMAIN_NAME:8000"
    echo "WS_URL=wss://$DOMAIN_NAME:8000"
    echo "REACT_APP_API_URL=https://$DOMAIN_NAME:8000"
else
    echo "API_URL=http://$DOMAIN_NAME:8000"
    echo "WS_URL=ws://$DOMAIN_NAME:8000"
    echo "REACT_APP_API_URL=http://$DOMAIN_NAME:8000"
fi)

# Development settings
DEBUG_MODE=$([ "$APP_ENV" = "development" ] && echo "true" || echo "false")
APP_LOG_LEVEL=$([ "$APP_ENV" = "development" ] && echo "DEBUG" || echo "INFO")

# Timezone
TZ=America/New_York
ENVEOF
    
    # Copy environment file
    execute_scp "$HOME/fks.env" "/home/fks_user/fks.env" "Copying environment file"
    
    # Deploy the application
    execute_ssh "
        cd /home/fks_user/fks
        
        # Move environment file with proper permissions
        sudo cp /home/fks_user/fks.env .env
        sudo chown fks_user:fks_user .env
        sudo chmod 600 .env
        
        # Docker authentication as fks_user
        echo '🔐 Docker Hub authentication...'
        sudo -u fks_user bash -c 'echo \"$DOCKER_TOKEN\" | docker login -u \"$DOCKER_USERNAME\" --password-stdin'
        
        # Get fks_user UID/GID for proper permissions
        FKS_UID=\$(id -u fks_user)
        FKS_GID=\$(id -g fks_user)
        
        # Append USER_ID and GROUP_ID to .env file using sudo
        echo '📝 Adding user mappings to .env...'
        echo '' | sudo tee -a .env > /dev/null
        echo \"USER_ID=\$FKS_UID\" | sudo tee -a .env > /dev/null
        echo \"GROUP_ID=\$FKS_GID\" | sudo tee -a .env > /dev/null
        
        # Create docker-compose.override.yml with proper permissions
        echo '📄 Creating docker-compose.override.yml...'
        sudo -u fks_user tee docker-compose.override.yml > /dev/null << 'OVERRIDE'


services:
  api:
    user: \"\${USER_ID:-1001}:\${GROUP_ID:-1001}\"
  worker:
    user: \"\${USER_ID:-1001}:\${GROUP_ID:-1001}\"
  data:
    user: \"\${USER_ID:-1001}:\${GROUP_ID:-1001}\"
  web:
    user: \"\${USER_ID:-1001}:\${GROUP_ID:-1001}\"
  nginx:
    user: \"\${USER_ID:-1001}:\${GROUP_ID:-1001}\"
OVERRIDE
        
        # Ensure correct ownership of all files
        sudo chown fks_user:fks_user docker-compose.override.yml
        
        # Fix directory permissions
        echo '🔧 Setting directory permissions...'
        sudo chown -R fks_user:fks_user /home/fks_user/fks
        sudo chmod -R 775 /home/fks_user/fks/data 2>/dev/null || true
        sudo chmod -R 775 /home/fks_user/fks/logs 2>/dev/null || true
        sudo mkdir -p /home/fks_user/fks/logs
        sudo chown fks_user:fks_user /home/fks_user/fks/logs
        
        # Make scripts executable
        sudo chmod +x /home/fks_user/fks/scripts/orchestration/*.sh 2>/dev/null || true
        sudo chmod +x /home/fks_user/fks/start.sh 2>/dev/null || true
        
        # Export environment variables for start.sh
        export USE_DOCKER_HUB_IMAGES=true
        export DOCKER_USERNAME='$DOCKER_USERNAME'
        export DOCKER_TOKEN='$DOCKER_TOKEN'
        export DOCKER_NAMESPACE='$DOCKER_USERNAME'
        export APP_ENV='$APP_ENV'
        
        # Use start.sh script to handle Docker services
        echo '🚀 Using start.sh to deploy services...'
        if sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            export USE_DOCKER_HUB_IMAGES=true
            export DOCKER_USERNAME=\"$DOCKER_USERNAME\"
            export DOCKER_TOKEN=\"$DOCKER_TOKEN\"
            export DOCKER_NAMESPACE=\"$DOCKER_USERNAME\"
            export APP_ENV=\"$APP_ENV\"
            ./start.sh
        '; then
            echo '✅ start.sh completed successfully'
        else
            echo '⚠️ start.sh completed with warnings'
        fi
        
        # Wait for services to initialize
        echo '⏳ Waiting for services to start...'
        sleep 30
        
        # Check final status
        echo ''
        echo '📊 Final Deployment Status:'
        sudo -u fks_user docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'
        
        echo ''
        echo '✅ Deployment complete!'
    " "Application deployment" 300
    
    # Cleanup
    rm -f $HOME/fks.env
}

# Function to check deployment health
check_deployment_health() {
    log "🏥 Checking deployment health..."
    
    execute_ssh "
        cd /home/fks_user/fks
        
        echo '📊 Container Status:'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        
        echo ''
        echo '🏥 Health Checks:'
        
        # Check services
        services=('80:HTTP' '3000:Web' '8000:API')
        for service in \"\${services[@]}\"; do
            port=\${service%%:*}
            name=\${service##*:}
            if curl -f -s -o /dev/null -m 5 http://localhost:\$port; then
                echo \"✅ \$name (port \$port) is responding\"
            else
                echo \"❌ \$name (port \$port) is not responding\"
            fi
        done
        
        # Check for unhealthy containers
        UNHEALTHY=\$(docker ps --filter health=unhealthy --format '{{.Names}}')
        if [ -n \"\$UNHEALTHY\" ]; then
            echo ''
            echo '⚠️ Unhealthy containers found:'
            echo \"\$UNHEALTHY\"
        fi
    " "Health check"
}

# Main deployment function
main() {
    log "🚀 FKS Trading Systems Deployment"
    log "================================"
    log "📋 Configuration:"
    log "  - Environment: $APP_ENV"
    log "  - Target: $TARGET_HOST"
    log "  - Domain: $DOMAIN_NAME"
    log "  - SSL: $ENABLE_SSL"
    log ""
    
    # Step 1: Check prerequisites
    check_prerequisites || exit 1
    
    # Step 2: Test SSH connection
    test_ssh_connection || exit 1
    
    # Step 3: Check server status
    check_server_status
    
    # Step 4: Setup SSL if enabled
    setup_ssl_certificates
    
    # Step 5: Backup existing data
    backup_existing_data
    
    # Step 6: Setup repository
    setup_repository || exit 1
    
    # Step 7: Deploy application
    deploy_application || exit 1
    
    # Step 8: Check deployment health
    check_deployment_health
    
    log ""
    log "✅ Deployment completed successfully!"
    log "🌐 Application URL: $([ "$ENABLE_SSL" = "true" ] && echo "https" || echo "http")://$DOMAIN_NAME"
    log ""
    log "📋 Quick commands:"
    log "  - Check status: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && docker compose ps'"
    log "  - View logs: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && docker compose logs -f'"
    log "  - Restart: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && docker compose restart'"
}

# Execute main function
main "$@"
