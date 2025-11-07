#!/bin/bash

# FKS Trading Systems - Simple SSL Deployment Script
set -e

# Environment variables
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
ENABLE_SSL="${ENABLE_SSL:-true}"
SSL_STAGING="${SSL_STAGING:-false}"
APP_ENV="${APP_ENV:-development}"
DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_TOKEN="${DOCKER_TOKEN:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# SSH execution function with timeout
execute_ssh() {
    local command="$1"
    local description="$2"
    local timeout="${3:-120}"
    
    log "📡 $description"
    
    if timeout "$timeout" sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 actions_user@"$TARGET_HOST" "$command"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description"
        return 1
    fi
}

# SCP with timeout function
execute_scp() {
    local source="$1"
    local dest="$2"
    local description="$3"
    local timeout="${4:-60}"
    
    log "📤 $description"
    
    if timeout "$timeout" sshpass -p "$ACTIONS_USER_PASSWORD" scp -o StrictHostKeyChecking=no -o ConnectTimeout=30 "$source" actions_user@"$TARGET_HOST":"$dest"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description"
        return 1
    fi
}

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems deployment..."
    
    # Test SSH
    if ! execute_ssh "echo 'SSH ready'" "SSH connectivity test" 10; then
        error "❌ SSH connection failed"
        exit 1
    fi
    
    # Check existing deployment status
    log "🔍 Checking existing deployment..."
    execute_ssh "
        echo '📊 Current Docker containers:'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo 'No containers running'
        
        echo ''
        echo '📁 Checking directory permissions:'
        ls -la /home/fks_user/ 2>/dev/null || echo 'Cannot access fks_user directory'
        
        echo ''
        echo '👥 Current user groups:'
        groups
    " "Check deployment status" 30
    
    # Handle SSL certificates (copy existing)
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Setting up SSL certificates..."
        
        execute_ssh "
            echo '📋 Checking for existing SSL certificates...'
            
            # First check if certificates exist
            if [ -f /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem ]; then
                echo '✅ Found existing SSL certificates'
                
                # Create SSL directory with proper permissions
                sudo mkdir -p /home/fks_user/ssl
                
                # Copy certificates
                sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /home/fks_user/ssl/cert.pem
                sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /home/fks_user/ssl/key.pem
                
                # Set ownership and permissions
                sudo chown -R fks_user:fks_user /home/fks_user/ssl
                sudo chmod 755 /home/fks_user/ssl
                sudo chmod 644 /home/fks_user/ssl/cert.pem
                sudo chmod 600 /home/fks_user/ssl/key.pem
                
                # Allow actions_user to read the certificates
                sudo usermod -a -G fks_user actions_user 2>/dev/null || true
                
                echo '✅ SSL certificates ready for Docker'
            else
                echo '⚠️ SSL certificates not found, will use HTTP'
            fi
        " "SSL certificate setup" 30
    fi
    
    # Repository setup with fixed permissions
    log "📥 Setting up repository..."
    execute_ssh "
        echo '📦 Repository setup with proper permissions...'
        
        # Ensure actions_user is in fks_user group
        sudo usermod -a -G fks_user actions_user || true
        
        # Remove old directory if exists
        sudo rm -rf /home/fks_user/fks
        
        # Create directory with proper permissions
        sudo mkdir -p /home/fks_user/fks
        sudo chown fks_user:fks_user /home/fks_user/fks
        sudo chmod 775 /home/fks_user/fks
        
        # Clone repository to temp location
        cd /tmp
        rm -rf fks_fresh
        git clone https://x-access-token:$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh
        
        # Move files with proper ownership
        sudo mv fks_fresh/* /home/fks_user/fks/
        sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
        rm -rf fks_fresh
        
        # Set proper ownership and permissions
        sudo chown -R fks_user:fks_user /home/fks_user/fks
        sudo chmod -R g+rw /home/fks_user/fks
        
        # Ensure actions_user can access the directory
        sudo chmod 755 /home/fks_user
        
        echo '✅ Repository ready with correct permissions'
    " "Repository setup" 120
    
    # Application deployment
    log "🚀 Deploying application..."
    
    # Create environment file locally
    log "📝 Creating environment configuration..."
    cat > /tmp/env_content << ENVEOF
COMPOSE_PROJECT_NAME=fks
APP_ENV=$APP_ENV
DOCKER_REGISTRY=docker.io
DOCKER_NAMESPACE=$DOCKER_USERNAME
API_PORT=8000
WEB_PORT=3000
DATA_PORT=9001
HTTP_PORT=80
HTTPS_PORT=443
POSTGRES_PORT=5432
REDIS_PORT=6379
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=fks_postgres_$(openssl rand -hex 8)
REDIS_PASSWORD=fks_redis_$(openssl rand -hex 8)
DOMAIN_NAME=$DOMAIN_NAME
ENABLE_SSL=$ENABLE_SSL
SSL_STAGING=$SSL_STAGING
SSL_MOUNT_PATH=/home/fks_user/ssl
API_HOST=api
WEB_HOST=web
WORKER_HOST=worker
WORKER_PORT=8001
TZ=America/New_York
ENVEOF
    
    # Copy environment file with timeout
    if ! execute_scp "/tmp/env_content" "/tmp/env_content" "Copying environment configuration" 30; then
        error "Failed to copy environment file"
        rm -f /tmp/env_content
        exit 1
    fi
    
    # Deploy application with fixed permissions
    log "🐳 Starting Docker deployment..."
    if ! execute_ssh "
        set -e
        
        echo '👥 Refreshing group membership...'
        # Refresh group membership for current session
        newgrp fks_user <<'DEPLOY_SCRIPT' || sudo -u fks_user bash <<'DEPLOY_SCRIPT'
        
        cd /home/fks_user/fks
        
        echo '🔐 Docker authentication...'
        echo '$DOCKER_TOKEN' | docker login -u '$DOCKER_USERNAME' --password-stdin 2>&1
        
        echo '📄 Environment setup...'
        cp /tmp/env_content .env
        chmod 600 .env
        
        if [ '$ENABLE_SSL' = 'true' ] && [ -d /home/fks_user/ssl ]; then
            echo '🔐 Configuring SSL mount paths...'
            echo 'SSL_CERT_PATH=/home/fks_user/ssl/cert.pem' >> .env
            echo 'SSL_KEY_PATH=/home/fks_user/ssl/key.pem' >> .env
            echo '✅ SSL certificates configured for Docker mount'
        fi
        
        
        echo '🔧 Checking Docker networking...'\n        # Fix Docker iptables if needed\n        if ! iptables -L DOCKER-FORWARD -n &>/dev/null 2>&1; then\n            echo '⚠️ Docker iptables chains missing - fixing...'\n            systemctl restart docker\n            sleep 10\n        fi\n
        echo '🧹 Cleaning up old containers...'
        docker compose down --remove-orphans 2>&1 || true
        
        echo '🚀 Pulling latest images from Docker Hub...'
        docker compose pull 2>&1
        
        echo '🚀 Starting services (using pre-built images)...'
        docker compose up -d 2>&1  # Removed --build flag
        
        echo '⏳ Waiting for services to initialize...'
        sleep 20
        
        echo '📊 Service status:'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        
        echo '🔍 Checking service health...'
        docker compose ps
        
DEPLOY_SCRIPT
        
        # Cleanup
        rm -f /tmp/env_content
        
        echo '✅ Docker deployment completed'
    " "Docker container deployment" 300; then
        error "Docker deployment failed"
        rm -f /tmp/env_content
        
        # Try to get diagnostic info
        execute_ssh "
            echo '🔍 Diagnostic information:'
            echo '📁 Directory permissions:'
            ls -la /home/fks_user/fks 2>/dev/null || echo 'Cannot access directory'
            echo ''
            echo '🐳 Docker containers:'
            docker ps -a
            echo ''
            echo '📋 Docker logs (if available):'
            cd /home/fks_user/fks 2>/dev/null && docker compose logs --tail=50 2>/dev/null || echo 'Cannot access logs'
        " "Getting diagnostic info" 30
        
        exit 1
    fi
    
    rm -f /tmp/env_content
    
    # Final status check
    log "🔍 Final status check..."
    execute_ssh "
        # Use sudo to run commands as fks_user if needed
        sudo -u fks_user bash <<'EOF'
        cd /home/fks_user/fks
        
        echo '📊 Final container status:'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        
        echo ''
        echo '🏥 Health checks:'
        
        # Check HTTP
        if curl -f -s -o /dev/null -m 5 http://localhost:80; then
            echo '✅ HTTP (port 80) is responding'
        else
            echo '❌ HTTP (port 80) is not responding'
        fi
        
        # Check API
        if curl -f -s -o /dev/null -m 5 http://localhost:8000/health 2>/dev/null || curl -f -s -o /dev/null -m 5 http://localhost:8000; then
            echo '✅ API (port 8000) is responding'
        else
            echo '⚠️  API (port 8000) may still be starting up'
        fi
        
        # Check Web
        if curl -f -s -o /dev/null -m 5 http://localhost:3000; then
            echo '✅ Web UI (port 3000) is responding'
        else
            echo '⚠️  Web UI (port 3000) may still be starting up'
        fi
        
        # Check HTTPS if enabled
        if [ '$ENABLE_SSL' = 'true' ]; then
            if curl -f -s -o /dev/null -k -m 5 https://localhost:443; then
                echo '✅ HTTPS (port 443) is responding'
            else
                echo '⚠️  HTTPS (port 443) may need certificate setup'
            fi
        fi
        
        echo ''
        echo '📋 Recent container logs:'
        docker compose logs --tail=20 nginx 2>&1 | grep -E '(error|Error|ERROR|started|Started|listening|Configuration complete)' || echo 'No significant nginx logs'
EOF
    " "Final status check" 60
    
    log "✅ Deployment completed!"
    log "🌐 Application URL: $([ '$ENABLE_SSL' = 'true' ] && echo 'https' || echo 'http')://$DOMAIN_NAME"
    log ""
    log "📋 Quick commands:"
    log "  - Check status: ssh actions_user@$TARGET_HOST 'sudo -u fks_user docker ps'"
    log "  - View logs: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && sudo -u fks_user docker compose logs -f'"
    log "  - Restart: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && sudo -u fks_user docker compose restart'"
}

# Execute
main "$@"