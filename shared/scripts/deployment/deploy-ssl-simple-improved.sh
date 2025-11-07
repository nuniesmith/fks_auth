#!/bin/bash

# FKS Trading Systems - Improved SSL Deployment Script
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

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
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
        
        echo ''
        echo '💾 Disk usage before cleanup:'
        df -h | grep -E '(Filesystem|/dev/)'
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
    
    # Backup existing data if needed
    log "💾 Backing up existing data..."
    execute_ssh "
        # Backup existing .env file if it exists
        if [ -f /home/fks_user/fks/.env ]; then
            sudo cp /home/fks_user/fks/.env /tmp/fks_env_backup_$(date +%Y%m%d_%H%M%S)
            echo '✅ Backed up existing .env file'
        fi
        
        # List Docker volumes (data persistence)
        echo '📊 Docker volumes (persistent data):'
        docker volume ls | grep fks || echo 'No FKS volumes found'
    " "Backup existing data" 30
    
    # Repository setup with fixed permissions
    log "📥 Setting up repository..."
    execute_ssh "
        echo '📦 Repository setup with proper permissions...'
        
        # Ensure actions_user is in fks_user group
        sudo usermod -a -G fks_user actions_user || true
        
        # Create backup of old directory if exists
        if [ -d /home/fks_user/fks ]; then
            sudo mv /home/fks_user/fks /home/fks_user/fks_backup_$(date +%Y%m%d_%H%M%S)
            echo '✅ Backed up old repository'
        fi
        
        # Create directory with proper permissions
        sudo mkdir -p /home/fks_user/fks
        sudo chown fks_user:fks_user /home/fks_user/fks
        sudo chmod 775 /home/fks_user/fks
        
        # Clone repository to temp location
        cd /tmp
        rm -rf fks_fresh
        git clone https://x-access-token:$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh
        
        # Get the latest commit info
        cd fks_fresh
        LATEST_COMMIT=\$(git rev-parse --short HEAD)
        echo \"📌 Latest commit: \$LATEST_COMMIT\"
        cd ..
        
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
    
    # Deploy application with fixed permissions and proper cleanup
    log "🐳 Starting Docker deployment..."
    if ! execute_ssh "
        set -e
        
        echo '🥥 Refreshing group membership...'
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
        
        echo '🔧 Checking Docker networking...'
        # Fix Docker iptables if needed
        if ! iptables -L DOCKER-USER -n &>/dev/null 2>/dev/null; then
            echo '⚠️ Docker iptables chains missing - fixing...'
            sudo systemctl restart docker
            sleep 10
        fi
        
        echo '🔐 Setting up Docker permissions for proper UID/GID mapping...'
        
        # Get fks_user UID and GID
        FKS_USER_UID=$(id -u fks_user)
        FKS_USER_GID=$(id -g fks_user)
        echo "📋 fks_user UID: \$FKS_USER_UID, GID: \$FKS_USER_GID"
        
        # Add USER_ID and GROUP_ID to .env file
        echo '' >> .env
        echo '# User ID mapping for Docker containers' >> .env
        echo "USER_ID=\$FKS_USER_UID" >> .env
        echo "GROUP_ID=\$FKS_USER_GID" >> .env
        
        # Create docker-compose.override.yml for permission fixes
        echo '📄 Creating docker-compose.override.yml for permission mapping...'
        cat > /home/fks_user/fks/docker-compose.override.yml << 'OVERRIDE_EOF'
# Docker Compose Override - Automated Permission Fix
# Ensures containers run with the same UID/GID as fks_user


services:
  # Python services
  api:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
  
  worker:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
  
  data:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
  
  ninja-api:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
  
  # Web service - critical for React development
  web:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
    volumes:
      # Ensure write permissions for npm operations
      - ./src/web/react:/app/src/web/react:rw
      - web_node_modules:/app/src/web/react/node_modules
  
  # ML/GPU services (if enabled)
  training:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
  
  transformer:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}

  # Node network service (Rust)
  node-network:
    user: "\${USER_ID:-1001}:\${GROUP_ID:-1001}"
    environment:
      USER_ID: \${USER_ID:-1001}
      GROUP_ID: \${GROUP_ID:-1001}
# Named volume for node_modules to avoid permission issues
volumes:
  web_node_modules:
    name: fks_web_node_modules_\${APP_ENV:-dev}
OVERRIDE_EOF
        
        # Fix directory permissions before starting services
        echo '🔧 Fixing directory permissions...'
        sudo chown -R fks_user:fks_user /home/fks_user/fks/src/web/react 2>/dev/null || true
        sudo chown -R fks_user:fks_user /home/fks_user/fks/data 2>/dev/null || true
        sudo chown -R fks_user:fks_user /home/fks_user/fks/logs 2>/dev/null || true
        
        # Ensure write permissions on key directories
        sudo chmod -R 775 /home/fks_user/fks/src/web/react 2>/dev/null || true
        sudo chmod -R 775 /home/fks_user/fks/data 2>/dev/null || true
        sudo chmod -R 775 /home/fks_user/fks/logs 2>/dev/null || true
        
        echo '✅ Docker permission fixes applied successfully'

        echo '🧹 Cleaning up old containers...'
        docker compose down --remove-orphans 2>/dev/null || true
        
        echo '📸 Saving current image list...'
        docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^($DOCKER_USERNAME/fks:|fks:)' > /tmp/old_images.txt || true
        
        echo '🚀 Pulling latest images from Docker Hub...'
        docker compose pull 2>/dev/null
        
        echo '🚀 Starting services (using pre-built images)...'
        docker compose up -d --force-recreate 2>/dev/null
        echo '⏳ Waiting for services to initialize...'
        sleep 30
        
        echo '📊 Service status:'
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        
        echo '🔍 Checking service health...'
        docker compose ps
        
        echo '🧹 Cleaning up old Docker images...'
        # Get new image list
        docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^($DOCKER_USERNAME/fks:|fks:)' > /tmp/new_images.txt || true
        
        # Find images that are no longer in use
        if [ -f /tmp/old_images.txt ] && [ -f /tmp/new_images.txt ]; then
            # Get images that are in old but not in new (these are the outdated ones)
            OLD_UNUSED_IMAGES=\$(comm -23 <(sort /tmp/old_images.txt) <(sort /tmp/new_images.txt))
            
            if [ -n \"\$OLD_UNUSED_IMAGES\" ]; then
                echo '🗑️ Removing old unused images:'
                echo \"\$OLD_UNUSED_IMAGES\"
                echo \"\$OLD_UNUSED_IMAGES\" | xargs -r docker rmi || true
            else
                echo '✅ No old images to remove'
            fi
        fi
        
        # Clean up dangling images
        echo '🧹 Removing dangling images...'
        docker image prune -f
        
        # Show disk usage after cleanup
        echo ''
        echo '💾 Disk usage after cleanup:'
        df -h | grep -E '(Filesystem|/dev/)'
        
        # Check for unhealthy containers
        echo ''
        echo '🏥 Checking for unhealthy containers...'
        UNHEALTHY=\$(docker ps --filter health=unhealthy --format '{{.Names}}')
        if [ -n \"\$UNHEALTHY\" ]; then
            echo '⚠️ Unhealthy containers found:'
            echo \"\$UNHEALTHY\"
            echo ''
            echo '📋 Logs from unhealthy containers:'
            for container in \$UNHEALTHY; do
                echo \"=== Logs for \$container ===\"
                docker logs --tail=50 \$container 2>&1 | grep -E '(error|Error|ERROR|failed|Failed|FAILED)' || echo 'No error logs found'
            done
        else
            echo '✅ All containers are healthy'
        fi
        
DEPLOY_SCRIPT
        
        # Cleanup
        rm -f /tmp/env_content /tmp/old_images.txt /tmp/new_images.txt
        
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
        # Run status check directly without user switching
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
        
        echo ''
        echo '🐳 Docker image status:'
        docker images | grep -E '(REPOSITORY|$DOCKER_USERNAME/fks)' | head -10
    " "Final status check" 60
    
    log "✅ Deployment completed!"
    log "🌐 Application URL: $([ '$ENABLE_SSL' = 'true' ] && echo 'https' || echo 'http')://$DOMAIN_NAME"
    log ""
    log "📋 Quick commands:"
    log "  - Check status: ssh actions_user@$TARGET_HOST 'docker ps'"
    log "  - View logs: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && docker compose logs -f'"
    log "  - Restart: ssh actions_user@$TARGET_HOST 'cd /home/fks_user/fks && docker compose restart'"
    log "  - Clean old images: ssh actions_user@$TARGET_HOST 'docker image prune -a -f'"
}

# Execute
main "$@"
