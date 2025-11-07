#!/bin/bash

# Comprehensive fix for development deployment issues
# This script addresses nginx SSL issues, development configuration, and service problems

set -e

# Configuration
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_TOKEN="${DOCKER_TOKEN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    
    log "📡 $description"
    
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$TARGET_HOST" "$command"; then
            log "✅ Success: $description"
            return 0
        else
            error "❌ Failed: $description"
            return 1
        fi
    else
        error "❌ No password available for SSH"
        return 1
    fi
}

main() {
    log "🔧 Starting comprehensive development deployment fix..."
    
    # Step 1: Fix environment configuration
    log "🔧 Step 1: Fixing environment configuration for development..."
    execute_ssh "
        echo '🔧 Updating environment configuration for development...'
        
        cd /home/fks_user/fks
        
        # Create a proper development .env file
        sudo -u fks_user bash -c 'cat > .env << \"DEVENV\"
# FKS Trading Systems - Development Configuration
# Fixed configuration for fks_dev server

# Environment
APP_ENV=development
ENVIRONMENT=development
NODE_ENV=development
DEBUG_MODE=true
APP_LOG_LEVEL=DEBUG
VERBOSE_LOGGING=true

# Docker Configuration
DOCKER_REGISTRY=docker.io
DOCKER_NAMESPACE=$DOCKER_USERNAME
USE_DOCKER_HUB_IMAGES=true
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1

# Service Ports
API_PORT=8000
WEB_PORT=3000
DATA_PORT=9001
HTTP_PORT=80
HTTPS_PORT=443
POSTGRES_PORT=5432
REDIS_PORT=6379

# Database Configuration
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=fks_postgres_dev_$(openssl rand -hex 8)

# Redis Configuration
REDIS_PASSWORD=fks_redis_dev_$(openssl rand -hex 8)
REDIS_MAXMEMORY=512mb
REDIS_MAXMEMORY_POLICY=allkeys-lru

# Security
JWT_SECRET_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)

# SSL Configuration - DISABLED FOR DEVELOPMENT
DOMAIN_NAME=localhost
ENABLE_SSL=false
SSL_STAGING=false

# Nginx Configuration
PROXY_CONNECT_TIMEOUT=30s
PROXY_SEND_TIMEOUT=30s
PROXY_READ_TIMEOUT=30s

# API Configuration
API_HOST=api
API_PORT=8000
WEB_HOST=web
WEB_PORT=3000

# Development Tools
ADMINER_PORT=8080
REDIS_COMMANDER_PORT=8082
CHOKIDAR_USEPOLLING=true
ENABLE_HOT_RELOAD=true

# Resource Limits (Development)
API_CPU_LIMIT=1
API_MEMORY_LIMIT=1024M
WEB_CPU_LIMIT=0.5
WEB_MEMORY_LIMIT=512M

# Logging
LOG_DRIVER=json-file
LOG_MAX_SIZE=10m
LOG_MAX_FILES=3

# Health Checks
HEALTHCHECK_INTERVAL=30s
HEALTHCHECK_TIMEOUT=10s
HEALTHCHECK_RETRIES=3
HEALTHCHECK_START_PERIOD=60s

# Timezone
TZ=America/New_York

# URLs
API_URL=http://localhost:8000
REACT_APP_API_URL=http://localhost:8000
WS_URL=ws://localhost:8000
DEVENV'
        
        # Set proper permissions
        chmod 600 .env
        echo \"✅ Development .env file created\"
        '
    " "Fix environment configuration"
    
    # Step 2: Stop all services and clean up
    log "🔧 Step 2: Stopping services and cleaning up..."
    execute_ssh "
        echo '🛑 Stopping all services...'
        
        cd /home/fks_user/fks
        
        sudo -u fks_user bash -c '
            # Stop all compose services
            docker compose down --timeout 30 || true
            docker compose -f docker-compose.yml -f docker-compose.dev.yml down --timeout 30 || true
            docker compose -f docker-compose.yml -f docker-compose.prod.yml down --timeout 30 || true
            
            # Remove problematic containers
            docker rm -f fks_nginx || true
            docker rm -f fks_api || true
            docker rm -f fks_web || true
            docker rm -f fks_worker || true
            docker rm -f fks_data || true
            
            # Clean up networks
            docker network prune -f || true
            
            # Clean up volumes if needed
            docker volume prune -f || true
        '
        
        echo '✅ Services stopped and cleaned up'
    " "Stop services and cleanup"
    
    # Step 3: Docker Hub authentication
    log "🔧 Step 3: Setting up Docker Hub authentication..."
    execute_ssh "
        echo '🔐 Setting up Docker Hub authentication...'
        
        cd /home/fks_user/fks
        
        sudo -u fks_user bash -c '
            if [ -n \"$DOCKER_TOKEN\" ] && [ -n \"$DOCKER_USERNAME\" ]; then
                echo \"$DOCKER_TOKEN\" | docker login -u \"$DOCKER_USERNAME\" --password-stdin docker.io
                echo \"✅ Docker Hub authentication successful\"
            else
                echo \"⚠️ No Docker Hub credentials provided\"
            fi
        '
    " "Docker Hub authentication"
    
    # Step 4: Start services with proper configuration
    log "🔧 Step 4: Starting services with development configuration..."
    execute_ssh "
        echo '🚀 Starting services with development configuration...'
        
        cd /home/fks_user/fks
        
        sudo -u fks_user bash -c '
            # Source environment
            export \$(cat .env | xargs)
            
            # Use development compose configuration
            if [ -f docker-compose.dev.yml ]; then
                echo \"🔧 Using development compose files\"
                docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
            else
                echo \"🔧 Using base compose configuration\"
                docker compose up -d
            fi
            
            echo \"⏳ Waiting for services to start...\"
            sleep 30
            
            # Check service status
            echo \"📊 Service status:\"
            docker compose ps
            
            # Check nginx specifically
            echo \"📋 Nginx container logs:\"
            docker logs fks_nginx --tail 10 || echo \"Nginx container not found or not running\"
            
            # Check if services are responding
            echo \"🔍 Testing service connectivity:\"
            
            # Test API
            if curl -f http://localhost:8000/health 2>/dev/null; then
                echo \"✅ API service is responding\"
            else
                echo \"⚠️ API service not responding yet\"
            fi
            
            # Test Web
            if curl -f http://localhost:3000 2>/dev/null; then
                echo \"✅ Web service is responding\"
            else
                echo \"⚠️ Web service not responding yet\"
            fi
            
            # Test Nginx
            if curl -f http://localhost:80 2>/dev/null; then
                echo \"✅ Nginx service is responding\"
            else
                echo \"⚠️ Nginx service not responding yet\"
            fi
        '
    " "Start services with development configuration"
    
    # Step 5: Final status check
    log "🔧 Step 5: Final status check..."
    execute_ssh "
        echo '📊 Final deployment status:'
        
        cd /home/fks_user/fks
        
        sudo -u fks_user bash -c '
            echo \"=== Docker Containers ===\"
            docker ps --format \"table {{.Names}}\\t{{.Status}}\\t{{.Ports}}\"
            
            echo \"\"
            echo \"=== Docker Compose Services ===\"
            docker compose ps
            
            echo \"\"
            echo \"=== Service Health ===\"
            
            # Check each service
            for service in postgres redis api web worker data; do
                if docker compose ps \$service | grep -q \"Up\"; then
                    echo \"✅ \$service: Running\"
                else
                    echo \"❌ \$service: Not running\"
                fi
            done
            
            # Check nginx separately
            if docker compose ps nginx | grep -q \"Up\"; then
                echo \"✅ nginx: Running\"
            else
                echo \"❌ nginx: Not running\"
                echo \"📋 Nginx logs:\"
                docker logs fks_nginx --tail 20 || echo \"No nginx logs available\"
            fi
        '
    " "Final status check"
    
    log "✅ Development deployment fix completed!"
    log "🌐 Services should be available at:"
    log "  - Web Interface: http://$TARGET_HOST:3000"
    log "  - API: http://$TARGET_HOST:8000"
    log "  - Data Service: http://$TARGET_HOST:9001"
    log "  - Main Site (via nginx): http://$TARGET_HOST"
    log ""
    log "💡 If nginx is still having issues, the other services should work directly"
    log "💡 Use 'docker logs fks_nginx' to check nginx-specific issues"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
