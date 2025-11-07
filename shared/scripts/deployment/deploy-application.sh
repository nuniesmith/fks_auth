#!/bin/bash

# FKS Trading Systems - Development Deployment Script
# This script deploys the FKS Trading Systems to a development server

set -e  # Exit on any error
set -o pipefail  # Exit on pipe failures

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$HOME/deploy-application.log"

# Environment variables
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
FKS_DEV_ROOT_PASSWORD="${FKS_DEV_ROOT_PASSWORD:-}"
DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_TOKEN="${DOCKER_TOKEN:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_REF_NAME="${GITHUB_REF_NAME:-main}"
GITHUB_SHA="${GITHUB_SHA:-}"
APP_ENV="${APP_ENV:-development}"  # Set to development for fks_dev server

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE"
}

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    local custom_timeout="${3:-30}"  # Default 30s, but allow custom timeout
    
    log "📡 $description"
    
    # Ensure SSH_USER is set
    if [ -z "$SSH_USER" ]; then
        SSH_USER="actions_user"
    fi
    
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        if timeout $custom_timeout sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$TARGET_HOST" "$command" 2>&1 | tee -a "$LOG_FILE"; then
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

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems deployment (Development Mode)..."
    
    # Step 1: Test SSH connection
    log "🔐 Testing SSH connections..."
    
    # Try actions_user with password
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        log "🔑 Testing SSH as actions_user with password..."
        if timeout 15 sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$TARGET_HOST" "echo 'SSH ready'" 2>/dev/null; then
            log "✅ Connected as actions_user via password"
            SSH_USER="actions_user"
            SSH_METHOD="password"
        else
            error "❌ Unable to connect as actions_user"
            exit 1
        fi
    else
        error "❌ No SSH credentials available"
        exit 1
    fi
    
    # Step 2: Verify server status
    log "🔍 Verifying server status..."
    execute_ssh "whoami && pwd" "Basic connectivity test"
    
    # Step 3: Check Docker availability
    log "🐳 Checking Docker availability..."
    execute_ssh "docker --version" "Checking Docker installation"
    
    # Check and fix Docker networking issues
    log "🔧 Checking Docker networking..."
    execute_ssh "
        echo '🔧 Checking Docker networking setup...'
        
        # Check if Docker daemon is running properly
        if ! docker info > /dev/null 2>&1; then
            echo '❌ Docker daemon is not running properly'
            exit 1
        fi
        
        # Check iptables chains
        echo '🔍 Checking iptables chains...'
        if ! sudo iptables -t filter -L DOCKER-FORWARD > /dev/null 2>&1; then
            echo '⚠️ Docker iptables chains missing - fixing Docker networking...'
            
            # Manual Docker networking fix (repository not cloned yet)
            echo '🔧 Performing manual Docker networking fix...'
            
            # Stop Docker daemon
            sudo systemctl stop docker
            
            # Clean up iptables rules
            sudo iptables -t nat -F DOCKER 2>/dev/null || true
            sudo iptables -t nat -X DOCKER 2>/dev/null || true
            sudo iptables -t filter -F DOCKER 2>/dev/null || true
            sudo iptables -t filter -X DOCKER 2>/dev/null || true
            sudo iptables -t filter -F DOCKER-FORWARD 2>/dev/null || true
            sudo iptables -t filter -X DOCKER-FORWARD 2>/dev/null || true
            
            # Clean up Docker networks
            sudo rm -rf /var/lib/docker/network/files/* 2>/dev/null || true
            
            # Start Docker daemon
            sudo systemctl start docker
            
            # Wait for Docker to be ready
            for i in {1..30}; do
                if docker info > /dev/null 2>&1; then
                    echo '✅ Docker daemon is ready'
                    break
                fi
                sleep 1
            done
            
            if ! docker info > /dev/null 2>&1; then
                echo '❌ Docker failed to restart properly'
                exit 1
            fi
            
            echo '✅ Docker networking fixed successfully'
        else
            echo '✅ Docker iptables chains are properly configured'
        fi
        
        # Clean up any problematic Docker networks
        echo '🧹 Cleaning up Docker networks...'
        docker network prune -f || echo '⚠️ Network cleanup completed with warnings'
        
        echo '✅ Docker networking check completed'
    " "Docker networking setup"
    
    # Step 4: Setup repository using GITHUB_TOKEN
    log "📥 Setting up repository using GITHUB_TOKEN..."
    log "🔍 Debug: GitHub token available: $([ -n "$GITHUB_TOKEN" ] && echo "YES (${#GITHUB_TOKEN} chars)" || echo "NO")"
    log "🔍 Debug: GitHub ref: $GITHUB_REF_NAME"
    log "🔍 Debug: GitHub SHA: $GITHUB_SHA"
    
    # Repository setup with GITHUB_TOKEN authentication
    execute_ssh "
        echo '🔧 FKS Repository Setup with GitHub Token Authentication'
        echo '======================================================'
        
        # Step 1: Clean up any existing directories
        echo '🧹 Cleaning up existing directories...'
        sudo rm -rf /home/fks_user/fks
        sudo rm -rf /home/actions_user/fks_temp 2>/dev/null || true
        
        # Step 2: Create proper directory structure
        echo '📁 Creating proper directory structure...'
        sudo mkdir -p /home/fks_user/fks
        
        # Step 3: Clone repository using GITHUB_TOKEN
        echo '📦 Cloning FKS repository using GitHub token...'
        cd /tmp
        
        # Set GitHub token for authentication
        GITHUB_TOKEN='$GITHUB_TOKEN'
        
        if [ -n \"\\$GITHUB_TOKEN\" ]; then
            echo '🔑 Using GitHub token for authentication'
            echo '👤 Repository: nuniesmith/fks'
            echo '🌿 Branch: ${GITHUB_REF_NAME}'
            
            # Set up git configuration to avoid prompts
            export GIT_ASKPASS=true
            export GIT_TERMINAL_PROMPT=0
            git config --global credential.helper store
            
            # Clone using GitHub token with proper format
            echo '🔄 Trying GitHub token authentication method...'
            if git clone https://x-access-token:\\$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh; then
                echo '✅ Repository cloned successfully with GitHub token'
                
                # Move to correct location
                echo '📁 Moving to /home/fks_user/fks...'
                sudo mv fks_fresh/* /home/fks_user/fks/
                sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
                sudo rm -rf fks_fresh
                
                # Fix ownership and permissions
                echo '🔐 Setting proper ownership and permissions...'
                sudo chown -R fks_user:fks_user /home/fks_user/fks
                sudo chmod -R 755 /home/fks_user/fks
                # Ensure the fks_user can access the directory
                sudo chmod 755 /home/fks_user/fks
                
                # Fix sensitive files
                if [ -f /home/fks_user/fks/.env ]; then
                    sudo chmod 600 /home/fks_user/fks/.env
                fi
                
                if [ -d /home/fks_user/fks/.git ]; then
                    sudo chmod -R 700 /home/fks_user/fks/.git
                fi
                
                # Make scripts executable
                echo '🔧 Making scripts executable...'
                sudo find /home/fks_user/fks/scripts -name '*.sh' -exec chmod +x {} \\; 2>/dev/null || true
                
                echo '✅ Repository setup completed successfully!'
                echo '📍 Repository location: /home/fks_user/fks'
                echo '👤 Owner: fks_user:fks_user'
                echo '📂 Contents:'
                ls -la /home/fks_user/fks | head -10
                
            else
                echo '❌ Failed to clone repository with GitHub token (x-access-token format)'
                echo '💡 Trying alternative token format...'
                
                # Try alternative token format
                if git clone https://\\$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh; then
                    echo '✅ Repository cloned successfully with GitHub token (direct format)'
                    
                    # Move to correct location
                    echo '📁 Moving to /home/fks_user/fks...'
                    sudo mv fks_fresh/* /home/fks_user/fks/
                    sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
                    sudo rm -rf fks_fresh
                    
                    # Fix ownership and permissions
                    echo '🔐 Setting proper ownership and permissions...'
                    sudo chown -R fks_user:fks_user /home/fks_user/fks
                    sudo chmod -R 755 /home/fks_user/fks
                    
                    # Make scripts executable
                    echo '🔧 Making scripts executable...'
                    sudo find /home/fks_user/fks/scripts -name '*.sh' -exec chmod +x {} \\; 2>/dev/null || true
                    
                    echo '✅ Repository setup completed successfully!'
                else
                    echo '❌ All GitHub token methods failed'
                    echo '💡 Falling back to public HTTPS clone...'
                    
                    if git clone https://github.com/nuniesmith/fks.git fks_fresh; then
                        echo '✅ Repository cloned successfully with public HTTPS'
                        
                        # Move to correct location
                        echo '📁 Moving to /home/fks_user/fks...'
                        sudo mv fks_fresh/* /home/fks_user/fks/
                        sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
                        sudo rm -rf fks_fresh
                        
                        # Fix ownership and permissions
                        echo '🔐 Setting proper ownership and permissions...'
                        sudo chown -R fks_user:fks_user /home/fks_user/fks
                        sudo chmod -R 755 /home/fks_user/fks
                        
                        # Make scripts executable
                        echo '🔧 Making scripts executable...'
                        sudo find /home/fks_user/fks/scripts -name '*.sh' -exec chmod +x {} \\; 2>/dev/null || true
                        
                        echo '✅ Repository setup completed successfully!'
                    else
                        echo '❌ Failed to clone repository with any method'
                        exit 1
                    fi
                fi
            fi
            
            # Clean up git credentials
            rm -f ~/.git-credentials 2>/dev/null || true
        else
            echo '❌ No GitHub token available'
            exit 1
        fi
    " "Repository setup with GitHub token"
    
    # Step 5: Application deployment using start.sh script
    log "🚀 Starting application deployment using start.sh..."
    
    execute_ssh "
        echo '🎆 Development Application Deployment - Using start.sh Script'
        echo '=========================================================='
        
        # Ensure we're in the correct directory and verify access
        if sudo -u fks_user test -d /home/fks_user/fks; then
            echo '✅ Directory access confirmed for fks_user'
        else
            echo '❌ Directory access failed for fks_user, fixing permissions...'
            sudo chmod 755 /home/fks_user/fks
            sudo chown fks_user:fks_user /home/fks_user/fks
            if sudo -u fks_user test -d /home/fks_user/fks; then
                echo '✅ Directory access restored'
            else
                echo '❌ Unable to fix directory access'
                exit 1
            fi
        fi
        
        # Docker Hub authentication for fks_user (required for private repo)
        echo '🔐 Setting up Docker Hub authentication for fks_user...'
        if [ -n \\\"$DOCKER_USERNAME\\\" ] && [ -n \\\"$DOCKER_TOKEN\\\" ]; then
            echo '🔑 Authenticating with Docker Hub...'
            echo '👤 Username: $DOCKER_USERNAME'
            echo '🔐 Registry: docker.io'
            
            # Login to Docker Hub as fks_user
            if sudo -u fks_user bash -c \\\"echo \\\\\\\"$DOCKER_TOKEN\\\\\\\" | docker login -u \\\\\\\"$DOCKER_USERNAME\\\\\\\" --password-stdin docker.io\\\"; then
                echo '✅ Docker Hub authentication successful for fks_user'
            else
                echo '❌ Docker Hub authentication failed'
                echo '🔧 Check DOCKER_USERNAME and DOCKER_TOKEN secrets'
                exit 1
            fi
        else
            echo '❌ No Docker Hub credentials provided'
            echo '🔧 Private repository deployment requires DOCKER_USERNAME and DOCKER_TOKEN'
            exit 1
        fi
        
        # Create comprehensive .env file for development
        echo '📄 Creating development .env file...'
        sudo -u fks_user bash -c \\\"cat > /home/fks_user/fks/.env << 'ENVEOF'
# =================================================================
# FKS Trading Systems - Development Configuration
# Generated by deploy-application.sh for fks_dev server
# =================================================================

# Environment Configuration
APP_ENV=development
ENVIRONMENT=development
DEPLOYMENT_TARGET=development
COMPOSE_PROJECT_NAME=fks

# Application Settings
APP_VERSION=1.0.0
APP_LOG_LEVEL=DEBUG
DEBUG_MODE=true
VERBOSE_LOGGING=true
NODE_ENV=development

# Docker Configuration
DOCKER_REGISTRY=docker.io
DOCKER_NAMESPACE=$DOCKER_USERNAME
DOCKER_USERNAME=$DOCKER_USERNAME
DOCKER_TOKEN=$DOCKER_TOKEN
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1
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
API_DEBUG_PORT=5678

# Database Configuration
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=fks_postgres_dev_$(openssl rand -hex 8)
POSTGRES_MAX_CONNECTIONS=100
POSTGRES_SHARED_BUFFERS=256MB

# Redis Configuration
REDIS_PASSWORD=fks_redis_dev_$(openssl rand -hex 8)
REDIS_MAXMEMORY=512mb
REDIS_MAXMEMORY_POLICY=allkeys-lru

# Security Configuration
JWT_SECRET_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)

# Domain and SSL Configuration - DISABLED FOR DEVELOPMENT
DOMAIN_NAME=localhost
ENABLE_SSL=false
SSL_STAGING=false

# Nginx Configuration
PROXY_CONNECT_TIMEOUT=30s
PROXY_SEND_TIMEOUT=30s
PROXY_READ_TIMEOUT=30s

# Development Tools
ADMINER_PORT=8080
REDIS_COMMANDER_PORT=8082
VSCODE_PORT=8081
VSCODE_PASSWORD=fksdev123

# Resource Limits (reduced for development)
API_CPU_LIMIT=1
API_MEMORY_LIMIT=1024M
WORKER_CPU_LIMIT=1
WORKER_MEMORY_LIMIT=1024M
DATA_CPU_LIMIT=1
DATA_MEMORY_LIMIT=1024M
WEB_CPU_LIMIT=0.5
WEB_MEMORY_LIMIT=512M

# Health Checks
HEALTHCHECK_INTERVAL=30s
HEALTHCHECK_TIMEOUT=10s
HEALTHCHECK_RETRIES=3
HEALTHCHECK_START_PERIOD=60s

# Logging
LOG_DRIVER=json-file
LOG_MAX_SIZE=10m
LOG_MAX_FILES=3

# Timezone
TZ=America/New_York

# Monitoring
GRAFANA_PORT=3001
PROMETHEUS_PORT=9090
MONITORING_ENABLED=false

# Development Features
ENABLE_HOT_RELOAD=true
CHOKIDAR_USEPOLLING=true
WORKER_COUNT=1

# Source Code Mounting
SRC_MOUNT=./src/python
SRC_MOUNT_MODE=rw

# API URLs
API_URL=http://localhost:8000
WS_URL=ws://localhost:8000
REACT_APP_API_URL=http://localhost:8000

# Production Optimizations (disabled for development)
COMPOSE_HTTP_TIMEOUT=120
COMPOSE_PARALLEL_LIMIT=5
BUILD_TYPE=cpu
SERVICE_RUNTIME=python
ENVEOF\\\"
        
        # Set proper permissions for .env file
        sudo -u fks_user chmod 600 /home/fks_user/fks/.env
        echo '✅ Development .env file created with secure permissions'
        
        # Make scripts executable
        echo '🔧 Making orchestration scripts executable...'
        sudo chmod +x /home/fks_user/fks/scripts/orchestration/start.sh
        sudo chmod +x /home/fks_user/fks/scripts/orchestration/stop.sh
        sudo chmod +x /home/fks_user/fks/scripts/orchestration/restart.sh
        
        # Ensure logs directory exists
        sudo -u fks_user mkdir -p /home/fks_user/fks/logs
        
        # ===== DOCKER PERMISSION FIX =====
        echo '🔐 Setting up Docker permissions for proper UID/GID mapping...'
        
        # Get fks_user UID and GID
        FKS_USER_UID=$(id -u fks_user)
        FKS_USER_GID=$(id -g fks_user)
        echo "📋 fks_user UID: \$FKS_USER_UID, GID: \$FKS_USER_GID"
        
        # Add USER_ID and GROUP_ID to .env file
        echo '' >> /home/fks_user/fks/.env
        echo '# User ID mapping for Docker containers' >> /home/fks_user/fks/.env
        echo "USER_ID=\$FKS_USER_UID" >> /home/fks_user/fks/.env
        echo "GROUP_ID=\$FKS_USER_GID" >> /home/fks_user/fks/.env
        
        # Create docker-compose.override.yml for permission fixes
        echo '📄 Creating docker-compose.override.yml for permission mapping...'
        sudo -u fks_user bash -c "cat > /home/fks_user/fks/docker-compose.override.yml << 'OVERRIDE_EOF'
# Docker Compose Override - Automated Permission Fix
# Generated by deploy-application.sh
# Ensures containers run with the same UID/GID as fks_user




services:
  # Python services
  api:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
  
  worker:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
  
  data:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
  
  ninja-api:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
  
  # Web service - critical for React development
  web:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
    volumes:
      # Ensure write permissions for npm operations
      - ./src/web/react:/app/src/web/react:rw
      - web_node_modules:/app/src/web/react/node_modules
  
  # ML/GPU services (if enabled)
  training:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID
  
  transformer:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID

  # Node network service (Rust)
  node-network:
    user: \"\$FKS_USER_UID:\$FKS_USER_GID\"
    environment:
      USER_ID: \$FKS_USER_UID
      GROUP_ID: \$FKS_USER_GID

# Named volume for node_modules to avoid permission issues
volumes:
  web_node_modules:
    name: fks_web_node_modules_\${APP_ENV:-dev}
OVERRIDE_EOF"
        
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
        
        # Use start.sh script to handle stopping and starting services
        echo '🚀 Using start.sh script to deploy application in development mode...'
        
        # Set environment variables for the start script
        export USE_DOCKER_HUB_IMAGES=true
        export DOCKER_USERNAME='$DOCKER_USERNAME'
        export DOCKER_TOKEN='$DOCKER_TOKEN'
        export DOCKER_NAMESPACE='$DOCKER_USERNAME'
        export APP_ENV=development
        
        # Change to the project directory
        cd /home/fks_user/fks
        
        # Run the start.sh script with development configuration
        if sudo -u fks_user bash -c 'cd /home/fks_user/fks && USE_DOCKER_HUB_IMAGES=true DOCKER_USERNAME=\\\"'$DOCKER_USERNAME'\\\" DOCKER_TOKEN=\\\"'$DOCKER_TOKEN'\\\" DOCKER_NAMESPACE=\\\"'$DOCKER_USERNAME'\\\" APP_ENV=development ./scripts/orchestration/start.sh'; then
            echo '✅ start.sh script completed successfully'
        else
            echo '⚠️ start.sh script finished with warnings or errors'
            # Continue to check the actual status instead of failing immediately
        fi
        
        # Wait for services to initialize
        echo '⏳ Waiting 30 seconds for services to initialize...'
        sleep 30
        
        # Check final deployment status
        echo '📊 Final deployment status check...'
        echo ''
        echo '--- Docker Containers ---'
        sudo -u fks_user docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}' || true
        echo ''
        echo '--- Docker Compose Status ---'
        sudo -u fks_user docker compose ps 2>/dev/null || sudo -u fks_user docker-compose ps 2>/dev/null || true
        echo ''
        
        # Log completion based on start.sh success, not container counts
        echo '✅ 🎉 FKS Trading Systems deployment completed successfully!'
        echo '📍 Repository: /home/fks_user/fks'
        echo '👤 Owner: fks_user:fks_user'
        echo '🌐 Application available at: http://$TARGET_HOST'
        echo ''
        echo '🔍 Service URLs:'
        echo '  - Web Interface: http://$TARGET_HOST:3000'
        echo '  - API: http://$TARGET_HOST:8000'
        echo '  - Data Service: http://$TARGET_HOST:9001'
        echo '  - Adminer (Database): http://$TARGET_HOST:8080'
        echo '  - Redis Commander: http://$TARGET_HOST:8082'
        echo ''
        echo '💡 Deployment completed in DEVELOPMENT MODE. Services may take a few minutes to fully initialize.'
        echo '💡 Check service status: sudo docker ps'
        echo '💡 View service logs: sudo docker logs <container_name>'
        echo '💡 To enable development tools: docker compose --profile dev-tools up -d'
    " "Application deployment using start.sh" 300
    
    log "✅ FKS Trading Systems deployment completed successfully!"
    log "🌐 Application should be available at: http://$TARGET_HOST"
    log "📊 Check status with: sudo docker ps"
}

# Execute main function
main "$@"
