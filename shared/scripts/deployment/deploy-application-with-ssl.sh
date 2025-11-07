#!/bin/bash

# FKS Trading Systems - Enhanced Deployment Script with SSL Support
# This script deploys the FKS Trading Systems with optional SSL certificate generation

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
APP_ENV="${APP_ENV:-production}"

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
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    local custom_timeout="${3:-60}"  # Default 60s for SSL operations
    
    log "📡 $description"
    
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

# Function to determine server IP
get_server_ip() {
    local ip=""
    
    # Try to get server IP from deployment logs or DNS
    if command -v dig > /dev/null 2>&1; then
        ip=$(dig +short "$TARGET_HOST" | head -n1)
    elif command -v nslookup > /dev/null 2>&1; then
        ip=$(nslookup "$TARGET_HOST" | grep -A1 "Name:" | grep "Address:" | cut -d: -f2 | tr -d ' ')
    fi
    
    # If we can't resolve, try to get from SSH connection
    if [ -z "$ip" ]; then
        ip=$(execute_ssh "curl -s ifconfig.me || curl -s icanhazip.com || echo 'unknown'" "Get server IP" 10 | tail -n1)
    fi
    
    echo "$ip"
}

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems deployment..."
    log "📋 Configuration:"
    log "  - Environment: $APP_ENV"
    log "  - Target: $TARGET_HOST"
    log "  - Domain: $DOMAIN_NAME"
    log "  - SSL Enabled: $ENABLE_SSL"
    log "  - SSL Staging: $SSL_STAGING"
    
    # Step 1: Test SSH connection
    log "🔐 Testing SSH connections..."
    
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
    
    # Step 4: Setup SSL certificates if enabled
    if [[ "$ENABLE_SSL" == "true" ]]; then
        log "🔐 Setting up SSL certificates with Cloudflare + Let's Encrypt..."
        execute_ssh "
            # Download and run the complete SSL setup script
            cd /home/fks_user/fks
            
            # Check if SSL setup script exists
            if [[ -f 'scripts/deployment/setup-ssl-complete.sh' ]]; then
                echo '🔐 Running FKS SSL setup script...'
                
                # Export required environment variables
                export DOMAIN_NAME='$DOMAIN_NAME'
                export ADMIN_EMAIL='$ADMIN_EMAIL'
                export CLOUDFLARE_API_TOKEN='$CLOUDFLARE_API_TOKEN'
                export CLOUDFLARE_ZONE_ID='$CLOUDFLARE_ZONE_ID'
                export SSL_STAGING='$SSL_STAGING'
                export WEB_PORT='3001'
                export API_PORT='4000'
                
                # Make script executable and run it
                chmod +x scripts/deployment/setup-ssl-complete.sh
                sudo -E scripts/deployment/setup-ssl-complete.sh
                
                if [[ \$? -eq 0 ]]; then
                    echo '✅ SSL setup completed successfully'
                else
                    echo '❌ SSL setup failed'
                    exit 1
                fi
            else
                echo '❌ SSL setup script not found'
                exit 1
            fi
        " "SSL Certificate Setup" 300
    else
        log "⚠️ SSL setup skipped (ENABLE_SSL is not true)"
    fi
    
    # Step 5: Fix Docker networking if needed
    log "🔧 Checking Docker networking..."
    execute_ssh "
        echo '🔧 Checking Docker networking setup...'
        
        if ! docker info > /dev/null 2>&1; then
            echo '❌ Docker daemon is not running properly'
            exit 1
        fi
        
        # Check iptables chains
        echo '🔍 Checking iptables chains...'
        if ! sudo iptables -t filter -L DOCKER-FORWARD > /dev/null 2>&1; then
            echo '⚠️ Docker iptables chains missing - fixing Docker networking...'
            
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
    
    # Step 5: Setup repository
    log "📥 Setting up repository using GITHUB_TOKEN..."
    execute_ssh "
        echo '🔧 FKS Repository Setup with GitHub Token Authentication'
        echo '======================================================'
        
        # Clean up any existing directories
        echo '🧹 Cleaning up existing directories...'
        sudo rm -rf /home/fks_user/fks
        sudo rm -rf /home/actions_user/fks_temp 2>/dev/null || true
        
        # Create proper directory structure
        echo '📁 Creating proper directory structure...'
        sudo mkdir -p /home/fks_user/fks
        
        # Clone repository using GITHUB_TOKEN
        echo '📦 Cloning FKS repository using GitHub token...'
        cd /tmp
        
        GITHUB_TOKEN='$GITHUB_TOKEN'
        
        if [ -n \"\\$GITHUB_TOKEN\" ]; then
            echo '🔑 Using GitHub token for authentication'
            echo '👤 Repository: nuniesmith/fks'
            echo '🌿 Branch: ${GITHUB_REF_NAME}'
            
            # Set up git configuration
            export GIT_ASKPASS=true
            export GIT_TERMINAL_PROMPT=0
            git config --global credential.helper store
            
            # Clone using GitHub token
            echo '🔄 Cloning repository...'
            if git clone https://x-access-token:\\$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh; then
                echo '✅ Repository cloned successfully'
                
                # Move to correct location
                echo '📁 Moving to /home/fks_user/fks...'
                sudo mv fks_fresh/* /home/fks_user/fks/
                sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
                sudo rm -rf fks_fresh
                
                # Fix ownership and permissions
                echo '🔐 Setting proper ownership and permissions...'
                sudo chown -R fks_user:fks_user /home/fks_user/fks
                sudo chmod -R 755 /home/fks_user/fks
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
            else
                echo '❌ Failed to clone repository'
                exit 1
            fi
            
            # Clean up git credentials
            rm -f ~/.git-credentials 2>/dev/null || true
        else
            echo '❌ No GitHub token available'
            exit 1
        fi
    " "Repository setup with GitHub token"
    
    # Step 6: SSL Certificate Generation (if enabled)
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Setting up SSL certificates with Let's Encrypt and Cloudflare..."
        
        # Get server IP
        SERVER_IP=$(get_server_ip)
        if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "unknown" ]; then
            warn "⚠️ Could not determine server IP, using target host for SSL setup"
            SERVER_IP="$TARGET_HOST"
        fi
        
        log "🌐 Server IP: $SERVER_IP"
        
        execute_ssh "
            echo '🔐 Setting up SSL certificates with Let\\'s Encrypt and Cloudflare...'
            echo '=============================================================='
            
            # Install required packages
            echo '📦 Installing required packages...'
            if ! command -v certbot > /dev/null 2>&1; then
                echo '📥 Installing certbot and cloudflare plugin...'
                sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare || {
                    # Try with AUR if standard packages fail
                    echo '🔄 Trying AUR packages...'
                    yay -S --noconfirm certbot certbot-dns-cloudflare || {
                        echo '❌ Failed to install certbot packages'
                        exit 1
                    }
                }
            fi
            
            if ! command -v jq > /dev/null 2>&1; then
                echo '📥 Installing jq...'
                sudo pacman -Sy --noconfirm jq
            fi
            
            # Update DNS A records
            echo '🌐 Updating DNS A records for $DOMAIN_NAME...'
            
            # Function to update DNS record
            update_dns_record() {
                local record_name=\"\$1\"
                local record_type=\"\$2\"
                local record_content=\"\$3\"
                
                echo \"🔍 Checking DNS record: \$record_name (\$record_type)\"
                
                # Get existing DNS records
                EXISTING_RECORD=\$(curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=\$record_type&name=\$record_name\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\")
                
                if ! echo \"\$EXISTING_RECORD\" | jq -e .success > /dev/null; then
                    echo \"❌ Failed to fetch DNS records for \$record_name\"
                    return 1
                fi
                
                RECORD_COUNT=\$(echo \"\$EXISTING_RECORD\" | jq '.result | length')
                CURRENT_IP=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].content // empty')
                
                if [[ \"\$RECORD_COUNT\" -eq 0 ]]; then
                    # Create new record
                    echo \"📝 Creating new \$record_type record for \$record_name...\"
                    DNS_RESPONSE=\$(curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records\" \\
                        -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                        -H \"Content-Type: application/json\" \\
                        --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                    
                    if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                        echo \"✅ Created \$record_type record for \$record_name\"
                    else
                        echo \"❌ Failed to create \$record_type record for \$record_name\"
                        return 1
                    fi
                elif [[ \"\$CURRENT_IP\" != \"\$record_content\" ]]; then
                    # Update existing record
                    RECORD_ID=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].id')
                    echo \"🔄 Updating \$record_type record for \$record_name (was: \$CURRENT_IP, now: \$record_content)...\"
                    DNS_RESPONSE=\$(curl -s -X PUT \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/\$RECORD_ID\" \\
                        -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                        -H \"Content-Type: application/json\" \\
                        --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                    
                    if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                        echo \"✅ Updated \$record_type record for \$record_name\"
                    else
                        echo \"❌ Failed to update \$record_type record for \$record_name\"
                        return 1
                    fi
                else
                    echo \"✅ \$record_type record for \$record_name is already correct: \$CURRENT_IP\"
                fi
            }
            
            # Update DNS records
            update_dns_record \"$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
            update_dns_record \"www.$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
            
            # Create Cloudflare credentials file for certbot
            echo '🔐 Setting up Cloudflare credentials for certbot...'
            CLOUDFLARE_CREDS_FILE=\"/root/.cloudflare-credentials\"
            sudo bash -c \"cat > \\\$CLOUDFLARE_CREDS_FILE << 'CFEOF'
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
CFEOF\"
            sudo chmod 600 \"\$CLOUDFLARE_CREDS_FILE\"
            
            # Wait for DNS propagation
            echo '⏳ Waiting for DNS propagation...'
            sleep 60
            
            # Generate SSL certificate
            echo '🔐 Generating SSL certificate with Let\\'s Encrypt...'
            
            STAGING_FLAG=\"\"
            if [ \"$SSL_STAGING\" = \"true\" ]; then
                STAGING_FLAG=\"--staging\"
                echo \"⚠️ Using Let's Encrypt staging environment\"
            fi
            
            # Run certbot with Cloudflare DNS challenge
            if sudo certbot certonly \\
                --dns-cloudflare \\
                --dns-cloudflare-credentials \"\$CLOUDFLARE_CREDS_FILE\" \\
                --email \"$ADMIN_EMAIL\" \\
                --agree-tos \\
                --non-interactive \\
                --expand \\
                \$STAGING_FLAG \\
                -d \"$DOMAIN_NAME\" \\
                -d \"www.$DOMAIN_NAME\"; then
                echo '✅ SSL certificate generated successfully'
            else
                echo '❌ Failed to generate SSL certificate'
                exit 1
            fi
            
            # Clean up credentials file
            sudo rm -f \"\$CLOUDFLARE_CREDS_FILE\"
            
            # Set up certificate auto-renewal
            echo '🔄 Setting up automatic certificate renewal...'
            CRON_JOB=\"0 2 * * 0 /usr/bin/certbot renew --quiet && /usr/bin/systemctl reload nginx\"
            (sudo crontab -l 2>/dev/null; echo \"\$CRON_JOB\") | sudo crontab -
            
            echo '✅ SSL certificates configured successfully'
        " "SSL certificate setup" 120
    else
        warn "⚠️ SSL setup skipped (ENABLE_SSL=$ENABLE_SSL, tokens available: $([ -n "$CLOUDFLARE_API_TOKEN" ] && echo "yes" || echo "no"))"
    fi
    
    # Step 7: Application deployment
    log "🚀 Starting application deployment..."
    
    execute_ssh "
        echo '🎆 Application Deployment with SSL Support'
        echo '======================================='
        
        # Navigate to project directory
        cd /home/fks_user/fks
        
        # Docker Hub authentication
        echo '🔐 Setting up Docker Hub authentication...'
        if [ -n \\\"$DOCKER_USERNAME\\\" ] && [ -n \\\"$DOCKER_TOKEN\\\" ]; then
            if sudo -u fks_user bash -c \\\"echo \\\\\\\"$DOCKER_TOKEN\\\\\\\" | docker login -u \\\\\\\"$DOCKER_USERNAME\\\\\\\" --password-stdin docker.io\\\"; then
                echo '✅ Docker Hub authentication successful'
            else
                echo '❌ Docker Hub authentication failed'
                exit 1
            fi
        else
            echo '❌ No Docker Hub credentials provided'
            exit 1
        fi
        
        # Create environment file
        echo '📄 Creating environment file...'
        sudo -u fks_user bash -c \\\"cat > .env << 'ENVEOF'
# FKS Trading Systems - $([ '$APP_ENV' = 'development' ] && echo 'Development' || echo 'Production') Configuration
COMPOSE_PROJECT_NAME=fks
APP_ENV=$APP_ENV
ENVIRONMENT=$APP_ENV
NODE_ENV=$APP_ENV

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

# Database Configuration
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=fks_postgres_$([ '$APP_ENV' = 'development' ] && echo 'dev' || echo 'prod')_\$(openssl rand -hex 8)
POSTGRES_MAX_CONNECTIONS=100
POSTGRES_SHARED_BUFFERS=256MB

# Redis Configuration
REDIS_PASSWORD=fks_redis_$([ '$APP_ENV' = 'development' ] && echo 'dev' || echo 'prod')_\$(openssl rand -hex 8)
REDIS_MAXMEMORY=512mb
REDIS_MAXMEMORY_POLICY=allkeys-lru

# Security Configuration
JWT_SECRET_KEY=\$(openssl rand -hex 32)
SECRET_KEY=\$(openssl rand -hex 32)

# Domain and SSL Configuration
DOMAIN_NAME=$DOMAIN_NAME
ENABLE_SSL=$ENABLE_SSL
SSL_STAGING=$SSL_STAGING

# Nginx Configuration
API_HOST=api
API_PORT=8000
WEB_HOST=web
WEB_PORT=3000
PROXY_CONNECT_TIMEOUT=30s
PROXY_SEND_TIMEOUT=30s
PROXY_READ_TIMEOUT=30s

# Application URLs
API_URL=http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:8000
WS_URL=ws$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:8000
REACT_APP_API_URL=http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:8000

# Debug and Development
DEBUG_MODE=$([ '$APP_ENV' = 'development' ] && echo 'true' || echo 'false')
APP_LOG_LEVEL=$([ '$APP_ENV' = 'development' ] && echo 'DEBUG' || echo 'INFO')
VERBOSE_LOGGING=$([ '$APP_ENV' = 'development' ] && echo 'true' || echo 'false')

# Resource Limits
API_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1' || echo '2')
API_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1024M' || echo '2048M')
WEB_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '0.5' || echo '1')
WEB_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '512M' || echo '1024M')
WORKER_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1' || echo '2')
WORKER_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1024M' || echo '2048M')
DATA_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1' || echo '2')
DATA_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1024M' || echo '2048M')

# Health Checks
HEALTHCHECK_INTERVAL=30s
HEALTHCHECK_TIMEOUT=10s
HEALTHCHECK_RETRIES=3
HEALTHCHECK_START_PERIOD=60s

# Logging
LOG_DRIVER=json-file
LOG_MAX_SIZE=$([ '$APP_ENV' = 'development' ] && echo '10m' || echo '100m')
LOG_MAX_FILES=3

# Timezone
TZ=America/New_York

# Monitoring
GRAFANA_PORT=3001
PROMETHEUS_PORT=9090
MONITORING_ENABLED=$([ '$APP_ENV' = 'development' ] && echo 'false' || echo 'true')

# Development Tools (only if development)
$([ '$APP_ENV' = 'development' ] && cat << 'DEVTOOLS'
ADMINER_PORT=8080
REDIS_COMMANDER_PORT=8082
VSCODE_PORT=8081
CHOKIDAR_USEPOLLING=true
ENABLE_HOT_RELOAD=true
WORKER_COUNT=1
SRC_MOUNT=./src/python
SRC_MOUNT_MODE=rw
DEVTOOLS
)

# Production Optimizations
COMPOSE_HTTP_TIMEOUT=$([ '$APP_ENV' = 'development' ] && echo '120' || echo '300')
COMPOSE_PARALLEL_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '5' || echo '10')
BUILD_TYPE=cpu
SERVICE_RUNTIME=python
ENVEOF\\\"
        
        # Set proper permissions
        sudo -u fks_user chmod 600 .env
        echo '✅ Environment file created'
        
        # Make scripts executable
        echo '🔧 Making scripts executable...'
        sudo chmod +x scripts/orchestration/*.sh
        
        # Create logs directory
        sudo -u fks_user mkdir -p logs
        
        # Fix Docker iptables before starting services
        echo '🔧 Ensuring Docker iptables are properly configured...'
        sudo bash -c '
            # Check if Docker iptables chains exist
            if ! iptables -t filter -L DOCKER-FORWARD >/dev/null 2>&1; then
                echo "⚠️ Docker iptables chains missing - applying fix..."
                
                # Stop all containers
                docker stop \$(docker ps -aq) 2>/dev/null || true
                
                # Clean up any broken Docker iptables rules
                iptables -t nat -F DOCKER 2>/dev/null || true
                iptables -t nat -X DOCKER 2>/dev/null || true
                iptables -t filter -F DOCKER 2>/dev/null || true
                iptables -t filter -X DOCKER 2>/dev/null || true
                iptables -t filter -F DOCKER-FORWARD 2>/dev/null || true
                iptables -t filter -X DOCKER-FORWARD 2>/dev/null || true
                iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
                iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
                iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
                iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
                iptables -t filter -F DOCKER-USER 2>/dev/null || true
                iptables -t filter -X DOCKER-USER 2>/dev/null || true
                
                # Clean up Docker network state
                rm -rf /var/lib/docker/network/files/* 2>/dev/null || true
                
                # Restart Docker to recreate chains
                systemctl restart docker
                
                # Wait for Docker to be ready
                for i in {1..30}; do
                    if docker info >/dev/null 2>&1; then
                        echo "✅ Docker daemon is ready"
                        break
                    fi
                    sleep 1
                done
            else
                echo "✅ Docker iptables chains are properly configured"
            fi
        '
        
        # Start services
        echo '🚀 Starting services...'
        if sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            export \$(cat .env | xargs)
            
            # Stop any existing containers first
            echo \"🛑 Stopping any existing containers...\"
            docker compose down --remove-orphans || true
            
            # Clean up problematic networks
            echo \"🧹 Cleaning up Docker networks...\"
            docker network prune -f || true
            
            # Remove the fks_network if it exists
            docker network rm fks_network 2>/dev/null || true
            
            # Choose compose file based on environment
            if [ \"$APP_ENV\" = \"development\" ] && [ -f docker-compose.dev.yml ]; then
                echo \"🔧 Using development configuration\"
                docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate
            elif [ \"$APP_ENV\" = \"production\" ] && [ -f docker-compose.prod.yml ]; then
                echo \"🔧 Using production configuration\"
                docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
            else
                echo \"🔧 Using base configuration\"
                docker compose up -d --force-recreate
            fi
        '; then
            echo '✅ Services started successfully'
        else
            echo '⚠️ Service start completed with warnings'
        fi
        
        # Wait for services to initialize
        echo '⏳ Waiting for services to initialize...'
        sleep 30
        
        # Check final status
        echo '📊 Final deployment status:'
        echo '--- Docker Containers ---'
        sudo -u fks_user docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'
        echo ''
        echo '--- Docker Compose Services ---'
        sudo -u fks_user docker compose ps
        
        echo '✅ Application deployment completed!'
        echo '🌐 Application available at:'
        echo '  - Web Interface: http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:3000'
        echo '  - API: http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:8000'
        echo '  - Data Service: http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME:9001'
        echo '  - Main Site: http$([ '$ENABLE_SSL' = 'true' ] && echo 's' || echo '')://$DOMAIN_NAME'
        echo ''
        echo '💡 SSL Status: $([ '$ENABLE_SSL' = 'true' ] && echo 'Enabled' || echo 'Disabled')'
        echo '💡 Environment: $APP_ENV'
    " "Application deployment" 300
    
    log "✅ FKS Trading Systems deployment completed successfully!"
    log "🌐 Application should be available at: http$([ "$ENABLE_SSL" = "true" ] && echo 's' || echo '')://$DOMAIN_NAME"
    log "📊 Check status with: sudo docker ps"
    
    if [ "$ENABLE_SSL" = "true" ]; then
        log "🔐 SSL certificates are configured and active"
        log "📋 Certificate info: sudo certbot certificates"
        log "🔄 Test renewal: sudo certbot renew --dry-run"
    fi
}

# Execute main function
main "$@"
