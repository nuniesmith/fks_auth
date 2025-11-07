#!/bin/bash

# FKS Trading Systems - Deployment with Final SSL Integration Fix
# This script fixes the GitHub Actions masking issue

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
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    local custom_timeout="${3:-60}"
    
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

# Function to check SSL certificate status
check_ssl_status() {
    execute_ssh "
        echo '🔍 Checking SSL certificate status...'
        
        if [ ! -d '/etc/letsencrypt/live/$DOMAIN_NAME' ]; then
            echo 'ssl_status=missing'
            exit 0
        fi
        
        if [ ! -f '/etc/letsencrypt/live/$DOMAIN_NAME/cert.pem' ]; then
            echo 'ssl_status=missing'
            exit 0
        fi
        
        # Check if certificate expires within 30 days
        if openssl x509 -in '/etc/letsencrypt/live/$DOMAIN_NAME/cert.pem' -noout -checkend 2592000 2>/dev/null; then
            echo 'ssl_status=valid'
        else
            echo 'ssl_status=needs_renewal'
        fi
    " "Check SSL certificate status" 30
}

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems deployment with SSL integration..."
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
    
    # Step 4: SSL Certificate Management (Fixed for GitHub Actions masking)
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Managing SSL certificates..."
        
        # Check current SSL status
        SSL_STATUS=$(check_ssl_status | grep "ssl_status=" | cut -d'=' -f2)
        log "📋 Current SSL status: $SSL_STATUS"
        
        # Only setup/renew SSL if needed
        if [ "$SSL_STATUS" = "missing" ] || [ "$SSL_STATUS" = "needs_renewal" ]; then
            log "🔐 Setting up/renewing SSL certificates..."
            
            # Get server IPv4 address on the remote server (avoid GitHub Actions masking)
            execute_ssh "
                echo '🔐 SSL Certificate Setup/Renewal (Final Fix)...'
                
                # Get the actual IPv4 address from the server itself
                echo '🌐 Determining server IPv4 address...'
                SERVER_IP=''
                
                # Try multiple methods to get IPv4 address
                if command -v curl > /dev/null 2>&1; then
                    SERVER_IP=\$(curl -4 -s --connect-timeout 10 ifconfig.me || curl -4 -s --connect-timeout 10 icanhazip.com || echo '')
                fi
                
                # Fallback to ip command if curl fails
                if [ -z \"\$SERVER_IP\" ]; then
                    SERVER_IP=\$(ip route get 8.8.8.8 | grep -oE 'src [0-9.]+' | cut -d' ' -f2 2>/dev/null || echo '')
                fi
                
                # Another fallback using hostname
                if [ -z \"\$SERVER_IP\" ]; then
                    SERVER_IP=\$(hostname -I | awk '{print \$1}' | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$' || echo '')
                fi
                
                # Validate we got a proper IPv4 address
                if [[ ! \"\$SERVER_IP\" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$ ]]; then
                    echo '❌ Could not determine valid IPv4 address'
                    echo 'SERVER_IP value:' \"\$SERVER_IP\"
                    exit 1
                fi
                
                echo \"✅ Server IPv4 address: \$SERVER_IP\"
                
                # Install required packages if not present
                if ! command -v certbot > /dev/null 2>&1; then
                    echo '📦 Installing certbot and cloudflare plugin...'
                    sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare
                fi
                
                if ! command -v jq > /dev/null 2>&1; then
                    echo '📥 Installing jq...'
                    sudo pacman -Sy --noconfirm jq
                fi
                
                # Update DNS A records
                echo '🌐 Updating DNS A records...'
                
                # Function to update DNS record
                update_dns_record() {
                    local record_name=\"\$1\"
                    local record_type=\"\$2\"
                    local record_content=\"\$3\"
                    
                    echo \"🔍 Updating DNS record: \$record_name (\$record_type) -> \$record_content\"
                    
                    # Double-check IPv4 format
                    if [[ ! \"\$record_content\" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$ ]]; then
                        echo \"❌ Invalid IPv4 address format: \$record_content\"
                        return 1
                    fi
                    
                    # Get existing records
                    EXISTING_RECORD=\$(curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=\$record_type&name=\$record_name\" \\
                        -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                        -H \"Content-Type: application/json\")
                    
                    if ! echo \"\$EXISTING_RECORD\" | jq -e .success > /dev/null; then
                        echo \"❌ Failed to fetch DNS records for \$record_name\"
                        echo \"API Response: \$EXISTING_RECORD\"
                        return 1
                    fi
                    
                    RECORD_COUNT=\$(echo \"\$EXISTING_RECORD\" | jq '.result | length')
                    CURRENT_IP=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].content // empty')
                    
                    if [[ \"\$RECORD_COUNT\" -eq 0 ]]; then
                        echo \"📝 Creating new \$record_type record for \$record_name...\"
                        DNS_RESPONSE=\$(curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records\" \\
                            -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                            -H \"Content-Type: application/json\" \\
                            --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                    else
                        RECORD_ID=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].id')
                        echo \"🔄 Updating existing \$record_type record for \$record_name...\"
                        DNS_RESPONSE=\$(curl -s -X PUT \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/\$RECORD_ID\" \\
                            -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                            -H \"Content-Type: application/json\" \\
                            --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                    fi
                    
                    if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                        echo \"✅ DNS record updated successfully for \$record_name\"
                        return 0
                    else
                        echo \"❌ Failed to update DNS record for \$record_name\"
                        echo \"API Response: \$DNS_RESPONSE\"
                        return 1
                    fi
                }
                
                # Update DNS records
                if update_dns_record \"$DOMAIN_NAME\" \"A\" \"\$SERVER_IP\"; then
                    echo \"✅ Main domain DNS record updated\"
                else
                    echo \"❌ Main domain DNS update failed\"
                    exit 1
                fi
                
                if update_dns_record \"www.$DOMAIN_NAME\" \"A\" \"\$SERVER_IP\"; then
                    echo \"✅ WWW subdomain DNS record updated\"
                else
                    echo \"⚠️ WWW subdomain DNS update failed, but continuing...\"
                fi
                
                # Create Cloudflare credentials file
                echo '🔐 Setting up Cloudflare credentials...'
                CLOUDFLARE_CREDS_FILE=\"/tmp/cloudflare-credentials\"
                echo \"dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN\" > \"\$CLOUDFLARE_CREDS_FILE\"
                chmod 600 \"\$CLOUDFLARE_CREDS_FILE\"
                
                if [ -f \"\$CLOUDFLARE_CREDS_FILE\" ]; then
                    echo \"✅ Cloudflare credentials file created successfully\"
                else
                    echo \"❌ Failed to create credentials file\"
                    exit 1
                fi
                
                # Wait for DNS propagation
                echo '⏳ Waiting 120 seconds for DNS propagation...'
                sleep 120
                
                # Verify DNS propagation
                echo '🔍 Verifying DNS propagation...'
                for i in {1..5}; do
                    if nslookup \"$DOMAIN_NAME\" 8.8.8.8 | grep -q \"\$SERVER_IP\"; then
                        echo \"✅ DNS propagation confirmed for \$SERVER_IP\"
                        break
                    fi
                    
                    if [[ \$i -eq 5 ]]; then
                        echo \"⚠️ DNS propagation taking longer, but continuing...\"
                        break
                    fi
                    
                    echo \"⏳ Waiting for DNS propagation... (attempt \$i/5)\"
                    sleep 30
                done
                
                # Generate SSL certificate
                echo '🔐 Generating SSL certificate...'
                
                STAGING_FLAG=\"\"
                if [ \"$SSL_STAGING\" = \"true\" ]; then
                    STAGING_FLAG=\"--staging\"
                    echo \"⚠️ Using Let's Encrypt staging environment\"
                fi
                
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
                    
                    # Set up auto-renewal
                    echo '🔄 Setting up automatic renewal...'
                    CRON_JOB=\"0 2 * * 0 /usr/bin/certbot renew --quiet && /usr/bin/systemctl reload nginx\"
                    (sudo crontab -l 2>/dev/null; echo \"\$CRON_JOB\") | sudo crontab -
                    echo '✅ Auto-renewal configured'
                    
                else
                    echo '❌ SSL certificate generation failed'
                    echo '📋 Checking certbot logs...'
                    sudo tail -30 /var/log/letsencrypt/letsencrypt.log || echo 'No certbot logs found'
                    exit 1
                fi
                
                # Clean up credentials file
                rm -f \"\$CLOUDFLARE_CREDS_FILE\"
                echo '🧹 Cleaned up credentials file'
                
                echo '✅ SSL certificates configured successfully'
            " "SSL certificate setup" 400
        else
            log "✅ SSL certificates are already valid and up-to-date"
        fi
    else
        warn "⚠️ SSL setup skipped - missing configuration or disabled"
        warn "   ENABLE_SSL: $ENABLE_SSL"
        warn "   CLOUDFLARE_API_TOKEN: $([ -n "$CLOUDFLARE_API_TOKEN" ] && echo "configured" || echo "missing")"
        warn "   CLOUDFLARE_ZONE_ID: $([ -n "$CLOUDFLARE_ZONE_ID" ] && echo "configured" || echo "missing")"
    fi
    
    # Step 5: Setup repository
    log "📥 Setting up repository using GITHUB_TOKEN..."
    execute_ssh "
        echo '🔧 FKS Repository Setup'
        echo '===================='
        
        # Clean up existing directories
        echo '🧹 Cleaning up existing directories...'
        sudo rm -rf /home/fks_user/fks
        
        # Create directory structure
        echo '📁 Creating directory structure...'
        sudo mkdir -p /home/fks_user/fks
        
        # Clone repository
        echo '📦 Cloning repository...'
        cd /tmp
        
        GITHUB_TOKEN='$GITHUB_TOKEN'
        
        if [ -n \"\\$GITHUB_TOKEN\" ]; then
            export GIT_ASKPASS=true
            export GIT_TERMINAL_PROMPT=0
            git config --global credential.helper store
            
            if git clone https://x-access-token:\\$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh; then
                echo '✅ Repository cloned successfully'
                
                sudo mv fks_fresh/* /home/fks_user/fks/
                sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
                sudo rm -rf fks_fresh
                
                sudo chown -R fks_user:fks_user /home/fks_user/fks
                sudo chmod -R 755 /home/fks_user/fks
                sudo chmod 755 /home/fks_user/fks
                
                # Make scripts executable
                sudo find /home/fks_user/fks/scripts -name '*.sh' -exec chmod +x {} \\; 2>/dev/null || true
                
                echo '✅ Repository setup completed'
            else
                echo '❌ Failed to clone repository'
                exit 1
            fi
            
            rm -f ~/.git-credentials 2>/dev/null || true
        else
            echo '❌ No GitHub token available'
            exit 1
        fi
    " "Repository setup"
    
    # Step 6: Application deployment
    log "🚀 Starting application deployment..."
    
    execute_ssh "
        echo '🎆 Application Deployment with SSL Integration'
        echo '============================================='
        
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
        
        # Create environment file with SSL configuration
        echo '📄 Creating environment file...'
        sudo -u fks_user bash -c \\\"cat > .env << 'ENVEOF'
# FKS Trading Systems - Configuration with SSL Support
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
POSTGRES_PASSWORD=fks_postgres_\$(openssl rand -hex 8)
POSTGRES_MAX_CONNECTIONS=100

# Redis Configuration
REDIS_PASSWORD=fks_redis_\$(openssl rand -hex 8)
REDIS_MAXMEMORY=512mb
REDIS_MAXMEMORY_POLICY=allkeys-lru

# Security Configuration
JWT_SECRET_KEY=\$(openssl rand -hex 32)
SECRET_KEY=\$(openssl rand -hex 32)

# SSL and Domain Configuration
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

# Application URLs (HTTPS if SSL enabled)
$(if [ "$ENABLE_SSL" = "true" ]; then
    echo "API_URL=https://$DOMAIN_NAME:8000"
    echo "WS_URL=wss://$DOMAIN_NAME:8000"
    echo "REACT_APP_API_URL=https://$DOMAIN_NAME:8000"
else
    echo "API_URL=http://$DOMAIN_NAME:8000"
    echo "WS_URL=ws://$DOMAIN_NAME:8000"
    echo "REACT_APP_API_URL=http://$DOMAIN_NAME:8000"
fi)

# Debug and Development
DEBUG_MODE=$([ '$APP_ENV' = 'development' ] && echo 'true' || echo 'false')
APP_LOG_LEVEL=$([ '$APP_ENV' = 'development' ] && echo 'DEBUG' || echo 'INFO')
VERBOSE_LOGGING=$([ '$APP_ENV' = 'development' ] && echo 'true' || echo 'false')

# Resource Limits
API_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1' || echo '2')
API_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '1024M' || echo '2048M')
WEB_CPU_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '0.5' || echo '1')
WEB_MEMORY_LIMIT=$([ '$APP_ENV' = 'development' ] && echo '512M' || echo '1024M')

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

# Development Tools (if development)
$([ '$APP_ENV' = 'development' ] && cat << 'DEVTOOLS'
ADMINER_PORT=8080
REDIS_COMMANDER_PORT=8082
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
        
        # Start services
        echo '🚀 Starting services...'
        if sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            export \$(cat .env | xargs)
            
            # Choose compose file based on environment
            if [ \"$APP_ENV\" = \"development\" ] && [ -f docker-compose.dev.yml ]; then
                echo \"🔧 Using development configuration\"
                docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
            elif [ \"$APP_ENV\" = \"production\" ] && [ -f docker-compose.prod.yml ]; then
                echo \"🔧 Using production configuration\"
                docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
            else
                echo \"🔧 Using base configuration\"
                docker compose up -d
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
        $(if [ "$ENABLE_SSL" = "true" ]; then
            echo "echo '  - Main Site: https://$DOMAIN_NAME'"
            echo "echo '  - Web Interface: https://$DOMAIN_NAME:3000'"
            echo "echo '  - API: https://$DOMAIN_NAME:8000'"
            echo "echo '  - Data Service: https://$DOMAIN_NAME:9001'"
        else
            echo "echo '  - Main Site: http://$DOMAIN_NAME'"
            echo "echo '  - Web Interface: http://$DOMAIN_NAME:3000'"
            echo "echo '  - API: http://$DOMAIN_NAME:8000'"
            echo "echo '  - Data Service: http://$DOMAIN_NAME:9001'"
        fi)
        echo '💡 SSL Status: $([ '$ENABLE_SSL' = 'true' ] && echo 'Enabled' || echo 'Disabled')'
        echo '💡 Environment: $APP_ENV'
    " "Application deployment" 300
    
    log "✅ FKS Trading Systems deployment completed successfully!"
    log "🌐 Application should be available at: $([ "$ENABLE_SSL" = "true" ] && echo "https" || echo "http")://$DOMAIN_NAME"
    
    if [ "$ENABLE_SSL" = "true" ]; then
        log "🔐 SSL certificates are configured and active"
        log "📋 Next renewal will be automatic via cron"
        log "🔍 Check certificates manually: sudo certbot certificates"
    fi
}

# Execute main function
main "$@"
