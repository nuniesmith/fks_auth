#!/bin/bash

# FKS Trading Systems - Clean SSL Deployment Script
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

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    
    log "📡 $description"
    
    if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no actions_user@"$TARGET_HOST" "$command"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description"
        return 1
    fi
}

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems SSL deployment..."
    
    # Test SSH
    if ! execute_ssh "echo 'SSH ready'" "SSH connectivity test"; then
        error "❌ SSH connection failed"
        exit 1
    fi
    
    # Check Docker
    execute_ssh "docker --version" "Docker version check"
    
    # Generate SSL certificates
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Setting up SSL certificates..."
        
        # Create the SSL setup script as a separate file to avoid quoting issues
        cat > /tmp/ssl_setup.sh << 'SSLEOF'
#!/bin/bash
set -e

echo "🔐 SSL Certificate Setup..."

# Get server IP
SERVER_IP=$(curl -4 -s ifconfig.me)
echo "Server IP: $SERVER_IP"

# Install certbot if needed
if ! command -v certbot >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare
fi

# Install jq if needed
if ! command -v jq >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm jq
fi

# Create credentials file
CREDS_FILE="/tmp/cf-creds"
echo "dns_cloudflare_api_token = CLOUDFLARE_API_TOKEN_PLACEHOLDER" > "$CREDS_FILE"
chmod 600 "$CREDS_FILE"

# Generate certificate
STAGING_ARG=""
if [ "SSL_STAGING_PLACEHOLDER" = "true" ]; then
    STAGING_ARG="--staging"
fi

sudo certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CREDS_FILE" \
    --email "ADMIN_EMAIL_PLACEHOLDER" \
    --agree-tos \
    --non-interactive \
    $STAGING_ARG \
    -d "DOMAIN_NAME_PLACEHOLDER" \
    -d "www.DOMAIN_NAME_PLACEHOLDER"

# Copy certificates for Docker
sudo mkdir -p /home/fks_user/ssl
sudo cp -L /etc/letsencrypt/live/DOMAIN_NAME_PLACEHOLDER/fullchain.pem /home/fks_user/ssl/cert.pem
sudo cp -L /etc/letsencrypt/live/DOMAIN_NAME_PLACEHOLDER/privkey.pem /home/fks_user/ssl/key.pem
sudo chown -R fks_user:fks_user /home/fks_user/ssl
sudo chmod 644 /home/fks_user/ssl/cert.pem
sudo chmod 600 /home/fks_user/ssl/key.pem

# Clean up
rm -f "$CREDS_FILE"

echo "✅ SSL certificates configured"
SSLEOF

        # Replace placeholders in the script
        sed -i "s/CLOUDFLARE_API_TOKEN_PLACEHOLDER/$CLOUDFLARE_API_TOKEN/g" /tmp/ssl_setup.sh
        sed -i "s/SSL_STAGING_PLACEHOLDER/$SSL_STAGING/g" /tmp/ssl_setup.sh
        sed -i "s/ADMIN_EMAIL_PLACEHOLDER/$ADMIN_EMAIL/g" /tmp/ssl_setup.sh
        sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME/g" /tmp/ssl_setup.sh
        
        # Copy script to server and execute
        scp -o StrictHostKeyChecking=no /tmp/ssl_setup.sh actions_user@"$TARGET_HOST":/tmp/ssl_setup.sh
        
        if execute_ssh "chmod +x /tmp/ssl_setup.sh && /tmp/ssl_setup.sh && rm -f /tmp/ssl_setup.sh" "SSL certificate generation"; then
            log "✅ SSL certificates generated successfully"
        else
            error "❌ SSL certificate generation failed"
            exit 1
        fi
        
        # Clean up local script
        rm -f /tmp/ssl_setup.sh
    else
        log "⚠️ SSL setup skipped - missing configuration or disabled"
    fi
    
    # Repository setup
    log "📥 Setting up repository..."
    execute_ssh "
        sudo rm -rf /home/fks_user/fks
        sudo mkdir -p /home/fks_user/fks
        cd /tmp
        
        git clone https://x-access-token:$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh
        sudo mv fks_fresh/* /home/fks_user/fks/
        sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
        sudo rm -rf fks_fresh
        sudo chown -R fks_user:fks_user /home/fks_user/fks
        sudo chmod -R 755 /home/fks_user/fks
    " "Repository setup"
    
    # Application deployment
    log "🚀 Starting application deployment..."
    
    # Create environment file content
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
API_HOST=api
WEB_HOST=web
WORKER_HOST=worker
WORKER_PORT=8001
TZ=America/New_York
ENVEOF
    
    # Copy environment file to server
    scp -o StrictHostKeyChecking=no /tmp/env_content actions_user@"$TARGET_HOST":/tmp/env_content
    
    execute_ssh "
        cd /home/fks_user/fks
        
        # Docker login
        sudo -u fks_user bash -c \"echo '$DOCKER_TOKEN' | docker login -u '$DOCKER_USERNAME' --password-stdin\"
        
        # Create environment file
        sudo -u fks_user cp /tmp/env_content .env
        sudo -u fks_user chmod 600 .env
        
        # Update SSL mount path in docker-compose if SSL is enabled
        if [ '$ENABLE_SSL' = 'true' ]; then
            sudo -u fks_user sed -i 's|./config/ssl:/etc/nginx/ssl:ro|/home/fks_user/ssl:/etc/nginx/ssl:ro|g' docker-compose.yml
        fi
        
        # Start services
        sudo -u fks_user docker compose up -d
        
        echo '✅ Application deployment completed'
        
        # Show status
        sudo -u fks_user docker ps
        
        # Clean up
        rm -f /tmp/env_content
    " "Application deployment"
    
    # Clean up local files
    rm -f /tmp/env_content
    
    log "✅ Deployment completed successfully!"
    log "🌐 Application available at: $([ '$ENABLE_SSL' = 'true' ] && echo 'https' || echo 'http')://$DOMAIN_NAME"
}

# Run main function
main "$@"
