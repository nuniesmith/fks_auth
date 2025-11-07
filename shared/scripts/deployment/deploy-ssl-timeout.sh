#!/bin/bash

# FKS Trading Systems - SSL Deployment with Timeout Handling
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
    local timeout="${3:-300}"  # Default 5 minutes
    
    log "📡 $description"
    
    if timeout "$timeout" sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 actions_user@"$TARGET_HOST" "$command"; then
        log "✅ Success: $description"
        return 0
    else
        error "❌ Failed: $description (timeout: ${timeout}s)"
        return 1
    fi
}

# Main deployment function
main() {
    log "🚀 Starting FKS Trading Systems SSL deployment..."
    
    # Test SSH with short timeout
    if ! execute_ssh "echo 'SSH ready'" "SSH connectivity test" 10; then
        error "❌ SSH connection failed"
        exit 1
    fi
    
    # Check Docker with short timeout
    execute_ssh "docker --version" "Docker version check" 10
    
    # Check if SSL certificates already exist
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Checking existing SSL certificates..."
        
        if execute_ssh "ls -la /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" "Check existing certificates" 10; then
            log "✅ SSL certificates already exist, setting up for Docker..."
            
            # Just copy existing certificates
            execute_ssh "
                sudo mkdir -p /home/fks_user/ssl
                sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /home/fks_user/ssl/cert.pem
                sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /home/fks_user/ssl/key.pem
                sudo chown -R fks_user:fks_user /home/fks_user/ssl
                sudo chmod 644 /home/fks_user/ssl/cert.pem
                sudo chmod 600 /home/fks_user/ssl/key.pem
                echo '✅ SSL certificates copied for Docker'
            " "Copy existing SSL certificates" 30
        else
            log "🔐 Generating new SSL certificates..."
            
            # Create a simpler SSL setup script
            cat > /tmp/ssl_setup.sh << 'SSLEOF'
#!/bin/bash
set -e

echo "🔐 SSL Certificate Generation (with timeout)..."

# Get server IP quickly
echo "🌐 Getting server IP..."
SERVER_IP=$(timeout 30 curl -4 -s ifconfig.me || echo "")
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip route get 8.8.8.8 | grep -oE 'src [0-9.]+' | cut -d' ' -f2 | head -1)
fi
echo "Server IP: $SERVER_IP"

# Install certbot quickly
echo "📦 Installing certbot..."
if ! command -v certbot >/dev/null 2>&1; then
    timeout 180 sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare || {
        echo "❌ Certbot installation timeout"
        exit 1
    }
fi

# Create credentials file
echo "🔐 Creating credentials..."
CREDS_FILE="/tmp/cf-creds"
echo "dns_cloudflare_api_token = CLOUDFLARE_API_TOKEN_PLACEHOLDER" > "$CREDS_FILE"
chmod 600 "$CREDS_FILE"

# Generate certificate with timeout
echo "🔐 Generating certificate..."
STAGING_ARG=""
if [ "SSL_STAGING_PLACEHOLDER" = "true" ]; then
    STAGING_ARG="--staging"
fi

timeout 300 sudo certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CREDS_FILE" \
    --dns-cloudflare-propagation-seconds 60 \
    --email "ADMIN_EMAIL_PLACEHOLDER" \
    --agree-tos \
    --non-interactive \
    $STAGING_ARG \
    -d "DOMAIN_NAME_PLACEHOLDER" \
    -d "www.DOMAIN_NAME_PLACEHOLDER" || {
    echo "❌ Certificate generation timeout"
    exit 1
}

# Copy certificates for Docker
echo "📋 Copying certificates for Docker..."
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

            # Replace placeholders
            sed -i "s/CLOUDFLARE_API_TOKEN_PLACEHOLDER/$CLOUDFLARE_API_TOKEN/g" /tmp/ssl_setup.sh
            sed -i "s/SSL_STAGING_PLACEHOLDER/$SSL_STAGING/g" /tmp/ssl_setup.sh
            sed -i "s/ADMIN_EMAIL_PLACEHOLDER/$ADMIN_EMAIL/g" /tmp/ssl_setup.sh
            sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME/g" /tmp/ssl_setup.sh
            
            # Copy and execute with timeout
            scp -o StrictHostKeyChecking=no -o ConnectTimeout=30 /tmp/ssl_setup.sh actions_user@"$TARGET_HOST":/tmp/ssl_setup.sh
            
            if execute_ssh "chmod +x /tmp/ssl_setup.sh && /tmp/ssl_setup.sh && rm -f /tmp/ssl_setup.sh" "SSL certificate generation" 600; then
                log "✅ SSL certificates generated successfully"
            else
                error "❌ SSL certificate generation failed or timed out"
                log "⚠️ Continuing deployment without SSL..."
                ENABLE_SSL="false"
            fi
            
            rm -f /tmp/ssl_setup.sh
        fi
    else
        log "⚠️ SSL setup skipped - missing configuration or disabled"
    fi
    
    # Repository setup with timeout
    log "📥 Setting up repository..."
    execute_ssh "
        echo '📦 Repository setup...'
        sudo rm -rf /home/fks_user/fks
        sudo mkdir -p /home/fks_user/fks
        cd /tmp
        
        timeout 120 git clone https://x-access-token:$GITHUB_TOKEN@github.com/nuniesmith/fks.git fks_fresh || {
            echo '❌ Repository clone timeout'
            exit 1
        }
        
        sudo mv fks_fresh/* /home/fks_user/fks/
        sudo mv fks_fresh/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
        sudo rm -rf fks_fresh
        sudo chown -R fks_user:fks_user /home/fks_user/fks
        sudo chmod -R 755 /home/fks_user/fks
        echo '✅ Repository setup complete'
    " "Repository setup" 180
    
    # Application deployment with timeout
    log "🚀 Starting application deployment..."
    
    # Create environment file
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
    
    # Copy environment file
    scp -o StrictHostKeyChecking=no -o ConnectTimeout=30 /tmp/env_content actions_user@"$TARGET_HOST":/tmp/env_content
    
    execute_ssh "
        cd /home/fks_user/fks
        
        echo '🔐 Docker login...'
        sudo -u fks_user bash -c \"echo '$DOCKER_TOKEN' | docker login -u '$DOCKER_USERNAME' --password-stdin\"
        
        echo '📄 Creating environment file...'
        sudo -u fks_user cp /tmp/env_content .env
        sudo -u fks_user chmod 600 .env
        
        echo '🔧 Updating docker-compose configuration...'
        if [ '$ENABLE_SSL' = 'true' ]; then
            sudo -u fks_user sed -i 's|./config/ssl:/etc/nginx/ssl:ro|/home/fks_user/ssl:/etc/nginx/ssl:ro|g' docker-compose.yml
        fi
        
        echo '🚀 Starting Docker services...'
        sudo -u fks_user timeout 300 docker compose up -d || {
            echo '❌ Docker compose timeout'
            exit 1
        }
        
        echo '✅ Application deployment completed'
        
        echo '📊 Container status:'
        sudo -u fks_user docker ps
        
        # Clean up
        rm -f /tmp/env_content
    " "Application deployment" 420
    
    # Clean up local files
    rm -f /tmp/env_content
    
    log "✅ Deployment completed successfully!"
    log "🌐 Application available at: $([ '$ENABLE_SSL' = 'true' ] && echo 'https' || echo 'http')://$DOMAIN_NAME"
    
    if [ "$ENABLE_SSL" = "true" ]; then
        log "🔐 SSL certificates are configured"
    else
        log "⚠️ SSL was disabled or failed - using HTTP"
    fi
}

# Run main function
main "$@"
