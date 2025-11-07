#!/bin/bash

# FKS Trading Systems - Simplified SSL Deployment
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

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
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
    log "🔐 Testing SSH connection..."
    if ! execute_ssh "echo 'SSH ready'" "SSH connectivity test"; then
        error "❌ SSH connection failed"
        exit 1
    fi
    
    # Check Docker
    log "🐳 Checking Docker..."
    execute_ssh "docker --version" "Docker version check"
    
    # Generate SSL certificates
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
        log "🔐 Setting up SSL certificates..."
        
        execute_ssh "
            echo '🔐 SSL Certificate Setup...'
            
            # Get server IP
            SERVER_IP=\$(curl -4 -s ifconfig.me)
            echo \"Server IP: \$SERVER_IP\"
            
            # Install certbot if needed
            if ! command -v certbot >/dev/null 2>&1; then
                sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare
            fi
            
            # Create credentials file
            echo 'dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN' | sudo tee /tmp/cf-creds >/dev/null
            sudo chmod 600 /tmp/cf-creds
            
            # Update DNS records first
            if command -v jq >/dev/null 2>&1; then
                echo "📡 Updating DNS records..."
                curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
                    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
                    -H "Content-Type: application/json" \
                    --data "{"type":"A","name":"$DOMAIN_NAME","content":"$SERVER_IP","ttl":300}" || true
                curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
                    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
                    -H "Content-Type: application/json" \
                    --data "{"type":"A","name":"www.$DOMAIN_NAME","content":"$SERVER_IP","ttl":300}" || true
                echo "✅ DNS records updated"
                sleep 60
            fi

            # Generate certificate
            sudo certbot certonly \\
                --dns-cloudflare \\
                --dns-cloudflare-credentials /tmp/cf-creds \\
                --email '$ADMIN_EMAIL' \\
                --agree-tos \\
                --non-interactive \\
                $([ '$SSL_STAGING' = 'true' ] && echo '--staging' || echo '') \\
                -d '$DOMAIN_NAME' \\
                -d 'www.$DOMAIN_NAME'
            
            # Copy certificates for Docker
            sudo mkdir -p /home/fks_user/ssl
            sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /home/fks_user/ssl/cert.pem
            sudo cp -L /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /home/fks_user/ssl/key.pem
            sudo chown -R fks_user:fks_user /home/fks_user/ssl
            sudo chmod 644 /home/fks_user/ssl/cert.pem
            sudo chmod 600 /home/fks_user/ssl/key.pem
            
            # Clean up
            sudo rm -f /tmp/cf-creds
            
            echo '✅ SSL certificates configured'
        " "SSL certificate generation" || {
            error "❌ SSL certificate generation failed"
            exit 1
        }
    else
        warn "⚠️ SSL setup skipped"
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
    execute_ssh "
        cd /home/fks_user/fks
        
        # Docker login
        sudo -u fks_user bash -c \"echo '$DOCKER_TOKEN' | docker login -u '$DOCKER_USERNAME' --password-stdin\"
        
        # Create environment file
        sudo -u fks_user cat > .env << ENVEOF
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
POSTGRES_PASSWORD=fks_postgres_\$(openssl rand -hex 8)
REDIS_PASSWORD=fks_redis_\$(openssl rand -hex 8)
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
        
        # Update SSL mount path in docker-compose
        sudo -u fks_user sed -i 's|./config/ssl:/etc/nginx/ssl:ro|/home/fks_user/ssl:/etc/nginx/ssl:ro|g' docker-compose.yml
        
        # Start services
        sudo -u fks_user docker compose up -d
        
        echo '✅ Application deployment completed'
        
        # Show status
        sudo -u fks_user docker ps
    " "Application deployment"
    
    log "✅ Deployment completed successfully!"
    log "🌐 Application available at: $([ '$ENABLE_SSL' = 'true' ] && echo 'https' || echo 'http')://$DOMAIN_NAME"
}

# Run main function
main "$@"
