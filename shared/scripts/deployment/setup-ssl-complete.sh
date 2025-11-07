#!/bin/bash

# ============================================================================
# FKS Trading Systems - Complete SSL Setup for Development Server
# ============================================================================
# This script sets up SSL certificates using Cloudflare DNS + Let's Encrypt
# for the fkstrading.xyz domain on your development server
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_step() { echo -e "${CYAN}🔧 $1${NC}"; }

# Configuration - Update these with your values
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
SSL_STAGING="${SSL_STAGING:-false}"

# Ports for services
WEB_PORT="${WEB_PORT:-3001}"
API_PORT="${API_PORT:-4000}"
BUILD_API_PORT="${BUILD_API_PORT:-4000}"

# Usage function
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Environment variables (required):"
    echo "  CLOUDFLARE_API_TOKEN    Cloudflare API token with Zone:Edit permissions"
    echo "  CLOUDFLARE_ZONE_ID      Cloudflare Zone ID for your domain"
    echo ""
    echo "Optional environment variables:"
    echo "  DOMAIN_NAME             Domain name (default: fkstrading.xyz)"
    echo "  ADMIN_EMAIL             Admin email (default: nunie.smith01@gmail.com)"
    echo "  SSL_STAGING             Use staging environment (default: false)"
    echo "  WEB_PORT                React app port (default: 3001)"
    echo "  API_PORT                Build API port (default: 4000)"
    echo ""
    echo "Example:"
    echo "  export CLOUDFLARE_API_TOKEN='your_token_here'"
    echo "  export CLOUDFLARE_ZONE_ID='your_zone_id_here'"
    echo "  $0"
    exit 1
}

# Check if script is run as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root"
        log_info "Run as regular user with sudo access"
        exit 1
    fi
}

# Validate required parameters
validate_params() {
    log_step "Validating parameters..."
    
    if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
        log_error "CLOUDFLARE_API_TOKEN is required"
        usage
    fi
    
    if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then
        log_error "CLOUDFLARE_ZONE_ID is required"
        usage
    fi
    
    if [[ -z "$DOMAIN_NAME" ]]; then
        log_error "DOMAIN_NAME is required"
        usage
    fi
    
    if [[ -z "$ADMIN_EMAIL" ]]; then
        log_error "ADMIN_EMAIL is required"
        usage
    fi
    
    log_success "All required parameters provided"
}

# Get server IP
get_server_ip() {
    log_step "Getting server IP address..."
    
    # Try multiple methods to get the public IP
    SERVER_IP=""
    
    if command -v curl >/dev/null 2>&1; then
        SERVER_IP=$(timeout 10 curl -s https://ifconfig.me 2>/dev/null || echo "")
    fi
    
    if [[ -z "$SERVER_IP" ]] && command -v wget >/dev/null 2>&1; then
        SERVER_IP=$(timeout 10 wget -qO- https://ifconfig.me 2>/dev/null || echo "")
    fi
    
    if [[ -z "$SERVER_IP" ]]; then
        log_error "Could not determine server IP address"
        exit 1
    fi
    
    log_success "Server IP: $SERVER_IP"
}

# Install required packages
install_packages() {
    log_step "Installing required packages..."
    
    # Update package lists
    sudo apt-get update -qq
    
    # Install packages
    local packages=("nginx" "certbot" "python3-certbot-nginx" "python3-certbot-dns-cloudflare" "jq" "curl")
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log_info "Installing $package..."
            sudo apt-get install -y "$package"
        else
            log_success "$package already installed"
        fi
    done
}

# Update DNS records
update_dns_records() {
    log_step "Updating DNS records..."
    
    # Function to update/create DNS record
    update_dns_record() {
        local record_name="$1"
        local record_type="$2"
        local record_content="$3"
        
        log_info "Processing DNS record: $record_name ($record_type)"
        
        # Get existing records
        local response=$(curl -s -X GET \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=$record_type&name=$record_name" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json")
        
        if ! echo "$response" | jq -e .success >/dev/null; then
            log_error "Failed to fetch DNS records for $record_name"
            echo "Response: $response"
            return 1
        fi
        
        local record_count=$(echo "$response" | jq '.result | length')
        local current_content=$(echo "$response" | jq -r '.result[0].content // empty')
        
        if [[ "$record_count" -eq 0 ]]; then
            # Create new record
            log_info "Creating new $record_type record for $record_name..."
            local create_response=$(curl -s -X POST \
                "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
                -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$record_content\",\"ttl\":300}")
            
            if echo "$create_response" | jq -e .success >/dev/null; then
                log_success "Created $record_type record for $record_name"
            else
                log_error "Failed to create $record_type record for $record_name"
                echo "Response: $create_response"
                return 1
            fi
        elif [[ "$current_content" != "$record_content" ]]; then
            # Update existing record
            local record_id=$(echo "$response" | jq -r '.result[0].id')
            log_info "Updating $record_type record for $record_name (was: $current_content, now: $record_content)..."
            local update_response=$(curl -s -X PUT \
                "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
                -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$record_content\",\"ttl\":300}")
            
            if echo "$update_response" | jq -e .success >/dev/null; then
                log_success "Updated $record_type record for $record_name"
            else
                log_error "Failed to update $record_type record for $record_name"
                echo "Response: $update_response"
                return 1
            fi
        else
            log_success "$record_type record for $record_name is already correct: $current_content"
        fi
    }
    
    # Update root domain and www subdomain
    update_dns_record "$DOMAIN_NAME" "A" "$SERVER_IP"
    update_dns_record "www.$DOMAIN_NAME" "A" "$SERVER_IP"
    
    log_success "DNS records updated successfully"
}

# Setup Cloudflare credentials for certbot
setup_cloudflare_credentials() {
    log_step "Setting up Cloudflare credentials for certbot..."
    
    sudo mkdir -p /etc/letsencrypt
    
    # Create cloudflare.ini file
    sudo tee /etc/letsencrypt/cloudflare.ini >/dev/null <<EOF
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
    
    # Set secure permissions
    sudo chmod 600 /etc/letsencrypt/cloudflare.ini
    
    log_success "Cloudflare credentials configured"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_step "Generating SSL certificates..."
    
    local staging_flag=""
    if [[ "$SSL_STAGING" == "true" ]]; then
        staging_flag="--staging"
        log_warning "Using Let's Encrypt staging environment"
    else
        log_info "Using Let's Encrypt production environment"
    fi
    
    # Generate certificate
    sudo certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 60 \
        $staging_flag \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        -d "$DOMAIN_NAME" \
        -d "www.$DOMAIN_NAME" || {
        log_error "Certificate generation failed"
        return 1
    }
    
    log_success "SSL certificates generated successfully"
}

# Configure nginx with SSL
configure_nginx() {
    log_step "Configuring nginx with SSL..."
    
    # Create FKS Trading Systems nginx configuration
    sudo tee /etc/nginx/sites-available/fks_ssl >/dev/null <<EOF
# FKS Trading Systems - SSL Configuration
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Configuration
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # React App (main frontend)
    location / {
        proxy_pass http://localhost:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Build API
    location /api/ {
        proxy_pass http://localhost:$API_PORT/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Health check
    location /health {
        access_log off;
        return 200 "FKS Trading Systems - Healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Static files with caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files \$uri =404;
    }
}
EOF

    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/fks_ssl /etc/nginx/sites-enabled/
    
    # Remove default nginx site
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx configuration
    if sudo nginx -t; then
        log_success "Nginx configuration is valid"
    else
        log_error "Nginx configuration test failed"
        return 1
    fi
    
    # Reload nginx
    sudo systemctl reload nginx
    log_success "Nginx configured and reloaded"
}

# Setup SSL auto-renewal
setup_auto_renewal() {
    log_step "Setting up SSL certificate auto-renewal..."
    
    # Create renewal script
    sudo tee /usr/local/bin/renew-ssl.sh >/dev/null <<'EOF'
#!/bin/bash
# FKS SSL Renewal Script
/usr/bin/certbot renew --quiet --post-hook "systemctl reload nginx"
EOF
    
    sudo chmod +x /usr/local/bin/renew-ssl.sh
    
    # Add cron job for auto-renewal
    (sudo crontab -l 2>/dev/null | grep -v "renew-ssl.sh"; echo "0 3 * * * /usr/local/bin/renew-ssl.sh") | sudo crontab -
    
    log_success "SSL auto-renewal configured (runs daily at 3 AM)"
}

# Test SSL setup
test_ssl_setup() {
    log_step "Testing SSL setup..."
    
    # Wait a moment for services to be ready
    sleep 5
    
    # Test HTTPS access
    if curl -sS -f -m 10 "https://$DOMAIN_NAME/health" >/dev/null; then
        log_success "HTTPS access working correctly"
    else
        log_warning "HTTPS test failed - may need a moment to propagate"
    fi
    
    # Show certificate details
    log_info "Certificate details:"
    sudo certbot certificates | grep -A 10 "$DOMAIN_NAME" || true
}

# Display final status
show_final_status() {
    log_success "🎉 SSL setup complete!"
    echo ""
    log_info "Your FKS Trading Systems is now available at:"
    echo "  🌐 https://$DOMAIN_NAME"
    echo "  🌐 https://www.$DOMAIN_NAME"
    echo ""
    log_info "Services:"
    echo "  📊 React Frontend: https://$DOMAIN_NAME"
    echo "  🔧 Build API: https://$DOMAIN_NAME/api/"
    echo "  ❤️ Health Check: https://$DOMAIN_NAME/health"
    echo ""
    log_info "Certificate auto-renewal is configured"
    log_info "Certificates will be checked daily and renewed if needed"
}

# Main execution
main() {
    echo "============================================================================"
    log_info "FKS Trading Systems - SSL Setup Starting"
    echo "============================================================================"
    
    check_root
    validate_params
    get_server_ip
    install_packages
    update_dns_records
    setup_cloudflare_credentials
    generate_ssl_certificates
    configure_nginx
    setup_auto_renewal
    test_ssl_setup
    show_final_status
    
    echo "============================================================================"
    log_success "SSL Setup Complete!"
    echo "============================================================================"
}

# Handle command line arguments
if [[ "$#" -gt 0 && "$1" == "--help" ]]; then
    usage
fi

# Run main function
main "$@"
