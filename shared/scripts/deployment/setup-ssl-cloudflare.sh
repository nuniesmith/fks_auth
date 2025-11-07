#!/bin/bash
#
# FKS Trading Systems - SSL Setup with Cloudflare & Let's Encrypt
# This script sets up SSL certificates for fkstrading.xyz using Cloudflare DNS challenge
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Default values
DOMAIN_NAME=""
ADMIN_EMAIL=""
CLOUDFLARE_API_TOKEN=""
CLOUDFLARE_ZONE_ID=""
SERVER_IP=""
STAGING_MODE="false"
INCLUDE_WWW="false"
DNS_ONLY="false"
FORCE_RENEWAL="false"
NGINX_CONFIG_PATH="/etc/nginx/sites-available"
NGINX_ENABLED_PATH="/etc/nginx/sites-enabled"

# Usage function
usage() {
    echo "Usage: $0 --domain DOMAIN --email EMAIL --api-token TOKEN --zone-id ZONE_ID --server-ip IP [options]"
    echo ""
    echo "Required parameters:"
    echo "  --domain DOMAIN           Domain name (e.g., fkstrading.xyz)"
    echo "  --email EMAIL            Admin email for Let's Encrypt"
    echo "  --api-token TOKEN        Cloudflare API token"
    echo "  --zone-id ZONE_ID        Cloudflare Zone ID"
    echo "  --server-ip IP           Server IP address"
    echo ""
    echo "Optional parameters:"
    echo "  --staging                Use Let's Encrypt staging environment"
    echo "  --include-www            Include www subdomain in SSL certificate"
    echo "  --dns-only               Only update DNS records, skip SSL certificate generation"
    echo "  --force-renewal          Force renewal of existing SSL certificate"
    echo "  --help                   Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --domain fkstrading.xyz --email admin@example.com \\"
    echo "     --api-token abc123... --zone-id def456... --server-ip 1.2.3.4"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --email)
            ADMIN_EMAIL="$2"
            shift 2
            ;;
        --api-token)
            CLOUDFLARE_API_TOKEN="$2"
            shift 2
            ;;
        --zone-id)
            CLOUDFLARE_ZONE_ID="$2"
            shift 2
            ;;
        --server-ip)
            SERVER_IP="$2"
            shift 2
            ;;
        --staging)
            STAGING_MODE="true"
            shift
            ;;
        --include-www)
            INCLUDE_WWW="true"
            shift
            ;;
        --dns-only)
            DNS_ONLY="true"
            shift
            ;;
        --force-renewal)
            FORCE_RENEWAL="true"
            shift
            ;;
        --help)
            usage
            ;;
        *)
            log_error "Unknown parameter: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$DOMAIN_NAME" || -z "$ADMIN_EMAIL" || -z "$CLOUDFLARE_API_TOKEN" || -z "$CLOUDFLARE_ZONE_ID" || -z "$SERVER_IP" ]]; then
    log_error "Missing required parameters"
    echo ""
    usage
fi

log_info "Starting SSL setup for $DOMAIN_NAME"
log_info "Server IP: $SERVER_IP"
log_info "Admin Email: $ADMIN_EMAIL"
log_info "Staging Mode: $STAGING_MODE"

# Step 1: Install required packages
log_info "Installing required packages..."
if ! command -v nginx &> /dev/null; then
    log_info "Installing nginx..."
    pacman -Sy --noconfirm nginx
fi

if ! command -v certbot &> /dev/null; then
    log_info "Installing certbot and cloudflare plugin..."
    pacman -Sy --noconfirm certbot certbot-dns-cloudflare
fi

if ! command -v jq &> /dev/null; then
    log_info "Installing jq..."
    pacman -Sy --noconfirm jq
fi

log_success "Required packages installed"

# Step 2: Update DNS A records
log_info "Updating DNS A records for $DOMAIN_NAME..."

# Function to update DNS record
update_dns_record() {
    local record_name="$1"
    local record_type="$2"
    local record_content="$3"
    
    log_info "Checking DNS record: $record_name ($record_type)"
    
    # Get existing DNS records
    EXISTING_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=$record_type&name=$record_name" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    if ! echo "$EXISTING_RECORD" | jq -e .success > /dev/null; then
        log_error "Failed to fetch DNS records for $record_name"
        echo "Response: $EXISTING_RECORD"
        return 1
    fi
    
    RECORD_COUNT=$(echo "$EXISTING_RECORD" | jq '.result | length')
    CURRENT_IP=$(echo "$EXISTING_RECORD" | jq -r '.result[0].content // empty')
    
    if [[ "$RECORD_COUNT" -eq 0 ]]; then
        # Create new record
        log_info "Creating new $record_type record for $record_name..."
        DNS_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$record_content\",\"ttl\":300}")
        
        if echo "$DNS_RESPONSE" | jq -e .success > /dev/null; then
            log_success "Created $record_type record for $record_name"
        else
            log_error "Failed to create $record_type record for $record_name"
            echo "Response: $DNS_RESPONSE"
            return 1
        fi
    elif [[ "$CURRENT_IP" != "$record_content" ]]; then
        # Update existing record
        RECORD_ID=$(echo "$EXISTING_RECORD" | jq -r '.result[0].id')
        log_info "Updating $record_type record for $record_name (was: $CURRENT_IP, now: $record_content)..."
        DNS_RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$RECORD_ID" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$record_content\",\"ttl\":300}")
        
        if echo "$DNS_RESPONSE" | jq -e .success > /dev/null; then
            log_success "Updated $record_type record for $record_name"
        else
            log_error "Failed to update $record_type record for $record_name"
            echo "Response: $DNS_RESPONSE"
            return 1
        fi
    else
        log_success "$record_type record for $record_name is already correct: $CURRENT_IP"
    fi
}

# Update root domain A record
update_dns_record "$DOMAIN_NAME" "A" "$SERVER_IP"

# Update www subdomain A record if requested
if [[ "$INCLUDE_WWW" == "true" ]]; then
    update_dns_record "www.$DOMAIN_NAME" "A" "$SERVER_IP"
fi

log_success "DNS A record(s) updated successfully"

# Exit early if DNS-only mode
if [[ "$DNS_ONLY" == "true" ]]; then
    log_success "DNS-only mode: Skipping SSL certificate generation and nginx configuration"
    log_success "🎉 DNS setup completed successfully!"
    exit 0
fi

# Step 3: Create Cloudflare credentials file for certbot
log_info "Setting up Cloudflare credentials for certbot..."
CLOUDFLARE_CREDS_FILE="/root/.cloudflare-credentials"
cat > "$CLOUDFLARE_CREDS_FILE" << EOF
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
chmod 600 "$CLOUDFLARE_CREDS_FILE"
log_success "Cloudflare credentials configured"

# Step 4: Wait for DNS propagation
log_info "Waiting for DNS propagation..."
sleep 30

# Verify DNS propagation
log_info "Verifying DNS propagation..."
for i in {1..12}; do
    if nslookup "$DOMAIN_NAME" 8.8.8.8 | grep -q "$SERVER_IP"; then
        log_success "DNS propagation confirmed"
        break
    fi
    
    if [[ $i -eq 12 ]]; then
        log_warning "DNS propagation taking longer than expected, continuing anyway..."
        break
    fi
    
    log_info "Waiting for DNS propagation... (attempt $i/12)"
    sleep 10
done

# Step 5: Generate SSL certificate
log_info "Generating SSL certificate with Let's Encrypt..."

STAGING_FLAG=""
if [[ "$STAGING_MODE" == "true" ]]; then
    STAGING_FLAG="--staging"
    log_warning "Using Let's Encrypt staging environment"
fi

# Run certbot with Cloudflare DNS challenge
CERT_DOMAINS="-d $DOMAIN_NAME"
if [[ "$INCLUDE_WWW" == "true" ]]; then
    CERT_DOMAINS="$CERT_DOMAINS -d www.$DOMAIN_NAME"
fi

# Add force renewal flag if requested
FORCE_RENEWAL_FLAG=""
if [[ "$FORCE_RENEWAL" == "true" ]]; then
    FORCE_RENEWAL_FLAG="--force-renewal"
fi

log_info "Generating SSL certificate for: $DOMAIN_NAME$([ "$INCLUDE_WWW" == "true" ] && echo " and www.$DOMAIN_NAME")"

if certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CLOUDFLARE_CREDS_FILE" \
    --email "$ADMIN_EMAIL" \
    --agree-tos \
    --non-interactive \
    --expand \
    $STAGING_FLAG \
    $FORCE_RENEWAL_FLAG \
    $CERT_DOMAINS; then
    log_success "SSL certificate generated successfully"
else
    log_error "Failed to generate SSL certificate"
    exit 1
fi

# Step 6: Configure nginx
log_info "Configuring nginx for HTTPS..."

# Create nginx configuration
SERVER_NAME="$DOMAIN_NAME"
if [[ "$INCLUDE_WWW" == "true" ]]; then
    SERVER_NAME="$DOMAIN_NAME www.$DOMAIN_NAME"
fi

cat > "$NGINX_CONFIG_PATH/$DOMAIN_NAME" << EOF
server {
    listen 80;
    server_name $SERVER_NAME;
    
    # Redirect all HTTP traffic to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $SERVER_NAME;
    
    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    # SSL optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Root and index
    root /var/www/html;
    index index.html index.htm;
    
    # Default location (customize as needed)
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Proxy to FKS application (if running on different port)
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable the site
ln -sf "$NGINX_CONFIG_PATH/$DOMAIN_NAME" "$NGINX_ENABLED_PATH/$DOMAIN_NAME"

# Test nginx configuration
if nginx -t; then
    log_success "Nginx configuration is valid"
else
    log_error "Nginx configuration test failed"
    exit 1
fi

# Step 7: Start/restart nginx
log_info "Starting nginx..."
systemctl enable nginx
systemctl restart nginx

# Verify nginx is running
if systemctl is-active nginx > /dev/null; then
    log_success "Nginx is running"
else
    log_error "Nginx failed to start"
    systemctl status nginx --no-pager
    exit 1
fi

# Step 8: Set up automatic certificate renewal
log_info "Setting up automatic certificate renewal..."

# Create renewal cron job
CRON_JOB="0 2 * * 0 certbot renew --quiet && systemctl reload nginx"
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -

log_success "Certificate auto-renewal configured (weekly check)"

# Step 9: Test HTTPS connection
log_info "Testing HTTPS connection..."
sleep 5

if curl -s -I "https://$DOMAIN_NAME" | grep -q "200 OK"; then
    log_success "HTTPS connection test passed"
elif curl -s -I "https://$DOMAIN_NAME" | grep -q "HTTP"; then
    log_success "HTTPS connection established (may show different status code)"
else
    log_warning "HTTPS connection test inconclusive - manual verification recommended"
fi

# Step 10: Display summary
echo ""
log_success "🎉 SSL setup completed successfully!"
echo ""
echo -e "${GREEN}📋 Summary:${NC}"
echo -e "  🌐 Domain: ${BLUE}$DOMAIN_NAME${NC}"
echo -e "  🔒 SSL Certificate: ${GREEN}✅ Generated${NC}"
echo -e "  ⚙️  Nginx Configuration: ${GREEN}✅ Configured${NC}"
echo -e "  🔄 Auto-renewal: ${GREEN}✅ Enabled${NC}"
echo -e "  📍 DNS A Record: ${GREEN}✅ Updated${NC}"
echo ""
echo -e "${GREEN}🌐 Your site is now available at:${NC}"
echo -e "  • ${BLUE}https://$DOMAIN_NAME${NC} (HTTPS - recommended)"
echo -e "  • ${BLUE}http://$DOMAIN_NAME${NC} (redirects to HTTPS)"
echo ""
echo -e "${GREEN}📝 Next steps:${NC}"
echo -e "  • ${YELLOW}Customize nginx configuration${NC} in $NGINX_CONFIG_PATH/$DOMAIN_NAME"
echo -e "  • ${YELLOW}Deploy your application${NC} behind the SSL proxy"
echo -e "  • ${YELLOW}Test certificate renewal${NC}: certbot renew --dry-run"
echo -e "  • ${YELLOW}Monitor certificate expiry${NC}: certbot certificates"
echo ""

# Clean up credentials file for security
rm -f "$CLOUDFLARE_CREDS_FILE"
log_info "Cleaned up temporary credentials file"

log_success "SSL setup script completed!"

# Step 6.5: Check for additional nginx subdomains
log_info "Checking for additional nginx subdomains..."
if [ -d "$NGINX_CONFIG_PATH" ]; then
    # Look for additional subdomains in nginx configurations
    ADDITIONAL_DOMAINS=$(find "$NGINX_CONFIG_PATH" -name "*.conf" -o -name "*.$DOMAIN_NAME" | xargs grep -h "server_name" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9-]+\.$DOMAIN_NAME" | grep -v "^$DOMAIN_NAME$" | grep -v "^www\.$DOMAIN_NAME$" | sort -u || true)
    
    if [ -n "$ADDITIONAL_DOMAINS" ]; then
        log_info "Found additional nginx subdomains, updating DNS records:"
        for subdomain in $ADDITIONAL_DOMAINS; do
            log_info "  - $subdomain"
            update_dns_record "$subdomain" "A" "$SERVER_IP"
        done
    else
        log_info "No additional nginx subdomains found"
    fi
else
    log_info "Nginx configuration directory not found, skipping subdomain detection"
fi
