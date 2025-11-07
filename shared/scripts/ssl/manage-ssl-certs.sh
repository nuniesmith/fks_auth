#!/bin/bash

# FKS SSL Certificate Management Script
# Manages Let's Encrypt SSL certificates for fkstrading.xyz and subdomains
# Designed to work with Tailscale VPN-only setup

set -euo pipefail

# Configuration
DOMAIN="${DOMAIN:-fkstrading.xyz}"
EMAIL="${ADMIN_EMAIL:-${LETSENCRYPT_EMAIL:-nunie.smith01@gmail.com}}"
WEBROOT_PATH="${WEBROOT_PATH:-/var/www/html}"
CERT_PATH="/etc/letsencrypt/live"
LOG_FILE="/var/log/fks_ssl-manager.log"
STAGING="${STAGING:-false}"

# Subdomains to include in certificate
SUBDOMAINS=(
    "www"
    "api"
    "data"
    "worker"
    "nodes"
    "auth"
    "monitor"
    "admin"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${1}" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${1//\\033\[[0-9;]*m/}" >> "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "${RED}❌ This script must be run as root${NC}"
        exit 1
    fi
}

# Install certbot if not present
install_certbot() {
    log "${BLUE}🔍 Checking if certbot is installed...${NC}"
    
    if command -v certbot >/dev/null 2>&1; then
        log "${GREEN}✅ Certbot already installed${NC}"
        return 0
    fi
    
    log "${YELLOW}📦 Installing certbot...${NC}"
    
    # Detect package manager and install certbot
    if command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        pacman -S --noconfirm certbot certbot-nginx
    elif command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS
        yum install -y certbot python3-certbot-nginx
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora
        dnf install -y certbot python3-certbot-nginx
    else
        log "${RED}❌ Unsupported package manager. Please install certbot manually.${NC}"
        exit 1
    fi
    
    log "${GREEN}✅ Certbot installed successfully${NC}"
}

# Setup nginx if not configured
setup_nginx() {
    log "${BLUE}🔍 Checking nginx configuration...${NC}"
    
    # Create webroot directory
    mkdir -p "$WEBROOT_PATH"
    chown -R nginx:nginx "$WEBROOT_PATH" 2>/dev/null || chown -R www-data:www-data "$WEBROOT_PATH" 2>/dev/null || true
    
    # Create basic nginx configuration for ACME challenge
    if [ ! -f "/etc/nginx/sites-available/fks_ssl" ] && [ ! -f "/etc/nginx/conf.d/fks_ssl.conf" ]; then
        log "${YELLOW}📝 Creating nginx configuration for SSL setup...${NC}"
        
        # Determine nginx config location
        if [ -d "/etc/nginx/sites-available" ]; then
            NGINX_CONFIG="/etc/nginx/sites-available/fks_ssl"
            NGINX_ENABLED="/etc/nginx/sites-enabled/fks_ssl"
        else
            NGINX_CONFIG="/etc/nginx/conf.d/fks_ssl.conf"
            NGINX_ENABLED=""
        fi
        
        # Build domain list for nginx
        ALL_DOMAINS="$DOMAIN"
        for subdomain in "${SUBDOMAINS[@]}"; do
            ALL_DOMAINS="$ALL_DOMAINS $subdomain.$DOMAIN"
        done
        
        cat > "$NGINX_CONFIG" << EOF
# FKS SSL Certificate Setup Configuration
# This configuration handles ACME challenges for Let's Encrypt

server {
    listen 80;
    listen [::]:80;
    
    server_name $ALL_DOMAINS;
    
    # ACME challenge location
    location /.well-known/acme-challenge/ {
        root $WEBROOT_PATH;
        try_files \$uri =404;
    }
    
    # Redirect everything else to HTTPS (after SSL is configured)
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
        
        # Enable site if using sites-available structure
        if [ -n "$NGINX_ENABLED" ]; then
            ln -sf "$NGINX_CONFIG" "$NGINX_ENABLED"
        fi
        
        # Test and reload nginx
        if nginx -t; then
            systemctl reload nginx
            log "${GREEN}✅ Nginx configuration created and reloaded${NC}"
        else
            log "${RED}❌ Nginx configuration test failed${NC}"
            exit 1
        fi
    else
        log "${GREEN}✅ Nginx configuration already exists${NC}"
    fi
}

# Generate SSL certificate
generate_certificate() {
    log "${BLUE}🔐 Generating SSL certificate for $DOMAIN and subdomains...${NC}"
    
    # Build domain arguments for certbot
    DOMAIN_ARGS="-d $DOMAIN"
    for subdomain in "${SUBDOMAINS[@]}"; do
        DOMAIN_ARGS="$DOMAIN_ARGS -d $subdomain.$DOMAIN"
    done
    
    # Add staging flag if specified
    STAGING_FLAG=""
    if [ "$STAGING" = "true" ]; then
        STAGING_FLAG="--staging"
        log "${YELLOW}⚠️ Using Let's Encrypt staging environment${NC}"
    fi
    
    # Run certbot
    log "${BLUE}🚀 Running certbot...${NC}"
    
    if certbot certonly \
        --webroot \
        --webroot-path="$WEBROOT_PATH" \
        $DOMAIN_ARGS \
        --email "$EMAIL" \
        --agree-tos \
        --non-interactive \
        --expand \
        $STAGING_FLAG; then
        
        log "${GREEN}✅ SSL certificate generated successfully!${NC}"
        return 0
    else
        log "${RED}❌ Failed to generate SSL certificate${NC}"
        return 1
    fi
}

# Configure nginx with SSL
configure_ssl_nginx() {
    log "${BLUE}🔧 Configuring nginx with SSL...${NC}"
    
    # Create SSL configuration
    SSL_CONFIG="/etc/nginx/conf.d/fks_ssl-enabled.conf"
    
    cat > "$SSL_CONFIG" << EOF
# FKS Trading Systems - SSL Configuration
# Generated by FKS SSL Manager

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    
    server_name $DOMAIN $(printf "%s.$DOMAIN " "${SUBDOMAINS[@]}")";
    
    # ACME challenge location
    location /.well-known/acme-challenge/ {
        root $WEBROOT_PATH;
        try_files \$uri =404;
    }
    
    # Redirect to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS configuration for main domain
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name $DOMAIN www.$DOMAIN;
    
    # SSL configuration
    ssl_certificate $CERT_PATH/$DOMAIN/fullchain.pem;
    ssl_certificate_key $CERT_PATH/$DOMAIN/privkey.pem;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Document root
    root $WEBROOT_PATH;
    index index.html index.htm;
    
    # Default location
    location / {
        try_files \$uri \$uri/ =404;
    }
}

# HTTPS configuration for API services
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name api.$DOMAIN data.$DOMAIN worker.$DOMAIN;
    
    # SSL configuration
    ssl_certificate $CERT_PATH/$DOMAIN/fullchain.pem;
    ssl_certificate_key $CERT_PATH/$DOMAIN/privkey.pem;
    
    # SSL settings (same as above)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Proxy to Docker services
    location / {
        proxy_pass http://localhost:8080;  # Adjust port as needed
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# HTTPS configuration for admin services
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name auth.$DOMAIN monitor.$DOMAIN admin.$DOMAIN;
    
    # SSL configuration
    ssl_certificate $CERT_PATH/$DOMAIN/fullchain.pem;
    ssl_certificate_key $CERT_PATH/$DOMAIN/privkey.pem;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Proxy to admin services
    location / {
        proxy_pass http://localhost:9000;  # Adjust port as needed
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # Test nginx configuration
    if nginx -t; then
        systemctl reload nginx
        log "${GREEN}✅ Nginx SSL configuration applied successfully${NC}"
    else
        log "${RED}❌ Nginx SSL configuration test failed${NC}"
        return 1
    fi
}

# Setup auto-renewal
setup_auto_renewal() {
    log "${BLUE}⏰ Setting up automatic certificate renewal...${NC}"
    
    # Create renewal hook script
    RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/fks_renewal.sh"
    mkdir -p "$(dirname "$RENEWAL_HOOK")"
    
    cat > "$RENEWAL_HOOK" << 'EOF'
#!/bin/bash
# FKS SSL Certificate Renewal Hook

# Reload nginx after renewal
systemctl reload nginx

# Log renewal
echo "$(date): FKS SSL certificates renewed" >> /var/log/fks_ssl-manager.log
EOF
    
    chmod +x "$RENEWAL_HOOK"
    
    # Test renewal (dry run)
    log "${BLUE}🧪 Testing certificate renewal...${NC}"
    if certbot renew --dry-run; then
        log "${GREEN}✅ Certificate renewal test successful${NC}"
    else
        log "${YELLOW}⚠️ Certificate renewal test failed, but certificates are still valid${NC}"
    fi
}

# Status check
check_status() {
    log "${BLUE}📊 SSL Certificate Status:${NC}"
    
    if [ -d "$CERT_PATH/$DOMAIN" ]; then
        # Show certificate info
        openssl x509 -in "$CERT_PATH/$DOMAIN/cert.pem" -text -noout | grep -E "(Subject:|DNS:|Not After)" || true
        
        # Show expiry date
        EXPIRY=$(openssl x509 -in "$CERT_PATH/$DOMAIN/cert.pem" -noout -enddate | cut -d= -f2)
        log "${GREEN}📅 Certificate expires: $EXPIRY${NC}"
        
        # Check if certificate is valid
        if openssl x509 -in "$CERT_PATH/$DOMAIN/cert.pem" -checkend 86400 -noout >/dev/null; then
            log "${GREEN}✅ Certificate is valid for at least 24 hours${NC}"
        else
            log "${YELLOW}⚠️ Certificate expires within 24 hours${NC}"
        fi
    else
        log "${RED}❌ No certificate found for $DOMAIN${NC}"
        return 1
    fi
}

# Clean up function
cleanup() {
    log "${BLUE}🧹 Cleaning up SSL certificates...${NC}"
    
    # Remove certificates
    if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        certbot delete --cert-name "$DOMAIN" --non-interactive
        log "${GREEN}✅ SSL certificates removed${NC}"
    fi
    
    # Remove nginx configurations
    rm -f "/etc/nginx/sites-available/fks_ssl" "/etc/nginx/sites-enabled/fks_ssl"
    rm -f "/etc/nginx/conf.d/fks_ssl.conf" "/etc/nginx/conf.d/fks_ssl-enabled.conf"
    
    # Reload nginx
    nginx -t && systemctl reload nginx
    
    log "${GREEN}✅ SSL cleanup completed${NC}"
}

# Main function
main() {
    case "${1:-}" in
        "install")
            log "${BLUE}🚀 Installing SSL certificates for $DOMAIN...${NC}"
            check_root
            install_certbot
            setup_nginx
            generate_certificate
            configure_ssl_nginx
            setup_auto_renewal
            check_status
            log "${GREEN}🎉 SSL certificate installation completed!${NC}"
            ;;
        "renew")
            log "${BLUE}🔄 Renewing SSL certificates...${NC}"
            check_root
            certbot renew
            log "${GREEN}✅ Certificate renewal completed${NC}"
            ;;
        "status")
            check_status
            ;;
        "cleanup")
            check_root
            cleanup
            ;;
        "test")
            log "${BLUE}🧪 Testing SSL setup...${NC}"
            STAGING=true
            check_root
            install_certbot
            setup_nginx
            generate_certificate
            log "${GREEN}✅ SSL test completed (staging certificates)${NC}"
            ;;
        *)
            echo "FKS SSL Certificate Manager"
            echo ""
            echo "Usage: $0 {install|renew|status|cleanup|test}"
            echo ""
            echo "Commands:"
            echo "  install  - Install SSL certificates for fkstrading.xyz and subdomains"
            echo "  renew    - Renew existing certificates"
            echo "  status   - Check certificate status"
            echo "  cleanup  - Remove certificates and configurations"
            echo "  test     - Test installation using staging certificates"
            echo ""
            echo "Environment variables:"
            echo "  DOMAIN            - Main domain (default: fkstrading.xyz)"
            echo "  ADMIN_EMAIL       - Email for Let's Encrypt (default: nunie.smith01@gmail.com)"
            echo "  WEBROOT_PATH      - Webroot path (default: /var/www/html)"
            echo "  STAGING           - Use staging environment (default: false)"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
