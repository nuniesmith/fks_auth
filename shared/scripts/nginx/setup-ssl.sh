#!/bin/bash
# setup-ssl.sh - SSL/TLS certificate setup and configuration
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-ssl"
readonly SCRIPT_VERSION="3.0.0"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# SSL PREREQUISITES
# ============================================================================
setup_ssl_prerequisites() {
    log "Setting up SSL prerequisites..."
    
    # Create necessary directories
    mkdir -p /etc/letsencrypt
    mkdir -p /var/www/certbot
    mkdir -p /etc/nginx/ssl
    mkdir -p /var/log/letsencrypt
    
    # Set proper permissions
    chmod 755 /var/www/certbot
    chmod 700 /etc/letsencrypt
    chmod 755 /etc/nginx/ssl
    
    # Create certbot webroot
    chown http:http /var/www/certbot
    
    success "SSL directories created"
}

install_certbot_plugins() {
    log "Installing certbot plugins..."
    
    # Install Cloudflare plugin if API token is provided
    if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        log "Installing Cloudflare certbot plugin..."
        
        # Install via pip (more reliable than pacman for this plugin)
        if pip install --break-system-packages certbot-dns-cloudflare; then
            success "Cloudflare certbot plugin installed"
            create_cloudflare_credentials
        else
            warning "Failed to install Cloudflare plugin, will use HTTP challenge"
        fi
    else
        log "No Cloudflare API token provided, will use HTTP challenge"
    fi
    
    # Install additional useful plugins
    local plugins=("certbot-nginx")
    for plugin in "${plugins[@]}"; do
        if pacman -S --needed --noconfirm "$plugin" 2>/dev/null; then
            success "Installed certbot plugin: $plugin"
        else
            warning "Failed to install certbot plugin: $plugin"
        fi
    done
}

create_cloudflare_credentials() {
    log "Creating Cloudflare credentials file..."
    
    cat > /etc/letsencrypt/cloudflare.ini << EOF
# Cloudflare API token for DNS challenge
dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}
EOF
    
    chmod 600 /etc/letsencrypt/cloudflare.ini
    success "Cloudflare credentials file created"
}

configure_ssl_security() {
    log "Configuring SSL security settings..."
    
    # Generate DH parameters for better security (2048-bit for faster generation)
    if [[ ! -f /etc/nginx/ssl/dhparam.pem ]]; then
        log "Generating DH parameters (this may take a few minutes)..."
        openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
        success "DH parameters generated"
    fi
    
    # Create SSL configuration snippet
    cat > /etc/nginx/ssl/ssl-params.conf << 'EOF'
# SSL/TLS configuration
# Modern configuration for security and performance

# Protocols
ssl_protocols TLSv1.2 TLSv1.3;

# Cipher suites (modern configuration)
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# Prefer server ciphers
ssl_prefer_server_ciphers off;

# DH parameters
ssl_dhparam /etc/nginx/ssl/dhparam.pem;

# Session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/chain.pem;

# DNS resolvers for OCSP
resolver 8.8.8.8 8.8.4.4 1.1.1.1 valid=300s;
resolver_timeout 5s;

# Security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Content Security Policy (adjust as needed)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'self'; form-action 'self'; base-uri 'self';" always;
EOF
    
    success "SSL security configuration created"
}

create_cert_management_scripts() {
    log "Creating certificate management scripts..."
    
    # Certificate renewal script
    cat > /usr/local/bin/ssl-renew << 'EOF'
#!/bin/bash
# SSL certificate renewal script

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Configuration
DOMAIN="${DOMAIN_NAME:-7gram.xyz}"
LOG_FILE="/var/log/ssl-renewal.log"

# Logging
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

renew_certificates() {
    log "Starting certificate renewal check..."
    
    # Run certbot renewal
    if certbot renew --quiet --no-self-upgrade; then
        success "Certificate renewal check completed"
        
        # Check if any certificates were renewed
        if certbot certificates 2>/dev/null | grep -q "VALID: 89 days"; then
            log "Certificates were renewed, reloading nginx..."
            
            # Test nginx configuration
            if nginx -t; then
                systemctl reload nginx
                success "Nginx reloaded successfully"
                
                # Send notification
                send_renewal_notification "success" "SSL certificates renewed successfully"
            else
                error "Nginx configuration test failed after renewal"
                send_renewal_notification "error" "Nginx configuration test failed after SSL renewal"
                return 1
            fi
        else
            log "No certificates needed renewal"
        fi
        
        return 0
    else
        error "Certificate renewal failed"
        send_renewal_notification "error" "SSL certificate renewal failed"
        return 1
    fi
}

send_renewal_notification() {
    local status="$1"
    local message="$2"
    
    # Send Discord notification if webhook is configured
    local webhook_file="/etc/nginx-automation/deployment-config.json"
    if [[ -f "$webhook_file" ]]; then
        local webhook=$(jq -r '.discord_webhook // empty' "$webhook_file" 2>/dev/null)
        if [[ -n "$webhook" ]]; then
            local color
            case "$status" in
                success) color="3066993" ;;
                error) color="15158332" ;;
                *) color="16776960" ;;
            esac
            
            curl -s -H "Content-Type: application/json" \
                -d "{\"embeds\":[{\"title\":\"SSL Certificate Renewal - $(hostname)\",\"description\":\"$message\",\"color\":$color}]}" \
                "$webhook" >/dev/null 2>&1 || true
        fi
    fi
}

# Main execution
case "${1:-renew}" in
    renew)
        renew_certificates
        ;;
    check)
        log "Checking certificate status..."
        certbot certificates
        ;;
    force-renew)
        log "Forcing certificate renewal..."
        certbot renew --force-renewal --no-self-upgrade
        nginx -t && systemctl reload nginx
        ;;
    *)
        echo "Usage: $0 [renew|check|force-renew]"
        echo ""
        echo "Commands:"
        echo "  renew       - Check and renew certificates if needed (default)"
        echo "  check       - Show certificate status"
        echo "  force-renew - Force renewal of all certificates"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/ssl-renew
    
    # Certificate monitoring script
    cat > /usr/local/bin/ssl-check << 'EOF'
#!/bin/bash
# SSL certificate monitoring script

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_certificate_status() {
    local domain="$1"
    
    echo "=== SSL Certificate Status for $domain ==="
    echo ""
    
    # Check if certificate exists
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    if [[ ! -f "$cert_path" ]]; then
        echo -e "${RED}❌ Certificate not found${NC}"
        return 1
    fi
    
    # Get certificate information
    local cert_info
    cert_info=$(openssl x509 -in "$cert_path" -text -noout 2>/dev/null)
    
    if [[ -n "$cert_info" ]]; then
        # Extract expiration date
        local expire_date
        expire_date=$(echo "$cert_info" | grep "Not After" | sed 's/.*Not After : //')
        
        # Calculate days until expiration
        local expire_epoch
        expire_epoch=$(date -d "$expire_date" +%s 2>/dev/null)
        local current_epoch
        current_epoch=$(date +%s)
        local days_left
        days_left=$(( (expire_epoch - current_epoch) / 86400 ))
        
        # Show status with color coding
        echo "Certificate Details:"
        echo "  Domain: $domain"
        echo "  Expires: $expire_date"
        
        if [[ $days_left -gt 30 ]]; then
            echo -e "  Status: ${GREEN}✅ Valid ($days_left days remaining)${NC}"
        elif [[ $days_left -gt 7 ]]; then
            echo -e "  Status: ${YELLOW}⚠️ Expiring soon ($days_left days remaining)${NC}"
        else
            echo -e "  Status: ${RED}🚨 Expiring very soon ($days_left days remaining)${NC}"
        fi
        
        # Show subject alternative names
        local san
        san=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/.*DNS://' | tr ',' '\n' | sed 's/^ */  - /')
        if [[ -n "$san" ]]; then
            echo ""
            echo "Subject Alternative Names:"
            echo "$san"
        fi
        
        # Check OCSP stapling
        echo ""
        echo "OCSP Stapling Test:"
        if openssl s_client -connect "$domain:443" -servername "$domain" -status -verify_return_error </dev/null 2>/dev/null | grep -q "OCSP Response Status: successful"; then
            echo -e "  ${GREEN}✅ OCSP stapling working${NC}"
        else
            echo -e "  ${YELLOW}⚠️ OCSP stapling not working${NC}"
        fi
        
    else
        echo -e "${RED}❌ Unable to read certificate${NC}"
        return 1
    fi
}

test_ssl_configuration() {
    local domain="$1"
    
    echo ""
    echo "=== SSL Configuration Test ==="
    echo ""
    
    # Test SSL Labs rating (if available)
    echo "Testing SSL configuration..."
    
    # Test cipher suites
    echo "Supported protocols:"
    for protocol in tls1_2 tls1_3; do
        echo -n "  $protocol: "
        if openssl s_client -connect "$domain:443" -servername "$domain" -"$protocol" -verify_return_error </dev/null >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Supported${NC}"
        else
            echo -e "${RED}❌ Not supported${NC}"
        fi
    done
    
    # Test HSTS
    echo ""
    echo -n "HSTS header: "
    if curl -sI "https://$domain" 2>/dev/null | grep -qi "strict-transport-security"; then
        echo -e "${GREEN}✅ Present${NC}"
    else
        echo -e "${YELLOW}⚠️ Missing${NC}"
    fi
    
    # Test redirect
    echo -n "HTTP to HTTPS redirect: "
    local redirect_status
    redirect_status=$(curl -s -o /dev/null -w "%{http_code}" "http://$domain" 2>/dev/null)
    if [[ "$redirect_status" =~ ^30[12]$ ]]; then
        echo -e "${GREEN}✅ Working (HTTP $redirect_status)${NC}"
    else
        echo -e "${RED}❌ Not working (HTTP $redirect_status)${NC}"
    fi
}

# Main execution
DOMAIN="${1:-${DOMAIN_NAME:-7gram.xyz}}"

if [[ "$DOMAIN" == "help" ]] || [[ "$DOMAIN" == "--help" ]] || [[ "$DOMAIN" == "-h" ]]; then
    echo "Usage: $0 [domain]"
    echo ""
    echo "Check SSL certificate status and configuration"
    echo "If no domain is specified, uses DOMAIN_NAME from config"
    exit 0
fi

show_certificate_status "$DOMAIN"
test_ssl_configuration "$DOMAIN"
EOF
    
    chmod +x /usr/local/bin/ssl-check
    
    success "SSL management scripts created"
}

setup_ssl_monitoring() {
    log "Setting up SSL monitoring..."
    
    # Create SSL monitoring script
    cat > /usr/local/bin/ssl-monitor << 'EOF'
#!/bin/bash
# SSL certificate monitoring and alerting

set -euo pipefail

# Configuration
DOMAIN="${DOMAIN_NAME:-7gram.xyz}"
WARNING_DAYS=30
CRITICAL_DAYS=7
LOG_FILE="/var/log/ssl-monitor.log"

# Logging
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

check_certificate_expiry() {
    local domain="$1"
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    
    if [[ ! -f "$cert_path" ]]; then
        log "ERROR: Certificate not found for $domain"
        return 2
    fi
    
    # Get expiration date
    local expire_date
    expire_date=$(openssl x509 -in "$cert_path" -enddate -noout | cut -d= -f2)
    
    # Calculate days until expiration
    local expire_epoch
    expire_epoch=$(date -d "$expire_date" +%s)
    local current_epoch
    current_epoch=$(date +%s)
    local days_left
    days_left=$(( (expire_epoch - current_epoch) / 86400 ))
    
    log "INFO: Certificate for $domain expires in $days_left days"
    
    # Check thresholds
    if [[ $days_left -le $CRITICAL_DAYS ]]; then
        log "CRITICAL: Certificate for $domain expires in $days_left days"
        send_alert "critical" "$domain" "$days_left"
        return 2
    elif [[ $days_left -le $WARNING_DAYS ]]; then
        log "WARNING: Certificate for $domain expires in $days_left days"
        send_alert "warning" "$domain" "$days_left"
        return 1
    else
        log "INFO: Certificate for $domain is healthy ($days_left days remaining)"
        return 0
    fi
}

send_alert() {
    local level="$1"
    local domain="$2"
    local days_left="$3"
    
    local webhook_file="/etc/nginx-automation/deployment-config.json"
    if [[ -f "$webhook_file" ]]; then
        local webhook
        webhook=$(jq -r '.discord_webhook // empty' "$webhook_file" 2>/dev/null)
        
        if [[ -n "$webhook" ]]; then
            local color
            local emoji
            case "$level" in
                critical)
                    color="15158332"
                    emoji="🚨"
                    ;;
                warning)
                    color="16776960"
                    emoji="⚠️"
                    ;;
            esac
            
            local message="$emoji SSL Certificate Alert

**Domain:** $domain
**Days remaining:** $days_left
**Level:** ${level^^}

Please renew the certificate soon to avoid service disruption."
            
            curl -s -H "Content-Type: application/json" \
                -d "{\"embeds\":[{\"title\":\"SSL Certificate Alert - $(hostname)\",\"description\":\"$message\",\"color\":$color}]}" \
                "$webhook" >/dev/null 2>&1 || true
        fi
    fi
}

# Main execution
main() {
    log "Starting SSL certificate monitoring"
    
    # Check primary domain
    local exit_code=0
    check_certificate_expiry "$DOMAIN" || exit_code=$?
    
    # Check additional domains if they exist
    local additional_domains=("www.$DOMAIN")
    for additional_domain in "${additional_domains[@]}"; do
        if [[ -d "/etc/letsencrypt/live/$additional_domain" ]]; then
            check_certificate_expiry "$additional_domain" || exit_code=$?
        fi
    done
    
    log "SSL monitoring completed with exit code: $exit_code"
    exit $exit_code
}

main "$@"
EOF
    
    chmod +x /usr/local/bin/ssl-monitor
    
    # Add SSL monitoring to cron (daily check)
    (crontab -l 2>/dev/null; echo "0 8 * * * /usr/local/bin/ssl-monitor >/dev/null 2>&1") | crontab -
    
    success "SSL monitoring configured"
}

setup_ssl_renewal() {
    log "Setting up automatic SSL renewal..."
    
    # Add renewal to cron (twice daily)
    (crontab -l 2>/dev/null; echo "0 12,0 * * * /usr/local/bin/ssl-renew >/dev/null 2>&1") | crontab -
    
    # Create systemd timer as backup
    cat > /etc/systemd/system/ssl-renewal.service << 'EOF'
[Unit]
Description=SSL Certificate Renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ssl-renew
User=root
StandardOutput=journal
StandardError=journal
EOF
    
    cat > /etc/systemd/system/ssl-renewal.timer << 'EOF'
[Unit]
Description=Run SSL renewal twice daily
Requires=ssl-renewal.service

[Timer]
OnCalendar=*-*-* 12,0:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable ssl-renewal.timer
    
    success "Automatic SSL renewal configured"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting SSL setup..."
    
    # Check if SSL is enabled
    if [[ "${ENABLE_SSL:-true}" != "true" ]]; then
        log "SSL is disabled, skipping SSL setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "SSL disabled"
        return 0
    fi
    
    # Validate domain
    local domain="${DOMAIN_NAME:-7gram.xyz}"
    if [[ "$domain" == "localhost" ]] || ! validate_domain "$domain"; then
        warning "Invalid domain '$domain', skipping SSL setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "Invalid domain"
        return 0
    fi
    
    # Setup SSL infrastructure
    setup_ssl_prerequisites
    install_certbot_plugins
    configure_ssl_security
    create_cert_management_scripts
    setup_ssl_monitoring
    setup_ssl_renewal
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "SSL setup completed successfully"
    log "SSL certificates will be requested during post-reboot phase"
    log "Use 'ssl-check' to monitor certificate status"
    log "Use 'ssl-renew' to manually renew certificates"
}

# Execute main function
main "$@"