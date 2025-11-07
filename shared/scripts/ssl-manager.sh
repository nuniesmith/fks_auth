#!/bin/bash
# ssl-manager.sh
# SSL Certificate Management for FKS Web Service
# Adapted from nginx SSL management with FKS-specific configurations

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/ssl"
LETSENCRYPT_DIR="$PROJECT_ROOT/ssl/letsencrypt"
SELF_SIGNED_DIR="$PROJECT_ROOT/ssl/self-signed"
LOG_FILE="/var/log/fks_ssl-manager.log"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
API_DOMAIN="${API_DOMAIN:-api.fkstrading.xyz}"
AUTH_DOMAIN="${AUTH_DOMAIN:-auth.fkstrading.xyz}"
EMAIL="${LETSENCRYPT_EMAIL:-admin@${DOMAIN_NAME}}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

# Create directory structure
setup_directories() {
    log_info "📁 Setting up SSL directory structure..."
    mkdir -p "$SSL_DIR" "$LETSENCRYPT_DIR" "$SELF_SIGNED_DIR"
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
}

# Generate Diffie-Hellman parameters
generate_dhparam() {
    local dhparam_file="$SSL_DIR/dhparam.pem"
    
    if [ ! -f "$dhparam_file" ]; then
        log_info "🔐 Generating Diffie-Hellman parameters (this may take a while)..."
        openssl dhparam -out "$dhparam_file" 2048
        chmod 644 "$dhparam_file"
        log_success "✅ DH parameters generated"
    else
        log_info "✅ DH parameters already exist"
    fi
}

# Generate self-signed certificates for FKS domains
generate_self_signed() {
    local cert_dir="$SELF_SIGNED_DIR"
    
    log_info "🔒 Generating self-signed certificates for FKS domains..."
    
    # Generate DH parameters first
    generate_dhparam
    
    # Create certificate configuration with multiple domains
    cat > "$cert_dir/openssl.cnf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=CA
ST=Ontario
L=Toronto
O=FKS Trading
OU=IT Department
CN=$DOMAIN_NAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
#!/usr/bin/env bash
# Shim: ssl-manager moved to domains/ssl/manager.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/domains/ssl/manager.sh"
if [[ -f "$NEW_PATH" ]]; then
    exec "$NEW_PATH" "$@"
else
    echo "[WARN] Expected relocated script not found: $NEW_PATH" >&2
    echo "TODO: restore full ssl-manager implementation under domains/ssl/manager.sh" >&2
    exit 2
fi
    mkdir -p "$PROJECT_ROOT/config/certbot"
    cat > "$PROJECT_ROOT/config/certbot/cloudflare.ini" << EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
    chmod 600 "$PROJECT_ROOT/config/certbot/cloudflare.ini"
    
    # Run certbot with DNS-01 challenge for multiple domains
    if docker run --rm \
        -v "$LETSENCRYPT_DIR:/etc/letsencrypt" \
        -v "$PROJECT_ROOT/config/certbot:/etc/letsencrypt/config" \
        certbot/dns-cloudflare:latest \
        certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/config/cloudflare.ini \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        -d "$DOMAIN_NAME" \
        -d "$API_DOMAIN" \
        -d "$AUTH_DOMAIN" \
        -d "*.$DOMAIN_NAME" 2>&1 | tee -a "$LOG_FILE"; then
        
        log_success "✅ Let's Encrypt certificates generated successfully"
        return 0
    else
        log_error "❌ Failed to generate Let's Encrypt certificates"
        return 1
    fi
}

# Generate Let's Encrypt certificate using HTTP-01 challenge for main domain
generate_letsencrypt_http() {
    local domain="$DOMAIN_NAME"
    local webroot="/var/www/certbot"
    
    log_info "🔐 Generating Let's Encrypt certificate for $domain using HTTP-01..."
    
    # Ensure webroot directory exists
    mkdir -p "$webroot"
    
    # Run certbot with HTTP-01 challenge for main domain only
    if docker run --rm \
        -v "$LETSENCRYPT_DIR:/etc/letsencrypt" \
        -v "$webroot:/var/www/certbot" \
        -v "$PROJECT_ROOT/config/certbot:/etc/letsencrypt/config" \
        certbot/certbot:latest \
        certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        -d "$domain" 2>&1 | tee -a "$LOG_FILE"; then
        
        log_success "✅ Let's Encrypt certificate generated successfully"
        return 0
    else
        log_error "❌ Failed to generate Let's Encrypt certificate"
        return 1
    fi
}

# Link active certificates
link_certificate() {
    local source_dir="$1"
    local domain="$DOMAIN_NAME"
    
    log_info "🔗 Linking active certificates..."
    
    # Create active certificate links
    if [ -f "$source_dir/$domain.crt" ] && [ -f "$source_dir/$domain.key" ]; then
        ln -sf "$source_dir/$domain.crt" "$SSL_DIR/server.crt"
        ln -sf "$source_dir/$domain.key" "$SSL_DIR/server.key"
        
        # Create domain-specific links for nginx
        ln -sf "$source_dir/$domain.crt" "$SSL_DIR/$domain.crt"
        ln -sf "$source_dir/$domain.key" "$SSL_DIR/$domain.key"
        
        log_success "✅ Certificate linked successfully"
        return 0
    else
        log_error "❌ Certificate files not found in $source_dir"
        return 1
    fi
}

# Link Let's Encrypt certificate
link_letsencrypt() {
    local domain="$DOMAIN_NAME"
    local le_live="$LETSENCRYPT_DIR/live/$domain"
    
    if [ -f "$le_live/fullchain.pem" ] && [ -f "$le_live/privkey.pem" ]; then
        ln -sf "$le_live/fullchain.pem" "$SSL_DIR/server.crt"
        ln -sf "$le_live/privkey.pem" "$SSL_DIR/server.key"
        ln -sf "$le_live/fullchain.pem" "$SSL_DIR/$domain.crt"
        ln -sf "$le_live/privkey.pem" "$SSL_DIR/$domain.key"
        
        log_success "✅ Let's Encrypt certificates linked successfully"
        return 0
    else
        log_error "❌ Let's Encrypt certificate files not found"
        return 1
    fi
}

# Reload nginx
reload_nginx() {
    log_info "🔄 Reloading FKS web nginx..."
    
    if docker-compose -f "$PROJECT_ROOT/docker-compose.web.yml" exec nginx nginx -t; then
        if docker-compose -f "$PROJECT_ROOT/docker-compose.web.yml" exec nginx nginx -s reload; then
            log_success "✅ Nginx reloaded successfully"
            return 0
        else
            log_error "❌ Failed to reload nginx"
            return 1
        fi
    else
        log_error "❌ Nginx configuration test failed"
        return 1
    fi
}

# Check certificate expiry
check_certificate_expiry() {
    local cert_file="$1"
    local days_threshold="${2:-30}"
    
    if [ ! -f "$cert_file" ]; then
        return 1
    fi
    
    local expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    log_info "📅 Certificate expires in $days_until_expiry days"
    
    if [ "$days_until_expiry" -lt "$days_threshold" ]; then
        log_warn "⚠️  Certificate expires in less than $days_threshold days"
        return 1
    fi
    
    return 0
}

# Renew Let's Encrypt certificate
renew_letsencrypt() {
    log_info "🔄 Renewing Let's Encrypt certificates..."
    
    if docker run --rm \
        -v "$LETSENCRYPT_DIR:/etc/letsencrypt" \
        -v "/var/www/certbot:/var/www/certbot" \
        certbot/certbot:latest \
        renew --webroot --webroot-path=/var/www/certbot --quiet 2>&1 | tee -a "$LOG_FILE"; then
        
        log_success "✅ Certificate renewal completed"
        return 0
    else
        log_error "❌ Certificate renewal failed"
        return 1
    fi
}

# Main certificate management function
manage_certificate() {
    log_info "🚀 Starting SSL certificate management for FKS domains"
    log_info "📋 Domains: $DOMAIN_NAME, $API_DOMAIN, $AUTH_DOMAIN"
    
    setup_directories
    
    # Always generate self-signed as fallback
    generate_self_signed
    link_certificate "$SELF_SIGNED_DIR"
    
    # Try to get Let's Encrypt certificate
    local letsencrypt_success=false
    
    # Try DNS-01 challenge first (preferred for multi-domain)
    if [ -n "${CLOUDFLARE_EMAIL:-}" ] && [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
        log_info "🔄 Attempting DNS-01 challenge for multi-domain certificate..."
        if generate_letsencrypt_dns; then
            link_letsencrypt
            letsencrypt_success=true
        fi
    fi
    
    # Fallback to HTTP-01 for main domain if DNS-01 failed
    if [ "$letsencrypt_success" = false ] && check_domain_accessibility "$DOMAIN_NAME"; then
        log_info "🔄 Falling back to HTTP-01 challenge for main domain..."
        if generate_letsencrypt_http; then
            link_letsencrypt
            letsencrypt_success=true
        fi
    fi
    
    if [ "$letsencrypt_success" = true ]; then
        log_success "🎉 Using Let's Encrypt certificates"
        echo "letsencrypt" > "$SSL_DIR/cert_type"
    else
        log_warn "⚠️  Using self-signed certificates as fallback"
        echo "self-signed" > "$SSL_DIR/cert_type"
    fi
    
    # Reload nginx if it's running
    if docker-compose -f "$PROJECT_ROOT/docker-compose.web.yml" ps nginx | grep -q "Up"; then
        reload_nginx
    fi
    
    log_success "✅ SSL certificate management completed for FKS"
}

# Renewal function for cron/systemd
renew_certificates() {
    log_info "🔄 Starting certificate renewal check for FKS..."
    
    # Check if we have a Let's Encrypt certificate
    if [ -f "$SSL_DIR/cert_type" ] && [ "$(cat "$SSL_DIR/cert_type")" = "letsencrypt" ]; then
        local cert_file="$SSL_DIR/server.crt"
        
        if check_certificate_expiry "$cert_file" 30; then
            log_info "✅ Certificate is still valid, no renewal needed"
            return 0
        fi
        
        log_info "🔄 Certificate needs renewal, attempting renewal..."
        if renew_letsencrypt; then
            reload_nginx
            log_success "✅ Certificate renewed successfully"
        else
            log_error "❌ Certificate renewal failed, keeping existing certificate"
        fi
    else
        log_info "ℹ️  Using self-signed certificate, checking if Let's Encrypt is now possible..."
        manage_certificate
    fi
}

# Certificate status
show_status() {
    echo -e "${BLUE}📋 FKS SSL Certificate Status${NC}"
    echo "Domains: $DOMAIN_NAME, $API_DOMAIN, $AUTH_DOMAIN"
    
    if [ -f "$SSL_DIR/cert_type" ]; then
        local cert_type=$(cat "$SSL_DIR/cert_type")
        echo "Certificate Type: $cert_type"
    fi
    
    if [ -f "$SSL_DIR/server.crt" ]; then
        echo -e "\n${GREEN}Active Certificate Details:${NC}"
        openssl x509 -in "$SSL_DIR/server.crt" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After :|DNS:)"
        
        local expiry_date=$(openssl x509 -enddate -noout -in "$SSL_DIR/server.crt" | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        echo -e "\n${YELLOW}Expiry: $expiry_date ($days_until_expiry days remaining)${NC}"
    else
        echo -e "${RED}❌ No active certificate found${NC}"
    fi
}

# Help function
show_help() {
    cat << EOF
FKS SSL Certificate Manager

Usage: $0 [COMMAND]

Commands:
    setup       Initial SSL certificate setup (default)
    renew       Renew existing certificates
    self-signed Generate only self-signed certificate
    letsencrypt Generate only Let's Encrypt certificate
    status      Show certificate status
    help        Show this help message

Environment Variables:
    DOMAIN_NAME          Main domain (default: fkstrading.xyz)
    API_DOMAIN           API domain (default: api.fkstrading.xyz)
    AUTH_DOMAIN          Auth domain (default: auth.fkstrading.xyz)
    LETSENCRYPT_EMAIL    Email for Let's Encrypt registration
    CLOUDFLARE_EMAIL     Cloudflare account email (for DNS challenge)
    CLOUDFLARE_API_TOKEN Cloudflare API token (for DNS challenge)

Examples:
    $0 setup                    # Initial setup with fallback
    $0 renew                    # Renew certificates
    DOMAIN_NAME=test.fks.com $0 setup
EOF
}

# Main execution
main() {
    local command="${1:-setup}"
    
    case "$command" in
        setup)
            manage_certificate
            ;;
        renew)
            renew_certificates
            ;;
        self-signed)
            setup_directories
            generate_self_signed
            link_certificate "$SELF_SIGNED_DIR"
            echo "self-signed" > "$SSL_DIR/cert_type"
            ;;
        letsencrypt)
            setup_directories
            if generate_letsencrypt_dns || generate_letsencrypt_http; then
                link_letsencrypt
                echo "letsencrypt" > "$SSL_DIR/cert_type"
            fi
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
