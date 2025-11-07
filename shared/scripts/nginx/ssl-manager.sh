#!/bin/bash
# Comprehensive SSL Certificate Management with Self-Signed Fallback
# Handles Let's Encrypt certificate generation, renewal, and fallback to self-signed

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/ssl"
LETSENCRYPT_DIR="$PROJECT_ROOT/ssl/letsencrypt"
SELF_SIGNED_DIR="$PROJECT_ROOT/ssl/self-signed"
LOG_FILE="/var/log/nginx-ssl/manager.log"
DOMAIN_NAME="${DOMAIN_NAME:-7gram.xyz}"
EMAIL="${LETSENCRYPT_EMAIL:-admin@${DOMAIN_NAME}}"

# Detect Docker Compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    COMPOSE_CMD="docker compose"  # Default to modern format
fi

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
    
    # Ensure log file exists and is writable
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/nginx-ssl-manager.log"
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

# Generate self-signed certificates
generate_self_signed() {
    local domain="$1"
    local cert_dir="$SELF_SIGNED_DIR"
    
    log_info "🔒 Generating self-signed certificate for $domain..."
    
    # Generate DH parameters first
    generate_dhparam
    
    # Create certificate configuration
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
O=Development
OU=IT Department
CN=$domain

[v3_req]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = *.$domain
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    # Generate private key
    openssl genrsa -out "$cert_dir/$domain.key" 4096
    
    # Generate certificate
    openssl req -new -x509 -key "$cert_dir/$domain.key" \
        -out "$cert_dir/$domain.crt" \
        -days 365 \
        -config "$cert_dir/openssl.cnf" \
        -extensions v3_req
    
    # Set proper permissions
    chmod 600 "$cert_dir/$domain.key"
    chmod 644 "$cert_dir/$domain.crt"
    
    log_success "✅ Self-signed certificate generated successfully"
    return 0
}

# Check if domain is accessible from internet
check_domain_accessibility() {
    local domain="$1"
    
    log_info "🌐 Checking if $domain is accessible from internet..."
    
    # Try to resolve domain
    if ! dig +short "$domain" >/dev/null 2>&1; then
        log_warn "⚠️  Domain $domain does not resolve"
        return 1
    fi
    
    # Check if port 80 is accessible (required for HTTP-01 challenge)
    if ! timeout 10 bash -c "echo >/dev/tcp/$(dig +short "$domain")/80" 2>/dev/null; then
        log_warn "⚠️  Port 80 is not accessible on $domain"
        return 1
    fi
    
    log_success "✅ Domain $domain is accessible"
    return 0
}

# Generate Let's Encrypt certificate using HTTP-01 challenge
generate_letsencrypt_http() {
    local domain="$1"
    local webroot="/var/www/certbot"
    
    log_info "🔐 Generating Let's Encrypt certificate for $domain using HTTP-01..."
    
    # Ensure webroot directory exists
    mkdir -p "$webroot"
    
    # Run certbot with HTTP-01 challenge
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

# Generate Let's Encrypt certificate using DNS-01 challenge (Cloudflare)
generate_letsencrypt_dns() {
    local domain="$1"
    
    log_info "🔐 Generating Let's Encrypt certificate for $domain using DNS-01..."
    
    # Check for Cloudflare credentials
    if [ -z "${CLOUDFLARE_EMAIL:-}" ] || [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
        log_error "❌ Cloudflare credentials not found"
        return 1
    fi
    
    # Create Cloudflare credentials file
    mkdir -p "$PROJECT_ROOT/config/certbot"
    cat > "$PROJECT_ROOT/config/certbot/cloudflare.ini" << EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
    chmod 600 "$PROJECT_ROOT/config/certbot/cloudflare.ini"
    
    # Run certbot with DNS-01 challenge
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
        -d "$domain" \
        -d "*.$domain" 2>&1 | tee -a "$LOG_FILE"; then
        
        log_success "✅ Let's Encrypt certificate generated successfully"
        return 0
    else
        log_error "❌ Failed to generate Let's Encrypt certificate"
        return 1
    fi
}

# Link active certificate
link_certificate() {
    local source_dir="$1"
    local domain="$2"

    log_info "🔗 Linking active certificate (relative symlinks)..."

    # Create active certificate links
    if [ -f "$source_dir/$domain.crt" ] && [ -f "$source_dir/$domain.key" ]; then
        mkdir -p "$SSL_DIR"
        # Use relative symlinks so they resolve inside the container mount
        ln -srf "$source_dir/$domain.crt" "$SSL_DIR/server.crt"
        ln -srf "$source_dir/$domain.key" "$SSL_DIR/server.key"

        # Create domain-specific links for nginx
        ln -srf "$source_dir/$domain.crt" "$SSL_DIR/$domain.crt"
        ln -srf "$source_dir/$domain.key" "$SSL_DIR/$domain.key"

        chmod 644 "$SSL_DIR/server.crt" "$SSL_DIR/$domain.crt" 2>/dev/null || true
        chmod 600 "$SSL_DIR/server.key" "$SSL_DIR/$domain.key" 2>/dev/null || true

        log_success "✅ Certificate linked successfully"
        return 0
    else
        log_error "❌ Certificate files not found in $source_dir"
        return 1
    fi
}

# Link Let's Encrypt certificate
link_letsencrypt() {
    local domain="$1"
    local le_live="$LETSENCRYPT_DIR/live/$domain"

    if [ -f "$le_live/fullchain.pem" ] && [ -f "$le_live/privkey.pem" ]; then
        mkdir -p "$SSL_DIR"
        # Use relative symlinks from ssl/ to ssl/letsencrypt/... so they resolve in-container
        ln -srf "$le_live/fullchain.pem" "$SSL_DIR/server.crt"
        ln -srf "$le_live/privkey.pem"  "$SSL_DIR/server.key"
        ln -srf "$le_live/fullchain.pem" "$SSL_DIR/$domain.crt"
        ln -srf "$le_live/privkey.pem"  "$SSL_DIR/$domain.key"

        chmod 644 "$SSL_DIR/server.crt" "$SSL_DIR/$domain.crt" 2>/dev/null || true
        chmod 600 "$SSL_DIR/server.key" "$SSL_DIR/$domain.key" 2>/dev/null || true

        log_success "✅ Let's Encrypt certificate linked successfully"
        return 0
    else
        log_error "❌ Let's Encrypt certificate files not found in $le_live"
        return 1
    fi
}

# Reload nginx
reload_nginx() {
    log_info "🔄 Reloading nginx..."
    
    # Check if nginx container is running first
    if ! docker ps --filter "name=nginx" --filter "status=running" --format "{{.Names}}" | grep -q "nginx"; then
        log_warn "⚠️ Nginx container is not running, cannot reload"
        return 1
    fi
    
    # Use the compose command determined earlier
    if $COMPOSE_CMD exec nginx nginx -t 2>/dev/null; then
        if $COMPOSE_CMD exec nginx nginx -s reload 2>/dev/null; then
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
    local domain="$DOMAIN_NAME"
    
    log_info "🚀 Starting SSL certificate management for $domain"
    
    setup_directories
    
    # Always generate self-signed as fallback
    generate_self_signed "$domain"
    link_certificate "$SELF_SIGNED_DIR" "$domain"
    
    # Try to get Let's Encrypt certificate
    local letsencrypt_success=false
    
    if check_domain_accessibility "$domain"; then
        # Try HTTP-01 challenge first
        if generate_letsencrypt_http "$domain"; then
            link_letsencrypt "$domain"
            letsencrypt_success=true
        # Fallback to DNS-01 if HTTP-01 fails and credentials are available
        elif [ -n "${CLOUDFLARE_EMAIL:-}" ] && [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
            log_info "🔄 Falling back to DNS-01 challenge..."
            if generate_letsencrypt_dns "$domain"; then
                link_letsencrypt "$domain"
                letsencrypt_success=true
            fi
        fi
    else
        # Domain not accessible, try DNS-01 if credentials available
        if [ -n "${CLOUDFLARE_EMAIL:-}" ] && [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
            log_info "🔄 Domain not accessible, trying DNS-01 challenge..."
            if generate_letsencrypt_dns "$domain"; then
                link_letsencrypt "$domain"
                letsencrypt_success=true
            fi
        fi
    fi
    
    if [ "$letsencrypt_success" = true ]; then
        log_success "🎉 Using Let's Encrypt certificate"
        echo "letsencrypt" > "$SSL_DIR/cert_type"
    else
        log_warn "⚠️  Using self-signed certificate as fallback"
        echo "self-signed" > "$SSL_DIR/cert_type"
    fi
    
    # Reload nginx if it's running
    if docker ps --filter "name=nginx" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q "nginx"; then
        reload_nginx
    else
        log_info "ℹ️ Nginx container not running, skipping reload"
    fi
    
    log_success "✅ SSL certificate management completed"
}

# Renewal function for cron/systemd
renew_certificates() {
    local domain="$DOMAIN_NAME"
    
    log_info "🔄 Starting certificate renewal check..."
    
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

# Help function
show_help() {
    cat << EOF
SSL Certificate Manager

Usage: $0 [COMMAND]

Commands:
    setup       Initial SSL certificate setup (default)
    renew       Renew existing certificates
    self-signed Generate only self-signed certificate
    letsencrypt Generate only Let's Encrypt certificate
    status      Show certificate status
    help        Show this help message

Environment Variables:
    DOMAIN_NAME          Domain name for certificate (default: nginx.7gram.xyz)
    LETSENCRYPT_EMAIL    Email for Let's Encrypt registration
    CLOUDFLARE_EMAIL     Cloudflare account email (for DNS challenge)
    CLOUDFLARE_API_TOKEN Cloudflare API token (for DNS challenge)

Examples:
    $0 setup                    # Initial setup with fallback
    $0 renew                    # Renew certificates
    DOMAIN_NAME=example.com $0 setup
EOF
}

# Certificate status
show_status() {
    local domain="$DOMAIN_NAME"
    
    echo -e "${BLUE}📋 SSL Certificate Status${NC}"
    echo "Domain: $domain"
    
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
            generate_self_signed "$DOMAIN_NAME"
            link_certificate "$SELF_SIGNED_DIR" "$DOMAIN_NAME"
            echo "self-signed" > "$SSL_DIR/cert_type"
            ;;
        letsencrypt)
            setup_directories
            if generate_letsencrypt_http "$DOMAIN_NAME" || generate_letsencrypt_dns "$DOMAIN_NAME"; then
                link_letsencrypt "$DOMAIN_NAME"
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
