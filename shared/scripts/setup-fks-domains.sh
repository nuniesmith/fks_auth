#!/bin/bash

# FKS Trading Systems - Domain Setup Script
# This script helps configure DNS records for FKS Trading subdomains

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# FKS Trading Domain Configuration
DOMAIN="fkstrading.xyz"
TAILSCALE_IP="${TAILSCALE_IP:-}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"

# FKS Service Subdomains and their target ports
declare -A FKS_SERVICES=(
    ["app"]="3001"        # React frontend
    ["api"]="8000"        # Main API server
    ["data"]="9001"       # Data stream service
    ["db"]="5432"         # PostgreSQL database
    ["cache"]="6379"      # Redis cache
    ["worker"]="8001"     # Worker service
    ["ninja"]="7496"      # NinjaTrader connection
    ["code"]="8081"       # VS Code server
    ["monitor"]="3000"    # Monitoring dashboard
    ["grafana"]="3001"    # Grafana (if used)
    ["prometheus"]="9090" # Prometheus (if used)
    ["nodes"]="8080"      # Node network
    ["training"]="8088"   # AI training service
    ["transformer"]="8089" # Transformer service
)

print_banner() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "  FKS Trading Domain Setup"
    echo "=================================="
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_tailscale_ip() {
    if [[ -n "$TAILSCALE_IP" ]]; then
        print_info "Using provided Tailscale IP: $TAILSCALE_IP"
        return 0
    fi

    if command -v tailscale >/dev/null 2>&1; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | head -1)
        if [[ -n "$TAILSCALE_IP" ]]; then
            print_info "Detected Tailscale IP: $TAILSCALE_IP"
            return 0
        fi
    fi

    print_error "Could not detect Tailscale IP address"
    print_info "Please set TAILSCALE_IP environment variable or install Tailscale"
    return 1
}

check_cloudflare_config() {
    if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
        print_warning "CLOUDFLARE_API_TOKEN not set"
        print_info "You'll need to manually create DNS records in Cloudflare"
        return 1
    fi

    if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then
        print_warning "CLOUDFLARE_ZONE_ID not set"
        print_info "You'll need to manually create DNS records in Cloudflare"
        return 1
    fi

    return 0
}

create_cloudflare_record() {
    local subdomain="$1"
    local ip="$2"
    local record_type="A"

    print_info "Creating DNS record: ${subdomain}.${DOMAIN} -> ${ip}"

    if ! check_cloudflare_config; then
        return 1
    fi

    local response
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"${record_type}\",\"name\":\"${subdomain}\",\"content\":\"${ip}\",\"ttl\":300}")

    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        print_info "✓ Created ${subdomain}.${DOMAIN}"
        return 0
    else
        local errors
        errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"' 2>/dev/null || echo "API request failed")
        print_error "✗ Failed to create ${subdomain}.${DOMAIN}: ${errors}"
        return 1
    fi
}

list_dns_records() {
    print_step "FKS Trading DNS Records Configuration"
    echo
    print_info "Domain: ${DOMAIN}"
    print_info "Tailscale IP: ${TAILSCALE_IP}"
    echo
    print_info "Required DNS A Records:"
    echo

    for subdomain in "${!FKS_SERVICES[@]}"; do
        local port="${FKS_SERVICES[$subdomain]}"
        printf "  %-15s -> %-15s (Port %s)\n" "${subdomain}.${DOMAIN}" "${TAILSCALE_IP}" "${port}"
    done

    echo
    print_info "Main application URLs:"
    echo "  • Frontend:     https://app.${DOMAIN}"
    echo "  • API:          https://api.${DOMAIN}"
    echo "  • Data Stream:  https://data.${DOMAIN}"
    echo "  • VS Code:      https://code.${DOMAIN}"
    echo "  • Monitoring:   https://monitor.${DOMAIN}"
    echo
}

create_all_records() {
    print_step "Creating DNS records in Cloudflare"
    
    local success_count=0
    local total_count=${#FKS_SERVICES[@]}

    for subdomain in "${!FKS_SERVICES[@]}"; do
        if create_cloudflare_record "$subdomain" "$TAILSCALE_IP"; then
            ((success_count++))
        fi
        sleep 1  # Rate limiting
    done

    echo
    print_info "Created ${success_count}/${total_count} DNS records"
    
    if [[ $success_count -eq $total_count ]]; then
        print_info "✓ All DNS records created successfully!"
        return 0
    else
        print_warning "Some DNS records failed to create"
        return 1
    fi
}

generate_manual_instructions() {
    print_step "Manual DNS Configuration Instructions"
    echo
    print_info "If automatic creation failed, add these A records in Cloudflare:"
    echo

    for subdomain in "${!FKS_SERVICES[@]}"; do
        echo "  Name: ${subdomain}"
        echo "  Type: A"
        echo "  Content: ${TAILSCALE_IP}"
        echo "  TTL: 300 (5 minutes)"
        echo "  Proxy status: DNS only (gray cloud)"
        echo
    done
}

generate_nginx_config() {
    print_step "Generating Nginx reverse proxy configuration"
    
    local nginx_config="/home/jordan/fks/config/networking/nginx/fks_domains.conf"
    
    cat > "$nginx_config" <<EOF
# FKS Trading Systems - Domain-based Reverse Proxy Configuration
# Generated by setup-fks_domains.sh

EOF

    for subdomain in "${!FKS_SERVICES[@]}"; do
        local port="${FKS_SERVICES[$subdomain]}"
        cat >> "$nginx_config" <<EOF
# ${subdomain}.${DOMAIN} -> Port ${port}
server {
    listen 80;
    listen 443 ssl http2;
    server_name ${subdomain}.${DOMAIN};

    # SSL configuration (if using SSL)
    ssl_certificate /etc/ssl/certs/${DOMAIN}.crt;
    ssl_certificate_key /etc/ssl/private/${DOMAIN}.key;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        #!/usr/bin/env bash
        # Shim: setup-fks_domains moved to domains/infra/dns/setup-fks_domains.sh
        set -euo pipefail
        NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/domains/infra/dns/setup-fks_domains.sh"
        if [[ -f "$NEW_PATH" ]]; then
            exec "$NEW_PATH" "$@"
        else
            echo "[WARN] Expected relocated script not found: $NEW_PATH" >&2
            echo "TODO: restore full domain setup logic under domains/infra/dns/setup-fks_domains.sh" >&2
            exit 2
        fi
    if ! command -v curl >/dev/null 2>&1; then
        print_error "curl is required but not installed"
        exit 1
    fi

    # Detect Tailscale IP
    if ! detect_tailscale_ip; then
        exit 1
    fi

    # Show what will be configured
    list_dns_records

    # Ask for confirmation
    echo
    read -p "Do you want to proceed with DNS record creation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled"
        exit 0
    fi

    # Try automatic creation
    if check_cloudflare_config; then
        if create_all_records; then
            print_info "✓ DNS records created successfully!"
        else
            print_warning "Some records failed, see manual instructions below"
            generate_manual_instructions
        fi
    else
        generate_manual_instructions
    fi

    # Generate additional configurations
    generate_nginx_config
    update_environment_files

    # Test DNS resolution (after a delay for propagation)
    print_info "Waiting 30 seconds for DNS propagation..."
    sleep 30
    test_dns_resolution

    echo
    print_info "Domain setup completed!"
    print_info "Next steps:"
    echo "  1. Configure your nginx server with the generated config"
    echo "  2. Set up SSL certificates (Let's Encrypt recommended)"
    echo "  3. Restart your FKS services"
    echo "  4. Test the new domain endpoints"
    echo
}

# Handle script arguments
case "${1:-}" in
    "list")
        detect_tailscale_ip && list_dns_records
        ;;
    "test")
        detect_tailscale_ip && test_dns_resolution
        ;;
    "nginx")
        detect_tailscale_ip && generate_nginx_config
        ;;
    "manual")
        detect_tailscale_ip && generate_manual_instructions
        ;;
    *)
        main "$@"
        ;;
esac
