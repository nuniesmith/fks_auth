#!/bin/bash
#
# FKS Trading Systems - Setup DNS Subdomains
# This script creates/updates all necessary DNS records for FKS services
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
SERVER_IP=""
CLOUDFLARE_API_TOKEN=""
CLOUDFLARE_ZONE_ID=""
CREATE_MONITORING="true"

# List of subdomains to create
SUBDOMAINS=(
    "www"           # WWW subdomain
    "api"           # API backend
    "web"           # Web frontend
    "docs"          # Documentation
    "ws"            # WebSocket
)

# Optional monitoring subdomains
MONITORING_SUBDOMAINS=(
    "grafana"       # Grafana monitoring
    "netdata"       # Netdata monitoring
)

# Usage function
usage() {
    echo "Usage: $0 --domain DOMAIN --server-ip IP --api-token TOKEN --zone-id ZONE_ID [options]"
    echo ""
    echo "Required parameters:"
    echo "  --domain DOMAIN           Base domain name (e.g., fkstrading.xyz)"
    echo "  --server-ip IP            Server IP address"
    echo "  --api-token TOKEN         Cloudflare API token"
    echo "  --zone-id ZONE_ID         Cloudflare Zone ID"
    echo ""
    echo "Optional parameters:"
    echo "  --no-monitoring           Skip monitoring subdomains (grafana, netdata)"
    echo "  --help                    Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --server-ip)
            SERVER_IP="$2"
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
        --no-monitoring)
            CREATE_MONITORING="false"
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
if [[ -z "$DOMAIN_NAME" || -z "$SERVER_IP" || -z "$CLOUDFLARE_API_TOKEN" || -z "$CLOUDFLARE_ZONE_ID" ]]; then
    log_error "Missing required parameters"
    usage
fi

log_info "Setting up DNS records for FKS services"
log_info "Domain: $DOMAIN_NAME"
log_info "Server IP: $SERVER_IP"

# Function to create/update DNS record
update_dns_record() {
    local record_name="$1"
    local record_type="A"
    local record_content="$SERVER_IP"
    local full_name="$record_name"
    
    # Handle root domain
    if [[ "$record_name" == "@" ]]; then
        full_name="$DOMAIN_NAME"
    elif [[ "$record_name" != "$DOMAIN_NAME" ]]; then
        full_name="$record_name.$DOMAIN_NAME"
    fi
    
    log_info "Processing DNS record: $full_name"
    
    # Check if record exists
    EXISTING_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=$record_type&name=$full_name" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    if ! echo "$EXISTING_RECORD" | jq -e .success > /dev/null; then
        log_error "Failed to fetch DNS records for $full_name"
        echo "Response: $EXISTING_RECORD"
        return 1
    fi
    
    RECORD_COUNT=$(echo "$EXISTING_RECORD" | jq '.result | length')
    CURRENT_IP=$(echo "$EXISTING_RECORD" | jq -r '.result[0].content // empty')
    
    if [[ "$RECORD_COUNT" -eq 0 ]]; then
        # Create new record
        log_info "Creating new A record for $full_name..."
        DNS_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$full_name\",\"content\":\"$record_content\",\"ttl\":300,\"proxied\":false}")
        
        if echo "$DNS_RESPONSE" | jq -e .success > /dev/null; then
            log_success "Created A record for $full_name → $record_content"
        else
            log_error "Failed to create A record for $full_name"
            echo "Response: $DNS_RESPONSE"
            return 1
        fi
    elif [[ "$CURRENT_IP" != "$record_content" ]]; then
        # Update existing record
        RECORD_ID=$(echo "$EXISTING_RECORD" | jq -r '.result[0].id')
        log_info "Updating A record for $full_name (was: $CURRENT_IP)..."
        DNS_RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$RECORD_ID" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$full_name\",\"content\":\"$record_content\",\"ttl\":300,\"proxied\":false}")
        
        if echo "$DNS_RESPONSE" | jq -e .success > /dev/null; then
            log_success "Updated A record for $full_name → $record_content"
        else
            log_error "Failed to update A record for $full_name"
            echo "Response: $DNS_RESPONSE"
            return 1
        fi
    else
        log_success "A record for $full_name is already correct: $CURRENT_IP"
    fi
}

# Create/update root domain
log_info "Setting up root domain..."
update_dns_record "@"

# Create/update all service subdomains
log_info "Setting up service subdomains..."
for subdomain in "${SUBDOMAINS[@]}"; do
    update_dns_record "$subdomain"
done

# Create/update monitoring subdomains if enabled
if [[ "$CREATE_MONITORING" == "true" ]]; then
    log_info "Setting up monitoring subdomains..."
    for subdomain in "${MONITORING_SUBDOMAINS[@]}"; do
        update_dns_record "$subdomain"
    done
else
    log_info "Skipping monitoring subdomains (--no-monitoring specified)"
fi

# Create a wildcard CNAME for future services (optional)
log_info "Checking wildcard record..."
WILDCARD_NAME="*.$DOMAIN_NAME"
WILDCARD_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=CNAME&name=$WILDCARD_NAME" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json")

if echo "$WILDCARD_RECORD" | jq -e '.result | length == 0' > /dev/null; then
    log_info "Creating wildcard CNAME record..."
    WILDCARD_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"CNAME\",\"name\":\"*\",\"content\":\"$DOMAIN_NAME\",\"ttl\":300,\"proxied\":false}")
    
    if echo "$WILDCARD_RESPONSE" | jq -e .success > /dev/null; then
        log_success "Created wildcard CNAME record"
    else
        log_warning "Could not create wildcard CNAME (may conflict with A records)"
    fi
else
    log_info "Wildcard record already exists"
fi

# Summary
echo ""
log_success "DNS setup completed successfully!"
echo ""
echo -e "${GREEN}📋 DNS Records Created/Updated:${NC}"
echo -e "  • ${BLUE}$DOMAIN_NAME${NC} → $SERVER_IP"
for subdomain in "${SUBDOMAINS[@]}"; do
    echo -e "  • ${BLUE}$subdomain.$DOMAIN_NAME${NC} → $SERVER_IP"
done
if [[ "$CREATE_MONITORING" == "true" ]]; then
    for subdomain in "${MONITORING_SUBDOMAINS[@]}"; do
        echo -e "  • ${BLUE}$subdomain.$DOMAIN_NAME${NC} → $SERVER_IP"
    done
fi
echo ""
echo -e "${YELLOW}⏱️  DNS propagation may take up to 48 hours${NC}"
echo -e "${YELLOW}💡 Use 'dig' or 'nslookup' to verify DNS records${NC}"
echo ""

# Test DNS resolution
log_info "Testing DNS resolution..."
for test_domain in "$DOMAIN_NAME" "api.$DOMAIN_NAME" "web.$DOMAIN_NAME"; do
    if nslookup "$test_domain" 8.8.8.8 2>/dev/null | grep -q "$SERVER_IP"; then
        log_success "$test_domain resolves to $SERVER_IP"
    else
        log_warning "$test_domain not yet resolving (propagation pending)"
    fi
done

log_success "DNS subdomain setup script completed!"
