#!/bin/bash
#
# FKS Trading Systems - Cloudflare DNS Update Script
# Updates DNS records for main domain and service subdomains
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Default values
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
SERVER_IP="${SERVER_IP:-}"
UPDATE_SUBDOMAINS="${UPDATE_SUBDOMAINS:-true}"
DRY_RUN="${DRY_RUN:-false}"

# Service subdomains for Docker containers
SUBDOMAINS=(
    "api"        # API Gateway
    "app"        # Main application
    "admin"      # Admin panel
    "ws"         # WebSocket server
    "grafana"    # Grafana monitoring
    "prometheus" # Prometheus metrics
    "redis"      # Redis admin (if needed)
    "docs"       # Documentation
    "monitor"    # System monitoring
    "status"     # Status page
)

# Usage function
usage() {
    echo "Usage: $0 --server-ip IP [options]"
    echo ""
    echo "Required parameters:"
    echo "  --server-ip IP           Server IP address"
    echo ""
    echo "Optional parameters:"
    echo "  --domain DOMAIN          Domain name (default: $DOMAIN_NAME)"
    echo "  --api-token TOKEN        Cloudflare API token (or use CLOUDFLARE_API_TOKEN env var)"
    echo "  --zone-id ZONE_ID        Cloudflare Zone ID (or use CLOUDFLARE_ZONE_ID env var)"
    echo "  --no-subdomains          Skip updating service subdomains"
    echo "  --dry-run                Show what would be updated without making changes"
    echo "  --help                   Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  CLOUDFLARE_API_TOKEN     Cloudflare API token"
    echo "  CLOUDFLARE_ZONE_ID       Cloudflare Zone ID"
    echo "  DOMAIN_NAME              Domain name (default: fkstrading.xyz)"
    echo ""
    echo "Examples:"
    echo "  $0 --server-ip 192.168.1.100"
    echo "  $0 --server-ip 192.168.1.100 --domain example.com --no-subdomains"
    echo "  $0 --server-ip 192.168.1.100 --dry-run"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-ip)
            SERVER_IP="$2"
            shift 2
            ;;
        --domain)
            DOMAIN_NAME="$2"
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
        --no-subdomains)
            UPDATE_SUBDOMAINS="false"
            shift
            ;;
        --dry-run)
            DRY_RUN="true"
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
if [[ -z "$SERVER_IP" ]]; then
    log_error "Server IP is required"
    usage
fi

if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
    log_error "Cloudflare API token is required (use --api-token or CLOUDFLARE_API_TOKEN env var)"
    usage
fi

if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then
    log_error "Cloudflare Zone ID is required (use --zone-id or CLOUDFLARE_ZONE_ID env var)"
    usage
fi

# Validate IP address format
if ! [[ "$SERVER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    log_error "Invalid IP address format: $SERVER_IP"
    exit 1
fi

# Check if required tools are available
if ! command -v curl &> /dev/null; then
    log_error "curl is required but not installed"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    log_error "jq is required but not installed"
    exit 1
fi

log_info "Starting DNS update for $DOMAIN_NAME"
log_info "Server IP: $SERVER_IP"
log_info "Update subdomains: $UPDATE_SUBDOMAINS"
log_info "Dry run: $DRY_RUN"

# Function to get DNS record ID
get_dns_record_id() {
    local record_name="$1"
    local record_type="$2"
    
    local response=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=$record_name&type=$record_type" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    echo "$response" | jq -r '.result[0].id // empty'
}

# Function to create or update DNS record
update_dns_record() {
    local record_name="$1"
    local record_type="$2"
    local record_content="$3"
    local record_ttl="${4:-300}"
    local proxied="${5:-false}"
    
    log_info "Processing DNS record: $record_name ($record_type) -> $record_content"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would update $record_name ($record_type) to $record_content"
        return 0
    fi
    
    # Check if record exists
    local record_id=$(get_dns_record_id "$record_name" "$record_type")
    
    if [[ -n "$record_id" ]]; then
        # Update existing record
        log_info "Updating existing record: $record_name"
        local response=$(curl -s -X PUT \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"$record_type\",
                \"name\": \"$record_name\",
                \"content\": \"$record_content\",
                \"ttl\": $record_ttl,
                \"proxied\": $proxied
            }")
    else
        # Create new record
        log_info "Creating new record: $record_name"
        local response=$(curl -s -X POST \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"$record_type\",
                \"name\": \"$record_name\",
                \"content\": \"$record_content\",
                \"ttl\": $record_ttl,
                \"proxied\": $proxied
            }")
    fi
    
    # Check if the request was successful
    local success=$(echo "$response" | jq -r '.success')
    if [[ "$success" == "true" ]]; then
        log_success "Successfully updated $record_name"
    else
        local errors=$(echo "$response" | jq -r '.errors[] | .message' 2>/dev/null || echo "Unknown error")
        log_error "Failed to update $record_name: $errors"
        return 1
    fi
}

# Update main domain records
log_info "Updating main domain records..."

# Root domain (A record)
update_dns_record "$DOMAIN_NAME" "A" "$SERVER_IP" 300 false

# www subdomain (A record)
update_dns_record "www.$DOMAIN_NAME" "A" "$SERVER_IP" 300 false

# Update service subdomains if requested
if [[ "$UPDATE_SUBDOMAINS" == "true" ]]; then
    log_info "Updating service subdomains..."
    
    for subdomain in "${SUBDOMAINS[@]}"; do
        update_dns_record "$subdomain.$DOMAIN_NAME" "A" "$SERVER_IP" 300 false
    done
fi

# Create CNAME for wildcard subdomain support (optional)
log_info "Creating wildcard CNAME for additional subdomains..."
update_dns_record "*.$DOMAIN_NAME" "CNAME" "$DOMAIN_NAME" 300 false

log_success "DNS update completed successfully!"

# Display summary
echo ""
log_info "DNS Records Summary:"
echo "  Root domain: $DOMAIN_NAME -> $SERVER_IP"
echo "  WWW subdomain: www.$DOMAIN_NAME -> $SERVER_IP"

if [[ "$UPDATE_SUBDOMAINS" == "true" ]]; then
    echo "  Service subdomains:"
    for subdomain in "${SUBDOMAINS[@]}"; do
        echo "    $subdomain.$DOMAIN_NAME -> $SERVER_IP"
    done
fi

echo "  Wildcard CNAME: *.$DOMAIN_NAME -> $DOMAIN_NAME"

echo ""
log_info "You can now access your services at:"
echo "  Main site: https://$DOMAIN_NAME"
echo "  WWW site: https://www.$DOMAIN_NAME"

if [[ "$UPDATE_SUBDOMAINS" == "true" ]]; then
    echo "  API: https://api.$DOMAIN_NAME"
    echo "  App: https://app.$DOMAIN_NAME"
    echo "  Admin: https://admin.$DOMAIN_NAME"
    echo "  Monitoring: https://grafana.$DOMAIN_NAME"
    echo "  Status: https://status.$DOMAIN_NAME"
fi

echo ""
log_success "DNS configuration ready for SSL setup!"
