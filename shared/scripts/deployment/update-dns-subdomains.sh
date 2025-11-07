#!/bin/bash

# FKS Trading Systems - Cloudflare DNS Subdomain Update Script
# Updates DNS records for subdomains (api, data, worker, etc.)

set -e
set -o pipefail

# Configuration
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
SERVER_IP="${SERVER_IP:-}"
USE_TAILSCALE="${USE_TAILSCALE:-false}"
TAILSCALE_IP="${TAILSCALE_IP:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "🔍 Checking prerequisites..."
    
    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        error "CLOUDFLARE_API_TOKEN not set"
        return 1
    fi
    
    if [ -z "$CLOUDFLARE_ZONE_ID" ]; then
        error "CLOUDFLARE_ZONE_ID not set"
        return 1
    fi
    
    if [ -z "$SERVER_IP" ] && [ -z "$TAILSCALE_IP" ]; then
        error "Neither SERVER_IP nor TAILSCALE_IP is set"
        return 1
    fi
    
    # Check if we have curl
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        return 1
    fi
    
    # Check if we have jq
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed"
        return 1
    fi
    
    log "✅ Prerequisites check passed"
    return 0
}

# Function to get existing DNS record
get_dns_record() {
    local record_name="$1"
    local record_type="${2:-A}"
    
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name=${record_name}&type=${record_type}" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json")
    
    echo "$response" | jq -r '.result[0].id // empty'
}

# Function to create or update DNS record
update_dns_record() {
    local subdomain="$1"
    local ip_address="$2"
    local proxied="${3:-false}"
    local ttl="${4:-120}"
    local comment="${5:-}"
    
    # Construct full record name
    local record_name="${subdomain}.${DOMAIN_NAME}"
    if [ "$subdomain" = "@" ]; then
        record_name="$DOMAIN_NAME"
    fi
    
    log "🔍 Checking DNS record for ${record_name}..."
    
    # Check if record exists
    local record_id=$(get_dns_record "$record_name" "A")
    
    local dns_data=$(cat <<EOF
{
    "type": "A",
    "name": "${record_name}",
    "content": "${ip_address}",
    "ttl": ${ttl},
    "proxied": ${proxied}
}
EOF
)

    if [ -n "$comment" ]; then
        dns_data=$(echo "$dns_data" | jq --arg comment "$comment" '. + {comment: $comment}')
    fi
    
    if [ -n "$record_id" ]; then
        # Update existing record
        log "🔄 Updating existing record for ${record_name}..."
        local response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${record_id}" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "$dns_data")
        
        if echo "$response" | jq -e '.success' > /dev/null; then
            log "✅ Updated ${record_name} -> ${ip_address}"
        else
            error "Failed to update ${record_name}"
            echo "$response" | jq '.errors'
            return 1
        fi
    else
        # Create new record
        log "✨ Creating new record for ${record_name}..."
        local response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "$dns_data")
        
        if echo "$response" | jq -e '.success' > /dev/null; then
            log "✅ Created ${record_name} -> ${ip_address}"
        else
            error "Failed to create ${record_name}"
            echo "$response" | jq '.errors'
            return 1
        fi
    fi
}

# Main function
main() {
    log "🚀 FKS Trading Systems - DNS Subdomain Update"
    log "==========================================="
    log "📋 Configuration:"
    log "  - Domain: $DOMAIN_NAME"
    log "  - Public IP: ${SERVER_IP:-Not set}"
    log "  - Tailscale IP: ${TAILSCALE_IP:-Not set}"
    log "  - Use Tailscale: $USE_TAILSCALE"
    log ""
    
    # Check prerequisites
    check_prerequisites || exit 1
    
    # Determine which IP to use
    local target_ip="$SERVER_IP"
    local ip_type="Public"
    if [ "$USE_TAILSCALE" = "true" ] && [ -n "$TAILSCALE_IP" ]; then
        target_ip="$TAILSCALE_IP"
        ip_type="Tailscale"
    fi
    
    log "🎯 Using $ip_type IP: $target_ip"
    log ""
    
    # Define subdomains to update
    # Format: subdomain:proxied:ttl:comment
    local subdomains=(
        "@:false:120:Main domain"
        "www:false:120:WWW subdomain"
        "api:false:120:API service"
        "data:false:120:Data service"
        "worker:false:120:Worker service"
        "nodes:false:120:Node network"
        "auth:false:120:Authentik SSO"
        "monitor:false:120:Monitoring service"
        "admin:false:120:Admin interface"
    )
    
    # Process each subdomain
    local success_count=0
    local total_count=${#subdomains[@]}
    
    for subdomain_config in "${subdomains[@]}"; do
        IFS=':' read -r subdomain proxied ttl comment <<< "$subdomain_config"
        
        if update_dns_record "$subdomain" "$target_ip" "$proxied" "$ttl" "$comment"; then
            ((success_count++))
        fi
        
        # Small delay to avoid rate limiting
        sleep 0.5
    done
    
    log ""
    log "📊 Summary:"
    log "  - Total subdomains: $total_count"
    log "  - Successfully updated: $success_count"
    log "  - Failed: $((total_count - success_count))"
    
    if [ "$success_count" -eq "$total_count" ]; then
        log "✅ All DNS records updated successfully!"
        
        # Display the configured subdomains
        log ""
        log "🌐 Configured subdomains:"
        log "  - https://${DOMAIN_NAME} (Main site)"
        log "  - https://www.${DOMAIN_NAME} (WWW)"
        log "  - https://api.${DOMAIN_NAME} (API service)"
        log "  - https://data.${DOMAIN_NAME} (Data service)"
        log "  - https://worker.${DOMAIN_NAME} (Worker service)"
        log "  - https://nodes.${DOMAIN_NAME} (Node network)"
        log "  - https://auth.${DOMAIN_NAME} (Authentik SSO)"
        log "  - https://monitor.${DOMAIN_NAME} (Monitoring)"
        log "  - https://admin.${DOMAIN_NAME} (Admin panel)"
        
        if [ "$USE_TAILSCALE" = "true" ]; then
            log ""
            log "🔐 Note: These subdomains point to Tailscale IP ($target_ip)"
            log "   Access requires being connected to your Tailscale network"
        fi
        
        return 0
    else
        error "Some DNS records failed to update"
        return 1
    fi
}

# Handle command line options
case "$1" in
    --help|-h)
        echo "FKS Trading Systems - DNS Subdomain Update Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h          Show this help message"
        echo "  --public            Use public IP for DNS records (default)"
        echo "  --tailscale         Use Tailscale IP for DNS records"
        echo ""
        echo "Environment Variables:"
        echo "  CLOUDFLARE_API_TOKEN  Cloudflare API token (required)"
        echo "  CLOUDFLARE_ZONE_ID    Cloudflare Zone ID (required)"
        echo "  DOMAIN_NAME           Domain name (default: fkstrading.xyz)"
        echo "  SERVER_IP             Public server IP address"
        echo "  TAILSCALE_IP          Tailscale IP address"
        echo "  USE_TAILSCALE         Use Tailscale IP instead of public (true/false)"
        echo ""
        echo "Examples:"
        echo "  # Update with public IP"
        echo "  SERVER_IP=1.2.3.4 $0"
        echo ""
        echo "  # Update with Tailscale IP"
        echo "  TAILSCALE_IP=100.64.0.1 $0 --tailscale"
        echo ""
        exit 0
        ;;
    --public)
        USE_TAILSCALE="false"
        ;;
    --tailscale)
        USE_TAILSCALE="true"
        ;;
esac

# Run main function
main "$@"
