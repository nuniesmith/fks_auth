#!/bin/bash
# =================================================================
# update-cloudflare-subdomains.sh
# =================================================================
# Updates Cloudflare DNS with subdomain A records for FKS services
#
# Required environment variables:
# - CLOUDFLARE_API_TOKEN: API token with DNS edit permissions
# - CLOUDFLARE_ZONE_ID: Zone ID for your domain
# - DOMAIN_NAME: Your domain name (e.g., fkstrading.xyz)
# - SERVER_IP: IP address of your server
#
# Usage: ./update-cloudflare-subdomains.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check required environment variables
check_requirements() {
    local missing=()
    
    [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]] && missing+=("CLOUDFLARE_API_TOKEN")
    [[ -z "${CLOUDFLARE_ZONE_ID:-}" ]] && missing+=("CLOUDFLARE_ZONE_ID")
    [[ -z "${DOMAIN_NAME:-}" ]] && missing+=("DOMAIN_NAME")
    [[ -z "${SERVER_IP:-}" ]] && missing+=("SERVER_IP")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing required environment variables:${NC}"
        printf '%s\n' "${missing[@]}"
        echo -e "\n${YELLOW}Please set these variables and try again.${NC}"
        exit 1
    fi
}

# Function to update or create DNS record
update_dns_record() {
    local subdomain="$1"
    local record_name="$2"
    local description="$3"
    
    echo -e "\n${BLUE}📡 Processing ${description}...${NC}"
    
    # Get existing records
    local existing_records=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?type=A&name=${record_name}" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json")
    
    # Check if record exists
    local record_id=$(echo "$existing_records" | jq -r '.result[0].id // empty')
    
    if [[ -n "$record_id" ]]; then
        # Update existing record
        echo -e "${YELLOW}  🔄 Updating existing record...${NC}"
        local response=$(curl -s -X PUT \
            "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${record_id}" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"A\",
                \"name\": \"${record_name}\",
                \"content\": \"${SERVER_IP}\",
                \"ttl\": 120,
                \"proxied\": false
            }")
        
        if echo "$response" | jq -e '.success' > /dev/null; then
            echo -e "${GREEN}  ✅ Updated ${record_name} → ${SERVER_IP}${NC}"
        else
            echo -e "${RED}  ❌ Failed to update ${record_name}${NC}"
            echo "$response" | jq '.errors'
        fi
    else
        # Create new record
        echo -e "${YELLOW}  ✨ Creating new record...${NC}"
        local response=$(curl -s -X POST \
            "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"A\",
                \"name\": \"${record_name}\",
                \"content\": \"${SERVER_IP}\",
                \"ttl\": 120,
                \"proxied\": false
            }")
        
        if echo "$response" | jq -e '.success' > /dev/null; then
            echo -e "${GREEN}  ✅ Created ${record_name} → ${SERVER_IP}${NC}"
        else
            echo -e "${RED}  ❌ Failed to create ${record_name}${NC}"
            echo "$response" | jq '.errors'
        fi
    fi
}

# Main function
main() {
    echo -e "${BLUE}🚀 FKS Cloudflare DNS Updater${NC}"
    echo -e "${BLUE}================================${NC}"
    
    # Check requirements
    check_requirements
    
    echo -e "\n${GREEN}Configuration:${NC}"
    echo -e "  Domain: ${DOMAIN_NAME}"
    echo -e "  Server IP: ${SERVER_IP}"
    echo -e "  Zone ID: ${CLOUDFLARE_ZONE_ID:0:8}..."
    
    # Define subdomains
    declare -A subdomains=(
        ["@"]="${DOMAIN_NAME}|Root domain"
        ["www"]="www.${DOMAIN_NAME}|Main website"
        ["api"]="api.${DOMAIN_NAME}|API service"
        ["data"]="data.${DOMAIN_NAME}|Data service"
        ["worker"]="worker.${DOMAIN_NAME}|Worker service"
        ["nodes"]="nodes.${DOMAIN_NAME}|Node network"
        ["auth"]="auth.${DOMAIN_NAME}|Authentication (Authentik)"
        ["docs"]="docs.${DOMAIN_NAME}|Documentation"
        ["monitoring"]="monitoring.${DOMAIN_NAME}|Monitoring (Grafana)"
        ["metrics"]="metrics.${DOMAIN_NAME}|Metrics (Prometheus)"
    )
    
    # Update each subdomain
    for subdomain in "${!subdomains[@]}"; do
        IFS='|' read -r record_name description <<< "${subdomains[$subdomain]}"
        update_dns_record "$subdomain" "$record_name" "$description"
    done
    
    echo -e "\n${GREEN}✅ DNS update complete!${NC}"
    echo -e "\n${YELLOW}📝 Next steps:${NC}"
    echo -e "  1. Wait 1-5 minutes for DNS propagation"
    echo -e "  2. Update your nginx configuration to use subdomain routing"
    echo -e "  3. Test each subdomain: ping <subdomain>.${DOMAIN_NAME}"
    echo -e "\n${BLUE}Subdomains configured:${NC}"
    echo -e "  • https://${DOMAIN_NAME} - Main website"
    echo -e "  • https://api.${DOMAIN_NAME} - API service"
    echo -e "  • https://data.${DOMAIN_NAME} - Data service"
    echo -e "  • https://worker.${DOMAIN_NAME} - Worker service"
    echo -e "  • https://nodes.${DOMAIN_NAME} - Node network"
    echo -e "  • https://auth.${DOMAIN_NAME} - Authentication"
    echo -e "  • https://docs.${DOMAIN_NAME} - Documentation"
    echo -e "  • https://monitoring.${DOMAIN_NAME} - Grafana"
    echo -e "  • https://metrics.${DOMAIN_NAME} - Prometheus"
}

# Run main function
main "$@"
