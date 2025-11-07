#!/bin/bash

# =============================================================================
# Development Resource Cleanup Script
# =============================================================================
# This script cleans up old Tailscale devices and Linode servers during development
# Run this before deployments to ensure clean state
#
# Usage: ./cleanup-development-resources.sh [service_pattern]
# Examples:
#   ./cleanup-development-resources.sh            # Clean all services
#   ./cleanup-development-resources.sh fks        # Clean only FKS services
#   ./cleanup-development-resources.sh nginx      # Clean only nginx services
#   ./cleanup-development-resources.sh ats        # Clean only ATS services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service patterns to clean
SERVICE_PATTERN="${1:-all}"

echo -e "${BLUE}🧹 Development Resource Cleanup Script${NC}"
echo "============================================="

# Check required environment variables
if [[ -z "$LINODE_CLI_TOKEN" ]]; then
    echo -e "${YELLOW}⚠️ LINODE_CLI_TOKEN not set. Linode cleanup will be skipped.${NC}"
fi

if [[ -z "$TAILSCALE_OAUTH_CLIENT_ID" || -z "$TAILSCALE_OAUTH_SECRET" ]]; then
    echo -e "${YELLOW}⚠️ Tailscale OAuth credentials not set. Tailscale cleanup will be skipped.${NC}"
fi

# Function to cleanup Tailscale devices
cleanup_tailscale() {
    local pattern="$1"
    
    if [[ -z "$TAILSCALE_OAUTH_CLIENT_ID" || -z "$TAILSCALE_OAUTH_SECRET" ]]; then
        echo -e "${YELLOW}⚠️ Skipping Tailscale cleanup - credentials not available${NC}"
        return 0
    fi
    
    echo -e "${BLUE}🔗 Cleaning up Tailscale devices...${NC}"
    
    # Get OAuth token
    echo "Getting Tailscale OAuth token..."
    TOKEN_RESPONSE=$(curl -s -X POST "https://api.tailscale.com/api/v2/oauth/token" \
        -u "$TAILSCALE_OAUTH_CLIENT_ID:$TAILSCALE_OAUTH_SECRET" \
        -d "grant_type=client_credentials")
    
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
    
    if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
        echo -e "${RED}❌ Failed to get Tailscale OAuth token${NC}"
        echo "Response: $TOKEN_RESPONSE"
        return 1
    fi
    
    echo -e "${GREEN}✅ Got Tailscale OAuth token${NC}"
    
    # Get tailnet
    TAILNET="${TAILSCALE_OAUTH_CLIENT_ID%%.*}"
    echo "Using tailnet: $TAILNET"
    
    # List devices
    echo "Fetching device list..."
    DEVICES_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
        "https://api.tailscale.com/api/v2/tailnet/$TAILNET/devices")
    
    if [[ "$pattern" == "all" ]]; then
        # Clean all development services
        DEVICE_PATTERNS=("fks_auth" "fks_api" "fks_web" "nginx" "ats")
    elif [[ "$pattern" == "fks" ]]; then
        DEVICE_PATTERNS=("fks_auth" "fks_api" "fks_web")
    else
        DEVICE_PATTERNS=("$pattern")
    fi
    
    for device_pattern in "${DEVICE_PATTERNS[@]}"; do
        echo -e "${BLUE}🔍 Looking for devices matching: $device_pattern${NC}"
        
        DEVICES=$(echo "$DEVICES_RESPONSE" | jq -r --arg pattern "$device_pattern" '.devices[] | select(.hostname | startswith($pattern)) | "\(.id) \(.hostname)"')
        
        if [[ -n "$DEVICES" ]]; then
            echo "$DEVICES" | while read -r device_id hostname; do
                if [[ -n "$device_id" && "$device_id" != "null" ]]; then
                    echo -e "${YELLOW}🗑️ Removing Tailscale device: $hostname ($device_id)${NC}"
                    
                    DELETE_RESPONSE=$(curl -s -X DELETE \
                        -H "Authorization: Bearer $ACCESS_TOKEN" \
                        "https://api.tailscale.com/api/v2/device/$device_id")
                    
                    if [[ $? -eq 0 ]]; then
                        echo -e "${GREEN}✅ Removed device: $hostname${NC}"
                    else
                        echo -e "${RED}❌ Failed to remove device: $hostname${NC}"
                    fi
                    
                    # Small delay between deletions
                    sleep 1
                fi
            done
        else
            echo "No devices found matching pattern: $device_pattern"
        fi
    done
}

# Function to cleanup Linode servers
cleanup_linode() {
    local pattern="$1"
    
    if [[ -z "$LINODE_CLI_TOKEN" ]]; then
        echo -e "${YELLOW}⚠️ Skipping Linode cleanup - token not available${NC}"
        return 0
    fi
    
    echo -e "${BLUE}🖥️ Cleaning up Linode servers...${NC}"
    
    # Install linode-cli if not present
    if ! command -v linode-cli &> /dev/null; then
        echo "Installing linode-cli..."
        pip install linode-cli >/dev/null 2>&1
    fi
    
    # Configure linode-cli
    echo "[DEFAULT]
token = $LINODE_CLI_TOKEN" > ~/.linode-cli
    
    if [[ "$pattern" == "all" ]]; then
        # Clean all development services
        SERVER_PATTERNS=("fks_auth" "fks_api" "fks_web" "nginx" "ats")
    elif [[ "$pattern" == "fks" ]]; then
        SERVER_PATTERNS=("fks_auth" "fks_api" "fks_web")
    else
        SERVER_PATTERNS=("$pattern")
    fi
    
    for server_pattern in "${SERVER_PATTERNS[@]}"; do
        echo -e "${BLUE}🔍 Looking for servers matching: $server_pattern${NC}"
        
        # Get list of servers matching pattern
        OLD_SERVERS=$(linode-cli linodes list --json 2>/dev/null | jq -r --arg pattern "$server_pattern" '.[] | select(.label | startswith($pattern)) | "\(.id) \(.label)"')
        
        if [[ -n "$OLD_SERVERS" ]]; then
            echo "$OLD_SERVERS" | while read -r server_id label; do
                if [[ -n "$server_id" && "$server_id" != "null" ]]; then
                    echo -e "${YELLOW}🗑️ Removing Linode server: $label ($server_id)${NC}"
                    
                    if linode-cli linodes delete "$server_id" --json >/dev/null 2>&1; then
                        echo -e "${GREEN}✅ Removed server: $label${NC}"
                    else
                        echo -e "${RED}❌ Failed to remove server: $label${NC}"
                    fi
                    
                    # Wait between deletions to avoid rate limits
                    sleep 10
                fi
            done
        else
            echo "No servers found matching pattern: $server_pattern"
        fi
    done
}

# Main cleanup execution
echo -e "${BLUE}Starting cleanup for pattern: $SERVICE_PATTERN${NC}"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Installing jq..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y jq
    elif command -v brew &> /dev/null; then
        brew install jq
    else
        echo -e "${RED}❌ Please install jq manually${NC}"
        exit 1
    fi
fi

# Run cleanups
cleanup_tailscale "$SERVICE_PATTERN"
echo ""
cleanup_linode "$SERVICE_PATTERN"

echo ""
echo -e "${GREEN}✅ Cleanup completed for pattern: $SERVICE_PATTERN${NC}"
echo -e "${BLUE}You can now run your deployments with a clean state!${NC}"
