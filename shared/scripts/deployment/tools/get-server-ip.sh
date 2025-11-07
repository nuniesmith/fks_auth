#!/bin/bash
#
# FKS Trading Systems - Get Server IP from Linode
# This script gets the IP address of the FKS server from Linode API
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
LINODE_CLI_TOKEN="${LINODE_CLI_TOKEN:-}"
SERVER_LABEL_FILTER="${SERVER_LABEL_FILTER:-fks}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-plain}"

# Usage function
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --token TOKEN           Linode API token (or use LINODE_CLI_TOKEN env var)"
    echo "  --label LABEL           Server label filter (default: fks)"
    echo "  --format FORMAT         Output format: plain, json, env (default: plain)"
    echo "  --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                      # Get FKS server IP"
    echo "  $0 --format json        # Get server info as JSON"
    echo "  $0 --format env         # Get server info as environment variables"
    echo "  $0 --label my-server    # Get server with different label"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --token)
            LINODE_CLI_TOKEN="$2"
            shift 2
            ;;
        --label)
            SERVER_LABEL_FILTER="$2"
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
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
if [[ -z "$LINODE_CLI_TOKEN" ]]; then
    log_error "Linode API token is required (use --token or LINODE_CLI_TOKEN env var)"
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

log_info "Searching for servers with label filter: $SERVER_LABEL_FILTER"

# Get server information from Linode API
response=$(curl -s -H "Authorization: Bearer $LINODE_CLI_TOKEN" \
    "https://api.linode.com/v4/linode/instances")

if [[ $? -ne 0 ]]; then
    log_error "Failed to connect to Linode API"
    exit 1
fi

# Check if response is valid JSON
if ! echo "$response" | jq . > /dev/null 2>&1; then
    log_error "Invalid response from Linode API"
    exit 1
fi

# Filter servers by label
servers=$(echo "$response" | jq -r --arg filter "$SERVER_LABEL_FILTER" \
    '.data[] | select(.label | test($filter; "i")) | {id: .id, label: .label, ip: .ipv4[0], status: .status, region: .region, type: .type, created: .created}')

if [[ -z "$servers" ]]; then
    log_error "No servers found with label filter: $SERVER_LABEL_FILTER"
    exit 1
fi

# Count servers
server_count=$(echo "$servers" | jq -s 'length')

if [[ "$server_count" -eq 0 ]]; then
    log_error "No servers found with label filter: $SERVER_LABEL_FILTER"
    exit 1
elif [[ "$server_count" -gt 1 ]]; then
    log_warning "Found $server_count servers, using the first one"
fi

# Get the first server
server_info=$(echo "$servers" | jq -s '.[0]')

# Extract server details
server_id=$(echo "$server_info" | jq -r '.id')
server_label=$(echo "$server_info" | jq -r '.label')
server_ip=$(echo "$server_info" | jq -r '.ip')
server_status=$(echo "$server_info" | jq -r '.status')
server_region=$(echo "$server_info" | jq -r '.region')
server_type=$(echo "$server_info" | jq -r '.type')
server_created=$(echo "$server_info" | jq -r '.created')

# Validate IP address
if [[ -z "$server_ip" || "$server_ip" == "null" ]]; then
    log_error "Server found but no IP address available"
    exit 1
fi

# Output based on format
case "$OUTPUT_FORMAT" in
    "plain")
        echo "$server_ip"
        ;;
    "json")
        echo "$server_info" | jq .
        ;;
    "env")
        echo "SERVER_ID=$server_id"
        echo "SERVER_LABEL=$server_label"
        echo "SERVER_IP=$server_ip"
        echo "SERVER_STATUS=$server_status"
        echo "SERVER_REGION=$server_region"
        echo "SERVER_TYPE=$server_type"
        echo "SERVER_CREATED=$server_created"
        ;;
    *)
        log_error "Invalid output format: $OUTPUT_FORMAT"
        exit 1
        ;;
esac

# Log to stderr for debugging (won't interfere with output)
log_info "Found server: $server_label ($server_id)" >&2
log_info "IP: $server_ip, Status: $server_status, Region: $server_region" >&2
