#!/bin/bash
# Tailscale Setup Script
# Sets up Tailscale with OAuth authentication on a server
# Part of the GitHub Actions workflow refactoring

set -euo pipefail

# =============================================================================
# Configuration & Global Variables
# =============================================================================

SERVICE_NAME="${1:-}"
SERVER_IP="${2:-}"
TS_OAUTH_CLIENT_ID="${TS_OAUTH_CLIENT_ID:-}"
TS_OAUTH_SECRET="${TS_OAUTH_SECRET:-}"
TAILSCALE_TAILNET="${TAILSCALE_TAILNET:-}"

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    echo "🔗 [TAILSCALE] $*"
}

error() {
    echo "❌ [TAILSCALE ERROR] $*" >&2
    exit 1
}

# =============================================================================
# Validation Functions
# =============================================================================

validate_inputs() {
    log "Validating Tailscale setup inputs..."
    
    if [[ -z "$SERVICE_NAME" ]]; then
        error "SERVICE_NAME is required"
    fi
    
    if [[ -z "$SERVER_IP" ]]; then
        error "SERVER_IP is required"
    fi
    
    if [[ -z "$TS_OAUTH_CLIENT_ID" ]]; then
        error "TS_OAUTH_CLIENT_ID secret is required"
    fi
    
    if [[ -z "$TS_OAUTH_SECRET" ]]; then
        error "TS_OAUTH_SECRET secret is required"
    fi
    
    log "✅ All required Tailscale inputs provided"
}

# =============================================================================
# Tailscale Setup Functions
# =============================================================================

setup_tailscale_on_server() {
    local hostname="${SERVICE_NAME}-server"
    
    log "Setting up Tailscale on server $SERVER_IP with hostname $hostname..."
    
    # Execute Tailscale setup on the server
    ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" << 'EOF'
        # Install Tailscale if not already installed
        if ! command -v tailscale >/dev/null 2>&1; then
            echo "📦 Installing Tailscale..."
            curl -fsSL https://tailscale.com/install.sh | sh
        else
            echo "✅ Tailscale already installed"
        fi
        
        # Check if already connected
        if tailscale status >/dev/null 2>&1; then
            echo "🔗 Tailscale already connected"
            tailscale ip -4
            exit 0
        fi
        
        echo "🔗 Connecting to Tailscale network..."
EOF
    
    # Generate OAuth key and connect
    local auth_key
    auth_key=$(curl -s "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/keys" \
        -u "$TS_OAUTH_CLIENT_ID:$TS_OAUTH_SECRET" \
        -H "Content-Type: application/json" \
        -d '{
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": false,
                        "ephemeral": false,
                        "preauthorized": true,
                        "tags": ["tag:server", "tag:'"$SERVICE_NAME"'"]
                    }
                }
            },
            "expirySeconds": 3600
        }' | jq -r '.key')
    
    if [[ -z "$auth_key" || "$auth_key" == "null" ]]; then
        error "Failed to generate Tailscale auth key"
    fi
    
    # Connect to Tailscale with the auth key
    ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" \
        "tailscale up --authkey='$auth_key' --hostname='$hostname' --ssh --accept-routes"
    
    log "✅ Tailscale setup completed"
}

get_tailscale_ip() {
    log "Retrieving Tailscale IP address..."
    
    local tailscale_ip
    tailscale_ip=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" \
        "tailscale ip -4 2>/dev/null || echo 'pending'")
    
    if [[ "$tailscale_ip" == "pending" || -z "$tailscale_ip" ]]; then
        log "⏳ Waiting for Tailscale IP assignment..."
        sleep 10
        tailscale_ip=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" \
            "tailscale ip -4 2>/dev/null || echo 'failed'")
    fi
    
    if [[ "$tailscale_ip" == "failed" || -z "$tailscale_ip" ]]; then
        error "Failed to get Tailscale IP address"
    fi
    
    log "🔗 Tailscale IP: $tailscale_ip"
    echo "tailscale_ip=$tailscale_ip" >> "$GITHUB_OUTPUT"
    
    return 0
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "Starting Tailscale setup for $SERVICE_NAME..."
    
    validate_inputs
    setup_tailscale_on_server
    get_tailscale_ip
    
    log "🎉 Tailscale setup completed successfully!"
}

# Execute main function
main "$@"
