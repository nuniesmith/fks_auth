#!/bin/bash

# FKS Multi-Server Provisioning Script
# Provisions individual servers for the multi-server architecture

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
SERVER_TYPE=""
LINODE_TYPE=""
HOSTNAME=""
LABEL=""
SUBDOMAIN=""
MANAGEMENT_STRATEGY="reuse-existing-servers"
REGION="ca-central"
IMAGE="linode/arch"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

# Show help
show_help() {
    cat << EOF
FKS Multi-Server Provisioning Script

Usage: $0 [options]

Options:
    --server-type TYPE          Server type (auth|api|web)
    --linode-type TYPE          Linode instance type (g6-nanode-1, g6-standard-2, etc.)
    --hostname HOSTNAME         Server hostname
    --label LABEL               Server label for Linode dashboard
    --subdomain SUBDOMAIN       Subdomain for this server (e.g., auth.fkstrading.xyz)
    --management-strategy STR   Management strategy (reuse-existing-servers|force-new-servers|replace-existing-servers)
    --region REGION             Linode region (default: ca-central)
    --image IMAGE               Linode image (default: linode/arch)
    --help                      Show this help message

Examples:
    # Provision auth server
    $0 --server-type auth --linode-type g6-nanode-1 --hostname fks_auth --label "FKS Auth Server" --subdomain auth.fkstrading.xyz

    # Provision API server with more resources
    $0 --server-type api --linode-type g6-standard-2 --hostname fks_api --label "FKS API Server" --subdomain api.fkstrading.xyz

    # Force new web server
    $0 --server-type web --linode-type g6-nanode-1 --hostname fks_web --label "FKS Web Server" --subdomain web.fkstrading.xyz --management-strategy force-new-servers

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server-type)
                SERVER_TYPE="$2"
                shift 2
                ;;
            --linode-type)
                LINODE_TYPE="$2"
                shift 2
                ;;
            --hostname)
                HOSTNAME="$2"
                shift 2
                ;;
            --label)
                LABEL="$2"
                shift 2
                ;;
            --subdomain)
                SUBDOMAIN="$2"
                shift 2
                ;;
            --management-strategy)
                MANAGEMENT_STRATEGY="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --image)
                IMAGE="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Validate inputs
validate_inputs() {
    if [ -z "$SERVER_TYPE" ]; then
        log "ERROR" "Server type is required (--server-type)"
        exit 1
    fi
    
    if [[ ! "$SERVER_TYPE" =~ ^(auth|api|web)$ ]]; then
        log "ERROR" "Invalid server type. Must be: auth, api, or web"
        exit 1
    fi
    
    if [ -z "$LINODE_TYPE" ]; then
        log "ERROR" "Linode type is required (--linode-type)"
        exit 1
    fi
    
    if [ -z "$HOSTNAME" ]; then
        log "ERROR" "Hostname is required (--hostname)"
        exit 1
    fi
    
    if [ -z "$LABEL" ]; then
        log "ERROR" "Label is required (--label)"
        exit 1
    fi
    
    if [ -z "$SUBDOMAIN" ]; then
        log "ERROR" "Subdomain is required (--subdomain)"
        exit 1
    fi
    
    # Check required environment variables
    if [ -z "$LINODE_CLI_TOKEN" ]; then
        log "ERROR" "LINODE_CLI_TOKEN environment variable is required"
        exit 1
    fi
    
    if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
        log "ERROR" "FKS_DEV_ROOT_PASSWORD environment variable is required"
        exit 1
    fi
    
    if [ -z "$TAILSCALE_AUTH_KEY" ]; then
        log "ERROR" "TAILSCALE_AUTH_KEY environment variable is required"
        exit 1
    fi
}

# Setup Linode CLI
setup_linode_cli() {
    log "INFO" "Setting up Linode CLI..."
    
    # Install Linode CLI if not present
    if ! command -v linode-cli >/dev/null 2>&1; then
        log "INFO" "Installing Linode CLI..."
        python3 -m pip install --user linode-cli --quiet || {
            log "ERROR" "Failed to install Linode CLI"
            exit 1
        }
        export PATH="$HOME/.local/bin:$PATH"
        
        # Verify installation
        if ! command -v linode-cli >/dev/null 2>&1; then
            log "ERROR" "Linode CLI not found after installation"
            exit 1
        fi
    fi
    
    # Configure Linode CLI with minimal config (avoid type conflicts)
    mkdir -p ~/.config/linode-cli
    cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
default-user = DEFAULT
token = $LINODE_CLI_TOKEN
EOF
    chmod 600 ~/.config/linode-cli/config
    
    # Verify CLI works
    if ! linode-cli --version >/dev/null 2>&1; then
        log "ERROR" "Linode CLI installation verification failed"
        exit 1
    fi
    
    log "INFO" "Linode CLI configured"
}

# Check if server already exists
check_existing_server() {
    log "INFO" "Checking for existing $SERVER_TYPE server..."
    
    # Look for existing server with our label pattern
    EXISTING_SERVER_ID=$(linode-cli linodes list --text --no-headers --format "id,label" 2>/dev/null | grep -i "$HOSTNAME" | awk '{print $1}' | head -1)
    
    if [ -n "$EXISTING_SERVER_ID" ]; then
        EXISTING_SERVER_IP=$(linode-cli linodes view "$EXISTING_SERVER_ID" --text --no-headers --format "ipv4" 2>/dev/null | head -1)
        log "INFO" "Found existing $SERVER_TYPE server: ID=$EXISTING_SERVER_ID, IP=$EXISTING_SERVER_IP"
        echo "EXISTING_SERVER_ID=$EXISTING_SERVER_ID"
        echo "EXISTING_SERVER_IP=$EXISTING_SERVER_IP"
        return 0
    else
        log "INFO" "No existing $SERVER_TYPE server found"
        return 1
    fi
}

# Create new server
create_server() {
    log "INFO" "Creating new $SERVER_TYPE server..."
    log "INFO" "Type: $LINODE_TYPE, Region: $REGION, Image: $IMAGE"
    
    # Debug: Show what we're about to execute
    log "DEBUG" "Executing: linode-cli linodes create --type '$LINODE_TYPE' --region '$REGION' --image '$IMAGE' --label '$LABEL' --root_pass '[REDACTED]'"
    
    # Validate Linode type format
    if [[ ! "$LINODE_TYPE" =~ ^g[0-9]+-.*$ ]]; then
        log "ERROR" "Invalid Linode type format: '$LINODE_TYPE'. Expected format: g6-nanode-1, g6-standard-2, etc."
        exit 1
    fi
    
    # Test Linode CLI connection first with actual API call
    log "DEBUG" "Testing Linode CLI connection with real API call..."
    TEST_OUTPUT=$(linode-cli linodes list --text --no-headers --format "id" 2>&1)
    TEST_EXIT_CODE=$?
    
    if [ $TEST_EXIT_CODE -ne 0 ]; then
        log "ERROR" "Linode CLI connection failed. Exit code: $TEST_EXIT_CODE"
        log "ERROR" "CLI Test Output: $TEST_OUTPUT"
        
        # Check for specific error patterns
        if echo "$TEST_OUTPUT" | grep -i "401\|invalid.*token\|unauthorized" >/dev/null; then
            log "ERROR" "Authentication failed - Invalid or expired Linode API token"
            log "INFO" "Please check the LINODE_CLI_TOKEN secret in GitHub repository settings"
            log "INFO" "Token should be a personal access token from https://cloud.linode.com/profile/tokens"
        elif echo "$TEST_OUTPUT" | grep -i "403\|forbidden" >/dev/null; then
            log "ERROR" "Permission denied - Token may lack necessary permissions"
            log "INFO" "Token needs 'Linodes:Read/Write' permissions"
        elif echo "$TEST_OUTPUT" | grep -i "timeout\|network" >/dev/null; then
            log "ERROR" "Network connectivity issue to Linode API"
        else
            log "ERROR" "Unknown authentication/connection error"
        fi
        
        exit 1
    else
        log "INFO" "✅ Linode CLI connection test successful"
    fi
    
    # Create the server with detailed error output
    log "INFO" "Calling Linode API to create server..."
    log "DEBUG" "Full command: linode-cli linodes create --type '$LINODE_TYPE' --region '$REGION' --image '$IMAGE' --label '$LABEL' --root_pass '[REDACTED]' --text --no-headers --format 'id,ipv4'"
    
    # Debug environment before server creation
    echo "========== ENVIRONMENT DEBUG =========="
    log "DEBUG" "Token length: ${#LINODE_CLI_TOKEN}"
    log "DEBUG" "Token starts with: ${LINODE_CLI_TOKEN:0:10}..."
    log "DEBUG" "Current working directory: $(pwd)"
    log "DEBUG" "Linode CLI version: $(linode-cli --version 2>/dev/null || echo 'version check failed')"
    echo "========== END ENVIRONMENT DEBUG =========="
    
    SERVER_CREATE_OUTPUT=$(linode-cli linodes create \
        --type "$LINODE_TYPE" \
        --region "$REGION" \
        --image "$IMAGE" \
        --label "$LABEL" \
        --root_pass "$FKS_DEV_ROOT_PASSWORD" \
        --text --no-headers --format "id,ipv4" 2>&1)
    SERVER_CREATE_EXIT_CODE=$?
    
    # Always show the output for debugging - ensure it's visible
    echo "========== DEBUG OUTPUT START =========="
    log "DEBUG" "Linode CLI create output: $SERVER_CREATE_OUTPUT"
    log "DEBUG" "Linode CLI create exit code: $SERVER_CREATE_EXIT_CODE"
    echo "========== DEBUG OUTPUT END =========="
    
    if [ $SERVER_CREATE_EXIT_CODE -ne 0 ]; then
        echo "========== ERROR ANALYSIS START =========="
        log "ERROR" "Failed to create server. Exit code: $SERVER_CREATE_EXIT_CODE"
        log "ERROR" "Full error output: $SERVER_CREATE_OUTPUT"
        echo "Raw output follows:"
        echo "$SERVER_CREATE_OUTPUT"
        echo "========== ERROR ANALYSIS END =========="
        
        # Check for common error patterns and provide specific guidance
        if echo "$SERVER_CREATE_OUTPUT" | grep -i "401\|unauthorized\|invalid.*token" >/dev/null; then
            log "ERROR" "Authentication failed during server creation"
            log "INFO" "The LINODE_CLI_TOKEN appears to be invalid or expired"
        elif echo "$SERVER_CREATE_OUTPUT" | grep -i "invalid.*type\|unknown.*type" >/dev/null; then
            log "ERROR" "The Linode type '$LINODE_TYPE' is not valid or not available in region '$REGION'"
            log "INFO" "Attempting to fetch available types for region $REGION..."
            AVAILABLE_TYPES=$(linode-cli linodes types --text --no-headers --format "id,label" 2>/dev/null | head -10)
            if [ -n "$AVAILABLE_TYPES" ]; then
                log "INFO" "Available types in $REGION:"
                echo "$AVAILABLE_TYPES" | while read type_id type_label; do
                    log "INFO" "  - $type_id: $type_label"
                done
            else
                log "WARN" "Could not fetch available types"
            fi
        elif echo "$SERVER_CREATE_OUTPUT" | grep -i "insufficient.*credits\|billing\|payment" >/dev/null; then
            log "ERROR" "Insufficient account credits or billing issue"
            log "INFO" "Please check your Linode account billing status"
        elif echo "$SERVER_CREATE_OUTPUT" | grep -i "region.*unavailable\|invalid.*region" >/dev/null; then
            log "ERROR" "Region '$REGION' is not available"
        elif echo "$SERVER_CREATE_OUTPUT" | grep -i "quota\|limit.*exceeded" >/dev/null; then
            log "ERROR" "Account limits exceeded (server quota, resource limits, etc.)"
        elif echo "$SERVER_CREATE_OUTPUT" | grep -i "image.*unavailable\|invalid.*image" >/dev/null; then
            log "ERROR" "Image '$IMAGE' is not available in region '$REGION'"
        else
            log "ERROR" "Unknown server creation error"
            log "INFO" "Raw error details: $SERVER_CREATE_OUTPUT"
        fi
        
        exit 1
    fi
    
    if [ -z "$SERVER_CREATE_OUTPUT" ]; then
        log "ERROR" "No output from server creation command"
        exit 1
    fi
    
    # Parse output
    NEW_SERVER_ID=$(echo "$SERVER_CREATE_OUTPUT" | awk '{print $1}')
    NEW_SERVER_IP=$(echo "$SERVER_CREATE_OUTPUT" | awk '{print $2}')
    
    if [ -z "$NEW_SERVER_ID" ] || [ -z "$NEW_SERVER_IP" ]; then
        log "ERROR" "Failed to parse server creation output"
        exit 1
    fi
    
    log "INFO" "Server created successfully: ID=$NEW_SERVER_ID, IP=$NEW_SERVER_IP"
    
    # Wait for server to be running
    log "INFO" "Waiting for server to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        SERVER_STATUS=$(linode-cli linodes view "$NEW_SERVER_ID" --text --no-headers --format "status" 2>/dev/null)
        if [ "$SERVER_STATUS" = "running" ]; then
            log "INFO" "Server is running"
            break
        fi
        
        log "INFO" "Attempt $attempt/$max_attempts: Server status is $SERVER_STATUS, waiting..."
        sleep 10
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        log "ERROR" "Server did not become ready within expected time"
        exit 1
    fi
    
    # Wait additional time for SSH to be available
    log "INFO" "Waiting for SSH to be available..."
    sleep 60
    
    echo "NEW_SERVER_ID=$NEW_SERVER_ID"
    echo "NEW_SERVER_IP=$NEW_SERVER_IP"
    echo "IS_NEW_SERVER=true"
}

# Delete existing server
delete_server() {
    local server_id="$1"
    log "WARN" "Deleting existing server: $server_id"
    
    if linode-cli linodes delete "$server_id" 2>/dev/null; then
        log "INFO" "Server deleted successfully"
        
        # Wait for deletion to complete
        sleep 30
    else
        log "ERROR" "Failed to delete server $server_id"
        exit 1
    fi
}

# Setup server with basic configuration
setup_server() {
    local server_ip="$1"
    local is_new="$2"
    
    log "INFO" "Setting up server configuration..."
    
    # Test SSH connectivity
    log "INFO" "Testing SSH connectivity..."
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$server_ip" "echo 'SSH connection successful'" 2>/dev/null; then
            log "INFO" "SSH connection established"
            break
        fi
        
        log "INFO" "Attempt $attempt/$max_attempts: SSH not ready, waiting..."
        sleep 15
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        log "ERROR" "SSH connection failed after $max_attempts attempts"
        exit 1
    fi
    
    # Run basic server setup if it's a new server
    if [ "$is_new" = "true" ]; then
        log "INFO" "Running initial server setup..."
        
        # Copy and run the multi-server setup script
        sshpass -p "$FKS_DEV_ROOT_PASSWORD" scp -o StrictHostKeyChecking=no \
            "$SCRIPT_DIR/setup-server.sh" root@"$server_ip":/tmp/setup-server.sh
        
        sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no root@"$server_ip" "
            chmod +x /tmp/setup-server.sh
            /tmp/setup-server.sh --server-type '$SERVER_TYPE' --hostname '$HOSTNAME' --tailscale-key '$TAILSCALE_AUTH_KEY'
        "
        
        log "INFO" "Initial server setup completed"
    fi
    
    # Get Tailscale IP
    log "INFO" "Retrieving Tailscale IP..."
    local tailscale_ip=""
    local max_tailscale_attempts=15
    local tailscale_attempt=1
    
    while [ $tailscale_attempt -le $max_tailscale_attempts ]; do
        tailscale_ip=$(timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no root@"$server_ip" "
            if command -v tailscale >/dev/null 2>&1; then
                tailscale ip -4 2>/dev/null | head -1
            fi
        " 2>/dev/null | grep -E '^100\.' | head -1)
        
        if [ -n "$tailscale_ip" ] && [[ "$tailscale_ip" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log "INFO" "Tailscale IP retrieved: $tailscale_ip"
            break
        fi
        
        log "INFO" "Attempt $tailscale_attempt/$max_tailscale_attempts: Tailscale not ready, waiting..."
        sleep 10
        tailscale_attempt=$((tailscale_attempt + 1))
    done
    
    if [ -z "$tailscale_ip" ]; then
        log "WARN" "Could not retrieve Tailscale IP, using public IP"
        tailscale_ip="$server_ip"
    fi
    
    echo "TAILSCALE_IP=$tailscale_ip"
}

# Main function
main() {
    parse_args "$@"
    validate_inputs
    
    log "INFO" "🚀 Provisioning FKS $SERVER_TYPE server..."
    log "INFO" "Configuration:"
    log "INFO" "  - Type: $LINODE_TYPE"
    log "INFO" "  - Hostname: $HOSTNAME"
    log "INFO" "  - Subdomain: $SUBDOMAIN"
    log "INFO" "  - Management: $MANAGEMENT_STRATEGY"
    
    # Setup Linode CLI
    setup_linode_cli
    
    # Determine server action based on management strategy
    case "$MANAGEMENT_STRATEGY" in
        "reuse-existing-servers")
            if check_existing_server; then
                # Use existing server
                SERVER_ID="$EXISTING_SERVER_ID"
                SERVER_IP="$EXISTING_SERVER_IP"
                IS_NEW_SERVER="false"
                log "INFO" "Using existing server: $SERVER_ID"
            else
                # Create new server
                create_server
                SERVER_ID="$NEW_SERVER_ID"
                SERVER_IP="$NEW_SERVER_IP"
                IS_NEW_SERVER="true"
            fi
            ;;
        "force-new-servers")
            if check_existing_server; then
                delete_server "$EXISTING_SERVER_ID"
            fi
            create_server
            SERVER_ID="$NEW_SERVER_ID"
            SERVER_IP="$NEW_SERVER_IP"
            IS_NEW_SERVER="true"
            ;;
        "replace-existing-servers")
            if check_existing_server; then
                delete_server "$EXISTING_SERVER_ID"
                sleep 30  # Wait before creating new one
            fi
            create_server
            SERVER_ID="$NEW_SERVER_ID"
            SERVER_IP="$NEW_SERVER_IP"
            IS_NEW_SERVER="true"
            ;;
        *)
            log "ERROR" "Invalid management strategy: $MANAGEMENT_STRATEGY"
            exit 1
            ;;
    esac
    
    # Setup server
    setup_server "$SERVER_IP" "$IS_NEW_SERVER"
    
    # Save server details to environment file
    OUTPUT_FILE="${SERVER_TYPE}-server-details.env"
    cat > "$OUTPUT_FILE" << EOF
# FKS $SERVER_TYPE Server Details
${SERVER_TYPE^^}_SERVER_ID=$SERVER_ID
${SERVER_TYPE^^}_SERVER_IP=$SERVER_IP
${SERVER_TYPE^^}_TAILSCALE_IP=$TAILSCALE_IP
${SERVER_TYPE^^}_HOSTNAME=$HOSTNAME
${SERVER_TYPE^^}_SUBDOMAIN=$SUBDOMAIN
${SERVER_TYPE^^}_IS_NEW_SERVER=$IS_NEW_SERVER
EOF
    
    log "INFO" "✅ $SERVER_TYPE server provisioning completed!"
    log "INFO" "📄 Details saved to: $OUTPUT_FILE"
    log "INFO" "🔗 Server accessible at: https://$SUBDOMAIN (via Tailscale)"
}

# Run main function
main "$@"
