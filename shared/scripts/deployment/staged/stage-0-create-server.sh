#!/bin/bash

# FKS Trading Systems - Stage 0: Server Creation (Fixed)
# Creates Linode server and waits for it to be fully ready for SSH operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Default values
TARGET_SERVER="auto-detect"
FORCE_NEW_SERVER=false
SERVER_TYPE="g6-standard-2"
SERVER_REGION="ca-central"
SERVER_IMAGE="linode/arch"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-server)
            TARGET_SERVER="$2"
            shift 2
            ;;
        --force-new)
            FORCE_NEW_SERVER=true
            shift
            ;;
        --type)
            SERVER_TYPE="$2"
            shift 2
            ;;
        --region)
            SERVER_REGION="$2"
            shift 2
            ;;
        --image)
            SERVER_IMAGE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --target-server <option>    Target server (auto-detect|custom)"
            echo "  --force-new                 Force creation of new server"
            echo "  --type <type>               Linode instance type (default: g6-standard-2)"
            echo "  --region <region>           Linode region (default: ca-central)"
            echo "  --image <image>             Linode image (default: linode/arch)"
            echo "  --help                      Show this help message"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

log "Starting FKS Trading Systems - Stage 0: Server Creation"

# Validate required environment variables
if [ -z "$LINODE_CLI_TOKEN" ]; then
    error "LINODE_CLI_TOKEN environment variable is required"
    exit 1
fi

if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
    error "FKS_DEV_ROOT_PASSWORD environment variable is required"
    exit 1
fi

# Install and configure Linode CLI (improved)
log "Setting up Linode CLI..."

# Make sure we have pip
if ! command -v pip3 > /dev/null 2>&1; then
    if command -v pacman > /dev/null 2>&1; then
        sudo -n pacman -S --noconfirm python python-pip
    elif command -v apt-get > /dev/null 2>&1; then
        sudo -n apt-get update && sudo -n apt-get install -y python3 python3-pip
    fi
fi

# Install CLI with proper error handling
if ! command -v linode-cli > /dev/null 2>&1; then
    log "Installing Linode CLI..."
    
    # Try multiple installation methods
    if pip3 install --user linode-cli --quiet 2>/dev/null; then
        log "✅ Linode CLI installed via pip3 --user"
        export PATH="$HOME/.local/bin:$PATH"
    elif pip3 install linode-cli --quiet 2>/dev/null; then
        log "✅ Linode CLI installed via pip3 (system)"
    elif python3 -m pip install --user linode-cli --quiet 2>/dev/null; then
        log "✅ Linode CLI installed via python3 -m pip --user"
        export PATH="$HOME/.local/bin:$PATH"
    else
        error "Failed to install Linode CLI"
        exit 1
    fi
else
    log "✅ Linode CLI already available"
fi

# Verify installation and create wrapper if needed
if ! command -v linode-cli > /dev/null 2>&1; then
    log "⚠️ Linode CLI not found in PATH, trying Python module..."
    # Try direct Python execution
    if python3 -c "import linode_cli" 2>/dev/null; then
        log "✅ Linode CLI module is available via Python"
        # Create a wrapper function
        linode-cli() {
            python3 -m linode_cli "$@"
        }
        export -f linode-cli
    else
        error "Linode CLI installation failed or not in PATH"
        error "PATH: $PATH"
        error "Available in ~/.local/bin: $(ls -la ~/.local/bin/ | grep linode || echo 'Not found')"
        exit 1
    fi
else
    # CLI binary exists, but avoid testing it with interactive commands
    # Instead, just verify the Python module is available
    if python3 -c "import linodecli" 2>/dev/null; then
        log "✅ Linode CLI Python module is available"
        # Create wrapper function to ensure non-interactive usage
        linode-cli() {
            LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN" python3 -m linodecli "$@"
        }
        export -f linode-cli
    else
        log "⚠️ Linode CLI Python module not found, trying alternative methods..."
        
        # Try different module names
        if python3 -c "import linode_cli" 2>/dev/null; then
            log "✅ Linode CLI module available as 'linode_cli'"
            linode-cli() {
                LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN" python3 -m linode_cli "$@"
            }
            export -f linode-cli
        else
            error "Linode CLI module import failed with both 'linodecli' and 'linode_cli'"
            error "Attempting to reinstall with --force-reinstall..."
            
            # Try force reinstall
            if pip3 install --user --force-reinstall linode-cli --quiet 2>/dev/null; then
                log "✅ Linode CLI reinstalled successfully"
                export PATH="$HOME/.local/bin:$PATH"
                
                # Test again with both module names
                if python3 -c "import linodecli" 2>/dev/null; then
                    log "✅ Linode CLI module now working as 'linodecli'"
                    linode-cli() {
                        LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN" python3 -m linodecli "$@"
                    }
                    export -f linode-cli
                elif python3 -c "import linode_cli" 2>/dev/null; then
                    log "✅ Linode CLI module now working as 'linode_cli'"
                    linode-cli() {
                        LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN" python3 -m linode_cli "$@"
                    }
                    export -f linode-cli
                else
                    error "Linode CLI still not working after reinstall"
                    exit 1
                fi
            else
                error "Failed to reinstall Linode CLI"
                exit 1
            fi
        fi
    fi
fi

# Set environment variables for CLI
export LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"
export DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"

# Test CLI connection
log "Testing Linode CLI connection..."
if linode-cli linodes list --json > /dev/null 2>&1; then
    log "✅ Linode CLI connection successful"
else
    error "Linode CLI connection failed"
    exit 1
fi
# Function to wait for server to be fully ready
wait_for_server_ready() {
    local server_ip=$1
    local max_attempts=60  # 15 minutes total
    local attempt=1
    
    log "Waiting for server to be fully ready for SSH operations..."
    
    while [ $attempt -le $max_attempts ]; do
        log "Attempt $attempt/$max_attempts: Testing SSH connectivity..."
        
        # Define connection targets to try (IP and domain if available)
        CONNECTION_TARGETS=("$server_ip")
        if [ -n "${DOMAIN_NAME:-}" ] && [ "$DOMAIN_NAME" != "$server_ip" ]; then
            CONNECTION_TARGETS+=("$DOMAIN_NAME")
        fi
        if [ "$server_ip" != "fkstrading.xyz" ]; then
            CONNECTION_TARGETS+=("fkstrading.xyz")
        fi
        
        # Test basic network connectivity - try both ping and direct SSH port test
        NETWORK_REACHABLE=false
        
        # First try ping to IP
        if ping -c 1 -W 3 "$server_ip" > /dev/null 2>&1; then
            log "✅ Server IP is network reachable via ping"
            NETWORK_REACHABLE=true
        else
            log "⚠️ Server IP doesn't respond to ping, trying SSH port directly..."
            
            # If ping fails, try SSH port on all targets
            for test_target in "${CONNECTION_TARGETS[@]}"; do
                if timeout 10 bash -c "</dev/tcp/$test_target/22" 2>/dev/null; then
                    log "✅ SSH port is reachable on $test_target"
                    NETWORK_REACHABLE=true
                    break
                fi
            done
        fi
        
        if [ "$NETWORK_REACHABLE" = "true" ]; then
            log "✅ Server is network reachable"
            
            # Try multiple SSH authentication methods
            SSH_SUCCESS=false
            
            # Try multiple hosts and authentication methods
            for target_host in "${CONNECTION_TARGETS[@]}"; do
                log "Trying SSH connections to: $target_host"
                
                # Method 1: Try actions_user with SSH keys first
                if timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no actions_user@"$target_host" "echo 'SSH ready'" 2>/dev/null; then
                    log "✅ SSH authentication successful with actions_user@$target_host (key-based) - server is ready!"
                    SSH_SUCCESS=true
                    break
                # Method 2: Try jordan user with SSH keys
                elif timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no jordan@"$target_host" "echo 'SSH ready'" 2>/dev/null; then
                    log "✅ SSH authentication successful with jordan@$target_host (key-based) - server is ready!"
                    SSH_SUCCESS=true
                    break
                # Method 3: Try root with password authentication
                elif timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$target_host" "echo 'SSH ready'" 2>/dev/null; then
                    log "✅ SSH authentication successful with root@$target_host (password) - server is ready!"
                    SSH_SUCCESS=true
                    break
                # Method 4: Try root with key authentication (fallback)
                elif timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no root@"$target_host" "echo 'SSH ready'" 2>/dev/null; then
                    log "✅ SSH authentication successful with root@$target_host (key-based) - server is ready!"
                    SSH_SUCCESS=true
                    break
                fi
            done
            
            if [ "$SSH_SUCCESS" = "true" ]; then
                return 0
            else
                log "No authentication method worked on any target..."
                log "  Tried targets: ${CONNECTION_TARGETS[*]}"
                log "  Tried methods: actions_user (key), jordan (key), root (password), root (key)"
            fi
        else
            log "Server not yet network reachable..."
        fi
        
        log "Waiting 15 seconds before next attempt..."
        sleep 15
        attempt=$((attempt + 1))
    done
    
    error "Server did not become ready within timeout"
    return 1
}

# Check for existing server or create new one
TARGET_HOST=""
SERVER_ID=""
IS_NEW_SERVER=false

case "$TARGET_SERVER" in
    "auto-detect")
        log "Searching for existing FKS servers..."
        
        # Search for existing servers with better error handling
        EXISTING_SERVERS=""
        if linode-cli linodes list --json > /dev/null 2>&1; then
            EXISTING_SERVERS=$(linode-cli linodes list --json | jq -r '.[] | select(.label | test("fks")) | "\(.id)|\(.ipv4[0])"' 2>/dev/null || echo "")
        else
            warn "Could not list existing servers, will create new one"
            IS_NEW_SERVER=true
        fi
        
        if [ -n "$EXISTING_SERVERS" ] && [ "$FORCE_NEW_SERVER" != "true" ]; then
            SERVER_INFO=$(echo "$EXISTING_SERVERS" | head -1)
            SERVER_ID=$(echo "$SERVER_INFO" | cut -d'|' -f1)
            TARGET_HOST=$(echo "$SERVER_INFO" | cut -d'|' -f2)
            log "Found existing FKS server: ID=$SERVER_ID, IP=$TARGET_HOST"
            
            # Test if existing server is accessible
            if wait_for_server_ready "$TARGET_HOST"; then
                log "✅ Existing server is ready for use"
            else
                warn "Existing server is not accessible, creating new one..."
                IS_NEW_SERVER=true
            fi
        else
            if [ "$FORCE_NEW_SERVER" = "true" ]; then
                log "Force new server requested"
                
                # Delete existing servers if they exist
                if [ -n "$EXISTING_SERVERS" ]; then
                    echo "$EXISTING_SERVERS" | while IFS='|' read -r server_id server_ip; do
                        if [ -n "$server_id" ]; then
                            log "Deleting existing server $server_id..."
                            linode-cli linodes delete "$server_id" 2>/dev/null || true
                        fi
                    done
                    sleep 10
                fi
            fi
            IS_NEW_SERVER=true
        fi
        ;;
    *)
        error "Invalid target server option: $TARGET_SERVER"
        exit 1
        ;;
esac

# Create new server if needed
if [ "$IS_NEW_SERVER" = "true" ]; then
    log "Creating new Linode server..."
    log "  Type: $SERVER_TYPE"
    log "  Region: $SERVER_REGION"
    log "  Image: $SERVER_IMAGE"
    
    # Create the server with better error handling
    NEW_INSTANCE=$(linode-cli linodes create \
        --label "fks_dev" \
        --image "$SERVER_IMAGE" \
        --region "$SERVER_REGION" \
        --type "$SERVER_TYPE" \
        --root_pass "$FKS_DEV_ROOT_PASSWORD" \
        --json 2>&1)
    
    if [ $? -ne 0 ]; then
        error "Failed to create Linode instance"
        error "Output: $NEW_INSTANCE"
        exit 1
    fi
    
    # Debug: Show the raw output for troubleshooting
    log "Raw server creation output:"
    echo "$NEW_INSTANCE"
    
    # Parse server details with improved error handling
    # Extract the JSON part only (remove any warning messages)
    # First, remove the specific "Using default values" warning if present
    CLEAN_OUTPUT=$(echo "$NEW_INSTANCE" | sed '/^Failed to parse JSON: Using default values:/d')
    
    # Look for the first line that starts with '[{' or '{'
    JSON_PART=$(echo "$CLEAN_OUTPUT" | sed -n '/^[\[{]/,$p')
    
    # If that didn't work, try to find JSON by looking for the pattern
    if [ -z "$JSON_PART" ] || [ "$JSON_PART" = "$CLEAN_OUTPUT" ]; then
        # Try to extract everything from the first '[' or '{' character
        JSON_PART=$(echo "$CLEAN_OUTPUT" | sed 's/.*\(\[{.*\)/\1/')
        
        # If still no luck, try a different approach
        if [ -z "$JSON_PART" ]; then
            JSON_PART=$(echo "$CLEAN_OUTPUT" | grep -E '^\[?\{.*\}\]?$' || echo "$CLEAN_OUTPUT")
        fi
    fi
    
    log "Extracted JSON part:"
    echo "$JSON_PART" | jq . 2>/dev/null || echo "Failed to parse JSON: $JSON_PART"
    
    # Extract server ID with multiple fallback methods
    SERVER_ID=$(echo "$JSON_PART" | jq -r '.[0].id' 2>/dev/null || echo "")
    
    # If jq failed, try extracting server ID with regex
    if [ -z "$SERVER_ID" ] || [ "$SERVER_ID" = "null" ]; then
        SERVER_ID=$(echo "$JSON_PART" | grep -oE '"id":[[:space:]]*[0-9]+' | head -1 | grep -oE '[0-9]+' || echo "")
    fi
    
    # Try multiple ways to extract the IP address
    TARGET_HOST=$(echo "$JSON_PART" | jq -r '.[0].ipv4[0]' 2>/dev/null || echo "")
    
    # If the first method failed, try alternative approaches
    if [ -z "$TARGET_HOST" ] || [ "$TARGET_HOST" = "null" ]; then
        log "First IP extraction method failed, trying alternatives..."
        
        # Try extracting from the raw JSON structure
        TARGET_HOST=$(echo "$NEW_INSTANCE" | grep -o '"ipv4":\s*\["[^"]*"' | sed 's/.*"\([^"]*\)"/\1/' | head -1)
        
        if [ -z "$TARGET_HOST" ]; then
            # Try a more aggressive regex approach
            TARGET_HOST=$(echo "$NEW_INSTANCE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        fi
        
        if [ -z "$TARGET_HOST" ]; then
            error "Failed to get IP address of new instance after multiple attempts"
            error "Server creation output: $NEW_INSTANCE"
            error "Parsed Server ID: $SERVER_ID"
            exit 1
        else
            log "Successfully extracted IP using alternative method: $TARGET_HOST"
        fi
    fi
    
    log "Created new server: ID=$SERVER_ID, IP=$TARGET_HOST"
    
    # Wait for server to be ready
    if ! wait_for_server_ready "$TARGET_HOST"; then
        error "New server failed to become ready"
        exit 1
    fi
fi

# Create output file with server details
OUTPUT_FILE="server-details.env"
cat > "$OUTPUT_FILE" << EOF
# FKS Server Details - Generated by stage-0-create-server.sh
TARGET_HOST=$TARGET_HOST
SERVER_ID=$SERVER_ID
IS_NEW_SERVER=$IS_NEW_SERVER
SERVER_TYPE=$SERVER_TYPE
SERVER_REGION=$SERVER_REGION
SERVER_IMAGE=$SERVER_IMAGE
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DOMAIN_NAME=${DOMAIN_NAME:-fkstrading.xyz}
SERVER_IP=$TARGET_HOST
EOF

log "============================================"
log "🎉 Stage 0 Complete - Server Ready"
log "============================================"
log "Target Host: $TARGET_HOST"
log "Server ID: $SERVER_ID"
log "Is New Server: $IS_NEW_SERVER"
log "Ready for Stage 1: SSH operations confirmed"
log "Server details saved to: $OUTPUT_FILE"
log "============================================"