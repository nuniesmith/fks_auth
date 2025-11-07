#!/bin/bash

# FKS Trading Systems - Stage 0: Server Creation + SSH Key Generation
# Creates Linode server and immediately generates SSH keys for all users

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
OVERWRITE_EXISTING=false
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
        --overwrite-existing)
            OVERWRITE_EXISTING=true
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
            echo "  --overwrite-existing        Overwrite/replace existing server (destroys current)"
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

log "Starting FKS Trading Systems - Stage 0: Server Creation + SSH Setup"

# Get server label from environment variable or use default
SERVER_LABEL="${LINODE_SERVER_LABEL:-fks_dev}"
log "Using server label: $SERVER_LABEL"

# Validate required environment variables
if [ -z "$LINODE_CLI_TOKEN" ]; then
    error "LINODE_CLI_TOKEN environment variable is required"
    exit 1
fi

if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
    error "FKS_DEV_ROOT_PASSWORD environment variable is required"
    exit 1
fi

# Install dependencies
log "Installing required dependencies..."
if ! command -v sshpass > /dev/null 2>&1; then
    if command -v pacman > /dev/null 2>&1; then
        sudo -n pacman -S --noconfirm sshpass
    elif command -v apt-get > /dev/null 2>&1; then
        sudo -n apt-get update && sudo -n apt-get install -y sshpass
    fi
fi

# Install and configure Linode CLI (simplified)
log "Setting up Linode CLI..."
if ! command -v linode-cli > /dev/null 2>&1; then
    log "Installing Linode CLI..."
    if pip3 install --user linode-cli --quiet 2>/dev/null; then
        export PATH="$HOME/.local/bin:$PATH"
    else
        error "Failed to install Linode CLI"
        exit 1
    fi
fi

# Set environment variables for CLI
export LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"
export DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"

# Test CLI connection
log "Testing Linode CLI connection..."
if ! timeout 30s linode-cli linodes list --json > /dev/null 2>&1; then
    error "Linode CLI connection failed or timed out"
    log "🔍 Debug: Testing basic Linode CLI connectivity..."
    
    # Try a simple regions list to test basic API access
    if timeout 15s linode-cli regions list > /dev/null 2>&1; then
        log "✅ Basic Linode API access works"
        log "❌ But linodes list failed - may be a permissions issue"
    else
        log "❌ Basic Linode API access failed"
        log "💡 Check LINODE_CLI_TOKEN validity and permissions"
    fi
    exit 1
else
    log "✅ Linode CLI connection successful"
fi

# Function to wait for server to be fully ready
wait_for_server_ready() {
    local server_ip=$1
    local max_attempts=40
    local attempt=1
    
    log "Waiting for server to be ready for SSH operations..."
    
    while [ $attempt -le $max_attempts ]; do
        log "Attempt $attempt/$max_attempts: Testing SSH connectivity..."
        
        # Try root with password authentication
        if timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "echo 'SSH ready'" 2>/dev/null; then
            log "✅ SSH authentication successful - server is ready!"
            return 0
        fi
        
        log "Waiting 15 seconds before next attempt..."
        sleep 15
        attempt=$((attempt + 1))
    done
    
    error "Server did not become ready within timeout"
    return 1
}

# Function to add GitHub SSH keys manually if server was created without them
add_github_ssh_keys() {
    local server_ip=$1
    log "🔑 Adding SSH keys from GitHub secrets to server..."
    
    # Create a script to add SSH keys from environment variables
    SSH_KEY_SCRIPT=$(mktemp)
    cat > "$SSH_KEY_SCRIPT" << 'SSH_KEY_EOF'
#!/bin/bash
set -e

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

# Create root .ssh directory if it doesn't exist
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Function to add a key to authorized_keys if it exists
add_ssh_key() {
    local key_name=$1
    local key_value=$2
    
    if [ -n "$key_value" ]; then
        log "Adding $key_name to authorized_keys"
        echo "$key_value" >> /root/.ssh/authorized_keys
    else
        log "No $key_name provided, skipping"
    fi
}

# Add SSH keys from environment variables (passed from GitHub secrets)
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Add SSH keys (these will be passed as environment variables)
add_ssh_key "ORYX_SSH_PUB" "$ORYX_SSH_KEY"
add_ssh_key "SULLIVAN_SSH_PUB" "$SULLIVAN_SSH_KEY"
add_ssh_key "FREDDY_SSH_PUB" "$FREDDY_SSH_KEY"
add_ssh_key "DESKTOP_SSH_PUB" "$DESKTOP_SSH_KEY"
add_ssh_key "MACBOOK_SSH_PUB" "$MACBOOK_SSH_KEY"

# Remove duplicates and empty lines
sort /root/.ssh/authorized_keys | uniq | grep -v '^$' > /root/.ssh/authorized_keys.tmp
mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

log "✅ SSH keys from GitHub secrets added successfully"
SSH_KEY_EOF

    # Upload and execute the SSH key script with environment variables
    log "Uploading SSH key script to server..."
    if ! sshpass -p "$FKS_DEV_ROOT_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_KEY_SCRIPT" root@"$server_ip":/tmp/add-ssh-keys.sh; then
        warn "Failed to upload SSH key script"
        rm -f "$SSH_KEY_SCRIPT"
        return 1
    fi

    log "Executing SSH key script on server..."
    if sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "
        export ORYX_SSH_KEY=\"${ORYX_SSH_PUB:-}\"
        export SULLIVAN_SSH_KEY=\"${SULLIVAN_SSH_PUB:-}\"
        export FREDDY_SSH_KEY=\"${FREDDY_SSH_PUB:-}\"
        export DESKTOP_SSH_KEY=\"${DESKTOP_SSH_PUB:-}\"
        export MACBOOK_SSH_KEY=\"${MACBOOK_SSH_PUB:-}\"
        chmod +x /tmp/add-ssh-keys.sh
        /tmp/add-ssh-keys.sh
        rm -f /tmp/add-ssh-keys.sh
    "; then
        log "✅ GitHub SSH keys added successfully"
    else
        warn "Failed to add SSH keys from GitHub secrets"
    fi

    # Cleanup
    rm -f "$SSH_KEY_SCRIPT"
}

# Function to generate SSH keys for all users
generate_ssh_keys() {
    local server_ip=$1
    log "🔑 Generating SSH keys for all users on server..."
    
    # Create the SSH key generation script
    SSH_SETUP_SCRIPT=$(mktemp)
    cat > "$SSH_SETUP_SCRIPT" << 'SSH_SETUP_EOF'
#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

log "Starting SSH key generation for all users..."

# Create users if they don't exist
log "Creating users..."

# Jordan user (admin)
if ! id jordan &>/dev/null; then
    useradd -m -s /bin/bash jordan
    log "Created jordan user"
fi

# FKS user (service account)
if ! id fks_user &>/dev/null; then
    useradd -m -s /bin/bash fks_user
    log "Created fks_user"
fi

# Actions user (GitHub Actions)
if ! id actions_user &>/dev/null; then
    useradd -m -s /bin/bash actions_user
    log "Created actions_user"
fi

# Function to generate SSH keys for a user
generate_user_ssh_key() {
    local username=$1
    local home_dir="/home/$username"
    
    if [ "$username" = "root" ]; then
        home_dir="/root"
    fi
    
    log "Generating SSH key for $username..."
    
    # Create .ssh directory
    mkdir -p "$home_dir/.ssh"
    chmod 700 "$home_dir/.ssh"
    
    # Remove any existing keys
    rm -f "$home_dir/.ssh/id_ed25519"*
    
    # Generate new Ed25519 key
    ssh-keygen -t ed25519 -f "$home_dir/.ssh/id_ed25519" -N "" -C "$username@fks_$(date +%Y%m%d)"
    
    # Set proper permissions
    chmod 600 "$home_dir/.ssh/id_ed25519"
    chmod 644 "$home_dir/.ssh/id_ed25519.pub"
    
    # Set up authorized_keys with the new key
    cp "$home_dir/.ssh/id_ed25519.pub" "$home_dir/.ssh/authorized_keys"
    chmod 600 "$home_dir/.ssh/authorized_keys"
    
    # Set ownership
    if [ "$username" != "root" ]; then
        chown -R "$username:$username" "$home_dir/.ssh"
    fi
    
    log "✅ SSH key generated for $username"
}

# Generate SSH keys for all users
generate_user_ssh_key "root"
generate_user_ssh_key "jordan"
generate_user_ssh_key "fks_user"
generate_user_ssh_key "actions_user"

# Get the actions_user public key for GitHub Actions
ACTIONS_USER_SSH_KEY=$(cat /home/actions_user/.ssh/id_ed25519.pub)

# Save all SSH keys to a summary file
cat > /root/ssh-keys-summary.txt << SSH_SUMMARY
# FKS SSH Keys Generated on $(date)

# Root SSH Key:
$(cat /root/.ssh/id_ed25519.pub)

# Jordan SSH Key:
$(cat /home/jordan/.ssh/id_ed25519.pub)

# FKS User SSH Key:
$(cat /home/fks_user/.ssh/id_ed25519.pub)

# Actions User SSH Key (for GitHub Actions):
$(cat /home/actions_user/.ssh/id_ed25519.pub)
SSH_SUMMARY

log "✅ All SSH keys generated successfully!"
log "📄 SSH keys summary saved to /root/ssh-keys-summary.txt"
log ""
log "🔑 ACTIONS_USER_SSH_KEY for GitHub Actions:"
echo "$ACTIONS_USER_SSH_KEY"
log ""
log "Copy this key and update your GitHub secret: ACTIONS_USER_SSH_PUB"
SSH_SETUP_EOF

    # Upload and execute the SSH setup script
    log "Uploading SSH setup script to server..."
    if ! sshpass -p "$FKS_DEV_ROOT_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_SETUP_SCRIPT" root@"$server_ip":/tmp/ssh-setup.sh; then
        error "Failed to upload SSH setup script"
        return 1
    fi

    log "Executing SSH setup script on server..."
    if sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "
        chmod +x /tmp/ssh-setup.sh
        /tmp/ssh-setup.sh
    "; then
        log "✅ SSH keys generated successfully"
        
        # Retrieve the actions_user SSH key
        log "Retrieving actions_user SSH key..."
        ACTIONS_USER_SSH_KEY=$(sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "cat /home/actions_user/.ssh/id_ed25519.pub" 2>/dev/null || echo "")
        
        if [ -n "$ACTIONS_USER_SSH_KEY" ]; then
            log "✅ Retrieved actions_user SSH key"
            echo "$ACTIONS_USER_SSH_KEY" > actions-user-ssh-key.txt
            
            # Export for GitHub Actions
            echo "ACTIONS_USER_SSH_PUB=$ACTIONS_USER_SSH_KEY"
            
            # Send Discord notification if webhook is available
            if [ -n "${DISCORD_WEBHOOK_SERVERS:-}" ]; then
                log "📢 Sending Discord notification..."
                send_discord_notification "$ACTIONS_USER_SSH_KEY"
            fi
        else
            warn "Failed to retrieve actions_user SSH key"
        fi
    else
        error "Failed to execute SSH setup script"
        return 1
    fi

    # Cleanup
    rm -f "$SSH_SETUP_SCRIPT"
}

# Function to send Discord notification
send_discord_notification() {
    local ssh_key="$1"
    
    # Create Discord message
    DISCORD_MESSAGE=$(cat << DISCORD_EOF
{
  "embeds": [
    {
      "title": "🔑 FKS Server SSH Keys Generated",
      "description": "New SSH keys have been generated for the FKS server.",
      "color": 3066993,
      "fields": [
        {
          "name": "Server IP",
          "value": "\`$TARGET_HOST\`",
          "inline": true
        },
        {
          "name": "Server ID",
          "value": "\`$SERVER_ID\`",
          "inline": true
        },
        {
          "name": "Actions User SSH Key",
          "value": "\`\`\`$ssh_key\`\`\`",
          "inline": false
        },
        {
          "name": "Next Steps",
          "value": "1. Copy the SSH key above\n2. Update GitHub secret: \`ACTIONS_USER_SSH_PUB\`\n3. Add as deploy key to repository\n4. Run Stage 1 deployment",
          "inline": false
        }
      ],
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
  ]
}
DISCORD_EOF
)

    # Send to Discord
    if curl -H "Content-Type: application/json" \
           -d "$DISCORD_MESSAGE" \
           "$DISCORD_WEBHOOK_SERVERS" >/dev/null 2>&1; then
        log "✅ Discord notification sent successfully"
    else
        warn "Failed to send Discord notification"
    fi
}

# Check for existing server or create new one
TARGET_HOST=""
SERVER_ID=""
IS_NEW_SERVER=false

case "$TARGET_SERVER" in
    "auto-detect")
        log "Searching for existing FKS servers..."
        
        # Use specific label if provided, otherwise search for any fks server
        SEARCH_PATTERN="${LINODE_SERVER_LABEL:-fks}"
        
        EXISTING_SERVERS=""
        if linode-cli linodes list --json > /dev/null 2>&1; then
            EXISTING_SERVERS=$(linode-cli linodes list --json | jq -r ".[] | select(.label | test(\"$SEARCH_PATTERN\")) | \"\(.id)|\(.ipv4[0])\"" 2>/dev/null || echo "")
        fi
        
        if [ -n "$EXISTING_SERVERS" ] && [ "$FORCE_NEW_SERVER" != "true" ] && [ "$OVERWRITE_EXISTING" != "true" ]; then
            SERVER_INFO=$(echo "$EXISTING_SERVERS" | head -1)
            SERVER_ID=$(echo "$SERVER_INFO" | cut -d'|' -f1)
            TARGET_HOST=$(echo "$SERVER_INFO" | cut -d'|' -f2)
            log "Found existing server matching '$SEARCH_PATTERN': ID=$SERVER_ID, IP=$TARGET_HOST"
            
            # Test if existing server is accessible
            if wait_for_server_ready "$TARGET_HOST"; then
                log "✅ Existing server is ready for use"
                log "🔑 Generating SSH keys for existing server..."
                generate_ssh_keys "$TARGET_HOST"
            else
                warn "Existing server is not accessible, creating new one..."
                IS_NEW_SERVER=true
            fi
        else
            if [ "$FORCE_NEW_SERVER" = "true" ]; then
                log "Force new server requested"
            elif [ "$OVERWRITE_EXISTING" = "true" ]; then
                log "Overwrite existing server requested - cleaning up current server"
            fi
                
            # Delete existing servers if they exist
            if [ -n "$EXISTING_SERVERS" ]; then
                echo "$EXISTING_SERVERS" | while IFS='|' read -r server_id server_ip; do
                    if [ -n "$server_id" ]; then
                        log "🗑️ Cleaning up existing server $server_id (IP: $server_ip)..."
                        
                        # Cleanup Tailscale if possible
                        if [ -n "$server_ip" ] && command -v sshpass >/dev/null 2>&1; then
                            log "🔗 Attempting Tailscale cleanup on $server_ip..."
                            timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "tailscale logout 2>/dev/null; systemctl stop tailscaled 2>/dev/null" 2>/dev/null || log "⚠️ Tailscale cleanup failed (server may be unreachable)"
                        fi
                        
                        # Cleanup Netdata if possible
                        if [ -n "$server_ip" ] && command -v sshpass >/dev/null 2>&1; then
                            log "📊 Attempting Netdata cleanup on $server_ip..."
                            timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "netdata-claim.sh -token= -rooms= -url= 2>/dev/null; systemctl stop netdata 2>/dev/null" 2>/dev/null || log "⚠️ Netdata cleanup failed (server may be unreachable)"
                        fi
                        
                        # Delete the server
                        log "🖥️ Deleting Linode server $server_id..."
                        linode-cli linodes delete "$server_id" 2>/dev/null || warn "Failed to delete server $server_id"
                    fi
                done
                
                # Wait for deletion to complete
                log "⏳ Waiting for server deletion to complete..."
                sleep 15
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
    
    # Get SSH keys from Linode
    log "Fetching SSH keys from Linode..."
    SSH_KEYS_JSON=$(linode-cli sshkeys list --json 2>/dev/null || echo "[]")
    
    # Display available SSH keys for debugging
    log "Available SSH keys in Linode account:"
    echo "$SSH_KEYS_JSON" | jq -r '.[] | "  - \(.label) (ID: \(.id)) - Type: \(.ssh_key | split(" ")[0])"' 2>/dev/null || echo "  None found"
    
    # Validate SSH keys and filter out invalid ones
    VALID_SSH_KEYS=""
    INVALID_SSH_KEYS=""
    
    if [ -n "$SSH_KEYS_JSON" ] && [ "$SSH_KEYS_JSON" != "[]" ]; then
        while IFS= read -r key_info; do
            if [ -n "$key_info" ]; then
                key_id=$(echo "$key_info" | jq -r '.id')
                key_label=$(echo "$key_info" | jq -r '.label')
                key_content=$(echo "$key_info" | jq -r '.ssh_key')
                key_type=$(echo "$key_content" | cut -d' ' -f1)
                
                # More robust SSH key validation
                key_is_valid=false
                
                # Check if key type is valid and key content is properly formatted
                case "$key_type" in
                    ssh-dss|ssh-rsa|ecdsa-sha2-nistp*|ssh-ed25519|sk-ecdsa-sha2-nistp256)
                        # Additional validation: check if key has at least 3 parts (type, key, comment optional)
                        key_parts=$(echo "$key_content" | wc -w)
                        if [ "$key_parts" -ge 2 ]; then
                            # Check if the key content looks valid (no control characters, proper base64-like content)
                            key_data=$(echo "$key_content" | cut -d' ' -f2)
                            if [ ${#key_data} -gt 20 ] && echo "$key_data" | grep -E '^[A-Za-z0-9+/=]+$' >/dev/null; then
                                key_is_valid=true
                            else
                                warn "SSH key $key_label has invalid base64 content: ${key_data:0:20}..."
                            fi
                        else
                            warn "SSH key $key_label has insufficient parts (expected ≥2, got $key_parts)"
                        fi
                        ;;
                    *)
                        warn "SSH key $key_label has unsupported type: $key_type"
                        ;;
                esac
                
                if [ "$key_is_valid" = "true" ]; then
                    VALID_SSH_KEYS="$VALID_SSH_KEYS $key_id"
                    log "✅ Valid SSH key: $key_label (ID: $key_id, Type: $key_type)"
                else
                    INVALID_SSH_KEYS="$INVALID_SSH_KEYS $key_id"
                    warn "❌ Invalid SSH key: $key_label (ID: $key_id, Type: $key_type) - Skipping"
                    log "🔍 Key content preview: ${key_content:0:100}..."
                fi
            fi
        done <<< "$(echo "$SSH_KEYS_JSON" | jq -c '.[]')"
    fi
    
    # Clean up the valid SSH keys list - use comma-separated format like the working version
    SSH_KEY_IDS=$(echo "$VALID_SSH_KEYS" | xargs | tr ' ' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
    
    if [ -n "$INVALID_SSH_KEYS" ]; then
        warn "Found invalid SSH keys that will be skipped: $INVALID_SSH_KEYS"
        log "💡 Consider removing or updating these keys in your Linode account"
    fi
    
    # Get server label from environment variable or use default
    SERVER_LABEL="${LINODE_SERVER_LABEL:-fks_dev}"
    
    # Create server command - start without SSH keys for reliability
    CREATE_CMD="linode-cli linodes create \
        --label \"$SERVER_LABEL\" \
        --image \"$SERVER_IMAGE\" \
        --region \"$SERVER_REGION\" \
        --type \"$SERVER_TYPE\" \
        --root_pass \"$FKS_DEV_ROOT_PASSWORD\" \
        --json 2>&1"
    
    # For now, skip SSH keys during creation due to persistent validation issues
    # SSH keys will be added manually after server creation
    log "⚠️ Creating server without SSH keys due to Linode API validation issues"
    log "ℹ️ SSH keys will be added manually after server creation"
    
    # Debug: Show the complete command being executed
    log "🔍 Debug: Complete command to be executed:"
    log "   $CREATE_CMD"
    
    # Create the server
    log "⚡ Executing server creation command with 60s timeout..."
    set +e  # Don't exit on command failure
    timeout --kill-after=10s 60s bash -c "eval "$CREATE_CMD"" > /tmp/linode_output.log 2>&1
    CREATE_EXIT_CODE=$?
    NEW_INSTANCE=$(cat /tmp/linode_output.log 2>/dev/null || echo "")
    set -e
    
    log "🔍 Debug: Command completed with exit code: $CREATE_EXIT_CODE"
    
    # Check if server creation succeeded
    if [ $CREATE_EXIT_CODE -eq 124 ]; then
        error "Server creation timed out after 60 seconds"
        log "🔍 Debug: Output from timed out command:"
        echo "$NEW_INSTANCE"
        exit 1
    elif [ $CREATE_EXIT_CODE -ne 0 ]; then
        error "Failed to create Linode instance (exit code: $CREATE_EXIT_CODE)"
        log "🔍 Debug: Failed command output:"
        echo "$NEW_INSTANCE"
        log "🔍 Debug: Failed command was:"
        log "   $CREATE_CMD"
        exit 1
    fi
    
    log "✅ Server created successfully!"
    
    # Parse server details
    JSON_PART=$(echo "$NEW_INSTANCE" | sed '/^Failed to parse JSON: Using default values:/d' | sed -n '/^[\[{]/,$p')
    
    SERVER_ID=$(echo "$JSON_PART" | jq -r '.[0].id' 2>/dev/null || echo "")
    TARGET_HOST=$(echo "$JSON_PART" | jq -r '.[0].ipv4[0]' 2>/dev/null || echo "")
    
    if [ -z "$SERVER_ID" ] || [ -z "$TARGET_HOST" ]; then
        error "Failed to parse server creation response"
        exit 1
    fi
    
    log "Created new server: ID=$SERVER_ID, IP=$TARGET_HOST"
        
        # Try alternative SSH key format first
        if [ -n "$SSH_KEY_IDS" ]; then
            log "🔄 Trying alternative SSH key format (space-separated with quotes)..."
            ALT_CMD="linode-cli linodes create \
                --label \"$SERVER_LABEL\" \
                --image \"$SERVER_IMAGE\" \
                --region \"$SERVER_REGION\" \
                --type \"$SERVER_TYPE\" \
                --root_pass \"$FKS_DEV_ROOT_PASSWORD\" \
                --authorized_keys \"$(echo "$SSH_KEY_IDS" | tr ',' ' ')\" \
                --json 2>&1"
            
            log "� Debug: Alternative command:"
            log "   $ALT_CMD"
            
            NEW_INSTANCE=$(eval "$ALT_CMD")
            CREATE_EXIT_CODE=$?
            
            if [ $CREATE_EXIT_CODE -eq 0 ]; then
                log "✅ Server created with alternative SSH key format!"
            else
                warn "Alternative SSH key format also failed (exit code: $CREATE_EXIT_CODE)"
                log "🔍 Debug: Alternative command output:"
                echo "$NEW_INSTANCE"
            fi
        fi
        
        # If still failed, retry without SSH keys
        if [ $CREATE_EXIT_CODE -ne 0 ]; then
            log "🔄 Final fallback: Creating server without SSH keys..."
            FALLBACK_CMD="linode-cli linodes create \
                --label \"$SERVER_LABEL\" \
                --image \"$SERVER_IMAGE\" \
                --region \"$SERVER_REGION\" \
                --type \"$SERVER_TYPE\" \
                --root_pass \"$FKS_DEV_ROOT_PASSWORD\" \
                --json 2>&1"
            
            log "🔍 Debug: Fallback command:"
            log "   $FALLBACK_CMD"
            
            set +e
            timeout --kill-after=10s 60s bash -c "eval \"$FALLBACK_CMD\"" > /tmp/linode_fallback_output.log 2>&1
            CREATE_EXIT_CODE=$?
            NEW_INSTANCE=$(cat /tmp/linode_fallback_output.log 2>/dev/null || echo "")
            set -e
            USED_FALLBACK=true
            
            if [ $CREATE_EXIT_CODE -eq 124 ]; then
                error "Final fallback timed out after 60 seconds"
                log "🔍 Debug: Fallback command output:"
                echo "$NEW_INSTANCE"
                exit 1
            elif [ $CREATE_EXIT_CODE -ne 0 ]; then
                error "Failed to create Linode instance even without SSH keys (exit code: $CREATE_EXIT_CODE)"
                log "🔍 Debug: Fallback command output:"
                echo "$NEW_INSTANCE"
                exit 1
            else
                warn "Server created successfully without pre-configured SSH keys"
                log "ℹ️ SSH keys will be added manually after server creation"
            fi
        fi
    fi
    
    # Parse server details
    JSON_PART=$(echo "$NEW_INSTANCE" | sed '/^Failed to parse JSON: Using default values:/d' | sed -n '/^[\[{]/,$p')
    
    SERVER_ID=$(echo "$JSON_PART" | jq -r '.[0].id' 2>/dev/null || echo "")
    TARGET_HOST=$(echo "$JSON_PART" | jq -r '.[0].ipv4[0]' 2>/dev/null || echo "")
    
    if [ -z "$SERVER_ID" ] || [ -z "$TARGET_HOST" ]; then
        error "Failed to parse server creation response"
        exit 1
    fi
    
    log "Created new server: ID=$SERVER_ID, IP=$TARGET_HOST"
    
    # Wait for server to be ready
    if ! wait_for_server_ready "$TARGET_HOST"; then
        error "New server failed to become ready"
        exit 1
    fi
    
    # Add GitHub SSH keys since we created server without Linode SSH keys
    log "🔑 Adding SSH keys from GitHub secrets..."
    add_github_ssh_keys "$TARGET_HOST"
    
    # Generate SSH keys immediately after server is ready
    log "🔑 Generating SSH keys for new server..."
    generate_ssh_keys "$TARGET_HOST"
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
log "🎉 Stage 0 Complete - Server + SSH Ready"
log "============================================"
log "Target Host: $TARGET_HOST"
log "Server ID: $SERVER_ID"
log "Is New Server: $IS_NEW_SERVER"
log "SSH Keys: Generated for all users"
log "Next Steps:"
log "1. Copy the ACTIONS_USER_SSH_PUB from above"
log "2. Update GitHub secret: ACTIONS_USER_SSH_PUB"
log "3. Add as deploy key to repository"
log "4. Run Stage 1 deployment"
log "============================================"
