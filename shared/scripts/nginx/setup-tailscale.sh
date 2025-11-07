#!/bin/bash
# setup-tailscale.sh - Tailscale installation and configuration
# Part of the modular StackScript system
# Version: 3.0.2 - Reboot-safe approach, deferred connection

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-tailscale"
readonly SCRIPT_VERSION="3.0.2"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# TAILSCALE INSTALLATION
# ============================================================================
install_tailscale() {
    log "Installing Tailscale..."
    
    # Check if already installed
    if command -v tailscale &>/dev/null; then
        log "Tailscale already installed, checking version..."
        tailscale version
        return 0
    fi
    
    # Download and install Tailscale
    local install_script="/tmp/tailscale-install.sh"
    
    if curl -fsSL https://tailscale.com/install.sh -o "$install_script"; then
        chmod +x "$install_script"
        
        # Run installer
        if bash "$install_script"; then
            success "Tailscale installed successfully"
        else
            error "Tailscale installation failed"
            return 1
        fi
    else
        error "Failed to download Tailscale installer"
        return 1
    fi
    
    # Verify installation
    if command -v tailscale &>/dev/null; then
        success "Tailscale installation verified"
        tailscale version
    else
        error "Tailscale installation verification failed"
        return 1
    fi
}

configure_tailscale_service() {
    log "Configuring Tailscale service (pre-reboot)..."
    
    # Create tailscaled configuration directory
    mkdir -p /var/lib/tailscale
    
    # Create systemd drop-in directory for tailscaled
    mkdir -p /etc/systemd/system/tailscaled.service.d
    
    # Create configuration override for better stability
    cat > /etc/systemd/system/tailscaled.service.d/override.conf << 'EOF'
[Unit]
# Ensure network is ready before starting
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
# Set state directory
StateDirectory=tailscale

# Restart policy for reliability
Restart=on-failure
RestartSec=30
StartLimitInterval=300
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal

# Wait for network readiness
ExecStartPre=/bin/bash -c 'until ping -c1 8.8.8.8 &>/dev/null; do sleep 2; done'
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service (but don't start yet - wait for reboot)
    if systemctl enable tailscaled; then
        success "Tailscaled service enabled for post-reboot startup"
    else
        error "Failed to enable tailscaled service"
        return 1
    fi
}

setup_tailscale_auth() {
    log "Setting up Tailscale authentication..."
    
    # Validate auth key
    if [[ -z "${TAILSCALE_AUTH_KEY:-}" ]]; then
        error "TAILSCALE_AUTH_KEY is required but not provided"
        return 1
    fi
    
    # Validate auth key format
    if [[ ! "$TAILSCALE_AUTH_KEY" =~ ^tskey- ]]; then
        error "Invalid Tailscale auth key format"
        return 1
    fi
    
    # Save auth key for post-reboot use
    echo "$TAILSCALE_AUTH_KEY" > "$CONFIG_DIR/tailscale-auth.key"
    chmod 600 "$CONFIG_DIR/tailscale-auth.key"
    
    success "Tailscale auth key saved for post-reboot connection"
}

create_tailscale_management_scripts() {
    log "Creating Tailscale management scripts..."
    
    # Create Tailscale status script
    cat > /usr/local/bin/tailscale-status << 'EOF'
#!/bin/bash
# Tailscale status and management script

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

show_status() {
    echo "=== Tailscale Status ==="
    echo ""
    
    # Service status
    if systemctl is-active --quiet tailscaled; then
        success "Tailscaled service is running"
    else
        error "Tailscaled service is not running"
        echo "  Status: $(systemctl is-active tailscaled)"
        echo "  Try: systemctl start tailscaled"
    fi
    
    # Connection status
    if tailscale status &>/dev/null; then
        echo ""
        echo "Connection Status:"
        tailscale status
        
        echo ""
        echo "IP Addresses:"
        local ips=$(tailscale ip 2>/dev/null)
        if [[ -n "$ips" ]]; then
            echo "$ips" | while read -r ip; do
                success "  $ip"
            done
        else
            warning "  No Tailscale IPs assigned"
        fi
        
        echo ""
        echo "DNS Settings:"
        tailscale dns status 2>/dev/null || warning "  DNS status unavailable"
        
    else
        warning "Not connected to Tailscale network"
        echo ""
        if [[ -f "/etc/nginx-automation/tailscale-auth.key" ]]; then
            echo "To connect using saved auth key:"
            echo "  tailscale-connect"
        else
            echo "To connect:"
            echo "  tailscale up --accept-routes"
        fi
    fi
}

show_logs() {
    echo "=== Recent Tailscale Logs ==="
    journalctl -u tailscaled --no-pager -n 20
}

reconnect() {
    log "Attempting to reconnect to Tailscale..."
    
    # Try with auth key if available
    if [[ -f "/etc/nginx-automation/tailscale-auth.key" ]]; then
        local auth_key
        auth_key=$(cat "/etc/nginx-automation/tailscale-auth.key")
        if tailscale up --authkey="$auth_key" --accept-routes --accept-dns=false; then
            success "Reconnection successful with auth key"
            show_status
            return 0
        fi
    fi
    
    # Fallback to regular connection
    if tailscale up --accept-routes --accept-dns=false; then
        success "Reconnection successful"
        show_status
    else
        error "Reconnection failed"
        return 1
    fi
}

case "${1:-status}" in
    status|"")
        show_status
        ;;
    logs)
        show_logs
        ;;
    reconnect)
        reconnect
        ;;
    restart)
        log "Restarting Tailscale service..."
        systemctl restart tailscaled
        sleep 5
        show_status
        ;;
    *)
        echo "Usage: $0 [status|logs|reconnect|restart]"
        echo ""
        echo "Commands:"
        echo "  status     - Show connection status (default)"
        echo "  logs       - Show recent service logs"
        echo "  reconnect  - Attempt to reconnect"
        echo "  restart    - Restart the service"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/tailscale-status
    
    # Create connection script for post-reboot
    cat > /usr/local/bin/tailscale-connect << 'EOF'
#!/bin/bash
# Tailscale connection script for post-reboot use

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

AUTH_KEY_FILE="/etc/nginx-automation/tailscale-auth.key"

main() {
    log "Connecting to Tailscale network..."
    
    # Check if already connected
    if tailscale status &>/dev/null && tailscale ip &>/dev/null; then
        success "Already connected to Tailscale"
        tailscale status
        return 0
    fi
    
    # Ensure service is running
    if ! systemctl is-active --quiet tailscaled; then
        log "Starting tailscaled service..."
        systemctl start tailscaled
        
        # Wait for service to be ready
        local retries=30
        for ((i=1; i<=retries; i++)); do
            if systemctl is-active --quiet tailscaled; then
                success "Tailscaled service started"
                break
            else
                if [[ $i -eq $retries ]]; then
                    error "Tailscaled service failed to start"
                    systemctl status tailscaled
                    return 1
                fi
                echo -n "."
                sleep 2
            done
        done
    fi
    
    # Connect using auth key
    if [[ -f "$AUTH_KEY_FILE" ]]; then
        log "Using saved authentication key..."
        local auth_key
        auth_key=$(cat "$AUTH_KEY_FILE")
        
        if [[ -n "$auth_key" ]]; then
            if tailscale up --authkey="$auth_key" --accept-routes --accept-dns=false; then
                success "Successfully connected to Tailscale network"
                
                # Show connection info
                echo ""
                log "Connection Details:"
                tailscale status
                
                echo ""
                log "Assigned IP addresses:"
                tailscale ip
                
                # Clean up auth key after successful connection
                rm -f "$AUTH_KEY_FILE"
                log "Auth key cleaned up after successful connection"
                
                return 0
            else
                error "Failed to connect with auth key"
                return 1
            fi
        else
            error "Auth key file is empty"
            return 1
        fi
    else
        error "Auth key file not found: $AUTH_KEY_FILE"
        log "Manual connection required: tailscale up"
        return 1
    fi
}

main "$@"
EOF
    
    chmod +x /usr/local/bin/tailscale-connect
    
    # Create network test script
    cat > /usr/local/bin/tailscale-test << 'EOF'
#!/bin/bash
# Tailscale network connectivity test

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_connectivity() {
    local target="$1"
    local name="$2"
    
    echo -n "Testing $name... "
    
    if ping -c 1 -W 3 "$target" &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

echo "=== Tailscale Network Test ==="
echo ""

# Get Tailscale status
if ! tailscale status &>/dev/null; then
    echo -e "${RED}ERROR:${NC} Not connected to Tailscale"
    echo "Run: tailscale-connect"
    exit 1
fi

# Test local Tailscale IP
local_ip=$(tailscale ip -4 2>/dev/null | head -n1)
if [[ -n "$local_ip" ]]; then
    echo "Local Tailscale IP: $local_ip"
else
    echo -e "${RED}ERROR:${NC} No Tailscale IP assigned"
    exit 1
fi

echo ""
echo "Connectivity Tests:"

# Test coordinator servers
test_connectivity "login.tailscale.com" "Tailscale coordinator"

# Test public internet
test_connectivity "8.8.8.8" "Public internet (Google DNS)"
test_connectivity "1.1.1.1" "Public internet (Cloudflare DNS)"

# Test other nodes in network (if any)
echo ""
echo "Network Nodes:"
if command -v jq &>/dev/null; then
    tailscale status --json 2>/dev/null | jq -r '.Peer[] | select(.Online == true) | "\(.DNSName) (\(.TailscaleIPs[0]))"' 2>/dev/null | while read -r node; do
        if [[ -n "$node" ]]; then
            local ip=$(echo "$node" | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+')
            local name=$(echo "$node" | cut -d'(' -f1 | tr -d ' ')
            if [[ -n "$ip" && "$ip" != "$local_ip" ]]; then
                test_connectivity "$ip" "$name"
            fi
        fi
    done
else
    echo "Install jq for detailed network node testing"
fi

echo ""
echo "Test completed."
EOF
    
    chmod +x /usr/local/bin/tailscale-test
    
    success "Tailscale management scripts created"
}

setup_firewall_preparation() {
    log "Preparing firewall configuration for Tailscale..."
    
    # Create script to set up firewall rules (to be run post-reboot)
    cat > /usr/local/bin/tailscale-firewall-setup << 'EOF'
#!/bin/bash
# Tailscale firewall setup script

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "[INFO] $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Setup UFW rules if available
setup_ufw() {
    if command -v ufw &>/dev/null; then
        log "Configuring UFW for Tailscale..."
        
        # Allow traffic on Tailscale interface
        ufw allow in on tailscale0 2>/dev/null || warning "Failed to add tailscale0 interface rule"
        
        # Allow Tailscale UDP port
        ufw allow 41641/udp comment 'Tailscale' 2>/dev/null || warning "Failed to add Tailscale port rule"
        
        success "UFW rules configured for Tailscale"
    else
        log "UFW not available"
    fi
}

# Setup iptables rules
setup_iptables() {
    log "Configuring iptables for Tailscale..."
    
    # Allow Tailscale traffic
    iptables -I INPUT -i tailscale0 -j ACCEPT 2>/dev/null || warning "Failed to add INPUT rule for tailscale0"
    iptables -I FORWARD -i tailscale0 -j ACCEPT 2>/dev/null || warning "Failed to add FORWARD rule for tailscale0"
    iptables -I FORWARD -o tailscale0 -j ACCEPT 2>/dev/null || warning "Failed to add OUTPUT rule for tailscale0"
    
    # Allow Tailscale UDP port
    iptables -I INPUT -p udp --dport 41641 -j ACCEPT 2>/dev/null || warning "Failed to add Tailscale port rule"
    
    success "iptables rules configured for Tailscale"
}

main() {
    setup_ufw
    setup_iptables
    log "Firewall configuration completed"
}

main "$@"
EOF
    
    chmod +x /usr/local/bin/tailscale-firewall-setup
    
    success "Firewall setup script created for post-reboot execution"
}

create_post_reboot_connection() {
    log "Creating post-reboot connection automation..."
    
    # Create a systemd service to auto-connect after reboot
    cat > /etc/systemd/system/tailscale-auto-connect.service << 'EOF'
[Unit]
Description=Auto-connect Tailscale after reboot
After=network-online.target tailscaled.service
Wants=network-online.target
Requires=tailscaled.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tailscale-connect
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
User=root

# Wait for network readiness
ExecStartPre=/bin/bash -c 'until ping -c1 8.8.8.8 &>/dev/null; do sleep 5; done'

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable the service to run after reboot
    systemctl daemon-reload
    systemctl enable tailscale-auto-connect.service
    
    success "Auto-connect service created and enabled"
}

create_simple_healthcheck() {
    log "Creating simplified health check..."
    
    # Create a simple health check that runs after successful connection
    cat > /usr/local/bin/tailscale-healthcheck << 'EOF'
#!/bin/bash
# Simple Tailscale health check

set -euo pipefail

LOG_FILE="/var/log/tailscale-healthcheck.log"
mkdir -p "$(dirname "$LOG_FILE")"

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if service is running
if ! systemctl is-active --quiet tailscaled; then
    log_message "ERROR: tailscaled service is not running, attempting restart"
    systemctl restart tailscaled
    exit 1
fi

# Check if connected
if ! tailscale status &>/dev/null; then
    log_message "WARNING: Not connected to Tailscale network"
    # Try to reconnect using saved auth key or manual method
    if [[ -f "/etc/nginx-automation/tailscale-auth.key" ]]; then
        auth_key=$(cat "/etc/nginx-automation/tailscale-auth.key")
        tailscale up --authkey="$auth_key" --accept-routes --accept-dns=false &>/dev/null || true
    else
        tailscale up --accept-routes --accept-dns=false &>/dev/null || true
    fi
    exit 1
fi

# Check connectivity
if ! ping -c 1 -W 5 login.tailscale.com &>/dev/null; then
    log_message "WARNING: Cannot reach Tailscale coordinator"
    exit 1
fi

log_message "INFO: All health checks passed"
exit 0
EOF
    
    chmod +x /usr/local/bin/tailscale-healthcheck
    
    success "Simple health check created"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting Tailscale setup (pre-reboot phase)..."
    
    # Validate prerequisites
    validate_required_var "TAILSCALE_AUTH_KEY"
    
    # Install Tailscale but don't start the service yet
    install_tailscale
    
    # Configure service for post-reboot startup
    configure_tailscale_service
    
    # Save auth key for post-reboot connection
    setup_tailscale_auth
    
    # Create management tools
    create_tailscale_management_scripts
    
    # Prepare firewall setup (to be run post-reboot)
    setup_firewall_preparation
    
    # Create auto-connection service for post-reboot
    create_post_reboot_connection
    
    # Create simple health check
    create_simple_healthcheck
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "Tailscale setup completed successfully (pre-reboot phase)"
    log "Tailscale will automatically connect after reboot"
    log "Manual connection command: tailscale-connect"
    log "Status check command: tailscale-status"
    log "Network test command: tailscale-test"
    
    # Create info file for post-reboot reference
    cat > "$CONFIG_DIR/tailscale-setup-info.txt" << EOF
Tailscale Setup Information
==========================

Status: Pre-reboot setup completed
Version: $SCRIPT_VERSION
Date: $(date)

Post-reboot commands:
- Check status: tailscale-status
- Manual connect: tailscale-connect  
- Test network: tailscale-test
- Setup firewall: tailscale-firewall-setup

The system will automatically attempt to connect to Tailscale after reboot.
If automatic connection fails, run: tailscale-connect
EOF
    
    log "Setup information saved to: $CONFIG_DIR/tailscale-setup-info.txt"
}

# Execute main function
main "$@"