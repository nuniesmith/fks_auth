#!/bin/bash

# FKS Trading Systems - Server Diagnostics Script
# This script helps diagnose deployment connection issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] INFO: $1${NC}"
}

# Get variables from environment or prompt
DOMAIN_NAME="${DOMAIN_NAME:-}"
SERVER_IP="${SERVER_IP:-}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"

echo "🔍 FKS Server Diagnostics"
echo "========================="
echo ""

# Try to get server info from previous deployment
if [ -f "server-details.env" ]; then
    log "📋 Found server details file..."
    source server-details.env
    if [ -n "$TARGET_HOST" ]; then
        SERVER_IP="$TARGET_HOST"
        log "Using server IP from server-details.env: $SERVER_IP"
    fi
fi

# Prompt for missing information
if [ -z "$DOMAIN_NAME" ]; then
    read -p "Enter your domain name (e.g., fkstrading.xyz): " DOMAIN_NAME
fi

if [ -z "$SERVER_IP" ]; then
    read -p "Enter your server IP address: " SERVER_IP
fi

if [ -z "$ACTIONS_USER_PASSWORD" ]; then
    read -s -p "Enter actions_user password: " ACTIONS_USER_PASSWORD
    echo ""
fi

echo ""
log "Testing targets:"
log "  - Domain: $DOMAIN_NAME"
log "  - Server IP: $SERVER_IP"
echo ""

# Function to test connectivity
test_target() {
    local target="$1"
    local label="$2"
    
    echo "🔍 Testing $label ($target)..."
    
    # Test 1: Ping
    if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
        log "  ✅ Ping: Responding"
    else
        warn "  ❌ Ping: Not responding"
    fi
    
    # Test 2: SSH port
    if timeout 5 nc -z "$target" 22 2>/dev/null; then
        log "  ✅ SSH Port: Open"
        
        # Test 3: SSH authentication
        if timeout 10 sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$target" "echo 'SSH test successful'" 2>/dev/null; then
            log "  ✅ SSH Auth: Success"
            
            # Test 4: Get server info
            info "  📋 Server Info:"
            sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$target" "
                echo '    - Hostname: '$(hostname)
                echo '    - Uptime: '$(uptime | cut -d, -f1)
                echo '    - Docker: '$(docker --version 2>/dev/null || echo 'Not installed')
                echo '    - Stage 2 Status: '$(systemctl is-active stage-2-finalize 2>/dev/null || echo 'Not found')
            " 2>/dev/null || warn "  ⚠️ Could not get detailed server info"
            
            return 0
        else
            error "  ❌ SSH Auth: Failed"
        fi
    else
        error "  ❌ SSH Port: Closed/Unreachable"
    fi
    
    return 1
}

# Test both targets
log "🔍 Testing connectivity to both targets..."
echo ""

DOMAIN_OK=false
IP_OK=false

if [ -n "$DOMAIN_NAME" ]; then
    if test_target "$DOMAIN_NAME" "Domain"; then
        DOMAIN_OK=true
    fi
    echo ""
fi

if [ -n "$SERVER_IP" ]; then
    if test_target "$SERVER_IP" "Server IP"; then
        IP_OK=true
    fi
    echo ""
fi

# Recommendations
echo "🎯 Recommendations:"
echo "==================="

if [ "$IP_OK" = "true" ] && [ "$DOMAIN_OK" = "false" ]; then
    log "✅ Use SERVER IP for deployment"
    log "💡 Your server is ready, but DNS might not be updated yet"
    echo "   Set TARGET_HOST=$SERVER_IP in your environment"
    echo ""
    echo "   Example deployment command:"
    echo "   TARGET_HOST=$SERVER_IP ./scripts/deployment/deploy.sh"
    
elif [ "$DOMAIN_OK" = "true" ]; then
    log "✅ Use DOMAIN NAME for deployment"
    log "💡 DNS is properly configured and server is ready"
    echo "   Set TARGET_HOST=$DOMAIN_NAME in your environment"
    
elif [ "$IP_OK" = "false" ] && [ "$DOMAIN_OK" = "false" ]; then
    error "❌ Neither target is accessible"
    echo ""
    echo "🔧 Troubleshooting steps:"
    echo "1. Check if server is still rebooting (wait 5-10 minutes)"
    echo "2. Verify server was created successfully in Linode dashboard"
    echo "3. Check if firewall is blocking SSH (port 22)"
    echo "4. Try SSH with root user first:"
    echo "   ssh root@$SERVER_IP"
    echo "5. Check Stage 2 service status:"
    echo "   ssh root@$SERVER_IP 'systemctl status stage-2-finalize'"
    
else
    warn "⚠️ Mixed results - use the working target"
fi

echo ""
log "🏁 Diagnostics complete"
