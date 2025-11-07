#!/bin/bash
# stage2-validation.sh - Validation scriptinfo "Checking Docker Networks"
echo "-------------------------"

# Get the service name (check if network config exists)
SERVICE_NAME=""
if [[ -f "/opt/docker-networks.conf" ]]; then
    source /opt/docker-networks.conf
fi

if [[ -n "$SERVICE_NAME" ]]; then
    EXPECTED_NETWORK="${SERVICE_NAME}-network"
    if docker network inspect "$EXPECTED_NETWORK" >/dev/null 2>&1; then
        success "Docker network '$EXPECTED_NETWORK' exists"
        # Get subnet info
        SUBNET=$(docker network inspect "$EXPECTED_NETWORK" --format='{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "unknown")
        info "  Subnet: $SUBNET"
    else
        error "Docker network '$EXPECTED_NETWORK' not found"
    fi
else
    # Fallback: check for any of the known networks
    EXPECTED_NETWORKS=("nginx-network" "fks_network" "ats-network")
    for network in "${EXPECTED_NETWORKS[@]}"; do
        if docker network inspect "$network" >/dev/null 2>&1; then
            success "Docker network '$network' exists"
            # Get subnet info
            SUBNET=$(docker network inspect "$network" --format='{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "unknown")
            info "  Subnet: $SUBNET"
            break
        fi
    done
fiompletion
# This script validates that Stage 2 completed successfully

set -euo pipefail

echo "🔍 Stage 2 Deployment Validation"
echo "================================"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# Check 1: System Services
echo ""
info "Checking System Services"
echo "------------------------"

# Docker
if systemctl is-active --quiet docker; then
    success "Docker service is running"
    if docker info >/dev/null 2>&1; then
        success "Docker daemon is responsive"
    else
        warning "Docker daemon not responding"
    fi
else
    error "Docker service is not running"
fi

# Tailscale
if systemctl is-active --quiet tailscaled; then
    success "Tailscale daemon is running"
    if tailscale status >/dev/null 2>&1; then
        success "Tailscale is connected"
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
        info "Tailscale IP: $TAILSCALE_IP"
    else
        warning "Tailscale daemon running but not connected"
    fi
else
    error "Tailscale daemon is not running"
fi

# Check 2: Docker Networks
echo ""
info "Checking Docker Networks"
echo "-------------------------"

# Check 3: Firewall Configuration
echo ""
info "Checking Firewall Configuration"
echo "--------------------------------"

if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        success "UFW firewall is active"
        if ufw status | grep -q "tailscale0"; then
            success "Tailscale interface allowed in UFW"
        else
            warning "Tailscale interface not explicitly allowed in UFW"
        fi
    else
        warning "UFW firewall is not active"
    fi
else
    warning "UFW not installed"
fi

# Check iptables for Docker chains
if iptables -t nat -L DOCKER >/dev/null 2>&1; then
    success "Docker iptables chains are configured"
else
    warning "Docker iptables chains not found"
fi

# Check 4: Tailscale Configuration
echo ""
info "Checking Tailscale Configuration"
echo "---------------------------------"

if tailscale status >/dev/null 2>&1; then
    # Check if routes are being advertised
    if tailscale status --peers=false --self | grep -q "advertised"; then
        success "Tailscale is advertising routes"
        info "Advertised routes:"
        tailscale status --peers=false --self | grep -E "(advertised|routes)" || true
    else
        warning "No routes being advertised by Tailscale"
    fi
    
    # Check connectivity
    if tailscale ping --c 1 --timeout 5s "$(tailscale ip -4)" >/dev/null 2>&1; then
        success "Tailscale self-connectivity test passed"
    else
        warning "Tailscale self-connectivity test failed"
    fi
else
    error "Cannot get Tailscale status"
fi

# Check 5: DNS Configuration
echo ""
info "Checking DNS Configuration"
echo "---------------------------"

if [[ -f "/tmp/tailscale_ip" ]]; then
    STORED_IP=$(cat /tmp/tailscale_ip)
    success "Tailscale IP stored: $STORED_IP"
    
    if [[ "$STORED_IP" != "pending" && "$STORED_IP" != "failed" && "$STORED_IP" != "unknown" ]]; then
        success "Valid Tailscale IP recorded"
    else
        warning "Tailscale IP shows: $STORED_IP"
    fi
else
    warning "No stored Tailscale IP found (/tmp/tailscale_ip missing)"
fi

# Check 6: Stage 2 Service Status
echo ""
info "Checking Stage 2 Service"
echo "-------------------------"

if systemctl list-units --type=service | grep -q "stage2-setup.service"; then
    success "Stage 2 systemd service exists"
    
    # Check service status
    if systemctl is-enabled stage2-setup.service >/dev/null 2>&1; then
        success "Stage 2 service is enabled"
    else
        warning "Stage 2 service is not enabled"
    fi
    
    # Check if service completed successfully
    EXIT_STATUS=$(systemctl show stage2-setup.service --property=ExecMainStatus --value 2>/dev/null || echo "unknown")
    if [[ "$EXIT_STATUS" == "0" ]]; then
        success "Stage 2 service completed successfully"
    else
        warning "Stage 2 service exit status: $EXIT_STATUS"
    fi
else
    warning "Stage 2 systemd service not found"
fi

# Check 7: User Configuration
echo ""
info "Checking User Configuration"
echo "----------------------------"

EXPECTED_USERS=("jordan" "actions_user")
for user in "${EXPECTED_USERS[@]}"; do
    if id "$user" >/dev/null 2>&1; then
        success "User '$user' exists"
        if groups "$user" | grep -q docker; then
            success "User '$user' is in docker group"
        else
            warning "User '$user' is not in docker group"
        fi
    else
        error "User '$user' does not exist"
    fi
done

# Check 8: File Permissions and Ownership
echo ""
info "Checking Critical Files"
echo "------------------------"

CRITICAL_FILES=(
    "/tmp/tailscale_ip"
    "/usr/local/bin/stage2-post-reboot.sh"
    "/opt/docker-networks.conf"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        success "File exists: $file"
        info "  Permissions: $(ls -la "$file" | awk '{print $1, $3, $4}')"
    else
        warning "File missing: $file"
    fi
done

# Summary
echo ""
echo "================================"
info "Validation Summary"
echo "================================"

# Count successes and warnings from above checks
if systemctl is-active --quiet docker && systemctl is-active --quiet tailscaled && tailscale status >/dev/null 2>&1; then
    success "Core services are operational"
else
    error "Critical services have issues"
fi

# Check for service-specific network
NETWORK_FOUND=false
if [[ -f "/opt/docker-networks.conf" ]]; then
    source /opt/docker-networks.conf
    if [[ -n "$SERVICE_NAME" ]] && docker network inspect "${SERVICE_NAME}-network" >/dev/null 2>&1; then
        NETWORK_FOUND=true
    fi
fi

# Fallback: check for any known network
if [[ "$NETWORK_FOUND" == "false" ]]; then
    for network in nginx-network fks_network ats-network; do
        if docker network inspect "$network" >/dev/null 2>&1; then
            NETWORK_FOUND=true
            break
        fi
    done
fi

if [[ "$NETWORK_FOUND" == "true" ]]; then
    success "Docker networks are configured"
else
    warning "Docker networks are missing"
fi

if [[ -f "/tmp/tailscale_ip" ]] && [[ "$(cat /tmp/tailscale_ip)" != "pending" ]] && [[ "$(cat /tmp/tailscale_ip)" != "failed" ]]; then
    success "Stage 2 deployment appears successful"
else
    warning "Stage 2 deployment may have issues"
fi

echo ""
info "For detailed logs, check:"
echo "  sudo journalctl -u stage2-setup.service --no-pager -l"
echo "  sudo journalctl -u tailscaled --no-pager -l --since='1 hour ago'"
echo "  docker network ls"
echo "  tailscale status"
