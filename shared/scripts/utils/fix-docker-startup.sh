#!/bin/bash

# FKS Docker Startup Fix
# Quick fix for Docker iptables issues during development
# This script can be run manually when docker-compose fails with networking errors

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR: $1${NC}"
}

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    error "This script requires root privileges"
    echo "Run with: sudo $0"
    exit 1
fi

log "🐳 FKS Docker Startup Fix"
log "Fixing Docker iptables networking issues..."

# Stop Docker daemon
log "Stopping Docker daemon..."
systemctl stop docker.service 2>/dev/null || true
sleep 3

# Clean up Docker iptables chains
log "Cleaning Docker iptables chains..."
for chain in DOCKER DOCKER-ISOLATION-STAGE-1 DOCKER-ISOLATION-STAGE-2 DOCKER-USER; do
    if iptables -L "$chain" -n >/dev/null 2>&1; then
        log "  Flushing chain: $chain"
        iptables -F "$chain" 2>/dev/null || true
        log "  Deleting chain: $chain"
        iptables -X "$chain" 2>/dev/null || true
    fi
done

# Clean NAT table
log "Cleaning Docker NAT rules..."
iptables -t nat -F DOCKER 2>/dev/null || true
iptables -t nat -X DOCKER 2>/dev/null || true

# Clean MANGLE table
log "Cleaning Docker MANGLE rules..."
iptables -t mangle -F DOCKER 2>/dev/null || true
iptables -t mangle -X DOCKER 2>/dev/null || true

# Remove Docker bridge interfaces
log "Removing Docker bridge interfaces..."
if ip link show docker0 >/dev/null 2>&1; then
    log "  Removing docker0 bridge"
    ip link set docker0 down 2>/dev/null || true
    ip link delete docker0 2>/dev/null || true
fi

# Remove any Docker-created bridge interfaces
for bridge in $(ip link show | grep 'br-' | awk -F': ' '{print $2}' | awk '{print $1}'); do
    log "  Removing bridge: $bridge"
    ip link set "$bridge" down 2>/dev/null || true
    ip link delete "$bridge" 2>/dev/null || true
done

# Start Docker daemon
log "Starting Docker daemon..."
systemctl start docker.service
sleep 5

# Wait for Docker to be ready
log "Waiting for Docker to initialize..."
timeout=30
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if systemctl is-active --quiet docker.service; then
        log "✅ Docker daemon is running"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if ! systemctl is-active --quiet docker.service; then
    error "❌ Docker daemon failed to start"
    exit 1
fi

# Test Docker networking
log "Testing Docker networking..."
test_network="fks_test-fix-$$"
if docker network create "$test_network" >/dev/null 2>&1; then
    log "✅ Docker network creation test: PASSED"
    docker network rm "$test_network" >/dev/null 2>&1
else
    error "❌ Docker network creation test: FAILED"
    echo ""
    echo "Docker may still have issues. Try:"
    echo "1. Reboot the system"
    echo "2. Check kernel modules: lsmod | grep netfilter"
    echo "3. Check iptables version: iptables --version"
    exit 1
fi

# Test basic container functionality
log "Testing Docker container functionality..."
if docker run --rm alpine:latest echo "Docker test successful" >/dev/null 2>&1; then
    log "✅ Docker container test: PASSED"
else
    warn "⚠️ Docker container test: FAILED (but networking is fixed)"
fi

log "🎉 Docker iptables fix completed successfully!"
echo ""
echo "You can now run your docker-compose commands:"
echo "  cd ~/fks"
echo "  ./start.sh"
echo "  # or"
echo "  docker-compose up -d"
echo ""
echo "If you still get networking errors, try:"
echo "  sudo reboot"
