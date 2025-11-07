#!/bin/bash

# Quick Docker Network Fix - Run this on the ATS server as root

echo "🔧 Quick Docker Network Fix"
echo "=========================="

# Step 1: Stop Docker
echo "🛑 Stopping Docker service..."
systemctl stop docker
sleep 3

# Step 2: Clean up iptables
echo "🧹 Cleaning up iptables Docker chains..."
iptables -t nat -F DOCKER 2>/dev/null || true
iptables -t filter -F DOCKER 2>/dev/null || true
iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

# Remove chains
iptables -t nat -X DOCKER 2>/dev/null || true
iptables -t filter -X DOCKER 2>/dev/null || true
iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

# Step 3: Remove bridge interfaces
echo "🧹 Removing Docker bridge interfaces..."
for interface in $(ip link show | grep br- | cut -d: -f2 | tr -d ' '); do
    echo "  Removing: $interface"
    ip link delete "$interface" 2>/dev/null || true
done

# Step 4: Clean Docker network data
echo "🧹 Cleaning Docker network data..."
rm -rf /var/lib/docker/network/* 2>/dev/null || true

# Step 5: Restart Docker
echo "🚀 Starting Docker service..."
systemctl start docker
sleep 10

# Step 6: Test
echo "🧪 Testing Docker..."
if docker info >/dev/null 2>&1; then
    echo "✅ Docker is working!"
    
    # Test network creation
    if docker network create test-net >/dev/null 2>&1; then
        echo "✅ Network creation works!"
        docker network rm test-net >/dev/null 2>&1
    else
        echo "❌ Network creation still fails"
    fi
else
    echo "❌ Docker still not working"
fi

echo ""
#!/bin/bash
# Quick Docker Compose Fix Script
# Can be called from any project to ensure Docker Compose works

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to detect and set the correct Docker Compose command
detect_compose_cmd() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        echo ""
    fi
}

# Main function
main() {
    log_info "🔧 Quick Docker Compose compatibility check..."
    
    # Check if Docker is available
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Detect compose command
    COMPOSE_CMD=$(detect_compose_cmd)
    
    if [[ -z "$COMPOSE_CMD" ]]; then
        log_error "No Docker Compose command available"
        log_info "Please install Docker Compose plugin or standalone docker-compose"
        exit 1
    fi
    
    log_info "✅ Found Docker Compose: $COMPOSE_CMD"
    
    # Test basic functionality
    if $COMPOSE_CMD --version >/dev/null 2>&1; then
        log_info "✅ Docker Compose is working"
        echo "$COMPOSE_CMD"
        exit 0
    else
        log_error "Docker Compose command failed"
        exit 1
    fi
}

main "$@"
