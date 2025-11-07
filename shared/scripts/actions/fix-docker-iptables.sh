#!/bin/bash
# =================================================================
# Docker iptables Fix for Arch Linux Servers
# =================================================================
# 
# This script fixes the iptables issues preventing Docker from
# creating networks properly on Arch Linux servers.
#
# Run this on any server that's having Docker networking issues.
#
set -euo pipefail

echo "🔧 Docker iptables Fix for Arch Linux Servers"
echo "=============================================="

# Function to check if we're running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "❌ This script must be run as root"
        echo "   Usage: sudo ./fix-docker-iptables.sh"
        exit 1
    fi
}

# Function to stop Docker safely
stop_docker() {
    echo "🛑 Stopping Docker services..."
    systemctl stop docker.socket || true
    systemctl stop docker.service || true
    sleep 3
}

# Function to clean up existing iptables rules
cleanup_iptables() {
    echo "🧹 Cleaning up existing Docker iptables rules..."
    
    # Remove Docker chains if they exist
    iptables -t nat -F DOCKER 2>/dev/null || true
    iptables -t filter -F DOCKER 2>/dev/null || true
    iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    iptables -t filter -F DOCKER-USER 2>/dev/null || true
    iptables -t filter -F DOCKER-CT 2>/dev/null || true
    
    # Delete Docker chains
    iptables -t nat -X DOCKER 2>/dev/null || true
    iptables -t filter -X DOCKER 2>/dev/null || true
    iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    iptables -t filter -X DOCKER-USER 2>/dev/null || true
    iptables -t filter -X DOCKER-CT 2>/dev/null || true
    
    echo "✅ iptables cleanup completed"
}

# Function to create required iptables chains
create_docker_chains() {
    echo "🔗 Creating required Docker iptables chains..."
    
    # Create NAT chains
    iptables -t nat -N DOCKER 2>/dev/null || true
    
    # Create FILTER chains
    iptables -t filter -N DOCKER 2>/dev/null || true
    iptables -t filter -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    iptables -t filter -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    iptables -t filter -N DOCKER-USER 2>/dev/null || true
    
    # Create the DOCKER-CT chain that was missing (critical for iptables connection tracking)
    iptables -t filter -N DOCKER-CT 2>/dev/null || true
    
    # Set up basic rules for Docker chains
    iptables -t filter -A DOCKER-USER -j RETURN 2>/dev/null || true
    iptables -t filter -A DOCKER-ISOLATION-STAGE-1 -j RETURN 2>/dev/null || true
    iptables -t filter -A DOCKER-ISOLATION-STAGE-2 -j RETURN 2>/dev/null || true
    
    echo "✅ Docker iptables chains created"
}

# Function to set up Docker forwarding rules
setup_docker_forwarding() {
    echo "📡 Setting up Docker forwarding rules..."
    
    # Set up the chain rules that Docker expects
    iptables -t nat -C PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
      iptables -t nat -I PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
    
    iptables -t nat -C OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
      iptables -t nat -I OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
    
    iptables -t filter -C FORWARD -j DOCKER-USER 2>/dev/null || \
      iptables -t filter -I FORWARD -j DOCKER-USER
    
    iptables -t filter -C FORWARD -j DOCKER-ISOLATION-STAGE-1 2>/dev/null || \
      iptables -t filter -I FORWARD -j DOCKER-ISOLATION-STAGE-1
    
    echo "✅ Docker forwarding rules configured"
}

# Function to restart Docker
restart_docker() {
    echo "🐳 Starting Docker services..."
    systemctl start docker.service
    systemctl enable docker.service
    
    # Wait for Docker to be ready
    echo "⏳ Waiting for Docker to be ready..."
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            echo "✅ Docker is ready"
            return 0
        fi
        sleep 2
    done
    
    echo "⚠️ Docker may not be fully ready yet"
}

# Function to test Docker networking
test_docker_networking() {
    echo "🧪 Testing Docker networking..."
    
    # Try to create a test network
    TEST_NETWORK="test-fix-$(date +%s)"
    if docker network create "$TEST_NETWORK" >/dev/null 2>&1; then
        echo "✅ Docker network creation successful"
        docker network rm "$TEST_NETWORK" >/dev/null 2>&1
    else
        echo "⚠️ Docker network creation still has issues"
        return 1
    fi
}

# Function to fix service-specific network issues  
fix_service_networks() {
    echo "🔧 Fixing service-specific Docker networks..."
    
    # Remove potentially corrupted service networks
    SERVICE_NETWORKS=(
        "nginx_nginx-network" 
        "fks_api-network" 
        "fks_web-network" 
        "fks_auth-network"
        "ats_ats-network"
    )
    
    for network in "${SERVICE_NETWORKS[@]}"; do
        if docker network ls --format "{{.Name}}" | grep -q "^${network}$"; then
            echo "🗑️ Removing existing network: $network"
            docker network rm "$network" 2>/dev/null || true
        fi
    done
    
    echo "✅ Service networks cleaned up"
}

# Main execution
main() {
    echo "🚀 Starting Docker iptables fix..."
    echo ""
    
    check_root
    stop_docker
    cleanup_iptables
    create_docker_chains
    setup_docker_forwarding
    restart_docker
    
    # Test basic networking
    if test_docker_networking; then
        # Clean up any potentially corrupted networks
        fix_service_networks
        
        echo ""
        echo "🎉 Docker iptables fix completed successfully!"
        echo ""
        echo "🔧 Next steps:"
        echo "  1. Try redeploying your services"
        echo "  2. Docker should now create networks without iptables errors"
        echo "  3. If you still have issues, check the Docker logs: journalctl -u docker"
        echo ""
    else
        echo ""
        echo "⚠️ Docker networking test failed"
        echo "You may need to:"
        echo "  1. Reboot the server"
        echo "  2. Check Docker logs: journalctl -u docker"
        echo "  3. Verify iptables modules are loaded: lsmod | grep iptable"
        echo "  4. Check for iptables-nft conflicts: pacman -Q | grep iptables"
    fi
}

# Run the fix
main "$@"
