#!/bin/bash

# Docker Network Troubleshooting Script
# Usage: ./fix-docker-network.sh

echo "🔧 Docker Network Troubleshooting Script"
echo "========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  This script needs to be run as root for network fixes"
   echo "Try: sudo $0"
   exit 1
fi

echo "🔍 Checking Docker status..."
systemctl is-active docker && echo "✅ Docker service is active" || echo "❌ Docker service is not active"

echo ""
echo "🔍 Checking iptables Docker chains..."
iptables -t nat -L DOCKER >/dev/null 2>&1 && echo "✅ Docker NAT chain exists" || echo "❌ Docker NAT chain missing"
iptables -t filter -L DOCKER >/dev/null 2>&1 && echo "✅ Docker FILTER chain exists" || echo "❌ Docker FILTER chain missing"

echo ""
echo "🔍 Current Docker networks:"
docker network ls 2>/dev/null || echo "❌ Cannot list Docker networks"

echo ""
echo "🔍 Current network interfaces:"
ip link show | grep -E "docker|br-" || echo "ℹ️  No Docker network interfaces found"

echo ""
echo "🔧 Performing network reset..."

# Stop Docker
echo "🛑 Stopping Docker..."
systemctl stop docker

# Wait a moment
sleep 2

# Clean up iptables rules
echo "🧹 Cleaning up iptables rules..."
iptables -t nat -F DOCKER 2>/dev/null || true
iptables -t filter -F DOCKER 2>/dev/null || true
iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

# Remove Docker chains
iptables -t nat -X DOCKER 2>/dev/null || true
iptables -t filter -X DOCKER 2>/dev/null || true
iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

# Remove Docker network interfaces
echo "🧹 Removing Docker network interfaces..."
for interface in $(ip link show | grep br- | cut -d: -f2 | tr -d ' '); do
    echo "  Removing interface: $interface"
    ip link delete "$interface" 2>/dev/null || true
done

# Clear any remaining Docker data
echo "🧹 Cleaning Docker data..."
rm -rf /var/lib/docker/network/* 2>/dev/null || true

# Restart Docker
echo "🚀 Restarting Docker..."
systemctl start docker

# Wait for Docker to be ready
echo "⏳ Waiting for Docker to be ready..."
sleep 10

# Verify Docker is working
if docker info >/dev/null 2>&1; then
    echo "✅ Docker is working properly"
    
    echo ""
    echo "🔍 New Docker networks:"
    docker network ls
    
    echo ""
    echo "🧪 Testing Docker network creation..."
    if docker network create test-network >/dev/null 2>&1; then
        echo "✅ Network creation test successful"
        docker network rm test-network >/dev/null 2>&1
    else
        echo "❌ Network creation test failed"
    fi
    
else
    echo "❌ Docker is still not working properly"
    echo "📝 Docker service status:"
    systemctl status docker
fi

echo ""
echo "✅ Network troubleshooting complete!"
echo "You can now try running docker-compose again."
