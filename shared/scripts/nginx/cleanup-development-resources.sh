#!/bin/bash
# Pre-deployment cleanup script for nginx
# Handles port conflicts and existing services

set -e

echo "🧹 Pre-deployment cleanup for nginx..."

# Function to check if a port is in use
port_in_use() {
    local port=$1
    netstat -tlnp 2>/dev/null | grep -q ":${port} " || \
    ss -tlnp 2>/dev/null | grep -q ":${port} " || \
    lsof -i :${port} 2>/dev/null | grep -q "LISTEN"
}

# Function to stop existing Netdata services
stop_existing_netdata() {
    echo "🔍 Checking for existing Netdata services..."
    
    # Stop Docker containers using port 19999
    if docker ps --filter "publish=19999" --format "{{.Names}}" 2>/dev/null | grep -q .; then
        echo "🛑 Stopping existing Docker containers on port 19999..."
        docker ps --filter "publish=19999" --format "{{.Names}}" | xargs -r docker stop
        docker ps -a --filter "publish=19999" --format "{{.Names}}" | xargs -r docker rm -f
    fi
    
    # Stop systemd Netdata service
    if systemctl is-active netdata >/dev/null 2>&1; then
        echo "🛑 Stopping systemd Netdata service..."
        systemctl stop netdata || true
        systemctl disable netdata || true
    fi
    
    # Kill any processes using port 19999
    if port_in_use 19999; then
        echo "🔫 Killing processes using port 19999..."
        fuser -k 19999/tcp 2>/dev/null || true
        sleep 2
    fi
}

# Function to clean up Docker resources
cleanup_docker() {
    echo "🐳 Cleaning up existing nginx Docker resources..."
    
    # Stop and remove nginx-related containers
    if docker ps -a --filter "name=nginx" --format "{{.Names}}" 2>/dev/null | grep -q .; then
        echo "🛑 Stopping existing nginx containers..."
        docker ps -a --filter "name=nginx" --format "{{.Names}}" | xargs -r docker stop 2>/dev/null || true
        docker ps -a --filter "name=nginx" --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null || true
    fi
    
    # Remove nginx network if it exists and is not in use
    if docker network ls --filter "name=nginx-network" --format "{{.Name}}" 2>/dev/null | grep -q "nginx-network"; then
        echo "🌐 Removing existing nginx network..."
        docker network rm nginx-network 2>/dev/null || true
    fi
    
    # Clean up dangling resources
    docker system prune -f --volumes 2>/dev/null || true
}

# Main cleanup
main() {
    echo "🚀 Starting nginx pre-deployment cleanup..."
    
    stop_existing_netdata
    cleanup_docker
    
    # Verify port is now available
    if port_in_use 19999; then
        echo "⚠️ Port 19999 is still in use after cleanup"
        echo "🔍 Processes using port 19999:"
        netstat -tlnp 2>/dev/null | grep ":19999 " || true
        lsof -i :19999 2>/dev/null || true
    else
        echo "✅ Port 19999 is now available"
    fi
    
    echo "✅ Pre-deployment cleanup completed"
}

# Run main function
main "$@"
