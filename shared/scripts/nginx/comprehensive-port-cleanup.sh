#!/bin/bash
# Comprehensive port cleanup script for nginx deployment
# Handles conflicts on ports 80, 443, 8080, 8081, 8082, 19999

set -e

echo "🧹 Comprehensive pre-deployment cleanup for nginx..."

# Common ports used by nginx deployment
CRITICAL_PORTS=(80 443 8080 8081 8082 19999)

# Function to check if a port is in use
port_in_use() {
    local port=$1
    ss -tlnp 2>/dev/null | grep -q ":${port} " || \
    lsof -i :${port} 2>/dev/null | grep -q "LISTEN" 2>/dev/null
}

# Function to stop containers using specific port
stop_containers_on_port() {
    local port=$1
    echo "🔍 Checking port $port for conflicts..."
    
    # Find containers using this port
    containers=$(docker ps --format "table {{.Names}}\t{{.Ports}}" | grep ":$port" | awk '{print $1}' | head -10)
    
    if [ ! -z "$containers" ]; then
        echo "🛑 Stopping containers using port $port:"
        echo "$containers"
        echo "$containers" | xargs -r docker stop 2>/dev/null || true
        echo "$containers" | xargs -r docker rm -f 2>/dev/null || true
    fi
    
    # Kill any remaining processes using this port
    if port_in_use $port; then
        echo "🔫 Killing remaining processes on port $port..."
        sudo fuser -k ${port}/tcp 2>/dev/null || true
        sleep 1
    fi
}

# Function to clean up all Docker resources
cleanup_all_docker() {
    echo "🐳 Comprehensive Docker cleanup..."
    
    # Stop all nginx-related containers
    echo "🛑 Stopping all nginx-related containers..."
    docker ps -a --filter "name=nginx" --format "{{.Names}}" | xargs -r docker stop 2>/dev/null || true
    docker ps -a --filter "name=nginx" --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null || true
    
    # Stop FKS containers that might conflict
    docker ps -a --filter "name=fks" --format "{{.Names}}" | xargs -r docker stop 2>/dev/null || true
    docker ps -a --filter "name=fks" --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null || true
    
    # Remove nginx networks
    docker network ls --filter "name=nginx" --format "{{.Name}}" | xargs -r docker network rm 2>/dev/null || true
    
    # Clean up all unused Docker resources
    docker system prune -af --volumes 2>/dev/null || true
}

# Main cleanup function
main() {
    echo "🚀 Starting comprehensive pre-deployment cleanup..."
    
    # Stop containers on all critical ports
    for port in "${CRITICAL_PORTS[@]}"; do
        stop_containers_on_port $port
    done
    
    # Comprehensive Docker cleanup
    cleanup_all_docker
    
    # Verify all ports are now available
    echo "🔍 Verifying port availability..."
    all_clear=true
    for port in "${CRITICAL_PORTS[@]}"; do
        if port_in_use $port; then
            echo "⚠️ Port $port is still in use"
            ss -tlnp 2>/dev/null | grep ":$port " || true
            all_clear=false
        else
            echo "✅ Port $port is available"
        fi
    done
    
    if [ "$all_clear" = true ]; then
        echo "🎉 All critical ports are now available!"
    else
        echo "⚠️ Some ports may still have conflicts - check above"
    fi
    
    echo "✅ Comprehensive cleanup completed"
}

# Run main function
main "$@"
