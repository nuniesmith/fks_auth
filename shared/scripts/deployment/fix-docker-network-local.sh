#!/bin/bash
# fix-docker-network-local.sh - Fix local Docker network issues

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Function to fix local Docker network issues
fix_local_docker_network() {
    log "🔧 Fixing local Docker network issues..."
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Get the directory
    local project_dir="${PWD}"
    log "📁 Working in: $project_dir"
    
    # Stop all fks containers
    log "📦 Stopping fks containers..."
    docker-compose down || true
    
    # Remove the problematic network
    log "🌐 Removing fks_network..."
    docker network rm fks_network 2>/dev/null || true
    
    # Prune unused networks
    log "🧹 Pruning unused networks..."
    docker network prune -f
    
    # Option 1: Quick fix - just recreate and start
    log "🚀 Method 1: Quick restart with network recreation..."
    
    # Use --force-recreate to ensure clean start
    if docker-compose up -d --force-recreate; then
        log "✅ Services started successfully!"
    else
        warning "⚠️ Quick restart failed, trying deeper fix..."
        
        # Option 2: Deeper fix - reset Docker networking
        log "🔧 Method 2: Resetting Docker networking..."
        
        # Stop all containers
        log "📦 Stopping all containers..."
        docker stop $(docker ps -aq) 2>/dev/null || true
        
        # Remove all custom networks
        log "🌐 Removing all custom networks..."
        docker network ls --format '{{.Name}}' | grep -v -E '^(bridge|host|none)$' | xargs -r docker network rm 2>/dev/null || true
        
        # Restart Docker service
        log "🔄 Restarting Docker service..."
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart docker
        else
            # For non-systemd systems (like macOS)
            warning "Cannot restart Docker automatically. Please restart Docker Desktop manually."
            read -p "Press Enter after restarting Docker..."
        fi
        
        # Wait for Docker to be ready
        log "⏳ Waiting for Docker to be ready..."
        for i in {1..30}; do
            if docker info >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        
        # Try starting services again
        log "🚀 Starting services after Docker restart..."
        docker-compose up -d
    fi
    
    # Check status
    log "📊 Checking service status..."
    docker-compose ps
    
    log "✅ Docker network fix completed!"
    log ""
    log "📋 Service URLs:"
    log "  - Web Interface: http://localhost:3000"
    log "  - API: http://localhost:8000"
    log "  - Data Service: http://localhost:9001"
    log "  - Redis: localhost:6379"
    log "  - PostgreSQL: localhost:5432"
}

# Main execution
main() {
    fix_local_docker_network
}

main "$@"
