#!/bin/bash

# FKS Trading Systems - Docker Deployment Fix Script
# This script fixes Docker networking issues and ensures proper deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Function to fix Docker iptables
fix_docker_iptables() {
    log "Fixing Docker iptables chains..."
    
    # Check if Docker service is running
    if ! systemctl is-active --quiet docker; then
        warn "Docker service is not running. Starting Docker..."
        systemctl start docker
        sleep 5
    fi
    
    # Restart Docker to recreate iptables chains
    log "Restarting Docker service to recreate iptables chains..."
    systemctl restart docker
    sleep 10
    
    # Verify Docker iptables chains
    if iptables -L DOCKER-FORWARD -n &>/dev/null; then
        log "✅ Docker iptables chains are properly configured"
    else
        error "Docker iptables chains are still missing!"
        return 1
    fi
}

# Function to clean up Docker networks
cleanup_docker_networks() {
    log "Cleaning up Docker networks..."
    
    # Remove all containers first
    if [ "$(docker ps -aq)" ]; then
        log "Stopping and removing all containers..."
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm $(docker ps -aq) 2>/dev/null || true
    fi
    
    # Remove custom networks
    for network in $(docker network ls --format '{{.Name}}' | grep -v -E '^(bridge|host|none)$'); do
        log "Removing network: $network"
        docker network rm "$network" 2>/dev/null || true
    done
    
    log "✅ Docker networks cleaned up"
}

# Function to deploy FKS
deploy_fks() {
    local FKS_DIR="/home/fks_user/fks"
    
    if [ ! -d "$FKS_DIR" ]; then
        error "FKS directory not found at $FKS_DIR"
        return 1
    fi
    
    cd "$FKS_DIR"
    
    # Ensure proper ownership
    log "Setting proper ownership..."
    chown -R fks_user:fks_user "$FKS_DIR"
    
    # Run as fks_user
    log "Starting deployment as fks_user..."
    sudo -u fks_user bash << 'DEPLOY_SCRIPT'
    cd /home/fks_user/fks
    
    # Check if .env exists
    if [ ! -f .env ]; then
        echo "❌ .env file not found!"
        exit 1
    fi
    
    # Pull latest images
    echo "🐳 Pulling latest images..."
    docker compose pull
    
    # Start services
    echo "🚀 Starting services..."
    docker compose up -d
    
    # Wait for services
    echo "⏳ Waiting for services to initialize..."
    sleep 20
    
    # Check status
    echo "📊 Service status:"
    docker compose ps
DEPLOY_SCRIPT
}

# Main execution
main() {
    log "🚀 Starting FKS Docker deployment fix..."
    
    # Fix Docker iptables
    if ! fix_docker_iptables; then
        error "Failed to fix Docker iptables"
        exit 1
    fi
    
    # Clean up Docker networks
    cleanup_docker_networks
    
    # Deploy FKS
    if ! deploy_fks; then
        error "Failed to deploy FKS"
        exit 1
    fi
    
    log "✅ FKS Docker deployment completed successfully!"
}

# Run main function
main "$@"
