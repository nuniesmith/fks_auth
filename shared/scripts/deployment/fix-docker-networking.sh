#!/bin/bash

# FKS Trading Systems - Docker Networking Fix Script
# This script fixes common Docker networking issues, particularly iptables problems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

main() {
    log "INFO" "🔧 Starting Docker networking fix..."
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        log "ERROR" "This script requires root privileges or passwordless sudo"
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker >/dev/null 2>&1; then
        log "ERROR" "Docker is not installed"
        exit 1
    fi
    
    # Stop all Docker containers
    log "INFO" "🛑 Stopping all Docker containers..."
    if docker ps -q | xargs -r docker stop; then
        log "INFO" "✅ All containers stopped"
    else
        log "WARN" "⚠️ Some containers may not have stopped cleanly"
    fi
    
    # Remove all Docker networks (except default ones)
    log "INFO" "🧹 Cleaning up Docker networks..."
    docker network prune -f || log "WARN" "Network cleanup had warnings"
    
    # Stop Docker daemon
    log "INFO" "🛑 Stopping Docker daemon..."
    sudo systemctl stop docker
    
    # Clean up iptables rules
    log "INFO" "🧹 Cleaning up iptables rules..."
    
    # Remove Docker-related iptables rules
    sudo iptables -t nat -F DOCKER 2>/dev/null || true
    sudo iptables -t nat -X DOCKER 2>/dev/null || true
    sudo iptables -t filter -F DOCKER 2>/dev/null || true
    sudo iptables -t filter -X DOCKER 2>/dev/null || true
    sudo iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    sudo iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    sudo iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    sudo iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
    sudo iptables -t filter -F DOCKER-USER 2>/dev/null || true
    sudo iptables -t filter -X DOCKER-USER 2>/dev/null || true
    sudo iptables -t filter -F DOCKER-FORWARD 2>/dev/null || true
    sudo iptables -t filter -X DOCKER-FORWARD 2>/dev/null || true
    
    log "INFO" "✅ iptables cleanup completed"
    
    # Remove Docker network state
    log "INFO" "🧹 Cleaning up Docker network state..."
    sudo rm -rf /var/lib/docker/network/files/* 2>/dev/null || true
    
    # Start Docker daemon
    log "INFO" "🚀 Starting Docker daemon..."
    sudo systemctl start docker
    
    # Wait for Docker to be ready
    log "INFO" "⏳ Waiting for Docker daemon to be ready..."
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            log "INFO" "✅ Docker daemon is ready"
            break
        fi
        sleep 1
    done
    
    if ! docker info >/dev/null 2>&1; then
        log "ERROR" "❌ Docker daemon failed to start properly"
        exit 1
    fi
    
    # Test Docker networking
    log "INFO" "🧪 Testing Docker networking..."
    
    # Create a test network
    if docker network create test-network >/dev/null 2>&1; then
        log "INFO" "✅ Test network created successfully"
        docker network rm test-network >/dev/null 2>&1
        log "INFO" "✅ Test network removed successfully"
    else
        log "ERROR" "❌ Docker networking test failed"
        exit 1
    fi
    
    # Show current Docker status
    log "INFO" "📊 Docker status:"
    docker version --format 'Docker version: {{.Server.Version}}'
    docker info --format 'Docker root: {{.DockerRootDir}}'
    
    log "INFO" "✅ Docker networking fix completed successfully!"
    log "INFO" "🚀 You can now try running your Docker Compose services again"
}

# Run main function
main "$@"
