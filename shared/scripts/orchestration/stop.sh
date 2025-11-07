#!/bin/bash

# FKS Trading Systems - Stop Script
# This script provides safe shutdown capabilities

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/logs/stop.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
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
    esac
    
    # Also log to file
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Determine compose command
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    log "ERROR" "Docker Compose is not available!"
    exit 1
fi

main() {
    log "INFO" "🛑 Stopping FKS Trading Systems..."
    
    # Show current status
    log "INFO" "📊 Current service status:"
    $COMPOSE_CMD ps
    
    # Graceful shutdown
    log "INFO" "🛑 Stopping services gracefully..."
    $COMPOSE_CMD down --timeout 30
    
    # Clean up if requested
    if [ "$1" = "--clean" ]; then
        log "INFO" "🧹 Cleaning up Docker resources..."
        docker system prune -f
        log "INFO" "✅ Cleanup completed"
    fi
    
    log "INFO" "✅ FKS Trading Systems stopped successfully"
}

# Handle specific service stop
if [ $# -gt 0 ] && [ "$1" != "--clean" ]; then
    SERVICE="$1"
    log "INFO" "🛑 Stopping specific service: $SERVICE"
    $COMPOSE_CMD stop "$SERVICE"
    log "INFO" "✅ Service $SERVICE stopped"
else
    main "$@"
fi
