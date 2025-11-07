#!/bin/bash

# FKS Trading Systems - Restart Script
# This script provides safe restart capabilities with service validation

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/logs/restart.log"

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
    log "INFO" "🔄 Restarting FKS Trading Systems..."
    
    # Show current status
    log "INFO" "📊 Current service status:"
    $COMPOSE_CMD ps
    
    # Graceful restart
    log "INFO" "🛑 Stopping services gracefully..."
    $COMPOSE_CMD stop --timeout 30
    
    log "INFO" "🚀 Starting services..."
    $COMPOSE_CMD start
    
    # Wait for services
    log "INFO" "⏳ Waiting for services to initialize..."
    sleep 10
    
    # Show final status
    log "INFO" "📊 Final service status:"
    $COMPOSE_CMD ps
    
    # Quick health check
    FAILED_SERVICES=$($COMPOSE_CMD ps --services --filter "status=exited" | wc -l)
    if [ "$FAILED_SERVICES" -eq 0 ]; then
        log "INFO" "✅ All services restarted successfully!"
    else
        log "WARN" "⚠️ Some services may have issues - check logs with: docker compose logs"
    fi
}

# Handle specific service restart
if [ $# -gt 0 ]; then
    SERVICE="$1"
    log "INFO" "🔄 Restarting specific service: $SERVICE"
    $COMPOSE_CMD restart "$SERVICE"
    log "INFO" "✅ Service $SERVICE restarted"
else
    main
fi
