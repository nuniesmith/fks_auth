#!/bin/bash

# FKS Trading Systems - Stop Script
# Gracefully stops all FKS services

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Try load root .env (two levels up) for COMPOSE_DIR if available
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -f "$ROOT_DIR/.env" ]; then
    # shellcheck disable=SC1090
    set -a; source "$ROOT_DIR/.env"; set +a
fi

# Compose stack relocated into fks_master directory
: "${COMPOSE_DIR:=$SCRIPT_DIR}"
COMPOSE_BASE="$COMPOSE_DIR/docker-compose.yml"
COMPOSE_DEV="$COMPOSE_DIR/docker-compose.dev.yml"
COMPOSE_PROD="$COMPOSE_DIR/docker-compose.prod.yml"

# Simple logging
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

# Check Docker Compose command availability
check_compose_command() {
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        log "ERROR" "Docker Compose is not available!"
        exit 1
    fi
}

show_help() {
    echo "FKS Trading Systems Stop Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --force             Force stop and remove all containers"
    echo "  --volumes           Also remove volumes (WARNING: data loss)"
    echo "  --gpu-only          Stop only GPU services"
    echo "  --core-only         Stop only core services (keep GPU running)"
    echo ""
    echo "Examples:"
    echo "  $0                  # Graceful stop of all services"
    echo "  $0 --force          # Force stop and remove containers"
    echo "  $0 --force --volumes # Force stop and remove containers + volumes"
    echo "  $0 --gpu-only       # Stop only GPU services"
    echo ""
}

# Parse command line arguments
parse_args() {
    FORCE_STOP=false
    REMOVE_VOLUMES=false
    GPU_ONLY=false
    CORE_ONLY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --force)
                FORCE_STOP=true
                shift
                ;;
            --volumes)
                REMOVE_VOLUMES=true
                shift
                ;;
            --gpu-only)
                GPU_ONLY=true
                shift
                ;;
            --core-only)
                CORE_ONLY=true
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done
}

# Main stop function
main() {
    parse_args "$@"
    
    log "INFO" "🛑 Stopping FKS Trading Systems..."
    
    # Change to project directory
    cd "$PROJECT_ROOT"
    
    # Check Docker Compose command
    check_compose_command
    
    # Determine compose files to use
    # Always reference central compose stack
    COMPOSE_FILES="-f $COMPOSE_BASE"
    [ -f "$COMPOSE_DEV" ] && COMPOSE_FILES="$COMPOSE_FILES -f $COMPOSE_DEV"
    [ -f "$COMPOSE_PROD" ] && COMPOSE_FILES="$COMPOSE_FILES -f $COMPOSE_PROD"
    
    # Add GPU compose file if it exists and we're not doing core-only
    if [ "$CORE_ONLY" != "true" ] && [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.gpu.yml"
    fi
    
    # Show current status before stopping
    log "INFO" "📊 Current service status:"
    $COMPOSE_CMD $COMPOSE_FILES ps || true
    echo ""
    
    if [ "$GPU_ONLY" = "true" ]; then
        log "INFO" "🎮 Stopping GPU services only..."
        if [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ]; then
            # Stop GPU services specifically
            $COMPOSE_CMD -f docker-compose.gpu.yml --profile gpu stop
            if [ "$FORCE_STOP" = "true" ]; then
                $COMPOSE_CMD -f docker-compose.gpu.yml --profile gpu rm -f
            fi
        else
            log "WARN" "⚠️ GPU compose file not found"
        fi
    elif [ "$CORE_ONLY" = "true" ]; then
        log "INFO" "🔧 Stopping core services only (keeping GPU services running)..."
        # Stop core services without GPU
        $COMPOSE_CMD -f "$COMPOSE_BASE" stop
        if [ "$FORCE_STOP" = "true" ]; then
            $COMPOSE_CMD -f "$COMPOSE_BASE" rm -f
        fi
    else
        log "INFO" "🔄 Stopping all FKS services..."
        
        if [ "$FORCE_STOP" = "true" ]; then
            log "INFO" "⚡ Force stopping and removing containers..."
            $COMPOSE_CMD $COMPOSE_FILES down --remove-orphans
            
            if [ "$REMOVE_VOLUMES" = "true" ]; then
                log "WARN" "🗑️ Removing volumes (this will delete all data)..."
                $COMPOSE_CMD $COMPOSE_FILES down --remove-orphans --volumes
                
                # Also remove named volumes
                docker volume ls -q | grep fks_ | xargs -r docker volume rm || true
            fi
        else
            log "INFO" "🔄 Gracefully stopping services..."
            $COMPOSE_CMD $COMPOSE_FILES stop
        fi
    fi
    
    # Clean up any orphaned containers
    log "INFO" "🧹 Cleaning up orphaned containers..."
    docker container prune -f || true
    
    # Show final status
    echo ""
    log "INFO" "📊 Final service status:"
    $COMPOSE_CMD $COMPOSE_FILES ps || true
    
    # Show remaining FKS containers (if any)
    REMAINING_CONTAINERS=$(docker ps -a --filter "name=fks_" --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || echo "")
    if [ -n "$REMAINING_CONTAINERS" ] && [ "$REMAINING_CONTAINERS" != "NAMES	STATUS" ]; then
        echo ""
        log "INFO" "🐳 Remaining FKS containers:"
        echo "$REMAINING_CONTAINERS"
    else
        echo ""
        log "INFO" "✅ All FKS containers stopped"
    fi
    
    # Show GPU containers specifically if we have them
    GPU_CONTAINERS=$(docker ps -a --filter "name=fks_.*_gpu" --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || echo "")
    if [ -n "$GPU_CONTAINERS" ] && [ "$GPU_CONTAINERS" != "NAMES	STATUS" ]; then
        echo ""
        log "INFO" "🎮 GPU service status:"
        echo "$GPU_CONTAINERS"
    fi
    
    echo ""
    log "INFO" "🎉 FKS Trading Systems stop complete!"
    
    if [ "$FORCE_STOP" != "true" ]; then
        log "INFO" "💡 To completely remove containers, use: $0 --force"
        log "INFO" "💡 To remove containers and data, use: $0 --force --volumes"
    fi
    
    log "INFO" "🚀 To start services again, run: ./start.sh"
    if [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ]; then
        log "INFO" "🎮 To start with GPU support, run: ./start.sh --gpu"
    fi
}

# Run main function
main "$@"
