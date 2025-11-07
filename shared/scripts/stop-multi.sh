#!/bin/bash

# =================================================================
# FKS Trading Systems - Multi-Server Stop Script
# =================================================================
# 
# Supports both single-server and multi-server deployments:
# - Single Server: Stop all services on one server
# - Multi Server: Stop specific server type or all servers
# 
# =================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ENV_FILE="$PROJECT_ROOT/.env"

# Stop configuration
STOP_MODE="auto"          # auto, single, multi, auth, api, web, all
FORCE_STOP=false
REMOVE_VOLUMES=false
REMOVE_IMAGES=false
#!/usr/bin/env bash
# Shim: stop-multi moved to orchestration/multi/stop.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/orchestration/multi/stop.sh"
if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
        echo "$FKS_SERVER_TYPE"
        return
    fi
    
    # Check hostname patterns
    local hostname=$(hostname)
    case "$hostname" in
        *auth*|auth-*)
            echo "auth"
            return
            ;;
        *api*|api-*)
            echo "api"
            return
            ;;
        *web*|web-*)
            echo "web"
            return
            ;;
    esac
    
    # Default to single server
    echo "single"
}

# =================================================================
# DOCKER COMPOSE DETECTION
# =================================================================
detect_compose_command() {
    if command -v docker-compose &> /dev/null; then
        echo "docker-compose"
    elif docker compose version &> /dev/null; then
        echo "docker compose"
    else
        log "ERROR" "Docker Compose is not available!"
        exit 1
    fi
}

# =================================================================
# COMPOSE FILE SELECTION
# =================================================================
get_compose_files() {
    local mode="$1"
    local files=""
    
    case "$mode" in
        "single")
            files="docker-compose.yml"
            # Add additional compose files if they exist
            [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ] && files="$files -f docker-compose.gpu.yml"
            [ -f "$PROJECT_ROOT/docker-compose.minimal.yml" ] && files="$files -f docker-compose.minimal.yml"
            [ -f "$PROJECT_ROOT/docker-compose.dev.yml" ] && files="$files -f docker-compose.dev.yml"
            ;;
        "auth")
            files="docker-compose.auth.yml"
            ;;
        "api")
            files="docker-compose.api.yml"
            [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ] && files="$files -f docker-compose.gpu.yml"
            ;;
        "web")
            files="docker-compose.web.yml"
            ;;
        "multi"|"all")
            files=""
            [ -f "$PROJECT_ROOT/docker-compose.auth.yml" ] && files="$files docker-compose.auth.yml"
            [ -f "$PROJECT_ROOT/docker-compose.api.yml" ] && files="$files -f docker-compose.api.yml"
            [ -f "$PROJECT_ROOT/docker-compose.web.yml" ] && files="$files -f docker-compose.web.yml"
            [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ] && files="$files -f docker-compose.gpu.yml"
            ;;
    esac
    
    echo "$files"
}

# =================================================================
# SERVICE STOPPING
# =================================================================
stop_services() {
    local mode="$1"
    local compose_cmd=$(detect_compose_command)
    local compose_files=$(get_compose_files "$mode")
    
    log "STOP" "Stopping services in $mode mode..."
    
    if [ -z "$compose_files" ]; then
        log "WARN" "No compose files found for mode: $mode"
        return
    fi
    
    # Check if any services are running
    local running_containers=$($compose_cmd -f $compose_files ps -q 2>/dev/null || echo "")
    
    if [ -z "$running_containers" ]; then
        log "INFO" "No running containers found for $mode mode"
        return
    fi
    
    log "INFO" "Compose files: $compose_files"
    
    # Stop services gracefully
    if [ "$FORCE_STOP" = "true" ]; then
        log "WARN" "Force stopping containers..."
        $compose_cmd -f $compose_files kill
    else
        log "INFO" "Gracefully stopping containers..."
        $compose_cmd -f $compose_files stop
    fi
    
    # Remove containers
    log "INFO" "Removing containers..."
    $compose_cmd -f $compose_files down
    
    # Remove volumes if requested
    if [ "$REMOVE_VOLUMES" = "true" ]; then
        log "WARN" "Removing volumes..."
        $compose_cmd -f $compose_files down -v
    fi
    
    # Remove images if requested
    if [ "$REMOVE_IMAGES" = "true" ]; then
        log "WARN" "Removing images..."
        $compose_cmd -f $compose_files down --rmi all
    fi
    
    log "SUCCESS" "Services stopped successfully in $mode mode"
}

# =================================================================
# CLEANUP FUNCTIONS
# =================================================================
cleanup_docker() {
    local compose_cmd=$(detect_compose_command)
    
    log "INFO" "Performing Docker cleanup..."
    
    # Remove stopped containers
    log "INFO" "Removing stopped containers..."
    docker container prune -f 2>/dev/null || log "WARN" "Failed to prune containers"
    
    # Remove unused networks
    log "INFO" "Removing unused networks..."
    docker network prune -f 2>/dev/null || log "WARN" "Failed to prune networks"
    
    # Remove unused images
    if [ "$CLEANUP_ALL" = "true" ]; then
        log "WARN" "Removing all unused images..."
        docker image prune -a -f 2>/dev/null || log "WARN" "Failed to prune images"
    else
        log "INFO" "Removing dangling images..."
        docker image prune -f 2>/dev/null || log "WARN" "Failed to prune dangling images"
    fi
    
    # Remove unused volumes
    if [ "$REMOVE_VOLUMES" = "true" ]; then
        log "WARN" "Removing unused volumes..."
        docker volume prune -f 2>/dev/null || log "WARN" "Failed to prune volumes"
    fi
    
    log "SUCCESS" "Docker cleanup completed"
}

show_running_services() {
    local compose_cmd=$(detect_compose_command)
    
    log "INFO" "Checking for running FKS services..."
    
    # Check each possible deployment mode
    for mode in "single" "auth" "api" "web"; do
        local compose_files=$(get_compose_files "$mode")
        if [ -n "$compose_files" ]; then
            local running=$($compose_cmd -f $compose_files ps -q 2>/dev/null || echo "")
            if [ -n "$running" ]; then
                echo ""
                echo "🔸 $mode mode services:"
                $compose_cmd -f $compose_files ps
            fi
        fi
    done
    
    # Show any other FKS containers
    echo ""
    echo "🔸 All FKS containers:"
    docker ps --filter "name=fks" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "No FKS containers found"
}

# =================================================================
# INFORMATION DISPLAY
# =================================================================
show_stop_summary() {
    local mode="$1"
    
    echo ""
    echo "=========================================="
    echo "🛑 FKS Trading Systems - Stop Summary"
    echo "=========================================="
    echo ""
    echo "Stop Mode: $mode"
    echo "Force Stop: $([ "$FORCE_STOP" = "true" ] && echo "Yes" || echo "No")"
    echo "Remove Volumes: $([ "$REMOVE_VOLUMES" = "true" ] && echo "Yes" || echo "No")"
    echo "Remove Images: $([ "$REMOVE_IMAGES" = "true" ] && echo "Yes" || echo "No")"
    echo ""
    
    # Show remaining containers (if any)
    show_running_services
    
    echo ""
    echo "🔧 Next Steps:"
    echo "   • Restart:      ./start.sh"
    echo "   • View logs:    docker logs <container-name>"
    echo "   • Full cleanup: ./stop.sh --cleanup-all"
    echo ""
}

# =================================================================
# MULTI-SERVER OPERATIONS
# =================================================================
stop_all_servers() {
    log "STOP" "Stopping all servers in multi-server deployment..."
    
    # Stop each server type
    for server_type in "auth" "api" "web"; do
        if [ -f "$PROJECT_ROOT/docker-compose.$server_type.yml" ]; then
            log "INFO" "Stopping $server_type server..."
            stop_services "$server_type"
        else
            log "WARN" "No compose file found for $server_type server"
        fi
    done
    
    log "SUCCESS" "All servers stopped"
}

stop_remote_servers() {
    log "STOP" "Stopping remote servers..."
    
    # Load environment variables
    if [ -f "$ENV_FILE" ]; then
        set -a
        source "$ENV_FILE"
        set +a
    fi
    
    # Stop auth server
    if [ -n "$AUTH_SERVER_IP" ]; then
        log "INFO" "Stopping auth server at $AUTH_SERVER_IP..."
        ssh -o StrictHostKeyChecking=no "root@$AUTH_SERVER_IP" "cd /opt/fks && ./stop.sh --auth" || log "WARN" "Failed to stop auth server"
    fi
    
    # Stop API server
    if [ -n "$API_SERVER_IP" ]; then
        log "INFO" "Stopping API server at $API_SERVER_IP..."
        ssh -o StrictHostKeyChecking=no "root@$API_SERVER_IP" "cd /opt/fks && ./stop.sh --api" || log "WARN" "Failed to stop API server"
    fi
    
    # Stop web server
    if [ -n "$WEB_SERVER_IP" ]; then
        log "INFO" "Stopping web server at $WEB_SERVER_IP..."
        ssh -o StrictHostKeyChecking=no "root@$WEB_SERVER_IP" "cd /opt/fks && ./stop.sh --web" || log "WARN" "Failed to stop web server"
    fi
    
    log "SUCCESS" "Remote servers stop commands sent"
}

# =================================================================
# MAIN FUNCTION
# =================================================================
main() {
    local detected_env=$(detect_environment)
    
    # Override with command line arguments
    if [ "$STOP_MODE" = "auto" ]; then
        STOP_MODE="$detected_env"
    fi
    
    log "INFO" "🛑 Stopping FKS Trading Systems..."
    log "INFO" "Environment: $detected_env"
    log "INFO" "Stop Mode: $STOP_MODE"
    
    case "$STOP_MODE" in
        "single"|"auth"|"api"|"web")
            stop_services "$STOP_MODE"
            ;;
        "multi")
            stop_all_servers
            ;;
        "all")
            stop_all_servers
            ;;
        "remote")
            stop_remote_servers
            ;;
        *)
            log "ERROR" "Unknown stop mode: $STOP_MODE"
            exit 1
            ;;
    esac
    
    # Cleanup if requested
    if [ "$CLEANUP_ALL" = "true" ] || [ "$REMOVE_VOLUMES" = "true" ] || [ "$REMOVE_IMAGES" = "true" ]; then
        cleanup_docker
    fi
    
    # Show summary
    show_stop_summary "$STOP_MODE"
    
    log "SUCCESS" "🎉 FKS Trading Systems stopped successfully!"
}

# =================================================================
# COMMAND LINE PARSING
# =================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --single)
            STOP_MODE="single"
            shift
            ;;
        --multi)
            STOP_MODE="multi"
            shift
            ;;
        --auth)
            STOP_MODE="auth"
            shift
            ;;
        --api)
            STOP_MODE="api"
            shift
            ;;
        --web)
            STOP_MODE="web"
            shift
            ;;
        --all)
            STOP_MODE="all"
            shift
            ;;
        --remote)
            STOP_MODE="remote"
            shift
            ;;
        --force)
            FORCE_STOP=true
            shift
            ;;
        --remove-volumes)
            REMOVE_VOLUMES=true
            shift
            ;;
        --remove-images)
            REMOVE_IMAGES=true
            shift
            ;;
        --cleanup-all)
            CLEANUP_ALL=true
            REMOVE_VOLUMES=true
            REMOVE_IMAGES=true
            shift
            ;;
        --status)
            show_running_services
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# =================================================================
# HELP FUNCTION
# =================================================================
show_help() {
    cat << EOF
FKS Trading Systems - Multi-Server Stop Script

USAGE:
    $0 [OPTIONS] [MODE]

STOP MODES:
    --single        Stop single server deployment (default)
    --multi         Stop all servers in multi-server deployment
    --auth          Stop auth server only
    --api           Stop API server only  
    --web           Stop web server only
    --all           Stop all possible services
    --remote        Stop remote servers via SSH

OPTIONS:
    --force             Force stop containers (kill instead of stop)
    --remove-volumes    Remove Docker volumes
    --remove-images     Remove Docker images
    --cleanup-all       Complete cleanup (volumes + images + unused)
    --status            Show running services status
    --help, -h          Show this help message

EXAMPLES:
    $0                      # Auto-detect and stop
    $0 --single             # Stop single server
    $0 --multi              # Stop all servers
    $0 --auth               # Stop auth server only
    $0 --api --force        # Force stop API server
    $0 --web --cleanup-all  # Stop web server and cleanup
    $0 --remote             # Stop remote servers via SSH
    $0 --status             # Show status only

CLEANUP OPTIONS:
    $0 --remove-volumes     # Stop and remove data volumes
    $0 --remove-images      # Stop and remove Docker images
    $0 --cleanup-all        # Complete cleanup (DESTRUCTIVE)

ENVIRONMENT VARIABLES:
    AUTH_SERVER_IP=x.x.x.x    Auth server IP for remote stop
    API_SERVER_IP=x.x.x.x     API server IP for remote stop
    WEB_SERVER_IP=x.x.x.x     Web server IP for remote stop

EOF
}

# =================================================================
# SCRIPT EXECUTION
# =================================================================
main "$@"
