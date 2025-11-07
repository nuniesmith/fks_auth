#!/bin/bash
# =================================================================
# Universal Health Check Script
# =================================================================
# This script provides health checking for all FKS services
# Usage: healthcheck.sh [options]
# Options:
#   --port PORT       Port to check (default: SERVICE_PORT or 8000)
#   --timeout SEC     Timeout in seconds (default: 5)
#   --endpoint PATH   Health endpoint path (default: /health)
#   --type TYPE       Check type: http, tcp, process (default: auto)
#   --service NAME    Service name for process check
#   --verbose         Enable verbose output

set -euo pipefail

# Default values
PORT="${SERVICE_PORT:-8000}"
TIMEOUT=5
ENDPOINT="/health"
CHECK_TYPE="auto"
SERVICE_NAME="${SERVICE_NAME:-}"
VERBOSE=false
SERVICE_RUNTIME="${SERVICE_RUNTIME:-python}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --type)
            CHECK_TYPE="$2"
            shift 2
            ;;
        --service)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Logging functions
log() {
    if [ "$VERBOSE" = "true" ]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
    fi
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# HTTP health check
check_http() {
    local url="http://localhost:${PORT}${ENDPOINT}"
    log "Checking HTTP endpoint: $url"
    
    if command_exists curl; then
        if curl -sf -m "$TIMEOUT" "$url" -o /dev/null; then
            log "✅ HTTP check passed"
            return 0
        else
            log_error "HTTP check failed: curl exit code $?"
            return 1
        fi
    elif command_exists wget; then
        if wget -q -O /dev/null -T "$TIMEOUT" "$url"; then
            log "✅ HTTP check passed"
            return 0
        else
            log_error "HTTP check failed: wget exit code $?"
            return 1
        fi
    else
        log "No HTTP client available, falling back to TCP check"
        return 2
    fi
}

# TCP port check
check_tcp() {
    log "Checking TCP port: $PORT"
    
    if command_exists nc; then
        if nc -z -w "$TIMEOUT" localhost "$PORT" 2>/dev/null; then
            log "✅ TCP check passed"
            return 0
        else
            log_error "TCP check failed: port $PORT not responding"
            return 1
        fi
    elif command_exists timeout; then
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/localhost/$PORT" 2>/dev/null; then
            log "✅ TCP check passed"
            return 0
        else
            log_error "TCP check failed: port $PORT not responding"
            return 1
        fi
    else
        # Direct bash TCP check without timeout
        if (echo >/dev/tcp/localhost/"$PORT") 2>/dev/null; then
            log "✅ TCP check passed"
            return 0
        else
            log_error "TCP check failed: port $PORT not responding"
            return 1
        fi
    fi
}

# Process check
check_process() {
    local process_name="${SERVICE_NAME:-$SERVICE_RUNTIME}"
    log "Checking process: $process_name"
    
    # Check by process name
    if pgrep -f "$process_name" >/dev/null 2>&1; then
        log "✅ Process check passed"
        return 0
    fi
    
    # Check by port if process name check fails
    if command_exists lsof; then
        if lsof -i ":$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
            log "✅ Process listening on port $PORT"
            return 0
        fi
    elif command_exists ss; then
        if ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
            log "✅ Process listening on port $PORT"
            return 0
        fi
    elif command_exists netstat; then
        if netstat -tlnp 2>/dev/null | grep -q ":$PORT"; then
            log "✅ Process listening on port $PORT"
            return 0
        fi
    fi
    
    log_error "Process check failed: no process found"
    return 1
}

# Service-specific health checks
check_service_specific() {
    case "$SERVICE_RUNTIME" in
        python)
            # Check if Python virtual environment is activated
            if [ -n "${VIRTUAL_ENV:-}" ]; then
                log "✅ Python virtual environment active"
            fi
            
            # Check for common Python web frameworks
            if check_http; then
                return 0
            fi
            ;;
            
        rust)
            # Rust services typically have HTTP endpoints
            if check_http; then
                return 0
            fi
            ;;
            
        node)
            # Node.js services typically have HTTP endpoints
            if check_http; then
                return 0
            fi
            ;;
            
        dotnet)
            # .NET services typically have HTTP endpoints
            if check_http; then
                return 0
            fi
            ;;
            
        nginx)
            # Special handling for nginx
            if command_exists nginx; then
                if nginx -t 2>/dev/null; then
                    log "✅ Nginx configuration valid"
                    return 0
                fi
            fi
            ;;
    esac
    
    # Fallback to TCP check
    return 2
}

# Auto-detect check type
auto_detect_check() {
    log "Auto-detecting health check type for $SERVICE_RUNTIME service"
    
    # Try service-specific check first
    if check_service_specific; then
        return 0
    fi
    
    # Try HTTP check
    if check_http; then
        return 0
    fi
    
    # Fall back to TCP check
    if check_tcp; then
        return 0
    fi
    
    # Last resort: process check
    if check_process; then
        return 0
    fi
    
    return 1
}

# Main health check logic
main() {
    log "Starting health check for service: ${SERVICE_NAME:-unknown}"
    log "Runtime: $SERVICE_RUNTIME, Port: $PORT, Type: $CHECK_TYPE"
    
    case "$CHECK_TYPE" in
        http)
            if check_http; then
                exit 0
            fi
            ;;
            
        tcp)
            if check_tcp; then
                exit 0
            fi
            ;;
            
        process)
            if check_process; then
                exit 0
            fi
            ;;
            
        auto|*)
            if auto_detect_check; then
                exit 0
            fi
            ;;
    esac
    
    # Health check failed
    log_error "Health check failed for ${SERVICE_NAME:-service} on port $PORT"
    exit 1
}

# Run main function
main