#!/bin/sh
# entrypoint-runtime.sh - Enhanced runtime dispatcher for FKS services
# UPDATED: Fixed logging permissions and improved error handling
set -eu  # Removed pipefail as it's not available in all shells

# =====================================================
# LOGGING AND UTILITIES
# =====================================================

# Enhanced logging with color support
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    RED='' 
    GREEN='' 
    YELLOW='' 
    BLUE='' 
    PURPLE='' 
    CYAN='' 
    NC=''
fi

log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
    if [ "${APP_LOG_LEVEL:-INFO}" = "DEBUG" ]; then
        echo "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Basic service dispatcher
log_info "Starting FKS service: ${SERVICE_TYPE:-unknown}"
log_info "Environment: ${APP_ENV:-development}"
log_info "Runtime: ${SERVICE_RUNTIME:-python}"

# Handle different service types
case "${SERVICE_TYPE:-api}" in
    api)
        log_info "Starting API service on port ${SERVICE_PORT:-8000}"
        cd /app && exec python -m src.python.api.main
        ;;
    worker)
        log_info "Starting Worker service with ${WORKER_COUNT:-2} workers"
        cd /app && exec python -m src.python.worker.main
        ;;
    web)
        log_info "Starting Web interface on port 3000"
        cd /app && exec node /app/src/web/server.js
        ;;
    *)
        log_info "Starting generic service: ${SERVICE_TYPE}"
        if [ -f "/app/scripts/docker/entrypoint-${SERVICE_TYPE}.sh" ]; then
            exec "/app/scripts/docker/entrypoint-${SERVICE_TYPE}.sh" "$@"
        else
            log_error "No specific handler for ${SERVICE_TYPE}, using default"
            exec "$@"
        fi
        ;;
esac
