#!/bin/bash
# Comprehensive health check script for FKS services
# Handles various service types, runtimes, and build types (CPU/GPU)
set -eo pipefail

# --------------------------------------
# Configuration & Environment Variables
# --------------------------------------
SERVICE_TYPE=${SERVICE_TYPE:-app}
SERVICE_RUNTIME=${SERVICE_RUNTIME:-python}
SERVICE_PORT=${SERVICE_PORT:-8000}
BUILD_TYPE=${BUILD_TYPE:-cpu}
CURL_TIMEOUT=${CURL_TIMEOUT:-5}
PROCESS_CHECK_TIMEOUT=${PROCESS_CHECK_TIMEOUT:-3}
GPU_CHECK_TIMEOUT=${GPU_CHECK_TIMEOUT:-10}
APP_DIR=${APP_DIR:-/app}
HEALTHCHECK_DEBUG=${HEALTHCHECK_DEBUG:-false}

# --------------------------------------
# Utility Functions
# --------------------------------------

# Colorized logging functions
log_info() { echo -e "\033[0;32m[INFO]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "\033[0;33m[WARN]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_debug() { if [ "${HEALTHCHECK_DEBUG}" = "true" ]; then echo -e "\033[0;36m[DEBUG]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; fi; }

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Check if a process is running (with timeout)
check_process() {
    local process_pattern="$1"
    log_debug "Checking for process matching: $process_pattern"
    
    # Use timeout command if available
    if command_exists timeout; then
        if timeout ${PROCESS_CHECK_TIMEOUT} sh -c "ps aux | grep -v grep | grep -q \"$process_pattern\""; then
            log_debug "Process found: $process_pattern"
            return 0
        else
            log_error "Process not found: $process_pattern"
            return 1
        fi
    else
        # Fallback without timeout
        if ps aux | grep -v grep | grep -q "$process_pattern"; then
            log_debug "Process found: $process_pattern"
            return 0
        else
            log_error "Process not found: $process_pattern"
            return 1
        fi
    fi
}

# Check an HTTP endpoint (with timeout)
check_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    log_debug "Checking endpoint: $url (expecting status: $expected_status)"
    
    # Check if curl exists
    if ! command_exists curl; then
        log_error "curl command not found, cannot check endpoint"
        return 1
    fi
    
    # Get HTTP status code
    local http_status
    http_status=$(curl --silent --output /dev/null --write-out "%{http_code}" --max-time ${CURL_TIMEOUT} "$url" 2>/dev/null)
    local exit_code=$?
    
    # Check for curl errors
    if [ $exit_code -ne 0 ]; then
        log_error "Failed to connect to $url (curl exit code: $exit_code)"
        return 1
    fi
    
    # Check status code
    if [ "$http_status" = "$expected_status" ]; then
        log_debug "Endpoint $url returned status $http_status (success)"
        return 0
    else
        log_error "Endpoint $url returned unexpected status $http_status, expected $expected_status"
        return 1
    fi
}

# Check GPU availability
check_gpu() {
    log_debug "Checking GPU availability"
    
    # Check if this is a GPU build
    if [ "${BUILD_TYPE}" != "gpu" ]; then
        log_debug "Not a GPU build, skipping GPU check"
        return 0
    fi
    
    # Check if nvidia-smi is available
    if ! command_exists nvidia-smi; then
        log_warn "GPU build but nvidia-smi command not found"
        return 1
    fi
    
    # Check if GPU is accessible
    if command_exists timeout; then
        if timeout ${GPU_CHECK_TIMEOUT} nvidia-smi --query-gpu=name --format=csv,noheader > /dev/null; then
            local gpu_count
            gpu_count=$(nvidia-smi --list-gpus | wc -l)
            log_debug "GPU available: $gpu_count device(s) detected"
            return 0
        else
            log_error "GPU check failed: nvidia-smi returned error"
            return 1
        fi
    else
        # Fallback without timeout
        if nvidia-smi --query-gpu=name --format=csv,noheader > /dev/null; then
            local gpu_count
            gpu_count=$(nvidia-smi --list-gpus | wc -l)
            log_debug "GPU available: $gpu_count device(s) detected"
            return 0
        else
            log_error "GPU check failed: nvidia-smi returned error"
            return 1
        fi
    fi
}

# --------------------------------------
# Main Health Check Logic
# --------------------------------------

log_info "Starting health check for ${SERVICE_TYPE} service (runtime: ${SERVICE_RUNTIME}, build type: ${BUILD_TYPE})"

# Track check status
MAIN_CHECK_PASSED=false
GPU_CHECK_PASSED=false

# Perform service-specific health check
case "${SERVICE_TYPE}" in
    # API and web services - check HTTP health endpoint
    api|web|registry|connector|execution)
        if check_endpoint "http://localhost:${SERVICE_PORT}/health"; then
            MAIN_CHECK_PASSED=true
        fi
        ;;
    
    # Worker services - check process existence
    worker|workers)
        if check_process "worker"; then
            MAIN_CHECK_PASSED=true
        fi
        ;;
    
    # Application services - check API health endpoint
    app)
        if check_endpoint "http://localhost:${SERVICE_PORT}/api/health"; then
            MAIN_CHECK_PASSED=true
        elif check_endpoint "http://localhost:${SERVICE_PORT}/health"; then
            # Fallback to standard health endpoint
            log_info "Using fallback health endpoint"
            MAIN_CHECK_PASSED=true
        fi
        ;;
    
    # Training services - check process existence
    training)
        if check_process "training"; then
            MAIN_CHECK_PASSED=true
        fi
        ;;
    
    # Default fallback checks
    *)
        # Try custom healthcheck script if exists
        if [ -f "${APP_DIR}/scripts/docker/healthcheck-${SERVICE_TYPE}.sh" ]; then
            log_info "Using custom health check script for ${SERVICE_TYPE}"
            source "${APP_DIR}/scripts/docker/healthcheck-${SERVICE_TYPE}.sh"
            # Custom scripts should exit on their own if they fail
            MAIN_CHECK_PASSED=true
        
        # Try HTTP endpoint if port is specified
        elif [ -n "${SERVICE_PORT}" ]; then
            if check_endpoint "http://localhost:${SERVICE_PORT}/health"; then
                MAIN_CHECK_PASSED=true
            elif check_endpoint "http://localhost:${SERVICE_PORT}/"; then
                # Try root endpoint as fallback
                MAIN_CHECK_PASSED=true
            fi
        
        # Runtime-specific process checks
        else
            if [ "${SERVICE_RUNTIME}" = "rust" ]; then
                # For Rust services, check binary is running
                if check_process "${SERVICE_TYPE}"; then
                    MAIN_CHECK_PASSED=true
                fi
            elif [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then
                # For Python services, check Python process with service name
                if check_process "python.*${SERVICE_TYPE}"; then
                    MAIN_CHECK_PASSED=true
                fi
            else
                # Unknown runtime - default to success but log warning
                log_warn "Unknown runtime ${SERVICE_RUNTIME}, cannot perform specific check"
                MAIN_CHECK_PASSED=true
            fi
        fi
        ;;
esac

# For GPU builds, check GPU availability if service check passed
if [ "${BUILD_TYPE}" = "gpu" ] && [ "${MAIN_CHECK_PASSED}" = "true" ]; then
    if check_gpu; then
        GPU_CHECK_PASSED=true
    fi
else
    # Not a GPU build or service check failed
    GPU_CHECK_PASSED=true  # Skip GPU check for non-GPU builds
fi

# Determine final health status
if [ "${MAIN_CHECK_PASSED}" = "true" ] && [ "${GPU_CHECK_PASSED}" = "true" ]; then
    log_info "Health check passed for ${SERVICE_TYPE} (runtime: ${SERVICE_RUNTIME})"
    exit 0
elif [ "${MAIN_CHECK_PASSED}" = "false" ]; then
    log_error "Service health check failed for ${SERVICE_TYPE}"
    exit 1
elif [ "${GPU_CHECK_PASSED}" = "false" ]; then
    log_error "GPU health check failed for ${SERVICE_TYPE}"
    exit 2
else
    # This should never happen, but just in case
    log_error "Unknown health check status"
    exit 3
fi