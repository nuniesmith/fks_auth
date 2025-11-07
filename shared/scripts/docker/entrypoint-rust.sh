# =====================================================
# FILE: entrypoint-rust.sh (Rust-specific) 
# =====================================================
#!/bin/bash
# entrypoint-rust.sh - Enhanced Rust entrypoint
set -euo pipefail

# Basic logging with colors
log_info() { echo -e "\033[0;32m[INFO]\033[0m $(date -Iseconds) - $1"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m $(date -Iseconds) - $1" >&2; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $(date -Iseconds) - $1" >&2; }
log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo -e "\033[0;36m[DEBUG]\033[0m $(date -Iseconds) - $1"; }
log_section() { echo -e "\n\033[0;34m===== $1: $2 =====\033[0m"; }

# Import common functions if available
if [[ -f "/app/scripts/docker/common.sh" ]]; then
    source "/app/scripts/docker/common.sh"
fi

# Core environment variables with validation
APP_DIR="${APP_DIR:-/app}"
CONFIG_DIR="${CONFIG_DIR:-${APP_DIR}/config}"
BUILD_TYPE="${BUILD_TYPE:-cpu}"
SERVICE_TYPE="${SERVICE_TYPE:-node}"
SERVICE_NAME="${SERVICE_NAME:-fks_${SERVICE_TYPE}}"
SERVICE_PORT="${SERVICE_PORT:-9000}"
APP_ENV="${APP_ENV:-development}"
APP_LOG_LEVEL="${APP_LOG_LEVEL:-INFO}"

# Enable debug if needed
[[ "$APP_LOG_LEVEL" == "DEBUG" ]] && export DEBUG="true"

log_section "RUST" "Starting Rust service: ${SERVICE_TYPE}"

# Validate essential directories
if [[ ! -d "$APP_DIR" ]]; then
    log_error "App directory not found: $APP_DIR"
    exit 1
fi

# Load environment files with validation
log_info "Loading environment configuration"
ENV_FILES=(
    "${APP_DIR}/.env"
    "${APP_DIR}/.env.${APP_ENV}"
    "${APP_DIR}/.env.${SERVICE_TYPE}"
    "${APP_DIR}/.env.${SERVICE_TYPE}.${APP_ENV}"
    "${CONFIG_DIR}/.env"
    "${CONFIG_DIR}/.env.${APP_ENV}"
    "${CONFIG_DIR}/.env.${SERVICE_TYPE}"
)

env_files_loaded=0
for env_file in "${ENV_FILES[@]}"; do
    if [[ -f "$env_file" && -r "$env_file" ]]; then
        log_debug "Loading environment file: $env_file"
        set -o allexport
        source "$env_file"
        set +o allexport
        ((env_files_loaded++))
    fi
done

log_info "Loaded $env_files_loaded environment file(s)"

# Setup signal handlers
cleanup_rust_processes() {
    log_debug "Rust service cleanup initiated"
}

trap cleanup_rust_processes EXIT
trap 'log_info "Received SIGTERM, shutting down..."; exit 0' SIGTERM
trap 'log_info "Received SIGINT, shutting down..."; exit 0' SIGINT

# Create essential directories
log_info "Setting up directories"
ESSENTIAL_DIRS=(
    "${APP_DIR}/logs"
    "${APP_DIR}/data"
    "${APP_DIR}/data/cache"
    "${APP_DIR}/data/storage"
    "${APP_DIR}/outputs"
    "${APP_DIR}/outputs/${SERVICE_NAME}"
    "${APP_DIR}/data/cache/${SERVICE_NAME}"
)

for dir in "${ESSENTIAL_DIRS[@]}"; do
    if mkdir -p "$dir" 2>/dev/null; then
        log_debug "Created/verified directory: $dir"
    else
        log_warn "Failed to create directory: $dir"
    fi
done

# GPU Detection (if GPU build)
if [[ "$BUILD_TYPE" == "gpu" ]]; then
    log_info "Detecting GPU configuration"
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L &>/dev/null; then
        GPU_COUNT=$(nvidia-smi -L | wc -l)
        log_info "✅ GPU detected: $GPU_COUNT GPU(s) available"
        export GPU_AVAILABLE="true"
    else
        log_warn "⚠️ No GPU detected"
        export GPU_AVAILABLE="false"
    fi
fi

# Configuration file discovery
log_info "Discovering configuration files"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/fks/main.yaml}"
SERVICE_CONFIG="${CONFIG_DIR}/fks/${SERVICE_TYPE}.yaml"
NETWORK_CONFIG="${CONFIG_DIR}/fks/node_network/${SERVICE_TYPE}.yaml"

CONFIG_PATH=""
for config_file in "$SERVICE_CONFIG" "$NETWORK_CONFIG" "$CONFIG_FILE"; do
    if [[ -f "$config_file" && -r "$config_file" ]]; then
        CONFIG_PATH="$config_file"
        log_info "✅ Using configuration: $CONFIG_PATH"
        break
    fi
done

if [[ -z "$CONFIG_PATH" ]]; then
    log_warn "⚠️ No configuration file found"
    # Try to create basic configuration
    if [[ -f "${APP_DIR}/scripts/docker/setup-config.sh" && -x "${APP_DIR}/scripts/docker/setup-config.sh" ]]; then
        log_info "Running configuration setup script"
        "${APP_DIR}/scripts/docker/setup-config.sh"
        
        # Re-check for configuration
        for config_file in "$SERVICE_CONFIG" "$NETWORK_CONFIG" "$CONFIG_FILE"; do
            if [[ -f "$config_file" && -r "$config_file" ]]; then
                CONFIG_PATH="$config_file"
                log_info "✅ Created and using configuration: $CONFIG_PATH"
                break
            fi
        done
    fi
fi

# Set Rust environment variables
export RUST_LOG="${APP_LOG_LEVEL,,}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export SERVICE_PORT="$SERVICE_PORT"
export SERVICE_HOST="${SERVICE_HOST:-0.0.0.0}"
export CONFIG_PATH

log_debug "Rust environment configured:"
log_debug "  RUST_LOG=$RUST_LOG"
log_debug "  RUST_BACKTRACE=$RUST_BACKTRACE"
log_debug "  SERVICE_PORT=$SERVICE_PORT"
log_debug "  SERVICE_HOST=$SERVICE_HOST"

# Binary discovery with enhanced logic
log_info "Discovering Rust binary for service: $SERVICE_TYPE"

# Define binary search paths based on service type
case "$SERVICE_TYPE" in
    node|registry)
        BINARY_PATHS=(
            "/app/bin/network/trading-node"
            "/app/bin/network/${SERVICE_TYPE}"
            "/app/bin/network/fks_${SERVICE_TYPE}"
            "/app/bin/${SERVICE_TYPE}"
        )
        ;;
    execution|executor)
        BINARY_PATHS=(
            "/app/bin/execution/trading-execution"
            "/app/bin/execution/${SERVICE_TYPE}"
            "/app/bin/execution/fks_${SERVICE_TYPE}"
            "/app/bin/${SERVICE_TYPE}"
        )
        ;;
    connector|gateway)
        BINARY_PATHS=(
            "/app/bin/connector/network-connector"
            "/app/bin/connector/${SERVICE_TYPE}"
            "/app/bin/connector/fks_${SERVICE_TYPE}"
            "/app/bin/network/${SERVICE_TYPE}"
            "/app/bin/${SERVICE_TYPE}"
        )
        ;;
    *)
        BINARY_PATHS=(
            "/app/bin/${SERVICE_TYPE}"
            "/app/bin/network/${SERVICE_TYPE}"
            "/app/bin/execution/${SERVICE_TYPE}"
            "/app/bin/connector/${SERVICE_TYPE}"
            "/app/bin/fks_${SERVICE_TYPE}"
        )
        ;;
esac

# Find and validate binary
BINARY_PATH=""
for path in "${BINARY_PATHS[@]}"; do
    if [[ -f "$path" && -x "$path" ]]; then
        BINARY_PATH="$path"
        log_info "✅ Found Rust binary: $BINARY_PATH"
        break
    fi
    log_debug "Binary not found: $path"
done

if [[ -z "$BINARY_PATH" ]]; then
    log_error "❌ No executable binary found for Rust service: ${SERVICE_TYPE}"
    log_info "Searched paths:"
    for path in "${BINARY_PATHS[@]}"; do
        log_info "  - $path"
    done
    
    # List available binaries for debugging
    log_info "Available binaries:"
    find /app/bin -type f -executable 2>/dev/null | head -10 | while read -r binary; do
        log_info "  - $binary"
    done
    
    exit 1
fi

# Build command with arguments
CMD="\"${BINARY_PATH}\""

# Add standard arguments
[[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
[[ -n "$APP_LOG_LEVEL" ]] && CMD="${CMD} --log-level=${APP_LOG_LEVEL}"
[[ -n "$SERVICE_PORT" ]] && CMD="${CMD} --port=${SERVICE_PORT}"
[[ -n "$SERVICE_HOST" ]] && CMD="${CMD} --host=${SERVICE_HOST}"

# Add any additional arguments passed to the script
if [[ $# -gt 0 ]]; then
    CMD="${CMD} $*"
fi

# Summary and execution
log_section "SUMMARY" "Rust Service Configuration"
log_info "Version: ${APP_VERSION:-unknown}"
log_info "Build Type: ${BUILD_TYPE}"
log_info "Service Type: ${SERVICE_TYPE}"
log_info "Service Name: ${SERVICE_NAME}"
log_info "Environment: ${APP_ENV}"
log_info "Log Level: ${APP_LOG_LEVEL}"
log_info "Binary: ${BINARY_PATH}"
log_info "Config: ${CONFIG_PATH:-none}"
log_info "Port: ${SERVICE_PORT}"
log_info "Host: ${SERVICE_HOST}"
log_info "Command: $CMD"

log_section "EXEC" "Starting Rust service"

# Execute the service
log_debug "Executing command: $CMD"
eval "$CMD" &
child_pid=$!
log_info "🚀 Rust service started with PID $child_pid"

# Wait for the process to finish
wait "$child_pid"
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    log_info "✅ Service exited successfully (code $exit_code)"
else
    log_error "❌ Service exited with error code $exit_code"
fi

exit $exit_code