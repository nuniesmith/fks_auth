#!/bin/bash
# entrypoint.sh - A single unified entrypoint for all FKS services
set -euo pipefail

# =====================================================
# INITIALIZATION AND COMMON FUNCTIONS
# =====================================================

# Global variables for process management
declare -a RUST_DEPENDENCIES=()
declare -a RUST_PIDS=()
declare -a CLEANUP_FUNCTIONS=()
MAIN_PID=""
SHUTDOWN_INITIATED=false

# Import common functions if available
if [[ -f "/app/scripts/docker/common.sh" ]]; then
    source "/app/scripts/docker/common.sh"
else
    # Define minimal logging functions if common.sh is not available
    log_info() { 
        echo -e "[INFO] $(date -Iseconds) - $1" | tee -a "${LOG_FILE:-/dev/stderr}"
    }
    log_warn() { 
        echo -e "[WARN] $(date -Iseconds) - $1" | tee -a "${LOG_FILE:-/dev/stderr}" >&2
    }
    log_error() { 
        echo -e "[ERROR] $(date -Iseconds) - $1" | tee -a "${LOG_FILE:-/dev/stderr}" >&2
    }
    log_debug() { 
        if [[ "${DEBUG:-false}" == "true" ]]; then 
            echo -e "[DEBUG] $(date -Iseconds) - $1" | tee -a "${LOG_FILE:-/dev/stderr}"
        fi
    }
    log_section() { 
        echo -e "\n===== $1: $2 =====" | tee -a "${LOG_FILE:-/dev/stderr}"
    }
    
    # Function to create and verify directories
    create_and_verify_dir() {
        local dir="$1"
        local owner="${2:-$(whoami)}"
        
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir" 2>/dev/null; then
                log_debug "Created directory: $dir"
            else
                log_warn "Failed to create directory: $dir"
                return 1
            fi
        fi
        
        if [[ ! -w "$dir" ]]; then
            log_warn "Directory not writable: $dir"
            return 1
        fi
        
        # Set ownership if different from current user and we have permission
        if [[ "$owner" != "$(whoami)" ]] && [[ "$(id -u)" == "0" ]]; then
            chown "$owner:$owner" "$dir" 2>/dev/null || log_debug "Could not change ownership of $dir"
        fi
        
        return 0
    }
    
    # Function to load environment files safely
    load_env_file() {
        local env_file="$1"
        if [[ -f "$env_file" && -r "$env_file" ]]; then
            log_debug "Loading environment file: $env_file"
            # Validate env file format before sourcing
            if grep -q '^[a-zA-Z_][a-zA-Z0-9_]*=' "$env_file" 2>/dev/null; then
                set -o allexport
                source "$env_file"
                set +o allexport
                return 0
            else
                log_warn "Invalid environment file format: $env_file"
            fi
        fi
        return 1
    }
    
    # Function to check if a parameter exists in a command
    has_parameter() {
        local param="$1"
        local cmd="$2"
        [[ "$cmd" == *"$param"* ]]
    }
    
    # Function to check if a command exists
    command_exists() {
        command -v "$1" >/dev/null 2>&1
    }
    
    # Function to validate critical environment variables
    validate_environment() {
        local required_vars=("SERVICE_TYPE" "SERVICE_RUNTIME" "APP_DIR")
        local missing_vars=()
        
        for var in "${required_vars[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                missing_vars+=("$var")
            fi
        done
        
        if [[ ${#missing_vars[@]} -gt 0 ]]; then
            log_error "Missing required environment variables: ${missing_vars[*]}"
            return 1
        fi
        
        return 0
    }
    
    # Enhanced signal handler setup
    setup_signal_handlers() {
        trap 'handle_signal SIGTERM' SIGTERM
        trap 'handle_signal SIGINT' SIGINT
        trap 'handle_signal SIGQUIT' SIGQUIT
        trap 'handle_exit' EXIT
    }
    
    handle_signal() {
        local signal="$1"
        if [[ "$SHUTDOWN_INITIATED" == "true" ]]; then
            log_debug "Signal $signal received but shutdown already in progress"
            return
        fi
        
        SHUTDOWN_INITIATED=true
        log_info "Received $signal, initiating graceful shutdown..."
        
        # Stop main process first
        if [[ -n "$MAIN_PID" ]] && kill -0 "$MAIN_PID" 2>/dev/null; then
            log_info "Stopping main service (PID: $MAIN_PID)"
            kill -TERM "$MAIN_PID" 2>/dev/null || kill -KILL "$MAIN_PID" 2>/dev/null || true
            
            # Wait up to 30 seconds for graceful shutdown
            local count=0
            while kill -0 "$MAIN_PID" 2>/dev/null && [[ $count -lt 30 ]]; do
                sleep 1
                ((count++))
            done
            
            if kill -0 "$MAIN_PID" 2>/dev/null; then
                log_warn "Main service did not stop gracefully, forcing termination"
                kill -KILL "$MAIN_PID" 2>/dev/null || true
            fi
        fi
        
        cleanup_processes
        exit 0
    }
    
    handle_exit() {
        if [[ "$SHUTDOWN_INITIATED" == "false" ]]; then
            log_debug "Exit handler called"
            cleanup_processes
        fi
    }
    
    # Enhanced cleanup function
    cleanup_processes() {
        log_debug "Starting cleanup process"
        
        # Run custom cleanup functions
        for cleanup_func in "${CLEANUP_FUNCTIONS[@]}"; do
            if declare -F "$cleanup_func" > /dev/null; then
                log_debug "Running cleanup function: $cleanup_func"
                "$cleanup_func" || log_warn "Cleanup function $cleanup_func failed"
            fi
        done
        
        # Stop Rust dependencies
        for pid in "${RUST_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                log_info "Stopping Rust dependency (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
                
                # Wait briefly for graceful shutdown
                local count=0
                while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                    sleep 0.5
                    ((count++))
                done
                
                if kill -0 "$pid" 2>/dev/null; then
                    kill -KILL "$pid" 2>/dev/null || true
                fi
            fi
        done
        
        log_debug "Cleanup completed"
    }
    
    # GPU detection and configuration
    detect_and_configure_gpu() {
        if [[ "${BUILD_TYPE}" != "gpu" ]]; then
            export GPU_AVAILABLE="false"
            log_debug "CPU build - GPU detection skipped"
            return 0
        fi
        
        if command_exists nvidia-smi; then
            if nvidia-smi -L &>/dev/null; then
                local gpu_count
                gpu_count=$(nvidia-smi -L | wc -l)
                log_info "GPU detected: $gpu_count GPU(s) available"
                export GPU_AVAILABLE="true"
                export GPU_COUNT="$gpu_count"
                
                # Configure GPU memory limit if specified
                if [[ -n "${GPU_MEMORY_LIMIT:-}" ]]; then
                    log_info "Setting GPU memory limit: ${GPU_MEMORY_LIMIT}"
                    export TF_MEMORY_ALLOCATION="${GPU_MEMORY_LIMIT}"
                    export PYTORCH_CUDA_ALLOC_CONF="max_split_size_mb:${GPU_MEMORY_LIMIT}"
                fi
                
                # Set GPU device visibility
                if [[ -n "${GPU_DEVICE_ORDER:-}" ]]; then
                    export CUDA_VISIBLE_DEVICES="${GPU_DEVICE_ORDER}"
                    log_info "GPU device order set: ${GPU_DEVICE_ORDER}"
                fi
            else
                log_warn "nvidia-smi found but no GPUs detected"
                export GPU_AVAILABLE="false"
            fi
        else
            log_warn "nvidia-smi not available - no GPU support"
            export GPU_AVAILABLE="false"
        fi
    }
    
    # Environment setup with validation
    setup_environment() {
        # Validate critical environment variables
        if ! validate_environment; then
            log_error "Environment validation failed"
            exit 1
        fi
        
        # Set log level and file
        export LOG_LEVEL="${APP_LOG_LEVEL:-INFO}"
        export LOG_FILE="${LOGS_DIR:-${APP_DIR}/logs}/${SERVICE_NAME:-service}.log"
        
        # Create log directory
        create_and_verify_dir "$(dirname "$LOG_FILE")"
        
        # Set debug mode if needed
        if [[ "${APP_LOG_LEVEL}" == "DEBUG" ]]; then
            export DEBUG="true"
        fi
        
        # Environment-specific optimizations
        case "${APP_ENV}" in
            production)
                export KEEP_CONTAINER_ALIVE="${KEEP_CONTAINER_ALIVE:-false}"
                export ENABLE_HOT_RELOAD="${ENABLE_HOT_RELOAD:-false}"
                export PYTHONDONTWRITEBYTECODE=1
                export PYTHONOPTIMIZE=1
                export RUST_LOG="${RUST_LOG:-warn}"
                ;;
            staging)
                export KEEP_CONTAINER_ALIVE="${KEEP_CONTAINER_ALIVE:-true}"
                export ENABLE_HOT_RELOAD="${ENABLE_HOT_RELOAD:-false}"
                export RUST_LOG="${RUST_LOG:-info}"
                ;;
            development|*)
                export KEEP_CONTAINER_ALIVE="${KEEP_CONTAINER_ALIVE:-true}"
                export ENABLE_HOT_RELOAD="${ENABLE_HOT_RELOAD:-true}"
                export PYTHONDONTWRITEBYTECODE=0
                export RUST_LOG="${RUST_LOG:-debug}"
                ;;
        esac
        
        # Set up Python path
        if [[ "${SERVICE_RUNTIME}" == "python" || "${SERVICE_RUNTIME}" == "hybrid" ]]; then
            export PYTHONPATH="${SRC_DIR}:${APP_DIR}:${PYTHONPATH:-}"
            export PYTHONUNBUFFERED=1
        fi
        
        log_debug "Environment setup completed"
    }
    
    # Function to find and validate service files
    find_service_file() {
        local service_type="$1"
        local file_type="${2:-main.py}"
        
        local search_paths=(
            "${SRC_DIR}/main.py"
            "${SRC_DIR}/services/${service_type}/${file_type}"
            "${SRC_DIR}/${service_type}/${file_type}"
            "${APP_DIR}/services/${service_type}/${file_type}"
            "${APP_DIR}/${service_type}/${file_type}"
            "${SRC_DIR}/python/services/${service_type}/${file_type}"
        )
        
        for path in "${search_paths[@]}"; do
            if [[ -f "$path" && -r "$path" ]]; then
                echo "$path"
                return 0
            fi
        done
        
        return 1
    }
    
    # Function to wait for service health
    wait_for_service_health() {
        local service_name="$1"
        local port="${2:-$SERVICE_PORT}"
        local max_attempts="${3:-30}"
        local attempt=0
        
        log_info "Waiting for $service_name to become healthy on port $port"
        
        while [[ $attempt -lt $max_attempts ]]; do
            if command_exists curl; then
                if curl -s -f "http://localhost:$port/health" >/dev/null 2>&1; then
                    log_info "$service_name is healthy"
                    return 0
                fi
            elif command_exists nc; then
                if nc -z localhost "$port" 2>/dev/null; then
                    log_info "$service_name is responding on port $port"
                    return 0
                fi
            else
                # Fallback: just check if port is open
                if timeout 1 bash -c "</dev/tcp/localhost/$port" 2>/dev/null; then
                    log_info "$service_name is responding on port $port"
                    return 0
                fi
            fi
            
            sleep 2
            ((attempt++))
            log_debug "Health check attempt $attempt/$max_attempts for $service_name"
        done
        
        log_warn "$service_name health check failed after $max_attempts attempts"
        return 1
    }
fi

# =====================================================
# ENVIRONMENT VARIABLES AND CONFIGURATION
# =====================================================

# Core environment variables with defaults and validation
APP_DIR="${APP_DIR:-/app}"
SRC_DIR="${SRC_DIR:-${APP_DIR}/src}"
DATA_DIR="${DATA_DIR:-${APP_DIR}/data}"
CONFIG_DIR="${CONFIG_DIR:-${APP_DIR}/config}"
LOGS_DIR="${LOGS_DIR:-${APP_DIR}/logs}"
BUILD_TYPE="${BUILD_TYPE:-cpu}"
SERVICE_RUNTIME="${SERVICE_RUNTIME:-python}"
SERVICE_TYPE="${SERVICE_TYPE:-app}"
SERVICE_NAME="${SERVICE_NAME:-${SERVICE_TYPE}}"
SERVICE_PORT="${SERVICE_PORT:-8000}"
APP_ENV="${APP_ENV:-development}"
APP_LOG_LEVEL="${APP_LOG_LEVEL:-INFO}"
PYTHON_MODULE="${PYTHON_MODULE:-}"
DISPATCHER_MODULE="${DISPATCHER_MODULE:-main}"

# Validate essential directories exist
for essential_dir in "$APP_DIR" "$SRC_DIR"; do
    if [[ ! -d "$essential_dir" ]]; then
        echo "ERROR: Essential directory not found: $essential_dir" >&2
        exit 1
    fi
done

# Service-specific configuration with validation
TRADING_MODE="${TRADING_MODE:-paper}"
WORKER_COUNT="${WORKER_COUNT:-2}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-30}"
DATA_SOURCE="${DATA_SOURCE:-}"
SYMBOLS="${SYMBOLS:-}"
PINE_SCRIPT="${PINE_SCRIPT:-}"
SYMBOL="${SYMBOL:-BTCUSD}"
MODEL_TYPE="${MODEL_TYPE:-}"
TRAINING_DATA="${TRAINING_DATA:-}"
TRAINING_EPOCHS="${TRAINING_EPOCHS:-50}"
MONITORED_SERVICES="${MONITORED_SERVICES:-}"

# Health check configuration
ENABLE_HEALTH_CHECK="${ENABLE_HEALTH_CHECK:-true}"
HEALTH_CHECK_PORT="${HEALTH_CHECK_PORT:-$SERVICE_PORT}"
HEALTH_CHECK_PATH="${HEALTH_CHECK_PATH:-/health}"

# =====================================================
# STARTUP SEQUENCE
# =====================================================

# Setup signal handlers early
setup_signal_handlers

log_section "STARTUP" "FKS Service ${SERVICE_NAME} v${APP_VERSION:-unknown}"
log_info "Service Type: ${SERVICE_TYPE}"
log_info "Runtime: ${SERVICE_RUNTIME}"
log_info "Environment: ${APP_ENV}"
log_info "Build Type: ${BUILD_TYPE}"

# =====================================================
# ENVIRONMENT LOADING
# =====================================================

log_section "ENV" "Loading environment configuration"

# Load environment files in order of specificity (most specific last)
ENV_FILES=(
    "${APP_DIR}/.env"
    "${CONFIG_DIR}/.env"
    "${APP_DIR}/.env.${APP_ENV}"
    "${CONFIG_DIR}/.env.${APP_ENV}"
    "${APP_DIR}/.env.${SERVICE_TYPE}"
    "${CONFIG_DIR}/.env.${SERVICE_TYPE}"
    "${APP_DIR}/.env.${SERVICE_TYPE}.${APP_ENV}"
    "${CONFIG_DIR}/.env.${SERVICE_TYPE}.${APP_ENV}"
)

env_files_loaded=0
for env_file in "${ENV_FILES[@]}"; do
    if load_env_file "$env_file"; then
        ((env_files_loaded++))
    fi
done

log_info "Loaded $env_files_loaded environment file(s)"

# =====================================================
# DIRECTORY SETUP
# =====================================================

log_section "SETUP" "Creating and verifying directories"

# Run the directory setup script if available
if [[ -f "${APP_DIR}/scripts/docker/setup_directories.sh" && -x "${APP_DIR}/scripts/docker/setup_directories.sh" ]]; then
    log_info "Running directory setup script"
    "${APP_DIR}/scripts/docker/setup_directories.sh"
else
    # Essential directories for all services
    ESSENTIAL_DIRS=(
        "${DATA_DIR}"
        "${LOGS_DIR}"
        "${APP_DIR}/data/cache"
        "${APP_DIR}/data/storage"
        "${APP_DIR}/outputs"
        "${APP_DIR}/outputs/${SERVICE_NAME}"
        "${APP_DIR}/data/cache/${SERVICE_NAME}"
        "${APP_DIR}/tmp"
    )
    
    # Additional directories for Python services
    if [[ "${SERVICE_RUNTIME}" == "python" || "${SERVICE_RUNTIME}" == "hybrid" ]]; then
        ESSENTIAL_DIRS+=(
            "${SRC_DIR}/data"
            "./data"
        )
    fi

    # Create all directories
    dirs_created=0
    for dir in "${ESSENTIAL_DIRS[@]}"; do
        if create_and_verify_dir "$dir"; then
            ((dirs_created++))
        fi
    done
    
    log_info "Created/verified $dirs_created directories"
fi

# =====================================================
# VIRTUAL ENVIRONMENT (for Python-based services)
# =====================================================

if [[ "${SERVICE_RUNTIME}" == "python" || "${SERVICE_RUNTIME}" == "hybrid" ]]; then
    venv_activated=false
    
    # Try different virtual environment locations
    VENV_PATHS=("/opt/venv" "${APP_DIR}/venv" "${APP_DIR}/.venv")
    
    for venv_path in "${VENV_PATHS[@]}"; do
        if [[ -d "$venv_path" && -f "$venv_path/bin/activate" ]]; then
            source "$venv_path/bin/activate"
            log_info "Activated virtual environment: $venv_path"
            venv_activated=true
            break
        fi
    done
    
    if [[ "$venv_activated" == "false" ]]; then
        log_warn "No virtual environment found, using system Python"
    fi
    
    # Verify Python installation
    if ! python --version >/dev/null 2>&1; then
        log_error "Python not available"
        exit 1
    fi
    
    log_info "Python version: $(python --version)"
fi

# =====================================================
# GPU DETECTION AND ENVIRONMENT SETUP
# =====================================================

detect_and_configure_gpu
setup_environment

# =====================================================
# SERVICE CONFIGURATION
# =====================================================

log_section "CONFIG" "Service configuration for ${SERVICE_TYPE}"

# Config file locations based on service type
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/fks/main.yaml}"
SERVICE_CONFIG="${CONFIG_DIR}/fks/${SERVICE_TYPE}.yaml"
NETWORK_CONFIG="${CONFIG_DIR}/fks/node_network/${SERVICE_TYPE}.yaml"

# Determine configuration file to use
CONFIG_PATH=""
for config_file in "$SERVICE_CONFIG" "$NETWORK_CONFIG" "$CONFIG_FILE"; do
    if [[ -f "$config_file" && -r "$config_file" ]]; then
        CONFIG_PATH="$config_file"
        log_info "Using configuration: $CONFIG_PATH"
        break
    fi
done

if [[ -z "$CONFIG_PATH" ]]; then
    log_warn "No configuration file found"
    # Try to create basic configuration
    if [[ -f "${APP_DIR}/scripts/docker/setup_config.sh" && -x "${APP_DIR}/scripts/docker/setup_config.sh" ]]; then
        log_info "Running configuration setup script"
        "${APP_DIR}/scripts/docker/setup_config.sh"
        
        # Re-check for configuration file
        for config_file in "$SERVICE_CONFIG" "$NETWORK_CONFIG" "$CONFIG_FILE"; do
            if [[ -f "$config_file" && -r "$config_file" ]]; then
                CONFIG_PATH="$config_file"
                log_info "Created and using configuration: $CONFIG_PATH"
                break
            fi
        done
    fi
fi

# Export configuration path for use by services
export CONFIG_PATH

# Set service-specific environment variables
case "$SERVICE_TYPE" in
    api)
        export API_PORT="$SERVICE_PORT"
        export API_HOST="${API_HOST:-0.0.0.0}"
        ;;
    web|app)
        export WEB_PORT="$SERVICE_PORT"
        export WEB_HOST="${WEB_HOST:-0.0.0.0}"
        export NICEGUI_PORT="$SERVICE_PORT"
        export NICEGUI_HOST="${NICEGUI_HOST:-0.0.0.0}"
        ;;
    gateway)
        export GATEWAY_PORT="$SERVICE_PORT"
        export GATEWAY_HOST="${GATEWAY_HOST:-0.0.0.0}"
        ;;
esac

# =====================================================
# COMMAND DETERMINATION BASED ON RUNTIME
# =====================================================

# Set Rust environment variables (used by both Rust and hybrid services)
if [[ "${SERVICE_RUNTIME}" == "rust" || "${SERVICE_RUNTIME}" == "hybrid" ]]; then
    export RUST_LOG="${RUST_LOG:-${LOG_LEVEL,,}}"
    export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
    export SERVICE_PORT="$SERVICE_PORT"
    export SERVICE_HOST="${SERVICE_HOST:-0.0.0.0}"
    
    # Ensure Rust libraries are in the path for hybrid services
    if [[ "${SERVICE_RUNTIME}" == "hybrid" ]]; then
        export LD_LIBRARY_PATH="/app/bin:/app/bin/network:/app/bin/execution:/app/bin/connector:${LD_LIBRARY_PATH:-}"
    fi
fi

# Determine the command to run based on runtime type
CMD=""
case "${SERVICE_RUNTIME}" in
    python)
        log_info "Configuring Python runtime command"
        
        # Check for direct command arguments
        if [[ $# -gt 0 ]]; then
            log_info "Using direct arguments from command line: $*"
            CMD="python $*"
        else
            # Service command determination logic
            service_file=""
            
            # First priority: Try the unified main.py approach
            if service_file=$(find_service_file "$SERVICE_TYPE" "main.py") && [[ "$service_file" == */main.py ]]; then
                log_info "Using unified main.py dispatcher: $service_file"
                CMD="python -m main service ${SERVICE_TYPE}"
            # Second priority: Check for specific Python module in environment
            elif [[ -n "$PYTHON_MODULE" ]]; then
                log_info "Using explicit Python module: ${PYTHON_MODULE}"
                if [[ "$PYTHON_MODULE" == *":"* ]]; then
                    MODULE_PATH="${PYTHON_MODULE%:*}"
                    FUNCTION_NAME="${PYTHON_MODULE#*:}"
                    CMD="python -m ${MODULE_PATH} ${FUNCTION_NAME}"
                else
                    CMD="python -m ${PYTHON_MODULE}"
                fi
            # Third priority: Try service-specific module paths
            elif service_file=$(find_service_file "$SERVICE_TYPE" "main.py"); then
                log_info "Using service module: $service_file"
                # Convert file path to module path
                module_path="${service_file#$SRC_DIR/}"
                module_path="${module_path%.py}"
                module_path="${module_path//\//.}"
                CMD="python -m ${module_path}"
            else
                # Fallback to dispatcher module
                log_info "Using fallback dispatcher module: ${DISPATCHER_MODULE}"
                CMD="python -m ${DISPATCHER_MODULE} service ${SERVICE_TYPE}"
            fi
            
            # Add config parameters if not already present and config exists
            if [[ -n "$CONFIG_PATH" ]] && ! has_parameter "--config" "$CMD"; then
                CMD="${CMD} --config=\"${CONFIG_PATH}\""
            fi
            
            # Add log level if not already present
            if ! has_parameter "--log-level" "$CMD"; then
                CMD="${CMD} --log-level=${LOG_LEVEL}"
            fi
            
            # Service-specific parameters
            case "$SERVICE_TYPE" in
                app)
                    [[ -n "$TRADING_MODE" ]] && ! has_parameter "--mode" "$CMD" && CMD="${CMD} --mode=${TRADING_MODE}"
                    ;;
                worker|workers)
                    [[ -n "$WORKER_COUNT" ]] && ! has_parameter "--workers" "$CMD" && CMD="${CMD} --workers=${WORKER_COUNT}"
                    ;;
                data)
                    [[ -n "$DATA_SOURCE" ]] && ! has_parameter "--source" "$CMD" && CMD="${CMD} --source=${DATA_SOURCE}"
                    [[ -n "$SYMBOLS" ]] && ! has_parameter "--symbols" "$CMD" && CMD="${CMD} --symbols=${SYMBOLS}"
                    ;;
                pine)
                    [[ -n "$PINE_SCRIPT" ]] && ! has_parameter "--script" "$CMD" && CMD="${CMD} --script=\"${PINE_SCRIPT}\""
                    [[ -n "$SYMBOL" ]] && ! has_parameter "--symbol" "$CMD" && CMD="${CMD} --symbol=${SYMBOL}"
                    ;;
                training)
                    [[ -n "$MODEL_TYPE" ]] && ! has_parameter "--model" "$CMD" && CMD="${CMD} --model=${MODEL_TYPE}"
                    [[ -n "$TRAINING_DATA" ]] && ! has_parameter "--data" "$CMD" && CMD="${CMD} --data=\"${TRAINING_DATA}\""
                    [[ -n "$TRAINING_EPOCHS" ]] && ! has_parameter "--epochs" "$CMD" && CMD="${CMD} --epochs=${TRAINING_EPOCHS}"
                    if [[ "$GPU_AVAILABLE" == "false" && "$BUILD_TYPE" == "gpu" ]]; then
                        log_warn "GPU not available but required for training - adding CPU fallback flag"
                        CMD="${CMD} --cpu-fallback"
                    fi
                    ;;
                watcher|monitor)
                    [[ -n "$MONITOR_INTERVAL" ]] && ! has_parameter "--interval" "$CMD" && CMD="${CMD} --interval=${MONITOR_INTERVAL}"
                    [[ -n "$MONITORED_SERVICES" ]] && ! has_parameter "--services" "$CMD" && CMD="${CMD} --services=\"${MONITORED_SERVICES}\""
                    ;;
                *)
                    [[ -n "$SERVICE_PORT" ]] && ! has_parameter "--port" "$CMD" && CMD="${CMD} --port=${SERVICE_PORT}"
                    ;;
            esac
            
            # Add hot-reload flag if required
            if [[ "${ENABLE_HOT_RELOAD:-false}" == "true" ]] && ! has_parameter "--reload" "$CMD"; then
                CMD="${CMD} --reload"
            fi
        fi
        ;;
        
    rust)
        log_info "Configuring Rust runtime command"
        
        # Determine which binary to execute based on service type
        case "$SERVICE_TYPE" in
            node|registry)
                BINARY_PATHS=(
                    "/app/bin/network/trading-node"
                    "/app/bin/network/${SERVICE_TYPE}"
                    "/app/bin/${SERVICE_TYPE}"
                )
                ;;
            execution)
                BINARY_PATHS=(
                    "/app/bin/execution/trading-execution"
                    "/app/bin/execution/${SERVICE_TYPE}"
                    "/app/bin/${SERVICE_TYPE}"
                )
                ;;
            *)
                BINARY_PATHS=(
                    "/app/bin/${SERVICE_TYPE}"
                    "/app/bin/network/${SERVICE_TYPE}"
                    "/app/bin/execution/${SERVICE_TYPE}"
                    "/app/bin/${SERVICE_NAME}"
                )
                ;;
        esac
        
        # Find the first valid binary
        BINARY_PATH=""
        for path in "${BINARY_PATHS[@]}"; do
            if [[ -x "$path" ]]; then
                BINARY_PATH="$path"
                log_info "Found Rust binary: $BINARY_PATH"
                break
            fi
        done
        
        if [[ -z "$BINARY_PATH" ]]; then
            log_error "No executable binary found for Rust service ${SERVICE_TYPE}"
            log_debug "Searched paths: ${BINARY_PATHS[*]}"
            exit 1
        fi
        
        # Build command with arguments
        CMD="\"${BINARY_PATH}\""
        
        # Add config path if available
        [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
        
        # Add log level if specified
        [[ -n "$LOG_LEVEL" ]] && CMD="${CMD} --log-level=${LOG_LEVEL}"
        
        # Add port if needed
        [[ -n "$SERVICE_PORT" ]] && CMD="${CMD} --port=${SERVICE_PORT}"
        ;;
        
    hybrid)
        log_info "Configuring hybrid (Python + Rust) runtime command"
        
        # Handle special hybrid service types
        case "${SERVICE_TYPE}" in
            connector)
                # Service-specific Rust dependencies for connector
                if [[ -x "/app/bin/network/registry-client" ]]; then
                    RUST_DEPENDENCIES+=("/app/bin/network/registry-client")
                    log_info "Found registry client binary - will start as dependency"
                fi
                
                # Command determination for connector
                if [[ -f "/app/connector/app.py" ]]; then
                    log_info "Using direct Python connector app"
                    CMD="cd /app/connector && python app.py"
                    
                    # Add arguments if needed
                    [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
                    [[ -n "$LOG_LEVEL" ]] && CMD="${CMD} --log-level=${LOG_LEVEL}"
                    [[ -n "$SERVICE_PORT" ]] && CMD="${CMD} --port=${SERVICE_PORT}"
                elif [[ -x "/app/bin/connector/${SERVICE_TYPE}" ]]; then
                    log_info "Using hybrid connector binary: ${SERVICE_TYPE}"
                    BINARY_PATH="/app/bin/connector/${SERVICE_TYPE}"
                    CMD="\"${BINARY_PATH}\""
                    
                    [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
                    [[ -n "$LOG_LEVEL" ]] && CMD="${CMD} --log-level=${LOG_LEVEL}"
                    [[ -n "$SERVICE_PORT" ]] && CMD="${CMD} --port=${SERVICE_PORT}"
                else
                    # Fall back to main.py approach
                    log_info "Using main.py with connector service type"
                    CMD="python -m main service ${SERVICE_TYPE}"
                    
                    [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
                    CMD="${CMD} --log-level=${LOG_LEVEL}"
                    CMD="${CMD} --port=${SERVICE_PORT}"
                fi
                ;;
            gateway)
                # Service-specific Rust dependencies for gateway
                if [[ -x "/app/bin/network/gateway" ]]; then
                    RUST_DEPENDENCIES+=("/app/bin/network/gateway")
                    log_info "Found network gateway binary - will start as dependency"
                fi
                
                # Use unified main.py for Python part
                log_info "Using main.py with gateway service type"
                CMD="python -m main service ${SERVICE_TYPE}"
                
                [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
                CMD="${CMD} --log-level=${LOG_LEVEL}"
                CMD="${CMD} --port=${SERVICE_PORT}"
                ;;
            *)
                # Generic hybrid service - try to use main.py approach
                log_info "Using main.py with hybrid service type: ${SERVICE_TYPE}"
                CMD="python -m main service ${SERVICE_TYPE}"
                
                [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
                CMD="${CMD} --log-level=${LOG_LEVEL}"
                CMD="${CMD} --port=${SERVICE_PORT}"
                ;;
        esac
        
        # Add hot-reload flag if required
        if [[ "${ENABLE_HOT_RELOAD:-false}" == "true" ]] && ! has_parameter "--reload" "$CMD"; then
            CMD="${CMD} --reload"
        fi
        ;;
        
    node|nodejs)
        log_info "Configuring Node.js runtime command"
        
        # Validate Node.js environment
        if ! command -v node >/dev/null 2>&1; then
            log_error "Node.js not found but required for runtime ${SERVICE_RUNTIME}"
            exit 1
        fi
        
        NODE_VERSION=$(node --version 2>/dev/null || echo "unknown")
        log_info "Node.js version: $NODE_VERSION"
        
        # Emergency fallback cases for Node.js
        emergency_fallback=false
        
        # Check for direct command arguments
        if [[ $# -gt 0 ]]; then
            log_info "Using direct Node.js arguments: $*"
            CMD="node $*"
        else
            # Service command determination logic
            service_file=""
            
            # First priority: Try package.json scripts
            if [[ -f "package.json" ]] && command -v npm >/dev/null 2>&1; then
                if npm run --silent 2>/dev/null | grep -q "^  start"; then
                    log_info "Using npm start script"
                    CMD="npm start"
                elif npm run --silent 2>/dev/null | grep -q "^  ${SERVICE_TYPE}"; then
                    log_info "Using npm run ${SERVICE_TYPE} script"
                    CMD="npm run ${SERVICE_TYPE}"
                else
                    emergency_fallback=true
                fi
            else
                emergency_fallback=true
            fi
            
            # Emergency fallback: Try common Node.js entry points
            if [[ "$emergency_fallback" == "true" ]]; then
                log_warn "No package.json scripts found, trying emergency fallback"
                
                if [[ -f "index.js" ]]; then
                    log_info "Using index.js as entry point"
                    CMD="node index.js"
                elif [[ -f "app.js" ]]; then
                    log_info "Using app.js as entry point"
                    CMD="node app.js"
                elif [[ -f "server.js" ]]; then
                    log_info "Using server.js as entry point"
                    CMD="node server.js"
                elif [[ -f "src/index.js" ]]; then
                    log_info "Using src/index.js as entry point"
                    CMD="node src/index.js"
                elif [[ -f "src/app.js" ]]; then
                    log_info "Using src/app.js as entry point"
                    CMD="node src/app.js"
                else
                    log_error "No valid Node.js entry point found for service ${SERVICE_TYPE}"
                    log_debug "Searched: index.js, app.js, server.js, src/index.js, src/app.js"
                    exit 1
                fi
            fi
            
            # Add service-specific parameters
            case "$SERVICE_TYPE" in
                web|api)
                    if ! has_parameter "--port" "$CMD"; then
                        CMD="${CMD} --port=${SERVICE_PORT}"
                    fi
                    ;;
                worker|workers)
                    if [[ -n "$WORKER_COUNT" ]] && ! has_parameter "--workers" "$CMD"; then
                        CMD="${CMD} --workers=${WORKER_COUNT}"
                    fi
                    ;;
            esac
        fi
        ;;
        
    dotnet|csharp)
        log_info "Configuring .NET runtime command"
        
        # Validate .NET environment
        if ! command -v dotnet >/dev/null 2>&1; then
            log_error ".NET not found but required for runtime ${SERVICE_RUNTIME}"
            exit 1
        fi
        
        DOTNET_VERSION=$(dotnet --version 2>/dev/null || echo "unknown")
        log_info ".NET version: $DOTNET_VERSION"
        
        # Emergency fallback cases for .NET
        emergency_fallback=false
        
        # Check for direct command arguments
        if [[ $# -gt 0 ]]; then
            log_info "Using direct .NET arguments: $*"
            CMD="dotnet $*"
        else
            # Service command determination logic
            
            # First priority: Try to find a published DLL
            if [[ -f "${SERVICE_TYPE}.dll" ]]; then
                log_info "Using published DLL: ${SERVICE_TYPE}.dll"
                CMD="dotnet ${SERVICE_TYPE}.dll"
            elif [[ -f "bin/Release/net*/publish/${SERVICE_TYPE}.dll" ]]; then
                dll_path=$(find bin/Release/net*/publish/ -name "${SERVICE_TYPE}.dll" | head -1)
                log_info "Using published DLL: $dll_path"
                CMD="dotnet $dll_path"
            elif [[ -f "*.csproj" ]]; then
                csproj_file=$(find . -maxdepth 1 -name "*.csproj" | head -1)
                log_info "Using project file for dotnet run: $csproj_file"
                CMD="dotnet run --project $csproj_file"
            else
                emergency_fallback=true
            fi
            
            # Emergency fallback: Try common .NET entry points
            if [[ "$emergency_fallback" == "true" ]]; then
                log_warn "No .csproj or DLL found, trying emergency fallback"
                
                if [[ -f "Program.cs" ]]; then
                    log_info "Using dotnet run with Program.cs"
                    CMD="dotnet run"
                elif [[ -f "app.dll" ]]; then
                    log_info "Using app.dll as entry point"
                    CMD="dotnet app.dll"
                else
                    log_error "No valid .NET entry point found for service ${SERVICE_TYPE}"
                    log_debug "Searched: ${SERVICE_TYPE}.dll, *.csproj, Program.cs, app.dll"
                    exit 1
                fi
            fi
            
            # Add service-specific parameters
            case "$SERVICE_TYPE" in
                web|api)
                    if ! has_parameter "--urls" "$CMD"; then
                        CMD="${CMD} --urls=http://0.0.0.0:${SERVICE_PORT}"
                    fi
                    ;;
            esac
        fi
        ;;
        
    *)
        log_warn "Unknown runtime: ${SERVICE_RUNTIME}, defaulting to Python"
        CMD="python -m main service ${SERVICE_TYPE}"
        
        [[ -n "$CONFIG_PATH" ]] && CMD="${CMD} --config=\"${CONFIG_PATH}\""
        CMD="${CMD} --log-level=${LOG_LEVEL}"
        CMD="${CMD} --port=${SERVICE_PORT}"
        ;;
esac

# Validate that we have a command to run
if [[ -z "$CMD" ]]; then
    log_error "No command determined for service ${SERVICE_TYPE} with runtime ${SERVICE_RUNTIME}"
    exit 1
fi

# =====================================================
# START RUST DEPENDENCIES (if any)
# =====================================================

if [[ ${#RUST_DEPENDENCIES[@]} -gt 0 ]]; then
    log_section "RUST" "Starting ${#RUST_DEPENDENCIES[@]} Rust dependencies"
    
    # Start any required Rust dependency services
    for rust_bin in "${RUST_DEPENDENCIES[@]}"; do
        log_info "Starting Rust dependency: $rust_bin"
        
        # Build Rust command with config if available
        rust_cmd="\"$rust_bin\""
        [[ -n "$CONFIG_PATH" ]] && rust_cmd="${rust_cmd} --config=\"${CONFIG_PATH}\""
        [[ -n "$LOG_LEVEL" ]] && rust_cmd="${rust_cmd} --log-level=${LOG_LEVEL}"
        
        # Start the Rust process
        eval "$rust_cmd" &
        RUST_PID=$!
        RUST_PIDS+=("$RUST_PID")
        log_info "Started Rust process with PID $RUST_PID"
        
        # Give it a moment to initialize
        sleep 2
        
        # Check if process is still running
        if kill -0 "$RUST_PID" 2>/dev/null; then
            log_info "Rust dependency started successfully: $rust_bin"
            
            # Optionally wait for health check
            if [[ "$ENABLE_HEALTH_CHECK" == "true" ]]; then
                wait_for_service_health "$(basename "$rust_bin")" "$SERVICE_PORT" 10 || log_warn "Rust dependency health check failed"
            fi
        else
            log_error "Rust dependency failed to start: $rust_bin"
            exit 1
        fi
    done
fi

# =====================================================
# FINAL VALIDATION AND EXECUTION
# =====================================================

log_section "SUMMARY" "Service Configuration Summary"
log_info "Version: ${APP_VERSION:-unknown}"
log_info "Build Type: ${BUILD_TYPE}"
log_info "Runtime: ${SERVICE_RUNTIME}"
log_info "Service Type: ${SERVICE_TYPE}"
log_info "Service Name: ${SERVICE_NAME}"
log_info "Environment: ${APP_ENV}"
log_info "Log Level: ${LOG_LEVEL}"
log_info "Port: ${SERVICE_PORT}"
log_info "Config: ${CONFIG_PATH:-none}"
log_info "GPU Available: ${GPU_AVAILABLE:-false}"
if [[ ${#RUST_PIDS[@]} -gt 0 ]]; then
    log_info "Rust dependencies: ${#RUST_PIDS[@]} process(es) started (PIDs: ${RUST_PIDS[*]})"
fi
log_info "Working Directory: $(pwd)"
log_info "Command: $CMD"

# Change to source directory for Python services
if [[ "${SERVICE_RUNTIME}" == "python" || "${SERVICE_RUNTIME}" == "hybrid" ]]; then
    if [[ -d "$SRC_DIR" ]]; then
        cd "$SRC_DIR" || {
            log_error "Failed to change to source directory: $SRC_DIR"
            exit 1
        }
        log_debug "Changed to source directory: $SRC_DIR"
    fi
fi

log_section "EXEC" "Starting main service"

# Execute the service
eval "$CMD" &
MAIN_PID=$!
log_info "Main service started with PID $MAIN_PID"

# Optional: Wait for main service health check
if [[ "$ENABLE_HEALTH_CHECK" == "true" && "${SERVICE_RUNTIME}" != "rust" ]]; then
    wait_for_service_health "$SERVICE_NAME" "$SERVICE_PORT" 30 || log_warn "Main service health check failed"
fi

# Wait for the main process to finish
wait "$MAIN_PID"
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    log_info "Service exited successfully (code $exit_code)"
else
    log_error "Service exited with error code $exit_code"
fi

exit $exit_code