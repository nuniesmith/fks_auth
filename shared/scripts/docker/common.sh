#!/bin/bash
# Common functions and settings for all FKS service scripts
# This file should be sourced by other scripts

# ------------------------------------------
# Helper functions with improved formatting
# ------------------------------------------
log_info() { echo -e "\033[0;32m[INFO]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "\033[0;33m[WARN]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_debug() { if [ "${DEBUG:-false}" = "true" ]; then echo -e "\033[0;36m[DEBUG]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; fi; }
log_section() { echo -e "\n\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ [${1}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"; echo -e "\033[1;36m${2}\033[0m\n"; }

# Utility function for checking if a command exists
command_exists() { command -v "$1" &> /dev/null; }

# Function to safely load environment variables
load_env_file() {
    local env_file="$1"
    if [ -f "$env_file" ]; then
        log_info "Loading environment variables from $env_file"
        
        # Use grep to filter out problematic lines and source safely
        grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$env_file" | \
        grep -v '^#' | \
        while IFS='=' read -r key value; do
            # Export each variable safely
            export "$key"="$value"
        done
        
        return 0
    else
        log_debug "Environment file $env_file not found, skipping"
        return 1
    fi
}

# Check if a parameter is already in the command
has_parameter() {
    local param="$1"
    local cmd="$2"
    [[ "$cmd" == *"$param"* ]]
}

# Function to create directory with proper permissions
create_and_verify_dir() {
    local dir=$1
    local permission=${2:-777}
    
    # Check if directory exists, create if not
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" 2>/dev/null || { 
            log_warn "Failed to create directory: $dir"
            return 1
        }
    fi
    
    # Set permissions
    chmod -R "$permission" "$dir" 2>/dev/null || {
        log_warn "Failed to set permissions on: $dir"
        return 1
    }
    
    # Verify directory is writable
    if [ -w "$dir" ]; then
        log_debug "✅ Directory verified: $dir"
        return 0
    else
        log_warn "⚠️ Directory not writable: $dir"
        return 1
    fi
}

# Handle signals
handle_signal() {
    local signal=$1
    log_info "Received signal $signal. Shutting down gracefully..."
    
    if [ -n "$child_pid" ]; then
        log_debug "Sending TERM signal to child process $child_pid"
        kill -TERM "$child_pid" 2>/dev/null || true
        
        # Give the process some time to exit gracefully
        local timeout=30
        local count=0
        while kill -0 "$child_pid" 2>/dev/null && [ $count -lt $timeout ]; do
            sleep 1
            ((count++))
            if [ $((count % 5)) -eq 0 ]; then
                log_debug "Waiting for process to exit... ($count/$timeout seconds)"
            fi
        done
        
        # If still running after timeout, use KILL
        if kill -0 "$child_pid" 2>/dev/null; then
            log_warn "Process still running after $timeout seconds, sending KILL signal"
            kill -KILL "$child_pid" 2>/dev/null || true
        fi
        
        wait "$child_pid" 2>/dev/null || true
    fi
    
    log_info "Shutdown complete"
    exit 0
}

# Register signal handlers
setup_signal_handlers() {
    trap 'handle_signal SIGTERM' SIGTERM
    trap 'handle_signal SIGINT' SIGINT
    trap 'handle_signal SIGHUP' SIGHUP
    log_debug "Signal handlers registered"
}

# Function to detect and configure GPU
detect_and_configure_gpu() {
    if [ "$BUILD_TYPE" = "gpu" ]; then
        log_section "GPU" "Configuring GPU environment"
        
        if command_exists nvidia-smi; then
            # Try to get GPU information with timeout
            if timeout 10s nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader; then
                export GPU_COUNT=$(nvidia-smi --list-gpus | wc -l)
                log_info "NVIDIA GPU detected - $GPU_COUNT device(s) available"
                export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0}
                export NVIDIA_VISIBLE_DEVICES=${NVIDIA_VISIBLE_DEVICES:-all}
                export GPU_AVAILABLE=true
                
                # Check for memory limit setting
                if [ -n "$GPU_MEMORY_LIMIT" ]; then
                    log_info "GPU memory limit set to $GPU_MEMORY_LIMIT"
                fi
            else
                log_warn "GPU detected but nvidia-smi failed to query it properly"
                export GPU_AVAILABLE=limited
            fi
        else
            log_warn "GPU build type selected but no NVIDIA GPU detected or drivers not installed"
            export GPU_AVAILABLE=false
        fi
        
        # Verify tensorflow can access GPU if installed
        if python -c "import tensorflow as tf" &>/dev/null; then
            if python -c "import tensorflow as tf; print('GPU available for TensorFlow:', len(tf.config.list_physical_devices('GPU'))>0)" | grep -q "GPU available for TensorFlow: True"; then
                log_info "TensorFlow can access GPU"
            else
                log_warn "TensorFlow installed but cannot access GPU"
            fi
        fi
        
        # Verify PyTorch can access GPU if installed
        if python -c "import torch" &>/dev/null; then
            if python -c "import torch; print('GPU available for PyTorch:', torch.cuda.is_available())" | grep -q "GPU available for PyTorch: True"; then
                log_info "PyTorch can access GPU"
                log_info "$(python -c "import torch; print(f'PyTorch CUDA Device(s): {torch.cuda.device_count()}')")"
            else
                log_warn "PyTorch installed but cannot access GPU"
            fi
        fi
    else
        log_info "Running in CPU mode"
        export GPU_AVAILABLE=false
    fi
}

# Setup environment based on APP_ENV
setup_environment() {
    log_section "CONFIG" "Applying environment-specific configuration for $APP_ENV"

    case "$APP_ENV" in
        development)
            export DEBUG=true
            export LOG_LEVEL=${LOG_LEVEL:-DEBUG}
            export GENERATE_DOCS_ON_STARTUP=${GENERATE_DOCS_ON_STARTUP:-true}
            export ENABLE_HOT_RELOAD=${ENABLE_HOT_RELOAD:-true}
            ;;
        staging)
            export DEBUG=false
            export LOG_LEVEL=${LOG_LEVEL:-INFO}
            export GENERATE_DOCS_ON_STARTUP=${GENERATE_DOCS_ON_STARTUP:-true}
            export ENABLE_HOT_RELOAD=${ENABLE_HOT_RELOAD:-false}
            ;;
        production)
            export DEBUG=false
            export LOG_LEVEL=${LOG_LEVEL:-WARNING}
            export GENERATE_DOCS_ON_STARTUP=${GENERATE_DOCS_ON_STARTUP:-false}
            export ENABLE_HOT_RELOAD=${ENABLE_HOT_RELOAD:-false}
            ;;
        *)
            log_warn "Unknown environment: $APP_ENV, defaulting to development"
            export DEBUG=true
            export LOG_LEVEL=${LOG_LEVEL:-DEBUG}
            export GENERATE_DOCS_ON_STARTUP=${GENERATE_DOCS_ON_STARTUP:-true}
            export ENABLE_HOT_RELOAD=${ENABLE_HOT_RELOAD:-true}
            ;;
    esac

    # Validate logging level
    case "$LOG_LEVEL" in
        DEBUG|INFO|WARNING|ERROR|CRITICAL)
            # Valid level
            ;;
        *)
            log_warn "Invalid log level '$LOG_LEVEL', defaulting to INFO"
            export LOG_LEVEL=INFO
            ;;
    esac
}

# Execute function if it exists - FIX: Safely check for parameters
if [ "${1:-}" = "execute" ] && [ -n "${2:-}" ]; then
    # This allows calling specific functions from this script
    # Example: source common.sh execute setup_environment
    $2
fi