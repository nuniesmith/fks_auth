#!/bin/bash
# filepath: scripts/core/error_handling.sh
# FKS Trading Systems - Error Handling Module
# Comprehensive error handling and cleanup management

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly ERROR_HANDLING_MODULE_VERSION="2.5.0"
readonly ERROR_HANDLING_MODULE_LOADED="$(date +%s)"

# Error handling configuration
readonly ERROR_LOG_FILE="${FKS_ERROR_LOG:-./logs/fks_error.log}"
readonly MAX_ERROR_LOG_SIZE="${FKS_MAX_ERROR_LOG_SIZE:-10485760}"  # 10MB
readonly ERROR_CONTEXT_LINES="${FKS_ERROR_CONTEXT_LINES:-5}"

# Error tracking
declare -A ERROR_COUNTS
declare -A ERROR_TIMESTAMPS
declare -A ERROR_CONTEXTS

# Initialize error handling
init_error_handling() {
    # Create error log directory
    local error_log_dir
    error_log_dir=$(dirname "$ERROR_LOG_FILE")
    if [[ ! -d "$error_log_dir" ]]; then
        mkdir -p "$error_log_dir" 2>/dev/null || true
    fi
    
    # Initialize error log file
    if [[ ! -f "$ERROR_LOG_FILE" ]]; then
        cat > "$ERROR_LOG_FILE" << EOF
# FKS Trading Systems - Error Log
# Started: $(date)
# Mode: ${FKS_MODE:-unknown}
# PID: $$
# ==========================================

EOF
    fi
    
    log_debug "Error handling initialized - Log: $ERROR_LOG_FILE"
}

# error handling for the orchestrator
handle_orchestrator_error() {
    local exit_code=$1
    local line_number=$2
    local command="${3:-unknown}"
    local script_name="${4:-${BASH_SOURCE[1]:-unknown}}"
    
    # Log error details
    log_error "Orchestrator failed with exit code $exit_code at line $line_number"
    log_error "Failed command: $command"
    log_error "Script: $script_name"
    
    # Record error in log file
    record_error "orchestrator_failure" "$exit_code" "$line_number" "$command" "$script_name"
    
    # Show contextual information
    show_error_context "$exit_code" "$line_number" "$command"
    
    # Attempt recovery if possible
    if attempt_error_recovery "$exit_code" "$line_number"; then
        log_info "🔄 Error recovery attempted"
        return 0
    fi
    
    # Show troubleshooting information
    show_troubleshooting_steps "$exit_code"
    
    # Offer interactive help if in terminal
    if [[ -t 0 ]] && [[ "${FKS_INTERACTIVE_ERRORS:-true}" == "true" ]]; then
        offer_interactive_help "$exit_code"
    fi
    
    # Cleanup before exit
    cleanup_on_error "$exit_code"
    
    exit $exit_code
}

# Record error details
record_error() {
    local error_type="$1"
    local exit_code="$2"
    local line_number="$3"
    local command="$4"
    local script_name="$5"
    
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local error_id="${error_type}_${timestamp//[: -]/}"
    
    # Update error tracking
    ERROR_COUNTS["$error_type"]=$((${ERROR_COUNTS["$error_type"]:-0} + 1))
    ERROR_TIMESTAMPS["$error_type"]="$timestamp"
    ERROR_CONTEXTS["$error_type"]="Line $line_number: $command"
    
    # Log to error file
    {
        echo "[$timestamp] ERROR: $error_type"
        echo "  Exit Code: $exit_code"
        echo "  Line: $line_number"
        echo "  Command: $command"
        echo "  Script: $script_name"
        echo "  Mode: ${FKS_MODE:-unknown}"
        echo "  User: ${USER:-unknown}"
        echo "  PWD: $(pwd)"
        echo "  Environment: $(env | grep '^FKS_' | head -5)"
        echo "  Error ID: $error_id"
        echo "  ==========================================="
        echo ""
    } >> "$ERROR_LOG_FILE"
    
    # Rotate log if too large
    rotate_error_log_if_needed
    
    log_debug "Error recorded: $error_id"
}

# Show error context and helpful information
show_error_context() {
    local exit_code="$1"
    local line_number="$2"
    local command="$3"
    
    echo ""
    log_error "This is likely a setup or configuration issue."
    echo ""
    
    # Show mode information in error
    if [[ -n "${FKS_MODE:-}" ]]; then
        log_info "Current mode: ${WHITE}$FKS_MODE${NC}"
        log_info "Mode reason: $FKS_MODE_REASON"
    fi
    
    # Context-specific error messages
    case "$exit_code" in
        1)
            log_info "💡 Exit code 1 usually indicates a general error or false condition"
            ;;
        2)
            log_info "💡 Exit code 2 usually indicates incorrect usage or syntax error"
            ;;
        126)
            log_info "💡 Exit code 126 indicates permission denied or file not executable"
            ;;
        127)
            log_info "💡 Exit code 127 indicates command not found"
            ;;
        130)
            log_info "💡 Exit code 130 indicates script terminated by Ctrl+C"
            ;;
        *)
            log_info "💡 Exit code $exit_code indicates an unexpected error"
            ;;
    esac
    
    # Command-specific context
    if [[ "$command" =~ docker ]]; then
        log_info "🐳 Docker-related error - check Docker installation and daemon status"
    elif [[ "$command" =~ conda|python ]]; then
        log_info "🐍 Python/Conda-related error - check Python environment setup"
    elif [[ "$command" =~ chmod|mkdir ]]; then
        log_info "📁 File system error - check permissions and disk space"
    fi
}

# Attempt automatic error recovery
attempt_error_recovery() {
    local exit_code="$1"
    local line_number="$2"
    
    log_debug "Attempting error recovery for exit code $exit_code"
    
    case "$exit_code" in
        1)
            # General error - try basic recovery
            if attempt_basic_recovery; then
                return 0
            fi
            ;;
        126)
            # Permission error - try to fix permissions
            if attempt_permission_recovery; then
                return 0
            fi
            ;;
        127)
            # Command not found - try to suggest alternatives
            if attempt_command_recovery; then
                return 0
            fi
            ;;
    esac
    
    return 1
}

# Basic recovery attempts
attempt_basic_recovery() {
    log_debug "Attempting basic recovery..."
    
    # Check if main script exists and is executable
    if [[ -f "$MAIN_SCRIPT" ]] && [[ ! -x "$MAIN_SCRIPT" ]]; then
        log_info "🔧 Making main script executable..."
        if chmod +x "$MAIN_SCRIPT"; then
            log_success "✅ Main script permissions fixed"
            return 0
        fi
    fi
    
    # Check if required directories exist
    local required_dirs=("$SCRIPTS_RUN_DIR/core" "$SCRIPTS_RUN_DIR/utils")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_info "🔧 Creating missing directory: $dir"
            if mkdir -p "$dir"; then
                log_success "✅ Directory created: $dir"
            fi
        fi
    done
    
    return 1
}

# Permission recovery attempts
attempt_permission_recovery() {
    log_debug "Attempting permission recovery..."
    
    # Try to fix script permissions
    if [[ -f "$MAIN_SCRIPT" ]]; then
        log_info "🔧 Fixing script permissions..."
        if chmod +x "$MAIN_SCRIPT"; then
            log_success "✅ Script permissions fixed"
            
            # Fix other script permissions
            find "$SCRIPTS_RUN_DIR" -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true
            
            return 0
        fi
    fi
    
    return 1
}

# Command recovery attempts
attempt_command_recovery() {
    log_debug "Attempting command recovery..."
    
    # Check for common missing commands and suggest alternatives
    local missing_commands=("docker" "python3" "conda" "git")
    
    for cmd in "${missing_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            case "$cmd" in
                "docker")
                    log_info "🐳 Docker not found - consider installing Docker for server mode"
                    ;;
                "python3")
                    log_info "🐍 Python 3 not found - required for development mode"
                    ;;
                "conda")
                    log_info "🐍 Conda not found - consider installing Miniconda"
                    ;;
                "git")
                    log_info "📦 Git not found - useful for development workflow"
                    ;;
            esac
        fi
    done
    
    return 1
}

# Show troubleshooting steps
show_troubleshooting_steps() {
    local exit_code="$1"
    
    log_info "🔧 Troubleshooting steps:"
    echo "1. Run health check: $0 --health-check"
    echo "2. Enable debug mode: DEBUG=true $0 [options]"
    echo "3. Check mode detection: $0 --mode-info"
    echo "4. Install for current mode: $0 --install"
    echo "5. Try different mode: $0 --dev or $0 --server"
    echo "6. Check file permissions: find scripts/ -name '*.sh' -not -executable"
    echo "7. Verify script syntax: bash -n $MAIN_SCRIPT"
    echo "8. Check system dependencies: which bash python3 docker"
    echo "9. Review error logs: tail -f $ERROR_LOG_FILE"
    echo "10. Check documentation: https://github.com/nuniesmith/fks"
    echo ""
    
    # Mode-specific troubleshooting
    case "${FKS_MODE:-}" in
        "development")
            echo "${YELLOW}Development Mode Specific:${NC}"
            echo "• Check Python installation: python3 --version"
            echo "• Verify conda environment: conda env list"
            echo "• Install requirements: pip install -r requirements.txt"
            echo ""
            ;;
        "server")
            echo "${YELLOW}Server Mode Specific:${NC}"
            echo "• Check Docker status: docker info"
            echo "• Verify Docker Compose: docker-compose --version"
            echo "• Check container logs: docker-compose logs"
            echo ""
            ;;
    esac
}

# Offer interactive help
offer_interactive_help() {
    local exit_code="$1"
    
    echo "Would you like to:"
    echo "  1. Run health check"
    echo "  2. View error logs"
    echo "  3. Attempt automatic fix"
    echo "  4. Switch to different mode"
    echo "  5. Exit"
    echo ""
    echo -n "Choose an option (1-5): "
    
    local choice
    read -r -t 30 choice 2>/dev/null || choice="5"
    
    case "$choice" in
        1)
            echo ""
            handle_health_check_mode
            ;;
        2)
            echo ""
            show_recent_errors
            ;;
        3)
            echo ""
            attempt_automatic_fix
            ;;
        4)
            echo ""
            offer_mode_switch
            ;;
        *)
            echo ""
            log_info "Exiting..."
            ;;
    esac
}

# Show recent errors
show_recent_errors() {
    log_info "📋 Recent errors from log file:"
    
    if [[ -f "$ERROR_LOG_FILE" ]]; then
        echo ""
        tail -20 "$ERROR_LOG_FILE" | head -15
        echo ""
        log_info "Full error log: $ERROR_LOG_FILE"
    else
        log_info "No error log file found"
    fi
}

# Attempt automatic fix
attempt_automatic_fix() {
    log_info "🔧 Attempting automatic fixes..."
    
    local fixes_applied=0
    
    # Fix script permissions
    if find "$SCRIPTS_RUN_DIR" -name "*.sh" -type f -not -executable 2>/dev/null | grep -q .; then
        log_info "Fixing script permissions..."
        find "$SCRIPTS_RUN_DIR" -name "*.sh" -type f -exec chmod +x {} \;
        ((fixes_applied++))
    fi
    
    # Create missing directories
    local missing_dirs=()
    local required_dirs=("$SCRIPTS_RUN_DIR/core" "$SCRIPTS_RUN_DIR/utils" "${CONFIG_DIR:-./config}")
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            missing_dirs+=("$dir")
        fi
    done
    
    if [[ ${#missing_dirs[@]} -gt 0 ]]; then
        log_info "Creating missing directories..."
        for dir in "${missing_dirs[@]}"; do
            mkdir -p "$dir" 2>/dev/null && ((fixes_applied++))
        done
    fi
    
    # Create missing basic structure
    if [[ ! -f "$MAIN_SCRIPT" ]]; then
        log_info "Creating missing script structure..."
        if create_missing_structure; then
            ((fixes_applied++))
        fi
    fi
    
    if [[ $fixes_applied -gt 0 ]]; then
        log_success "✅ Applied $fixes_applied automatic fix(es)"
        log_info "Try running the command again"
    else
        log_info "No automatic fixes available"
    fi
}

# Offer mode switch
offer_mode_switch() {
    local current_mode="${FKS_MODE:-auto}"
    
    log_info "Current mode: $current_mode"
    echo ""
    echo "Available modes:"
    echo "  1. Development mode (--dev)"
    echo "  2. Server mode (--server)"
    echo "  3. Auto-detect mode (--auto)"
    echo "  4. Keep current mode"
    echo ""
    echo -n "Choose a mode (1-4): "
    
    local choice
    read -r -t 30 choice 2>/dev/null || choice="4"
    
    case "$choice" in
        1)
            log_info "Switching to development mode..."
            export FKS_MODE="development"
            export FKS_MODE_REASON="User selected via error recovery"
            ;;
        2)
            log_info "Switching to server mode..."
            export FKS_MODE="server"
            export FKS_MODE_REASON="User selected via error recovery"
            ;;
        3)
            log_info "Switching to auto-detect mode..."
            unset FKS_MODE
            detect_operating_mode
            export FKS_MODE="$FKS_MODE_DETECTED"
            ;;
        *)
            log_info "Keeping current mode: $current_mode"
            ;;
    esac
}

# Cleanup on error
cleanup_on_error() {
    local exit_code="$1"
    
    log_debug "Performing error cleanup (exit code: $exit_code)"
    
    # Stop any running timers
    if command -v stop_all_timers >/dev/null 2>&1; then
        stop_all_timers >/dev/null 2>&1 || true
    fi
    
    # Cleanup temporary files
    cleanup_temp_files
    
    # Save error state
    save_error_state "$exit_code"
    
    # Cleanup performance module if loaded
    if command -v cleanup_performance_module >/dev/null 2>&1; then
        cleanup_performance_module >/dev/null 2>&1 || true
    fi
    
    log_debug "Error cleanup completed"
}

# Regular cleanup function
cleanup_orchestrator() {
    local exit_code=$?
    
    # Stop any running timers
    if command -v stop_all_timers >/dev/null 2>&1; then
        stop_all_timers >/dev/null 2>&1 || true
    fi
    
    # Regular cleanup tasks
    cleanup_temp_files
    
    # Save session state
    save_session_state "$exit_code"
    
    log_debug "Orchestrator cleanup completed (exit code: $exit_code, mode: ${FKS_MODE:-unknown})"
    return $exit_code
}

# Cleanup temporary files
cleanup_temp_files() {
    local temp_patterns=("${TEMP_DIR:-./temp}/*" "/tmp/fks_*" "./logs/fks_debug_*.log")
    
    for pattern in "${temp_patterns[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            rm -f $pattern 2>/dev/null || true
            log_debug "Cleaned temporary files: $pattern"
        fi
    done
}

# Save error state for debugging
save_error_state() {
    local exit_code="$1"
    local state_file="${FKS_LOGS_DIR:-./logs}/fks_error_state_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "# FKS Error State Dump"
        echo "# Timestamp: $(date)"
        echo "# Exit Code: $exit_code"
        echo ""
        echo "## Environment Variables"
        env | grep '^FKS_' | sort
        echo ""
        echo "## System Information"
        echo "User: ${USER:-unknown}"
        echo "PWD: $(pwd)"
        echo "Shell: $0"
        echo "Args: $*"
        echo ""
        echo "## Error Counts"
        for error_type in "${!ERROR_COUNTS[@]}"; do
            echo "$error_type: ${ERROR_COUNTS[$error_type]} (last: ${ERROR_TIMESTAMPS[$error_type]})"
        done
        echo ""
        echo "## Recent Commands"
        history | tail -10 2>/dev/null || echo "History not available"
    } > "$state_file" 2>/dev/null || true
    
    log_debug "Error state saved: $state_file"
}

# Save regular session state
save_session_state() {
    local exit_code="$1"
    
    # Only save if not an error exit
    if [[ $exit_code -eq 0 ]]; then
        local state_file="${FKS_LOGS_DIR:-./logs}/fks_last_session.log"
        
        {
            echo "# FKS Last Session"
            echo "# Timestamp: $(date)"
            echo "# Exit Code: $exit_code"
            echo "# Mode: ${FKS_MODE:-unknown}"
            echo "# Duration: Session completed successfully"
        } > "$state_file" 2>/dev/null || true
    fi
}

# Rotate error log if it gets too large
rotate_error_log_if_needed() {
    if [[ -f "$ERROR_LOG_FILE" ]]; then
        local file_size
        file_size=$(wc -c < "$ERROR_LOG_FILE" 2>/dev/null || echo "0")
        
        if [[ $file_size -gt $MAX_ERROR_LOG_SIZE ]]; then
            local backup_file="${ERROR_LOG_FILE}.$(date +%Y%m%d_%H%M%S).old"
            mv "$ERROR_LOG_FILE" "$backup_file" 2>/dev/null || true
            
            # Create new log file
            cat > "$ERROR_LOG_FILE" << EOF
# FKS Trading Systems - Error Log (Rotated)
# Previous log: $backup_file
# Started: $(date)
# ==========================================

EOF
            log_debug "Error log rotated: $backup_file"
        fi
    fi
}

# Show error statistics
show_error_statistics() {
    if [[ ${#ERROR_COUNTS[@]} -eq 0 ]]; then
        log_info "No errors recorded in this session"
        return 0
    fi
    
    echo "${WHITE}📊 Error Statistics${NC}"
    echo "${CYAN}==================${NC}"
    echo ""
    
    for error_type in "${!ERROR_COUNTS[@]}"; do
        echo "${YELLOW}$error_type:${NC}"
        echo "  Count: ${ERROR_COUNTS[$error_type]}"
        echo "  Last occurrence: ${ERROR_TIMESTAMPS[$error_type]}"
        echo "  Context: ${ERROR_CONTEXTS[$error_type]}"
        echo ""
    done
    
    if [[ -f "$ERROR_LOG_FILE" ]]; then
        echo "${YELLOW}Error Log:${NC} $ERROR_LOG_FILE"
        local log_size
        log_size=$(wc -c < "$ERROR_LOG_FILE" 2>/dev/null || echo "0")
        echo "Log size: $(numfmt --to=iec $log_size 2>/dev/null || echo "${log_size} bytes")"
    fi
}

# Initialize error handling when module is loaded
init_error_handling

echo "📦 Loaded error handling module (v$ERROR_HANDLING_MODULE_VERSION)"