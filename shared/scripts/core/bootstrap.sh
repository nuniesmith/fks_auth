#!/bin/bash
# filepath: scripts/core/bootstrap.sh
# FKS Trading Systems - Bootstrap Module
# Handles system initialization and delegation to main script

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly BOOTSTRAP_MODULE_VERSION="2.5.0"
readonly BOOTSTRAP_MODULE_LOADED="$(date +%s)"

# Bootstrap configuration
readonly BOOTSTRAP_TIMEOUT="${FKS_BOOTSTRAP_TIMEOUT:-300}"  # 5 minutes
readonly BOOTSTRAP_VERBOSE="${FKS_BOOTSTRAP_VERBOSE:-false}"

# bootstrap and delegate with mode support
bootstrap_and_delegate() {
    local start_time=$(date +%s.%N)
    
    log_info "🚀 FKS Trading Systems Runner v${SCRIPT_VERSION:-2.5.0}"
    log_info "Bootstrapping modular script system..."
    start_timer "bootstrap" "System bootstrap process"
    
    # Verify bootstrap requirements
    if ! verify_bootstrap_requirements; then
        log_error "❌ Bootstrap requirements not met"
        return 1
    fi
    
    # Initialize core systems
    if ! initialize_core_systems; then
        log_error "❌ Core system initialization failed"
        return 1
    fi
    
    # Set up operating mode and environment
    setup_mode_environment
    
    # Validate system readiness
    if ! validate_system_readiness; then
        log_error "❌ System readiness validation failed"
        return 1
    fi
    
    # Set comprehensive environment variables for the modular system
    export_bootstrap_environment
    
    # Set performance timing
    local bootstrap_time
    bootstrap_time=$(stop_timer "bootstrap")
    
    # Delegate to main script with all arguments
    log_info "🎯 Delegating to modular main script... (bootstrap: ${bootstrap_time}s)"
    log_debug "Executing: $MAIN_SCRIPT $*"
    echo ""
    
    # Execute main script with proper error handling
    if execute_main_script "$@"; then
        log_debug "Main script completed successfully"
        return 0
    else
        local exit_code=$?
        log_error "Main script failed with exit code $exit_code"
        return $exit_code
    fi
}

# Verify bootstrap requirements
verify_bootstrap_requirements() {
    log_debug "Verifying bootstrap requirements..."
    
    local requirements_met=true
    
    # Check essential environment variables
    if [[ -z "${SCRIPT_DIR:-}" ]]; then
        log_error "❌ SCRIPT_DIR not set"
        requirements_met=false
    fi
    
    if [[ -z "${SCRIPTS_RUN_DIR:-}" ]]; then
        log_error "❌ SCRIPTS_RUN_DIR not set"
        requirements_met=false
    fi
    
    if [[ -z "${MAIN_SCRIPT:-}" ]]; then
        log_error "❌ MAIN_SCRIPT not set"
        requirements_met=false
    fi
    
    # Check critical directories
    if [[ ! -d "$SCRIPTS_RUN_DIR" ]]; then
        log_error "❌ Scripts directory not found: $SCRIPTS_RUN_DIR"
        requirements_met=false
    fi
    
    # Check main script existence
    if [[ ! -f "$MAIN_SCRIPT" ]]; then
        log_error "❌ Main script not found: $MAIN_SCRIPT"
        requirements_met=false
    fi
    
    # Check basic system commands
    local required_commands=("bash" "dirname" "basename" "cd" "mkdir" "chmod")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "❌ Required command not found: $cmd"
            requirements_met=false
        fi
    done
    
    if [[ "$requirements_met" == "true" ]]; then
        log_debug "✅ Bootstrap requirements verified"
        return 0
    else
        log_error "❌ Bootstrap requirements verification failed"
        return 1
    fi
}

# Initialize core systems
initialize_core_systems() {
    log_debug "Initializing core systems..."
    
    # Initialize logging system
    if ! initialize_logging_system; then
        log_error "❌ Logging system initialization failed"
        return 1
    fi
    
    # Initialize error handling
    if command -v init_error_handling >/dev/null 2>&1; then
        init_error_handling
        log_debug "✅ Error handling initialized"
    else
        log_warn "⚠️  Error handling module not available"
    fi
    
    # Initialize performance monitoring
    if command -v start_timer >/dev/null 2>&1; then
        log_debug "✅ Performance monitoring available"
    else
        log_warn "⚠️  Performance monitoring module not available"
    fi
    
    # Create necessary directories
    create_bootstrap_directories
    
    log_debug "✅ Core systems initialized"
    return 0
}

# Initialize logging system
initialize_logging_system() {
    # Create logs directory
    local logs_dir="${FKS_LOGS_DIR:-./logs}"
    if [[ ! -d "$logs_dir" ]]; then
        if mkdir -p "$logs_dir" 2>/dev/null; then
            log_debug "Created logs directory: $logs_dir"
        else
            log_warn "Could not create logs directory: $logs_dir"
        fi
    fi
    
    # Initialize log files
    local log_file="${FKS_LOG_FILE:-$logs_dir/fks.log}"
    if [[ ! -f "$log_file" ]]; then
        cat > "$log_file" << EOF
# FKS Trading Systems - Main Log
# Started: $(date)
# Mode: ${FKS_MODE:-unknown}
# PID: $$
# ==========================================

EOF
    fi
    
    return 0
}

# Create necessary directories for bootstrap
create_bootstrap_directories() {
    local bootstrap_dirs=(
        "${CONFIG_DIR:-./config}"
        "${DATA_DIR:-./data}"
        "${TEMP_DIR:-./temp}"
        "${FKS_LOGS_DIR:-./logs}"
    )
    
    for dir in "${bootstrap_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir" 2>/dev/null; then
                log_debug "Created directory: $dir"
            else
                log_debug "Could not create directory: $dir"
            fi
        fi
    done
}

# Validate system readiness
validate_system_readiness() {
    log_debug "Validating system readiness..."
    
    # Mode-specific dependency checks
    if ! check_mode_dependencies; then
        log_error "❌ Mode-specific dependencies not met"
        return 1
    fi
    
    # Script structure validation
    if ! validate_script_structure; then
        log_error "❌ Script structure validation failed"
        offer_structure_setup
        return 1
    fi
    
    # Main script validation
    if ! validate_main_script; then
        log_error "❌ Main script validation failed"
        return 1
    fi
    
    log_debug "✅ System readiness validated"
    return 0
}

# Export bootstrap environment variables
export_bootstrap_environment() {
    log_debug "Exporting bootstrap environment variables..."
    
    # Core script information
    export SCRIPT_VERSION="${SCRIPT_VERSION:-2.5.0}"
    export SCRIPT_NAME="${SCRIPT_NAME:-FKS Trading Systems Runner}"
    export PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
    export SCRIPTS_RUN_DIR
    
    # Logging configuration
    export LOG_LEVEL="${LOG_LEVEL:-INFO}"
    export DEBUG="${DEBUG:-false}"
    
    # Mode information
    export FKS_MODE
    export FKS_MODE_REASON
    
    # Bootstrap metadata
    export FKS_BOOTSTRAP_VERSION="$BOOTSTRAP_MODULE_VERSION"
    export FKS_BOOTSTRAP_TIME="$(date +%s)"
    export FKS_BOOTSTRAP_PID="$$"
    
    # Performance settings
    export FKS_PERFORMANCE_MONITORING="${FKS_PERFORMANCE_MONITORING:-true}"
    export FKS_ERROR_HANDLING="${FKS_ERROR_HANDLING:-true}"
    
    log_debug "✅ Bootstrap environment exported"
}

# Execute main script with comprehensive error handling
execute_main_script() {
    log_debug "Executing main script: $MAIN_SCRIPT"
    
    # Verify main script one more time
    if [[ ! -f "$MAIN_SCRIPT" ]]; then
        log_error "❌ Main script disappeared: $MAIN_SCRIPT"
        return 1
    fi
    
    if [[ ! -x "$MAIN_SCRIPT" ]]; then
        log_error "❌ Main script not executable: $MAIN_SCRIPT"
        return 1
    fi
    
    # Set up execution environment
    setup_execution_environment
    
    # Execute with timeout if available
    if command -v timeout >/dev/null 2>&1 && [[ "${FKS_USE_TIMEOUT:-true}" == "true" ]]; then
        local timeout_duration="${FKS_EXECUTION_TIMEOUT:-1800}"  # 30 minutes
        log_debug "Executing with timeout: ${timeout_duration}s"
        
        if timeout "$timeout_duration" "$MAIN_SCRIPT" "$@"; then
            return 0
        else
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                log_error "❌ Main script execution timed out after ${timeout_duration}s"
            fi
            return $exit_code
        fi
    else
        # Execute without timeout
        log_debug "Executing without timeout"
        exec "$MAIN_SCRIPT" "$@"
    fi
}

# Setup execution environment
setup_execution_environment() {
    # Set up signal handlers for the main script execution
    trap 'handle_execution_signal SIGINT' INT
    trap 'handle_execution_signal SIGTERM' TERM
    trap 'handle_execution_signal SIGQUIT' QUIT
    
    # Set execution-specific environment variables
    export FKS_EXECUTION_START="$(date +%s)"
    export FKS_EXECUTION_PID="$$"
    
    # Change to project root directory
    if [[ -n "${PROJECT_ROOT:-}" ]] && [[ -d "$PROJECT_ROOT" ]]; then
        cd "$PROJECT_ROOT" || log_warn "Could not change to project root: $PROJECT_ROOT"
    fi
    
    log_debug "Execution environment configured"
}

# Handle execution signals
handle_execution_signal() {
    local signal="$1"
    
    log_warn "Received signal: $signal"
    
    case "$signal" in
        SIGINT)
            log_info "🛑 Interrupt signal received - shutting down gracefully..."
            ;;
        SIGTERM)
            log_info "🛑 Termination signal received - shutting down..."
            ;;
        SIGQUIT)
            log_info "🛑 Quit signal received - performing cleanup..."
            ;;
    esac
    
    # Allow child processes to handle their own cleanup
    sleep 2
    
    # Exit with appropriate code
    exit 130  # Standard exit code for Ctrl+C
}

# Bootstrap validation and health check
validate_bootstrap_health() {
    log_info "🏥 Bootstrap Health Check"
    
    local health_issues=0
    
    # Check core modules availability
    local core_modules=(
        "logging"
        "mode_detection"
        "dependencies"
        "validation"
        "environment"
    )
    
    for module in "${core_modules[@]}"; do
        if [[ -f "$SCRIPTS_RUN_DIR/core/${module}.sh" ]]; then
            log_debug "✅ Core module available: $module"
        else
            log_warn "⚠️  Core module missing: $module"
            ((health_issues++))
        fi
    done
    
    # Check utility modules
    local util_modules=(
        "helpers"
        "menu"
        "cli"
        "setup"
        "performance"
    )
    
    for module in "${util_modules[@]}"; do
        if [[ -f "$SCRIPTS_RUN_DIR/utils/${module}.sh" ]]; then
            log_debug "✅ Utility module available: $module"
        else
            log_debug "ℹ️  Utility module missing: $module (optional)"
        fi
    done
    
    # Check mode-specific requirements
    case "${FKS_MODE:-}" in
        "development")
            if command -v python3 >/dev/null 2>&1; then
                log_debug "✅ Python 3 available for development mode"
            else
                log_error "❌ Python 3 required for development mode"
                ((health_issues++))
            fi
            ;;
        "server")
            if command -v docker >/dev/null 2>&1; then
                log_debug "✅ Docker available for server mode"
            else
                log_error "❌ Docker required for server mode"
                ((health_issues++))
            fi
            ;;
    esac
    
    # Report health status
    if [[ $health_issues -eq 0 ]]; then
        log_success "✅ Bootstrap health check passed"
        return 0
    else
        log_warn "⚠️  Bootstrap health check found $health_issues issue(s)"
        return 1
    fi
}

# Bootstrap recovery procedures
recover_bootstrap_failure() {
    local failure_type="$1"
    
    log_info "🔧 Attempting bootstrap recovery: $failure_type"
    
    case "$failure_type" in
        "missing_structure")
            log_info "Attempting to create missing script structure..."
            if create_missing_structure; then
                log_success "✅ Script structure recovery successful"
                return 0
            fi
            ;;
        "permission_error")
            log_info "Attempting to fix permission errors..."
            if fix_script_permissions; then
                log_success "✅ Permission recovery successful"
                return 0
            fi
            ;;
        "dependency_error")
            log_info "Attempting to resolve dependency issues..."
            if resolve_dependencies; then
                log_success "✅ Dependency recovery successful"
                return 0
            fi
            ;;
    esac
    
    log_error "❌ Bootstrap recovery failed: $failure_type"
    return 1
}

# Fix script permissions
fix_script_permissions() {
    log_debug "Fixing script permissions..."
    
    local fixed_count=0
    
    # Fix main script permissions
    if [[ -f "$MAIN_SCRIPT" ]] && [[ ! -x "$MAIN_SCRIPT" ]]; then
        if chmod +x "$MAIN_SCRIPT"; then
            log_debug "Fixed permissions: $MAIN_SCRIPT"
            ((fixed_count++))
        fi
    fi
    
    # Fix all shell scripts in the scripts directory
    if [[ -d "$SCRIPTS_RUN_DIR" ]]; then
        while IFS= read -r -d '' script_file; do
            if [[ ! -x "$script_file" ]]; then
                if chmod +x "$script_file"; then
                    log_debug "Fixed permissions: $script_file"
                    ((fixed_count++))
                fi
            fi
        done < <(find "$SCRIPTS_RUN_DIR" -name "*.sh" -type f -print0 2>/dev/null)
    fi
    
    if [[ $fixed_count -gt 0 ]]; then
        log_info "Fixed permissions on $fixed_count script(s)"
        return 0
    else
        log_debug "No permission fixes needed"
        return 1
    fi
}

# Resolve dependencies
resolve_dependencies() {
    log_debug "Attempting to resolve dependencies..."
    
    # Check if we can run dependency checks
    if command -v check_mode_dependencies >/dev/null 2>&1; then
        if check_mode_dependencies; then
            log_info "Dependencies resolved successfully"
            return 0
        fi
    fi
    
    # Fallback: provide guidance
    log_info "Please install missing dependencies:"
    case "${FKS_MODE:-}" in
        "development")
            echo "  • Python 3: https://www.python.org/downloads/"
            echo "  • Conda (optional): https://docs.conda.io/en/latest/miniconda.html"
            ;;
        "server")
            echo "  • Docker: https://docs.docker.com/get-docker/"
            echo "  • Docker Compose: https://docs.docker.com/compose/install/"
            ;;
    esac
    
    return 1
}

# Show bootstrap information
show_bootstrap_info() {
    cat << EOF
${WHITE}🚀 FKS Bootstrap Information${NC}
${CYAN}============================${NC}

${YELLOW}Bootstrap Version:${NC} $BOOTSTRAP_MODULE_VERSION
${YELLOW}System Mode:${NC} ${FKS_MODE:-not set}
${YELLOW}Project Root:${NC} ${PROJECT_ROOT:-not set}
${YELLOW}Scripts Directory:${NC} ${SCRIPTS_RUN_DIR:-not set}
${YELLOW}Main Script:${NC} ${MAIN_SCRIPT:-not set}

${YELLOW}Bootstrap Configuration:${NC}
  Timeout: ${BOOTSTRAP_TIMEOUT}s
  Verbose: ${BOOTSTRAP_VERBOSE}
  Performance Monitoring: ${FKS_PERFORMANCE_MONITORING:-true}
  Error Handling: ${FKS_ERROR_HANDLING:-true}

${YELLOW}Environment Status:${NC}
  User: ${USER:-unknown}
  Shell: ${SHELL:-unknown}
  Working Directory: $(pwd)
  Process ID: $$

EOF
}

echo "📦 Loaded bootstrap module (v$BOOTSTRAP_MODULE_VERSION)"