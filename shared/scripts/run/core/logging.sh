#!/bin/bash
# filepath: scripts/core/logging.sh
# FKS Trading Systems - Logging System
# Version: 3.0.0

# Prevent multiple sourcing
[[ -n "${FKS_LOGGING_LOADED:-}" ]] && return 0
readonly FKS_LOGGING_LOADED=1

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

#=============================================================================
# MODULE METADATA & CONSTANTS
#=============================================================================

readonly LOGGING_MODULE_VERSION="3.0.0"
readonly LOGGING_MODULE_LOADED="$(date +%s)"

# Color definitions
readonly -A LOG_COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[0;33m'
    [BLUE]='\033[0;34m'
    [PURPLE]='\033[0;35m'
    [CYAN]='\033[0;36m'
    [WHITE]='\033[1;37m'
    [BOLD]='\033[1m'
    [DIM]='\033[2m'
    [NC]='\033[0m'
)

# Log level constants with numeric values
readonly -A LOG_LEVELS=(
    [DEBUG]=10
    [INFO]=20
    [WARN]=30
    [ERROR]=40
    [CRITICAL]=50
)

#=============================================================================
# CONFIGURATION
#=============================================================================

# Core logging settings
readonly LOG_LEVEL="${LOG_LEVEL:-INFO}"
readonly ENABLE_DEBUG="${DEBUG:-false}"
readonly FKS_LOG_TO_FILE="${FKS_LOG_TO_FILE:-true}"
readonly FKS_LOG_WITH_TIMESTAMP="${FKS_LOG_WITH_TIMESTAMP:-true}"
readonly FKS_LOG_WITH_PID="${FKS_LOG_WITH_PID:-false}"
readonly FKS_LOG_WITH_CALLER="${FKS_LOG_WITH_CALLER:-false}"

# File paths
readonly FKS_LOGS_DIR="${FKS_LOGS_DIR:-./logs}"
readonly FKS_LOG_FILE="${FKS_LOG_FILE:-$FKS_LOGS_DIR/fks.log}"
readonly FKS_ERROR_LOG="${FKS_ERROR_LOG:-$FKS_LOGS_DIR/fks_error.log}"
readonly FKS_DEBUG_LOG="${FKS_DEBUG_LOG:-$FKS_LOGS_DIR/fks_debug.log}"
readonly FKS_ACCESS_LOG="${FKS_ACCESS_LOG:-$FKS_LOGS_DIR/fks_access.log}"

# Rotation settings
readonly FKS_LOG_MAX_SIZE="${FKS_LOG_MAX_SIZE:-10485760}"  # 10MB
readonly FKS_LOG_BACKUP_COUNT="${FKS_LOG_BACKUP_COUNT:-5}"

# Internal state
declare -A _FKS_TIMERS=()

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================

# Get current timestamp
_get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Convert log level name to number
_get_log_level_number() {
    local level="${1^^}"
    echo "${LOG_LEVELS[$level]:-${LOG_LEVELS[INFO]}}"
}

# Check if level should be logged
_should_log() {
    local message_level="$1"
    local current_level_num=$(_get_log_level_number "$LOG_LEVEL")
    local message_level_num=$(_get_log_level_number "$message_level")
    
    [[ $message_level_num -ge $current_level_num ]]
}

# Generate log prefix
_generate_log_prefix() {
    local level="$1"
    local prefix=""
    
    [[ "$FKS_LOG_WITH_TIMESTAMP" == "true" ]] && prefix="[$(_get_timestamp)]"
    [[ "$FKS_LOG_WITH_PID" == "true" ]] && prefix="${prefix}[$$]"
    [[ -n "${FKS_MODE:-}" ]] && prefix="${prefix}[${FKS_MODE^^}]"
    prefix="${prefix}[${level^^}]"
    
    if [[ "$FKS_LOG_WITH_CALLER" == "true" ]]; then
        local caller_info
        caller_info=$(caller 2)
        if [[ -n "$caller_info" ]]; then
            local line_num=$(echo "$caller_info" | awk '{print $1}')
            local script_name=$(basename "$(echo "$caller_info" | awk '{print $3}')")
            prefix="${prefix}[${script_name}:${line_num}]"
        fi
    fi
    
    echo "$prefix"
}

# Write to log file with rotation check
_write_to_file() {
    local level="$1"
    local message="$2"
    local log_file="$3"
    
    if [[ "$FKS_LOG_TO_FILE" == "true" ]] && [[ -w "$(dirname "$log_file")" || ! -e "$(dirname "$log_file")" ]]; then
        local log_prefix
        log_prefix=$(_generate_log_prefix "$level")
        echo "$log_prefix $message" >> "$log_file" 2>/dev/null || true
        _check_rotation "$log_file"
    fi
}

#=============================================================================
# LOG ROTATION
#=============================================================================

_check_rotation() {
    local log_file="$1"
    [[ ! -f "$log_file" ]] && return 0
    
    local file_size
    file_size=$(wc -c < "$log_file" 2>/dev/null || echo "0")
    
    if [[ $file_size -gt $FKS_LOG_MAX_SIZE ]]; then
        _rotate_log "$log_file"
    fi
}

_rotate_log() {
    local log_file="$1"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local rotated_file="${log_file}.${timestamp}"
    
    if mv "$log_file" "$rotated_file" 2>/dev/null; then
        touch "$log_file"
        _cleanup_old_logs "$(dirname "$log_file")" "$(basename "$log_file")"
        log_debug "Log rotated: $(basename "$log_file")"
    fi
}

_cleanup_old_logs() {
    local log_dir="$1"
    local base_name="$2"
    
    find "$log_dir" -name "${base_name}.*" -type f 2>/dev/null | \
        sort -r | \
        tail -n +$((FKS_LOG_BACKUP_COUNT + 1)) | \
        xargs rm -f 2>/dev/null || true
}

#=============================================================================
# CORE LOGGING FUNCTIONS
#=============================================================================

# Main logging function
_log() {
    local level="$1"
    local color="$2"
    local message="$3"
    local log_file="${4:-$FKS_LOG_FILE}"
    
    _should_log "$level" || return 0
    
    # Console output with colors
    echo -e "${color}[${level}]${LOG_COLORS[NC]} ${message}" >&2
    
    # File output
    _write_to_file "$level" "$message" "$log_file"
}

# Level-specific logging functions
log_debug() {
    if [[ "$ENABLE_DEBUG" == "true" ]] || _should_log "DEBUG"; then
        _log "DEBUG" "${LOG_COLORS[DIM]}${LOG_COLORS[PURPLE]}" "$1" "$FKS_DEBUG_LOG"
    fi
}

log_info() {
    _log "INFO" "${LOG_COLORS[GREEN]}" "$1"
}

log_warn() {
    _log "WARN" "${LOG_COLORS[YELLOW]}" "$1"
}

log_error() {
    _log "ERROR" "${LOG_COLORS[RED]}" "$1" "$FKS_ERROR_LOG"
    _write_to_file "ERROR" "$1" "$FKS_LOG_FILE"  # Also write to main log
}

log_critical() {
    _log "CRITICAL" "${LOG_COLORS[BOLD]}${LOG_COLORS[RED]}" "$1" "$FKS_ERROR_LOG"
    _write_to_file "CRITICAL" "$1" "$FKS_LOG_FILE"  # Also write to main log
}

log_success() {
    _log "SUCCESS" "${LOG_COLORS[BOLD]}${LOG_COLORS[CYAN]}" "$1"
}

#=============================================================================
# SPECIALIZED LOGGING FUNCTIONS
#=============================================================================

log_header() {
    local message="$1"
    local char="${2:-=}"
    local separator
    separator=$(printf "%*s" 50 "" | tr ' ' "$char")
    
    echo ""
    log_info "$separator"
    log_info "  $message"
    log_info "$separator"
    echo ""
}

log_section() {
    local message="$1"
    local char="${2:--}"
    local separator
    separator=$(printf "%*s" $((${#message} + 4)) "" | tr ' ' "$char")
    
    echo ""
    log_info "$separator"
    log_info "  $message"
    log_info "$separator"
}

log_step() {
    local step="$1"
    local total="${2:-}"
    local message="$3"
    
    if [[ -n "$total" ]]; then
        log_info "📋 Step $step/$total: $message"
    else
        log_info "📋 Step $step: $message"
    fi
}

log_progress() {
    local current="$1"
    local total="$2"
    local message="${3:-Processing}"
    local percentage=$((current * 100 / total))
    
    log_info "⏳ $message... ($current/$total - ${percentage}%)"
}

log_access() {
    local operation="$1"
    local user="${2:-${USER:-unknown}}"
    local status="${3:-OK}"
    local details="${4:-}"
    
    local access_entry="$user | $operation | $status"
    [[ -n "$details" ]] && access_entry="$access_entry | $details"
    
    _write_to_file "ACCESS" "$access_entry" "$FKS_ACCESS_LOG"
}

log_performance() {
    local operation="$1"
    local duration="$2"
    local details="${3:-}"
    
    local message="⚡ $operation completed in ${duration}s"
    [[ -n "$details" ]] && message="$message ($details)"
    
    log_info "$message"
}

log_structured() {
    local level="$1"
    local event="$2"
    shift 2
    
    local structured_message="event=$event"
    while [[ $# -gt 0 ]]; do
        [[ "$1" =~ ^[a-zA-Z_][a-zA-Z0-9_]*=.* ]] && structured_message="$structured_message $1"
        shift
    done
    
    case "${level^^}" in
        DEBUG) log_debug "$structured_message" ;;
        INFO) log_info "$structured_message" ;;
        WARN|WARNING) log_warn "$structured_message" ;;
        ERROR) log_error "$structured_message" ;;
        CRITICAL|FATAL) log_critical "$structured_message" ;;
        *) log_info "$structured_message" ;;
    esac
}

#=============================================================================
# ERROR HANDLING & UTILITIES
#=============================================================================

log_and_exit() {
    local exit_code="$1"
    local message="$2"
    log_critical "$message"
    exit "$exit_code"
}

log_command() {
    local command="$1"
    shift
    local args=("$@")
    
    log_debug "Executing: $command ${args[*]}"
    
    if "$command" "${args[@]}"; then
        log_debug "Command succeeded: $command"
        return 0
    else
        local exit_code=$?
        log_error "Command failed with exit code $exit_code: $command"
        return $exit_code
    fi
}

log_context() {
    local context="$1"
    local level="$2"
    local message="$3"
    
    case "${level,,}" in
        debug) log_debug "[$context] $message" ;;
        info) log_info "[$context] $message" ;;
        warn|warning) log_warn "[$context] $message" ;;
        error) log_error "[$context] $message" ;;
        critical|fatal) log_critical "[$context] $message" ;;
        success) log_success "[$context] $message" ;;
        *) log_info "[$context] $message" ;;
    esac
}

#=============================================================================
# TIMING FUNCTIONS
#=============================================================================

start_timer() {
    local timer_name="$1"
    _FKS_TIMERS["$timer_name"]=$(date +%s.%N)
    log_debug "Timer started: $timer_name"
}

stop_timer() {
    local timer_name="$1"
    local start_time="${_FKS_TIMERS["$timer_name"]:-}"
    
    if [[ -z "$start_time" ]]; then
        log_warn "Timer not found: $timer_name"
        return 1
    fi
    
    local end_time
    end_time=$(date +%s.%N)
    local duration
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "unknown")
    
    log_performance "$timer_name" "$duration"
    unset _FKS_TIMERS["$timer_name"]
    echo "$duration"
}

#=============================================================================
# SYSTEM INFORMATION LOGGING
#=============================================================================

log_system_info() {
    log_header "System Information"
    log_info "OS: $(uname -s -r)"
    log_info "Architecture: $(uname -m)"
    log_info "User: $(whoami)"
    log_info "Working Directory: $(pwd)"
    log_info "Timestamp: $(date)"
    log_info "PID: $$"
    log_info "Shell: $SHELL"
    [[ -n "${BASH_VERSION:-}" ]] && log_info "Bash Version: $BASH_VERSION"
    echo ""
}

log_environment() {
    log_section "Environment Variables"
    env | grep -E '^(FKS_|DOCKER_|COMPOSE_|CONFIG_|DATA_|LOG_|PYTHON_)' | sort | while IFS= read -r line; do
        if [[ "$line" =~ (PASSWORD|SECRET|KEY|TOKEN)= ]]; then
            local var_name="${line%%=*}"
            log_debug "$var_name=***MASKED***"
        else
            log_debug "$line"
        fi
    done
    echo ""
}

#=============================================================================
# LOG ANALYSIS FUNCTIONS
#=============================================================================

show_log_summary() {
    local log_file="${1:-$FKS_LOG_FILE}"
    
    if [[ ! -f "$log_file" ]]; then
        log_warn "Log file not found: $log_file"
        return 1
    fi
    
    echo -e "${LOG_COLORS[WHITE]}📊 Log Summary: $(basename "$log_file")${LOG_COLORS[NC]}"
    echo -e "${LOG_COLORS[CYAN]}================================${LOG_COLORS[NC]}"
    echo ""
    
    local total_lines
    total_lines=$(wc -l < "$log_file" 2>/dev/null || echo "0")
    echo "Total entries: $total_lines"
    
    # Count entries by level
    for level in INFO WARN ERROR CRITICAL DEBUG; do
        if grep -q "\\[$level\\]" "$log_file" 2>/dev/null; then
            local count
            count=$(grep -c "\\[$level\\]" "$log_file" 2>/dev/null || echo "0")
            echo "$level entries: $count"
        fi
    done
    
    local file_size
    file_size=$(wc -c < "$log_file" 2>/dev/null || echo "0")
    echo "File size: $(numfmt --to=iec $file_size 2>/dev/null || echo "${file_size} bytes")"
    
    echo ""
}

show_recent_logs() {
    local lines="${1:-20}"
    local log_file="${2:-$FKS_LOG_FILE}"
    
    if [[ ! -f "$log_file" ]]; then
        log_warn "Log file not found: $log_file"
        return 1
    fi
    
    echo -e "${LOG_COLORS[WHITE]}📄 Recent Log Entries (last $lines lines):${LOG_COLORS[NC]}"
    echo -e "${LOG_COLORS[CYAN]}========================================${LOG_COLORS[NC]}"
    echo ""
    
    tail -n "$lines" "$log_file"
}

search_logs() {
    local pattern="$1"
    local log_file="${2:-$FKS_LOG_FILE}"
    local context_lines="${3:-2}"
    
    if [[ ! -f "$log_file" ]]; then
        log_warn "Log file not found: $log_file"
        return 1
    fi
    
    echo -e "${LOG_COLORS[WHITE]}🔍 Search Results for: '$pattern'${LOG_COLORS[NC]}"
    echo -e "${LOG_COLORS[CYAN]}================================${LOG_COLORS[NC]}"
    echo ""
    
    if grep -C "$context_lines" "$pattern" "$log_file" 2>/dev/null; then
        echo ""
        echo "Search completed in $(basename "$log_file")"
    else
        echo "No matches found for: '$pattern'"
    fi
}

show_logging_config() {
    cat << EOF
${LOG_COLORS[WHITE]}⚙️  FKS Logging Configuration${LOG_COLORS[NC]}
${LOG_COLORS[CYAN]}=============================${LOG_COLORS[NC]}

${LOG_COLORS[YELLOW]}Log Level:${LOG_COLORS[NC]} $LOG_LEVEL
${LOG_COLORS[YELLOW]}Debug Enabled:${LOG_COLORS[NC]} $ENABLE_DEBUG
${LOG_COLORS[YELLOW]}Log to File:${LOG_COLORS[NC]} $FKS_LOG_TO_FILE
${LOG_COLORS[YELLOW]}With Timestamp:${LOG_COLORS[NC]} $FKS_LOG_WITH_TIMESTAMP
${LOG_COLORS[YELLOW]}With PID:${LOG_COLORS[NC]} $FKS_LOG_WITH_PID
${LOG_COLORS[YELLOW]}With Caller:${LOG_COLORS[NC]} $FKS_LOG_WITH_CALLER

${LOG_COLORS[YELLOW]}Log Files:${LOG_COLORS[NC]}
  Main Log: $FKS_LOG_FILE
  Error Log: $FKS_ERROR_LOG
  Debug Log: $FKS_DEBUG_LOG
  Access Log: $FKS_ACCESS_LOG

${LOG_COLORS[YELLOW]}Log Rotation:${LOG_COLORS[NC]}
  Max Size: $(numfmt --to=iec $FKS_LOG_MAX_SIZE)
  Backup Count: $FKS_LOG_BACKUP_COUNT

${LOG_COLORS[YELLOW]}Log Directory:${LOG_COLORS[NC]} $FKS_LOGS_DIR
EOF

    if [[ -d "$FKS_LOGS_DIR" ]]; then
        echo ""
        echo -e "${LOG_COLORS[YELLOW]}Directory Status:${LOG_COLORS[NC]}"
        echo "  ✅ Logs directory exists"
        echo "  📁 Contents: $(ls -1 "$FKS_LOGS_DIR" 2>/dev/null | wc -l) file(s)"
        
        local total_size
        total_size=$(du -sb "$FKS_LOGS_DIR" 2>/dev/null | cut -f1 || echo "0")
        echo "  📊 Total Size: $(numfmt --to=iec $total_size 2>/dev/null || echo "${total_size} bytes")"
    else
        echo ""
        echo -e "${LOG_COLORS[RED]}❌ Logs directory does not exist${LOG_COLORS[NC]}"
    fi
    
    echo ""
}

#=============================================================================
# INITIALIZATION
#=============================================================================

init_logging() {
    # Create logs directory
    if [[ ! -d "$FKS_LOGS_DIR" ]]; then
        mkdir -p "$FKS_LOGS_DIR" 2>/dev/null || {
            echo "Warning: Could not create logs directory: $FKS_LOGS_DIR" >&2
        }
    fi
    
    # Initialize main log file
    if [[ "$FKS_LOG_TO_FILE" == "true" && -d "$FKS_LOGS_DIR" && ! -f "$FKS_LOG_FILE" ]]; then
        cat > "$FKS_LOG_FILE" << EOF
# FKS Trading Systems - Main Log
# Started: $(date)
# Mode: ${FKS_MODE:-unknown}
# PID: $$
# Log Level: $LOG_LEVEL
# ==========================================

EOF
    fi
    
    log_debug "Logging system initialized (v$LOGGING_MODULE_VERSION)"
    log_debug "Log file: $FKS_LOG_FILE"
    log_debug "Log level: $LOG_LEVEL"
}

#=============================================================================
# EXPORT FUNCTIONS
#=============================================================================

export -f log_debug log_info log_warn log_error log_critical log_success
export -f log_header log_section log_step log_progress log_access log_performance
export -f log_and_exit log_command log_context log_structured
export -f log_system_info log_environment
export -f start_timer stop_timer
export -f show_log_summary show_recent_logs search_logs show_logging_config

# Initialize logging system
init_logging

echo "📦 logging system loaded (v$LOGGING_MODULE_VERSION)"