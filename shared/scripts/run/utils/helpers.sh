#!/bin/bash
# filepath: fks/scripts/utils/helpers.sh
# FKS Trading Systems - Helper Utilities Module
# Common utility functions used throughout the system

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Prevent multiple sourcing
[[ -n "${FKS_UTILS_HELPERS_LOADED:-}" ]] && return 0
readonly FKS_UTILS_HELPERS_LOADED=1

# Module metadata
readonly HELPERS_MODULE_VERSION="3.1.0"
readonly HELPERS_MODULE_LOADED="$(date +%s)"

# Get script directory (avoid readonly conflicts)
if [[ -z "${HELPERS_SCRIPT_DIR:-}" ]]; then
    readonly HELPERS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Source dependencies with fallback
if [[ -f "$HELPERS_SCRIPT_DIR/../core/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$HELPERS_SCRIPT_DIR/../core/logging.sh"
elif [[ -f "$(dirname "$HELPERS_SCRIPT_DIR")/core/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$(dirname "$HELPERS_SCRIPT_DIR")/core/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[INFO] $*"; }
    log_warn() { echo "[WARN] $*"; }
    log_error() { echo "[ERROR] $*" >&2; }
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo "[DEBUG] $*" >&2; }
    log_success() { echo "[SUCCESS] $*"; }
fi

# =============================================================================
# STRING UTILITIES
# =============================================================================

# Check if string is empty or whitespace only
is_empty() {
    local str="$1"
    [[ -z "${str// }" ]]
}

# Check if string is not empty
is_not_empty() {
    local str="$1"
    [[ -n "${str// }" ]]
}

# Trim whitespace from string
trim() {
    local str="$1"
    # Remove leading whitespace
    str="${str#"${str%%[![:space:]]*}"}"
    # Remove trailing whitespace  
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

# Trim only leading whitespace
ltrim() {
    local str="$1"
    str="${str#"${str%%[![:space:]]*}"}"
    echo "$str"
}

# Trim only trailing whitespace
rtrim() {
    local str="$1"
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

# Convert string to lowercase/uppercase
to_lower() { echo "${1,,}"; }
to_upper() { echo "${1^^}"; }

# Legacy aliases for compatibility
to_lowercase() { to_lower "$1"; }
to_uppercase() { to_upper "$1"; }

# String checking functions
contains() {
    local haystack="$1" needle="$2"
    [[ "$haystack" == *"$needle"* ]]
}

starts_with() {
    local string="$1" prefix="$2"
    [[ "$string" == "$prefix"* ]]
}

ends_with() {
    local string="$1" suffix="$2"
    [[ "$string" == *"$suffix" ]]
}

# Case-insensitive string functions
contains_ci() {
    local haystack="$1" needle="$2"
    [[ "${haystack,,}" == *"${needle,,}"* ]]
}

starts_with_ci() {
    local string="$1" prefix="$2"
    [[ "${string,,}" == "${prefix,,}"* ]]
}

ends_with_ci() {
    local string="$1" suffix="$2"
    [[ "${string,,}" == *"${suffix,,}" ]]
}

# Split string by delimiter into array
split_string() {
    local string="$1" delimiter="${2:-,}"
    local -n result_array=$3
    
    # Clear the array first
    result_array=()
    
    # Handle empty string
    if [[ -z "$string" ]]; then
        return 0
    fi
    
    # Use IFS to split
    local old_ifs="$IFS"
    IFS="$delimiter" read -ra result_array <<< "$string"
    IFS="$old_ifs"
}

# Join array elements with delimiter
join_array() {
    local delimiter="$1"
    shift
    
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    
    local first="$1"
    shift
    printf "%s" "$first" "${@/#/$delimiter}"
}

# Generate random string
generate_random_string() {
    local length="${1:-8}" chars="${2:-a-zA-Z0-9}"
    
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-"$length"
    elif command -v /dev/urandom >/dev/null 2>&1; then
        tr -dc "$chars" < /dev/urandom | head -c"$length"
    else
        # Fallback using RANDOM
        local result=""
        local charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for ((i=0; i<length; i++)); do
            result+="${charset:$((RANDOM % ${#charset})):1}"
        done
        echo "$result"
    fi
}

# URL encode/decode functions
url_encode() {
    local string="$1"
    local length="${#string}"
    local char
    
    for ((i = 0; i < length; i++)); do
        char="${string:$i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-]) printf '%s' "$char" ;;
            *) printf '%%%02X' "'$char" ;;
        esac
    done
}

url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

# =============================================================================
# ARRAY UTILITIES
# =============================================================================

# Check if array contains element
array_contains() {
    local element="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$element" ]] && return 0
    done
    return 1
}

# Join array elements with delimiter (legacy alias)
array_join() { join_array "$@"; }

# Get array length (works with array reference)
array_length() {
    local -n arr_ref=$1
    echo "${#arr_ref[@]}"
}

# Remove element from array
array_remove() {
    local element="$1"
    local -n arr_ref=$2
    local new_array=()
    
    for item in "${arr_ref[@]}"; do
        [[ "$item" != "$element" ]] && new_array+=("$item")
    done
    
    arr_ref=("${new_array[@]}")
}

# Sort array
array_sort() {
    local -n arr_ref=$1
    local reverse="${2:-false}"
    
    if [[ "$reverse" == "true" ]]; then
        readarray -t arr_ref < <(printf '%s\n' "${arr_ref[@]}" | sort -r)
    else
        readarray -t arr_ref < <(printf '%s\n' "${arr_ref[@]}" | sort)
    fi
}

# Get unique elements from array
array_unique() {
    local -n arr_ref=$1
    readarray -t arr_ref < <(printf '%s\n' "${arr_ref[@]}" | sort -u)
}

# =============================================================================
# FILE SYSTEM UTILITIES
# =============================================================================

# File existence and permission checks
is_readable_file() { [[ -f "$1" && -r "$1" ]]; }
is_writable_file() { [[ -f "$1" && -w "$1" ]]; }
is_executable_file() { [[ -f "$1" && -x "$1" ]]; }
is_readable_dir() { [[ -d "$1" && -r "$1" ]]; }
is_writable_dir() { [[ -d "$1" && -w "$1" ]]; }
is_empty_dir() { [[ -d "$1" && -z "$(ls -A "$1" 2>/dev/null)" ]]; }

# Create directory with proper error handling
ensure_directory() {
    local dir="$1" mode="${2:-755}"
    
    if [[ -z "$dir" ]]; then
        log_error "Directory path cannot be empty"
        return 1
    fi
    
    if [[ ! -d "$dir" ]]; then
        if mkdir -p "$dir" 2>/dev/null; then
            chmod "$mode" "$dir" 2>/dev/null || true
            log_debug "Created directory: $dir"
        else
            log_error "Failed to create directory: $dir"
            return 1
        fi
    elif [[ ! -w "$dir" ]]; then
        log_error "Directory exists but is not writable: $dir"
        return 1
    fi
    
    return 0
}

# Create file with directory structure
ensure_file() {
    local file="$1" mode="${2:-644}"
    local dir
    dir="$(dirname "$file")"
    
    ensure_directory "$dir" || return 1
    
    if [[ ! -f "$file" ]]; then
        touch "$file" 2>/dev/null || {
            log_error "Failed to create file: $file"
            return 1
        }
        chmod "$mode" "$file" 2>/dev/null || true
        log_debug "Created file: $file"
    fi
    
    return 0
}

# Backup file with timestamp
backup_file() {
    local file="$1" backup_dir="${2:-$(dirname "$file")}"
    
    if [[ ! -f "$file" ]]; then
        log_error "File not found for backup: $file"
        return 1
    fi
    
    ensure_directory "$backup_dir" || return 1
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/$(basename "$file").backup.$timestamp"
    
    if cp "$file" "$backup_file" 2>/dev/null; then
        log_debug "Created backup: $backup_file"
        echo "$backup_file"
        return 0
    else
        log_error "Failed to create backup of: $file"
        return 1
    fi
}

# Safe file removal with confirmation
safe_remove() {
    local target="$1" confirm="${2:-true}"
    
    if [[ ! -e "$target" ]]; then
        log_warn "Target does not exist: $target"
        return 1
    fi
    
    if [[ "$confirm" == "true" ]]; then
        if ! ask_yes_no "Remove $target?" "n"; then
            log_info "Removal cancelled"
            return 1
        fi
    fi
    
    if [[ -d "$target" ]]; then
        if rm -rf "$target" 2>/dev/null; then
            log_debug "Removed directory: $target"
        else
            log_error "Failed to remove directory: $target"
            return 1
        fi
    else
        if rm -f "$target" 2>/dev/null; then
            log_debug "Removed file: $target"
        else
            log_error "Failed to remove file: $target"
            return 1
        fi
    fi
    
    return 0
}

# Get file size (cross-platform)
get_file_size() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        echo "0"
        return 1
    fi
    
    if command -v stat >/dev/null 2>&1; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            stat -f%z "$file" 2>/dev/null || echo "0"
        else
            stat -c%s "$file" 2>/dev/null || echo "0"
        fi
    elif command -v wc >/dev/null 2>&1; then
        wc -c < "$file" 2>/dev/null | tr -d ' ' || echo "0"
    else
        echo "0"
    fi
}

# Get human readable file size
human_readable_size() {
    local size="$1"
    local units=("B" "KB" "MB" "GB" "TB" "PB")
    local unit_index=0
    local decimal_size="$size"
    
    while (( $(echo "$decimal_size >= 1024" | bc -l 2>/dev/null || echo "$decimal_size -ge 1024" | awk '{print ($1 >= $2)}') )) && [[ $unit_index -lt $((${#units[@]} - 1)) ]]; do
        if command -v bc >/dev/null 2>&1; then
            decimal_size=$(echo "scale=1; $decimal_size / 1024" | bc)
        else
            decimal_size=$((decimal_size / 1024))
        fi
        ((unit_index++))
    done
    
    # Format with appropriate precision
    if command -v bc >/dev/null 2>&1 && [[ $unit_index -gt 0 ]]; then
        printf "%.1f%s\n" "$decimal_size" "${units[$unit_index]}"
    else
        printf "%d%s\n" "$decimal_size" "${units[$unit_index]}"
    fi
}

# Get file modification time
get_file_mtime() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        echo "0"
        return 1
    fi
    
    if command -v stat >/dev/null 2>&1; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            stat -f %m "$file" 2>/dev/null || echo "0"
        else
            stat -c %Y "$file" 2>/dev/null || echo "0"
        fi
    else
        echo "0"
    fi
}

# Find files by pattern with enhanced options
find_files() {
    local directory="$1" pattern="$2" max_depth="${3:-3}" file_type="${4:-f}"
    
    if [[ ! -d "$directory" ]]; then
        log_error "Directory not found: $directory"
        return 1
    fi
    
    find "$directory" -maxdepth "$max_depth" -name "$pattern" -type "$file_type" 2>/dev/null
}

# Count files in directory
count_files() {
    local directory="$1" pattern="${2:-*}"
    
    if [[ ! -d "$directory" ]]; then
        echo "0"
        return 1
    fi
    
    find "$directory" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | wc -l
}

# =============================================================================
# PROCESS UTILITIES
# =============================================================================

# Check if process is running (by PID or name)
is_process_running() {
    local identifier="$1"
    
    if [[ -z "$identifier" ]]; then
        return 1
    fi
    
    if [[ "$identifier" =~ ^[0-9]+$ ]]; then
        # Numeric - treat as PID
        kill -0 "$identifier" 2>/dev/null
    else
        # String - treat as process name
        pgrep -f "$identifier" >/dev/null 2>&1
    fi
}

# Get process PID by name
get_process_pid() {
    local process_name="$1"
    
    if [[ -z "$process_name" ]]; then
        return 1
    fi
    
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$process_name" | head -n 1
    else
        ps aux 2>/dev/null | grep "$process_name" | grep -v grep | awk '{print $2}' | head -n 1
    fi
}

# Get all PIDs for a process name
get_all_process_pids() {
    local process_name="$1"
    
    if [[ -z "$process_name" ]]; then
        return 1
    fi
    
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$process_name"
    else
        ps aux 2>/dev/null | grep "$process_name" | grep -v grep | awk '{print $2}'
    fi
}

# Kill process by name with signal
kill_process_by_name() {
    local process_name="$1" signal="${2:-TERM}" timeout="${3:-10}"
    
    if [[ -z "$process_name" ]]; then
        log_error "Process name cannot be empty"
        return 1
    fi
    
    local pids
    pids=$(get_all_process_pids "$process_name")
    
    if [[ -z "$pids" ]]; then
        log_debug "No processes found matching: $process_name"
        return 1
    fi
    
    log_debug "Sending $signal signal to processes: $pids"
    
    # Send signal to all matching processes
    echo "$pids" | while read -r pid; do
        [[ -n "$pid" ]] && kill -"$signal" "$pid" 2>/dev/null
    done
    
    # Wait for processes to exit if using TERM signal
    if [[ "$signal" == "TERM" ]] && [[ $timeout -gt 0 ]]; then
        local count=0
        while [[ $count -lt $timeout ]]; do
            if ! is_process_running "$process_name"; then
                log_debug "Process '$process_name' terminated successfully"
                return 0
            fi
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        log_warn "Process '$process_name' did not exit gracefully, sending KILL signal"
        kill_process_by_name "$process_name" "KILL" 0
    fi
    
    return 0
}

# Kill process gracefully with timeout
kill_process_gracefully() {
    local pid="$1" timeout="${2:-30}"
    
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
        log_error "Invalid PID: $pid"
        return 1
    fi
    
    if ! is_process_running "$pid"; then
        log_debug "Process $pid is not running"
        return 0
    fi
    
    log_debug "Sending TERM signal to process $pid"
    kill -TERM "$pid" 2>/dev/null || {
        log_error "Failed to send TERM signal to process $pid"
        return 1
    }
    
    # Wait for graceful shutdown
    local count=0
    while [[ $count -lt $timeout ]] && is_process_running "$pid"; do
        sleep 1
        ((count++))
    done
    
    if is_process_running "$pid"; then
        log_warn "Process $pid did not exit gracefully, sending KILL signal"
        kill -KILL "$pid" 2>/dev/null
        sleep 2
        
        if is_process_running "$pid"; then
            log_error "Failed to kill process $pid"
            return 1
        fi
    fi
    
    log_debug "Process $pid terminated successfully"
    return 0
}

# Wait for process to start
wait_for_process() {
    local process_name="$1" timeout="${2:-30}" interval="${3:-1}"
    
    if [[ -z "$process_name" ]]; then
        log_error "Process name cannot be empty"
        return 1
    fi
    
    log_debug "Waiting for process '$process_name' to start..."
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if is_process_running "$process_name"; then
            log_debug "Process '$process_name' is now running"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    log_error "Timeout waiting for process '$process_name' to start"
    return 1
}

# Get process information
get_process_info() {
    local pid="$1" info_type="${2:-cmd}"
    
    if [[ ! "$pid" =~ ^[0-9]+$ ]] || ! is_process_running "$pid"; then
        return 1
    fi
    
    case "$info_type" in
        "cmd"|"command")
            ps -p "$pid" -o cmd= 2>/dev/null | trim
            ;;
        "user")
            ps -p "$pid" -o user= 2>/dev/null | trim
            ;;
        "cpu")
            ps -p "$pid" -o %cpu= 2>/dev/null | trim
            ;;
        "mem"|"memory")
            ps -p "$pid" -o %mem= 2>/dev/null | trim
            ;;
        "rss")
            ps -p "$pid" -o rss= 2>/dev/null | trim
            ;;
        "start")
            ps -p "$pid" -o lstart= 2>/dev/null | trim
            ;;
        *)
            ps -p "$pid" -o "$info_type"= 2>/dev/null | trim
            ;;
    esac
}

# =============================================================================
# NETWORK UTILITIES
# =============================================================================

# Check if port is open with improved reliability
check_port() {
    local host="${1:-localhost}" port="$2" timeout="${3:-5}"
    
    if [[ -z "$port" ]] || ! is_valid_port "$port"; then
        log_error "Invalid port: $port"
        return 1
    fi
    
    # Try multiple methods for better compatibility
    if command -v nc >/dev/null 2>&1; then
        # netcat method (most reliable)
        if nc -z -w"$timeout" "$host" "$port" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # Bash TCP method (fallback)
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && return 0
    else
        (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && { exec 3<&-; return 0; }
    fi
    
    return 1
}

# Alias for consistency
is_port_open() { check_port "$@"; }

# Wait for port to become available
wait_for_port() {
    local host="${1:-localhost}" port="$2" timeout="${3:-60}" interval="${4:-2}"
    
    if [[ -z "$port" ]]; then
        log_error "Port must be specified"
        return 1
    fi
    
    log_debug "Waiting for $host:$port to be available (timeout: ${timeout}s)..."
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if check_port "$host" "$port" 1; then
            log_debug "Port $host:$port is available"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
        
        # Show progress for long waits
        if [[ $timeout -gt 30 ]] && [[ $((elapsed % 10)) -eq 0 ]]; then
            log_debug "Still waiting for $host:$port (${elapsed}s elapsed)..."
        fi
    done
    
    log_error "Timeout waiting for $host:$port (waited ${elapsed}s)"
    return 1
}

# Get next available port
get_free_port() {
    local start_port="${1:-8000}" max_attempts="${2:-100}"
    
    if ! is_valid_port "$start_port"; then
        log_error "Invalid start port: $start_port"
        return 1
    fi
    
    for ((i=0; i<max_attempts; i++)); do
        local port=$((start_port + i))
        if [[ $port -gt 65535 ]]; then
            log_error "Port range exceeded"
            return 1
        fi
        
        if ! check_port "localhost" "$port" 1; then
            echo "$port"
            return 0
        fi
    done
    
    log_error "No free port found in range $start_port-$((start_port + max_attempts - 1))"
    return 1
}

# Get local IP address with better detection
get_local_ip() {
    local interface="${1:-}"
    
    if [[ -n "$interface" ]]; then
        # Get IP for specific interface
        if command -v ip >/dev/null 2>&1; then
            ip addr show "$interface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -n 1
        elif command -v ifconfig >/dev/null 2>&1; then
            ifconfig "$interface" 2>/dev/null | grep -oP 'inet \K[\d.]+'
        fi
    else
        # Get primary IP address
        if command -v ip >/dev/null 2>&1; then
            # Linux method
            ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -n 1
        elif command -v route >/dev/null 2>&1 && [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS method
            route get default 2>/dev/null | grep interface: | awk '{print $2}' | head -n 1 | xargs ifconfig 2>/dev/null | grep -oP 'inet \K[\d.]+'
        elif command -v hostname >/dev/null 2>&1; then
            # Fallback method
            hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
        else
            echo "127.0.0.1"
        fi
    fi
}

# Get all network interfaces
get_network_interfaces() {
    if command -v ip >/dev/null 2>&1; then
        ip link show 2>/dev/null | grep -E "^[0-9]+" | awk -F': ' '{print $2}' | grep -v lo
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig 2>/dev/null | grep -E "^[a-zA-Z]" | awk '{print $1}' | sed 's/:$//' | grep -v lo
    else
        echo "eth0"  # Default fallback
    fi
}

# Test internet connectivity
test_internet_connectivity() {
    local timeout="${1:-5}"
    local test_hosts=("8.8.8.8" "1.1.1.1" "google.com")
    
    for host in "${test_hosts[@]}"; do
        if command -v ping >/dev/null 2>&1; then
            if ping -c 1 -W "$timeout" "$host" >/dev/null 2>&1; then
                return 0
            fi
        elif command -v curl >/dev/null 2>&1; then
            if curl -s --max-time "$timeout" --connect-timeout "$timeout" "http://$host" >/dev/null 2>&1; then
                return 0
            fi
        fi
    done
    
    return 1
}

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================

# Email validation with improved regex
is_valid_email() {
    local email="$1"
    local email_regex='^[a-zA-Z0-9.!#$%&'\''*+/=?^_`{|}~-]+@[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    [[ "$email" =~ $email_regex ]]
}

# URL validation with improved support
is_valid_url() {
    local url="$1"
    [[ "$url" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?)*([:/][^[:space:]]*)?$ ]]
}

# IP address validation (IPv4)
is_valid_ip() {
    local ip="$1"
    local IFS='.'
    local -a octets=($ip)
    
    [[ ${#octets[@]} -eq 4 ]] || return 1
    
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] && [[ $octet -ge 0 && $octet -le 255 ]] || return 1
    done
    
    return 0
}

# IPv6 validation
is_valid_ipv6() {
    local ipv6="$1"
    # Simplified IPv6 validation
    [[ "$ipv6" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || [[ "$ipv6" == "::1" ]]
}

# Port number validation
is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [[ $port -ge 1 && $port -le 65535 ]]
}

# Domain name validation
is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

# Path validation (more permissive)
is_valid_path() {
    local path="$1"
    # Allow more characters in paths
    [[ "$path" =~ ^[a-zA-Z0-9._/~-]+$ ]]
}

# Validate JSON string
is_valid_json() {
    local json_string="$1"
    
    if command -v jq >/dev/null 2>&1; then
        echo "$json_string" | jq empty >/dev/null 2>&1
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import json; json.loads('''$json_string''')" >/dev/null 2>&1
    else
        # Basic validation - just check for balanced braces
        local open_braces=$(echo "$json_string" | tr -cd '{' | wc -c)
        local close_braces=$(echo "$json_string" | tr -cd '}' | wc -c)
        [[ $open_braces -eq $close_braces ]]
    fi
}

# =============================================================================
# SYSTEM UTILITIES
# =============================================================================

# Get various system information with enhanced error handling
get_system_info() {
    local info_type="$1"
    
    case "$info_type" in
        "os") 
            uname -s 2>/dev/null || echo "Unknown" 
            ;;
        "arch"|"architecture") 
            uname -m 2>/dev/null || echo "Unknown" 
            ;;
        "kernel") 
            uname -r 2>/dev/null || echo "Unknown" 
            ;;
        "hostname") 
            hostname 2>/dev/null || echo "Unknown" 
            ;;
        "uptime") 
            if command -v uptime >/dev/null 2>&1; then
                uptime 2>/dev/null | awk '{print $3,$4}' | sed 's/,//' || echo "Unknown"
            else
                echo "Unknown"
            fi
            ;;
        "load") 
            if command -v uptime >/dev/null 2>&1; then
                uptime 2>/dev/null | awk -F'load average:' '{print $2}' | trim || echo "Unknown"
            else
                echo "Unknown"
            fi
            ;;
        "memory"|"mem")
            if command -v free >/dev/null 2>&1; then
                free -h 2>/dev/null | awk 'NR==2{printf "Used: %s/%s (%.1f%%)", $3,$2,$3/$2*100}' || echo "Unknown"
            else
                echo "Unknown"
            fi 
            ;;
        "disk") 
            df -h . 2>/dev/null | awk 'NR==2{printf "Used: %s/%s (%s)", $3,$2,$5}' || echo "Unknown" 
            ;;
        "cpu_count")
            if command -v nproc >/dev/null 2>&1; then
                nproc 2>/dev/null || echo "Unknown"
            elif [[ -f /proc/cpuinfo ]]; then
                grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "Unknown"
            else
                echo "Unknown"
            fi
            ;;
        "distribution"|"distro")
            if [[ -f /etc/os-release ]]; then
                grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Unknown"
            elif [[ "$OSTYPE" == "darwin"* ]] && command -v sw_vers >/dev/null 2>&1; then
                sw_vers -productName 2>/dev/null || echo "macOS"
            else
                echo "Unknown"
            fi
            ;;
        *) 
            echo "Unknown info type: $info_type"
            return 1 
            ;;
    esac
}

# System state checks
is_root() { [[ $EUID -eq 0 ]]; }
is_container() { [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || [[ -n "${container:-}" ]]; }
is_ssh_session() { [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]]; }
is_wsl() { [[ -f /proc/version ]] && grep -q "Microsoft\|WSL" /proc/version 2>/dev/null; }
is_macos() { [[ "$OSTYPE" == "darwin"* ]]; }
is_linux() { [[ "$OSTYPE" == "linux-gnu"* ]]; }

# Get current user info
get_current_user() { echo "${USER:-${USERNAME:-$(whoami 2>/dev/null || echo "unknown")}}"; }
get_user_home() { echo "${HOME:-$(eval echo ~$(get_current_user) 2>/dev/null || echo "/tmp")}"; }

# =============================================================================
# INTERACTIVE UTILITIES
# =============================================================================

# Ask yes/no question with default and timeout
ask_yes_no() {
    local question="$1" default="${2:-n}" timeout="${3:-0}"
    
    # Handle non-interactive environments
    if [[ ! -t 0 ]]; then
        echo "$default"
        case "$default" in
            [Yy]*) return 0 ;;
            *) return 1 ;;
        esac
    fi
    
    local prompt="$question"
    case "$default" in
        [Yy]*) prompt="$prompt (Y/n): " ;;
        [Nn]*) prompt="$prompt (y/N): " ;;
        *) prompt="$prompt (y/n): " ;;
    esac
    
    local answer
    if [[ $timeout -gt 0 ]]; then
        if read -r -t "$timeout" -p "$prompt" answer 2>/dev/null; then
            echo ""
        else
            echo ""
            log_debug "Question timed out, using default: $default"
            answer="$default"
        fi
    else
        read -r -p "$prompt" answer
    fi
    
    [[ -z "$answer" ]] && answer="$default"
    
    case "$answer" in
        [Yy]*) return 0 ;;
        [Nn]*) return 1 ;;
        *) 
            log_warn "Invalid answer: $answer"
            ask_yes_no "$question" "$default" "$timeout"
            ;;
    esac
}

# Progress bar display with enhanced features
show_progress() {
    local current="$1" total="$2" width="${3:-50}" char="${4:-#}" label="${5:-}"
    
    if [[ $total -eq 0 ]]; then
        total=1  # Prevent division by zero
    fi
    
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    # Build progress bar
    printf "\r"
    [[ -n "$label" ]] && printf "%s: " "$label"
    printf "["
    printf "%*s" $filled "" | tr ' ' "$char"
    printf "%*s" $empty ""
    printf "] %3d%% (%d/%d)" $percentage $current $total
    
    # New line when complete
    [[ $current -eq $total ]] && echo ""
}

# Simple spinner for long operations
show_spinner() {
    local pid="$1" message="${2:-Working...}"
    local spinchars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    local i=0
    
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r%s %c" "$message" "${spinchars:$((i++ % ${#spinchars})):1}"
        sleep 0.1
    done
    
    printf "\r%s Done!\n" "$message"
}

# =============================================================================
# CONFIGURATION UTILITIES
# =============================================================================

# Read configuration value from file with enhanced parsing
read_config() {
    local config_file="$1" key="$2" default_value="${3:-}"
    
    if [[ ! -f "$config_file" ]]; then
        echo "$default_value"
        return 1
    fi
    
    local value
    # Support different formats: key=value, key="value", key: value
    if value=$(grep -E "^${key}[[:space:]]*[=:]" "$config_file" 2>/dev/null | head -1); then
        # Extract value after = or :
        value=$(echo "$value" | sed -E "s/^${key}[[:space:]]*[=:][[:space:]]*//" | sed 's/^["'\'']*//;s/["'\'']*$//')
        echo "${value:-$default_value}"
    else
        echo "$default_value"
        return 1
    fi
}

# Write configuration value to file
write_config() {
    local config_file="$1" key="$2" value="$3"
    
    if [[ -z "$config_file" || -z "$key" ]]; then
        log_error "Config file and key must be specified"
        return 1
    fi
    
    ensure_directory "$(dirname "$config_file")" || return 1
    
    if [[ -f "$config_file" ]]; then
        # Update existing key or add new one
        if grep -q "^${key}[[:space:]]*=" "$config_file" 2>/dev/null; then
            # Use different sed syntax for better compatibility
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sed -i '' "s|^${key}[[:space:]]*=.*|${key}=\"${value}\"|" "$config_file"
            else
                sed -i "s|^${key}[[:space:]]*=.*|${key}=\"${value}\"|" "$config_file"
            fi
        else
            echo "${key}=\"${value}\"" >> "$config_file"
        fi
    else
        echo "${key}=\"${value}\"" > "$config_file"
    fi
}

# Read entire config file into associative array
read_config_file() {
    local config_file="$1"
    local -n config_array=$2
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Config file not found: $config_file"
        return 1
    fi
    
    config_array=()
    
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        
        # Clean up key and value
        key=$(echo "$key" | trim)
        value=$(echo "$value" | sed 's/^["'\'']*//;s/["'\'']*$//' | trim)
        
        config_array["$key"]="$value"
    done < "$config_file"
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Retry with exponential backoff and enhanced logging
retry_with_backoff() {
    local max_attempts="$1" initial_delay="$2"
    shift 2
    local command=("$@")
    
    if [[ $max_attempts -le 0 ]]; then
        log_error "Max attempts must be greater than 0"
        return 1
    fi
    
    local attempt=1
    local delay="$initial_delay"
    
    while [[ $attempt -le $max_attempts ]]; do
        log_debug "Attempt $attempt/$max_attempts: ${command[*]}"
        
        if "${command[@]}"; then
            log_debug "Command succeeded on attempt $attempt"
            return 0
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Command failed after $max_attempts attempts: ${command[*]}"
            return 1
        fi
        
        log_debug "Attempt $attempt failed, waiting ${delay}s before retry..."
        sleep "$delay"
        
        # Exponential backoff with jitter
        delay=$((delay * 2))
        # Add some randomness to prevent thundering herd
        if command -v shuf >/dev/null 2>&1; then
            local jitter=$((RANDOM % 5))
            delay=$((delay + jitter))
        fi
        
        ((attempt++))
    done
}

# Execute with timeout and better error handling
execute_with_timeout() {
    local timeout_duration="$1"
    shift
    local command=("$@")
    
    if [[ -z "$timeout_duration" ]]; then
        log_error "Timeout duration must be specified"
        return 1
    fi
    
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_duration" "${command[@]}"
        local exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            log_error "Command timed out after ${timeout_duration}s: ${command[*]}"
        fi
        
        return $exit_code
    else
        log_warn "timeout command not available, executing without timeout"
        "${command[@]}"
    fi
}

# Version comparison with better parsing
version_compare() {
    local version1="$1" version2="$2"
    
    if [[ "$version1" == "$version2" ]]; then
        return 0
    fi
    
    # Remove any non-numeric prefixes (like 'v')
    version1=${version1#v}
    version2=${version2#v}
    
    local IFS='.'
    local i ver1=($version1) ver2=($version2)
    
    # Normalize arrays to same length
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do 
        ver1[i]=0
    done
    for ((i=${#ver2[@]}; i<${#ver1[@]}; i++)); do 
        ver2[i]=0
    done
    
    # Compare each part
    for ((i=0; i<${#ver1[@]}; i++)); do
        # Remove any non-numeric suffixes (like 'rc1', 'beta')
        local num1=${ver1[i]//[^0-9]/}
        local num2=${ver2[i]//[^0-9]/}
        
        # Default to 0 if empty
        num1=${num1:-0}
        num2=${num2:-0}
        
        if ((10#$num1 > 10#$num2)); then 
            return 1  # version1 > version2
        elif ((10#$num1 < 10#$num2)); then 
            return 2  # version1 < version2
        fi
    done
    
    return 0  # versions are equal
}

# utility checks
command_exists() { command -v "$1" >/dev/null 2>&1; }

# Get script directory with better error handling
get_script_directory() { 
    local script_path="${1:-${BASH_SOURCE[1]}}"
    if [[ -n "$script_path" ]]; then
        cd "$(dirname "$script_path")" && pwd
    else
        pwd
    fi
}

# Get absolute path
get_absolute_path() {
    local path="$1"
    
    if [[ -z "$path" ]]; then
        return 1
    fi
    
    if [[ "$path" = /* ]]; then
        # Already absolute
        echo "$path"
    else
        # Make relative path absolute
        echo "$(pwd)/$path"
    fi
}

# =============================================================================
# CLEANUP AND SIGNAL HANDLING
# =============================================================================

# Clean up temporary files
cleanup_temp_files() {
    local temp_pattern="${1:-/tmp/fks_*}"
    local max_age_hours="${2:-24}"
    
    if command -v find >/dev/null 2>&1; then
        find /tmp -name "$(basename "$temp_pattern")" -type f -mtime +0 -delete 2>/dev/null || true
    fi
}

# Setup signal handlers for cleanup
setup_cleanup_handler() {
    local cleanup_function="$1"
    
    if [[ -n "$cleanup_function" ]] && declare -F "$cleanup_function" >/dev/null; then
        trap "$cleanup_function" EXIT
        trap "$cleanup_function" INT
        trap "$cleanup_function" TERM
    fi
}

# =============================================================================
# MODULE INITIALIZATION
# =============================================================================

# Export commonly used functions
export -f is_empty is_not_empty trim contains starts_with ends_with
export -f array_contains join_array ensure_directory backup_file
export -f is_process_running get_process_pid kill_process_gracefully
export -f check_port wait_for_port get_free_port
export -f is_valid_email is_valid_url is_valid_ip is_valid_port
export -f ask_yes_no show_progress command_exists version_compare

log_debug "📦 Loaded helpers utility module (v$HELPERS_MODULE_VERSION)"