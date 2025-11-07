#!/bin/bash
# common.sh - Shared utilities for modular StackScript system
# This file is sourced by all other scripts

# Prevent multiple sourcing
if [[ -n "${_COMMON_UTILS_LOADED:-}" ]]; then
    return 0
fi
readonly _COMMON_UTILS_LOADED=1

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================
readonly LOG_DIR="${LOG_DIR:-/var/log/linode-setup}"
readonly CONFIG_DIR="${CONFIG_DIR:-/etc/nginx-automation}"
readonly SCRIPT_BASE_URL="${SCRIPT_BASE_URL:-https://raw.githubusercontent.com/nuniesmith/nginx/main/scripts}"

# Ensure directories exist
mkdir -p "$LOG_DIR" "$CONFIG_DIR"

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

log() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message" | tee -a "${LOG_DIR}/current.log"
}

success() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "${LOG_DIR}/current.log"
    send_notification "success" "$message"
}

error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message" | tee -a "${LOG_DIR}/current.log"
    send_notification "error" "$message"
}

warning() {
    local message="$1"
    echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "${LOG_DIR}/current.log"
    send_notification "warning" "$message"
}

info() {
    local message="$1"
    echo -e "${CYAN}[INFO]${NC} $message" | tee -a "${LOG_DIR}/current.log"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local message="$1"
        echo -e "${PURPLE}[DEBUG]${NC} $message" | tee -a "${LOG_DIR}/current.log"
    fi
}

# ============================================================================
# NOTIFICATION FUNCTIONS
# ============================================================================
send_notification() {
    local level="$1"
    local message="$2"
    local hostname=$(hostname)
    
    # Discord notification
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        send_discord_notification "$level" "$message" "$hostname"
    fi
    
    # Slack notification (if configured)
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        send_slack_notification "$level" "$message" "$hostname"
    fi
}

send_discord_notification() {
    local level="$1"
    local message="$2"
    local hostname="$3"
    
    local color
    case "$level" in
        success) color="3066993" ;;  # Green
        error) color="15158332" ;;   # Red
        warning) color="16776960" ;; # Yellow
        *) color="3447003" ;;        # Blue
    esac
    
    local emoji
    case "$level" in
        success) emoji="✅" ;;
        error) emoji="❌" ;;
        warning) emoji="⚠️" ;;
        *) emoji="ℹ️" ;;
    esac
    
    local payload=$(cat << EOF
{
    "embeds": [{
        "title": "$emoji StackScript - $hostname",
        "description": "$message",
        "color": $color,
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "footer": {
            "text": "7gram Dashboard Setup"
        }
    }]
}
EOF
)
    
    curl -s -H "Content-Type: application/json" \
        -d "$payload" \
        "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

send_slack_notification() {
    local level="$1"
    local message="$2"
    local hostname="$3"
    
    local color
    case "$level" in
        success) color="good" ;;
        error) color="danger" ;;
        warning) color="warning" ;;
        *) color="#36a64f" ;;
    esac
    
    local payload=$(cat << EOF
{
    "attachments": [{
        "color": "$color",
        "title": "StackScript Update - $hostname",
        "text": "$message",
        "ts": $(date +%s)
    }]
}
EOF
)
    
    curl -s -X POST -H 'Content-type: application/json' \
        --data "$payload" \
        "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================
validate_required_var() {
    local var_name="$1"
    local var_value="${!var_name:-}"
    
    if [[ -z "$var_value" ]]; then
        error "Required variable $var_name is not set"
        return 1
    fi
    
    debug "Validated required variable: $var_name"
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_domain() {
    local domain="$1"
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_email() {
    local email="$1"
    if [[ $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# FILE AND TEMPLATE FUNCTIONS
# ============================================================================
download_template() {
    local template_name="$1"
    local destination="$2"
    local template_url="${SCRIPT_BASE_URL}/templates/${template_name}"
    
    log "Downloading template: $template_name"
    
    local curl_args="-fsSL"
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        curl_args="$curl_args -H 'Authorization: token $GITHUB_TOKEN'"
    fi
    
    local retries=3
    for ((i=1; i<=retries; i++)); do
        if eval "curl $curl_args '$template_url' -o '$destination'"; then
            success "Downloaded template: $template_name"
            return 0
        else
            warning "Download attempt $i/$retries failed for $template_name"
            if [[ $i -eq $retries ]]; then
                error "Failed to download $template_name after $retries attempts"
                return 1
            fi
            sleep 2
        fi
    done
}

substitute_template() {
    local template_file="$1"
    local output_file="$2"
    
    if [[ ! -f "$template_file" ]]; then
        error "Template file not found: $template_file"
        return 1
    fi
    
    # Create backup if output file exists
    if [[ -f "$output_file" ]]; then
        cp "$output_file" "${output_file}.backup.$(date +%s)"
    fi
    
    # Substitute environment variables
    envsubst < "$template_file" > "$output_file"
    
    debug "Template substitution completed: $template_file -> $output_file"
}

backup_file() {
    local file_path="$1"
    local backup_suffix="${2:-$(date +%Y%m%d-%H%M%S)}"
    
    if [[ -f "$file_path" ]]; then
        local backup_path="${file_path}.backup.${backup_suffix}"
        cp "$file_path" "$backup_path"
        debug "Created backup: $file_path -> $backup_path"
        echo "$backup_path"
    fi
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================
ensure_service_stopped() {
    local service_name="$1"
    
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        log "Stopping service: $service_name"
        systemctl stop "$service_name"
    fi
}

ensure_service_started() {
    local service_name="$1"
    
    if ! systemctl is-active --quiet "$service_name" 2>/dev/null; then
        log "Starting service: $service_name"
        systemctl start "$service_name"
    fi
}

enable_and_start_service() {
    local service_name="$1"
    
    log "Enabling and starting service: $service_name"
    
    if systemctl enable "$service_name" && systemctl start "$service_name"; then
        success "Service enabled and started: $service_name"
        return 0
    else
        error "Failed to enable/start service: $service_name"
        return 1
    fi
}

check_service_health() {
    local service_name="$1"
    local timeout="${2:-30}"
    
    log "Checking health of service: $service_name"
    
    local end_time=$(($(date +%s) + timeout))
    
    while [[ $(date +%s) -lt $end_time ]]; do
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            success "Service is healthy: $service_name"
            return 0
        fi
        sleep 2
    done
    
    error "Service health check failed: $service_name"
    return 1
}

# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================
wait_for_connectivity() {
    local host="${1:-google.com}"
    local timeout="${2:-60}"
    
    log "Waiting for network connectivity to $host..."
    
    local end_time=$(($(date +%s) + timeout))
    
    while [[ $(date +%s) -lt $end_time ]]; do
        if ping -c 1 -W 5 "$host" >/dev/null 2>&1; then
            success "Network connectivity confirmed"
            return 0
        fi
        sleep 5
    done
    
    error "Network connectivity timeout"
    return 1
}

check_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-10}"
    
    if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

get_public_ip() {
    local ip
    # Try multiple services
    for service in ipinfo.io/ip ifconfig.me/ip icanhazip.com; do
        if ip=$(curl -s --max-time 10 "$service" 2>/dev/null) && validate_ip "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    
    warning "Could not determine public IP address"
    return 1
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================
save_completion_status() {
    local script_name="$1"
    local status="$2"
    local message="${3:-}"
    
    local status_file="$CONFIG_DIR/completion-status.json"
    
    # Initialize status file if it doesn't exist
    if [[ ! -f "$status_file" ]]; then
        echo '{}' > "$status_file"
    fi
    
    # Update status
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq --arg script "$script_name" \
       --arg status "$status" \
       --arg timestamp "$timestamp" \
       --arg message "$message" \
       '.[$script] = {status: $status, timestamp: $timestamp, message: $message}' \
       "$status_file" > "${status_file}.tmp" && mv "${status_file}.tmp" "$status_file"
    
    debug "Saved completion status for $script_name: $status"
}

get_completion_status() {
    local script_name="$1"
    local status_file="$CONFIG_DIR/completion-status.json"
    
    if [[ -f "$status_file" ]]; then
        jq -r --arg script "$script_name" '.[$script].status // "not_started"' "$status_file"
    else
        echo "not_started"
    fi
}

load_config() {
    local config_file="$CONFIG_DIR/deployment-config.json"
    
    if [[ -f "$config_file" ]]; then
        # Export configuration as environment variables
        while IFS='=' read -r key value; do
            if [[ -n "$key" && -n "$value" ]]; then
                export "$key=$value"
                debug "Loaded config: $key=$value"
            fi
        done < <(jq -r 'to_entries[] | "\(.key)=\(.value)"' "$config_file" 2>/dev/null || true)
    fi
}

save_config_value() {
    local key="$1"
    local value="$2"
    local config_file="$CONFIG_DIR/deployment-config.json"
    
    # Initialize config file if it doesn't exist
    if [[ ! -f "$config_file" ]]; then
        echo '{}' > "$config_file"
    fi
    
    # Update configuration
    jq --arg key "$key" --arg value "$value" '.[$key] = $value' \
       "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
    
    debug "Saved config: $key=$value"
}

# ============================================================================
# RETRY AND ERROR HANDLING
# ============================================================================
retry_command() {
    local max_attempts="$1"
    local delay="$2"
    shift 2
    local command=("$@")
    
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if "${command[@]}"; then
            return 0
        else
            if [[ $attempt -eq $max_attempts ]]; then
                error "Command failed after $max_attempts attempts: ${command[*]}"
                return 1
            else
                warning "Command failed (attempt $attempt/$max_attempts): ${command[*]}"
                sleep "$delay"
                ((attempt++))
            fi
        fi
    done
}

with_timeout() {
    local timeout="$1"
    shift
    
    timeout "$timeout" "$@"
}

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================
get_system_info() {
    cat << EOF
{
    "hostname": "$(hostname)",
    "os": "$(lsb_release -ds 2>/dev/null || echo 'Unknown')",
    "kernel": "$(uname -r)",
    "memory": "$(free -h | awk '/^Mem:/ {print $2}')",
    "disk": "$(df -h / | awk 'NR==2 {print $2}')",
    "cpu": "$(nproc) cores",
    "uptime": "$(uptime -p)",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# ============================================================================
# INITIALIZATION
# ============================================================================
# Set up error handling for scripts that source this file
set -euo pipefail

# Create log file for current session
touch "${LOG_DIR}/current.log"

debug "Common utilities loaded successfully"