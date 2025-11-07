#!/bin/bash
# filepath: scripts/core/mode_detection.sh
# FKS Trading Systems - Mode Detection Module
# Handles automatic detection and configuration of operating modes

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly MODE_DETECTION_MODULE_VERSION="2.5.0"
readonly MODE_DETECTION_MODULE_LOADED="$(date +%s)"

# === MODE CONFIGURATION ===
# Detect and set operating mode: development or server
readonly MODE_AUTO_DETECT="${FKS_MODE_AUTO_DETECT:-true}"
readonly DEFAULT_MODE="${FKS_DEFAULT_MODE:-auto}"

# Mode detection variables
FKS_MODE=""
FKS_MODE_DETECTED=""
FKS_MODE_REASON=""

# === MODE DETECTION AND SETUP ===

# Detect operating mode based on environment
detect_operating_mode() {
    log_debug "Detecting operating mode..."
    
    # Check for explicit mode setting
    if [[ -n "${FKS_MODE:-}" ]]; then
        FKS_MODE_DETECTED="$FKS_MODE"
        FKS_MODE_REASON="Environment variable FKS_MODE"
        log_debug "Mode set via environment: $FKS_MODE_DETECTED"
        return 0
    fi
    
    # Auto-detection logic
    local indicators_server=0
    local indicators_dev=0
    local detection_reasons=()
    
    # Check for server indicators
    if [[ -n "${DOCKER_HOST:-}" ]] || [[ -S "/var/run/docker.sock" ]]; then
        ((indicators_server++))
        detection_reasons+=("Docker available")
    fi
    
    if [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]]; then
        ((indicators_server++))
        detection_reasons+=("SSH connection detected")
    fi
    
    if [[ "${USER:-}" == "root" ]] || [[ "${HOME:-}" == "/root" ]]; then
        ((indicators_server++))
        detection_reasons+=("Running as root")
    fi
    
    if [[ -f "/.dockerenv" ]]; then
        ((indicators_server++))
        detection_reasons+=("Running inside Docker")
    fi
    
    if [[ -d "/etc/systemd" ]] && [[ ! -d "/Applications" ]]; then
        ((indicators_server++))
        detection_reasons+=("Linux server environment")
    fi
    
    # Check for development indicators
    if [[ -d "$HOME/miniconda3" ]] || [[ -d "$HOME/anaconda3" ]] || command -v conda >/dev/null 2>&1; then
        ((indicators_dev++))
        detection_reasons+=("Conda available")
    fi
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ((indicators_dev++))
        detection_reasons+=("macOS detected")
    fi
    
    if [[ -d "/Applications" ]] || [[ -n "${DESKTOP_SESSION:-}" ]]; then
        ((indicators_dev++))
        detection_reasons+=("Desktop environment")
    fi
    
    if [[ -d ".git" ]] || [[ -n "$(git rev-parse --git-dir 2>/dev/null)" ]]; then
        ((indicators_dev++))
        detection_reasons+=("Git repository")
    fi
    
    if [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]] || [[ -f "environment.yml" ]]; then
        ((indicators_dev++))
        detection_reasons+=("Python development files")
    fi
    
    # Determine mode based on indicators
    if [[ $indicators_server -gt $indicators_dev ]]; then
        FKS_MODE_DETECTED="server"
        FKS_MODE_REASON="Server indicators: ${detection_reasons[*]}"
    elif [[ $indicators_dev -gt $indicators_server ]]; then
        FKS_MODE_DETECTED="development"
        FKS_MODE_REASON="Development indicators: ${detection_reasons[*]}"
    else
        # Tie-breaker: default to development if ambiguous
        FKS_MODE_DETECTED="development"
        FKS_MODE_REASON="Default (ambiguous environment)"
    fi
    
    log_debug "Mode detected: $FKS_MODE_DETECTED ($FKS_MODE_REASON)"
}

# Set operating mode
set_operating_mode() {
    local requested_mode="${1:-}"
    
    if [[ -n "$requested_mode" ]]; then
        case "$requested_mode" in
            "dev"|"development"|"local")
                FKS_MODE="development"
                FKS_MODE_REASON="Explicitly set to development"
                ;;
            "server"|"prod"|"production"|"docker")
                FKS_MODE="server"
                FKS_MODE_REASON="Explicitly set to server"
                ;;
            "auto")
                detect_operating_mode
                FKS_MODE="$FKS_MODE_DETECTED"
                ;;
            *)
                log_error "Invalid mode: $requested_mode. Use 'development' or 'server'"
                exit 1
                ;;
        esac
    else
        detect_operating_mode
        FKS_MODE="$FKS_MODE_DETECTED"
    fi
    
    # Export mode for child processes
    export FKS_MODE
    export FKS_MODE_REASON
    
    log_info "🎯 Operating Mode: ${WHITE}$FKS_MODE${NC}"
    log_debug "Reason: $FKS_MODE_REASON"
}

# Show mode information
show_mode_info() {
    set_operating_mode "auto"
    
    cat << EOF
${WHITE}FKS Mode Detection Information${NC}
${CYAN}===============================${NC}

${YELLOW}Current Mode:${NC} ${WHITE}$FKS_MODE${NC}
${YELLOW}Detection Reason:${NC} $FKS_MODE_REASON

${YELLOW}Environment Analysis:${NC}
EOF
    
    # Environment checks
    echo "  Platform: $(uname -s -m)"
    echo "  User: ${USER:-unknown}"
    echo "  Home: ${HOME:-unknown}"
    echo "  Shell: ${SHELL:-unknown}"
    
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "  SSH Connection: Yes"
    else
        echo "  SSH Connection: No"
    fi
    
    if [[ -f "/.dockerenv" ]]; then
        echo "  Inside Docker: Yes"
    else
        echo "  Inside Docker: No"
    fi
    
    echo ""
    echo "${YELLOW}Available Tools:${NC}"
    
    local tools=(
        "conda:Conda"
        "python3:Python 3"
        "docker:Docker"
        "git:Git"
        "systemctl:Systemctl"
    )
    
    for tool_spec in "${tools[@]}"; do
        local tool=$(echo "$tool_spec" | cut -d: -f1)
        local name=$(echo "$tool_spec" | cut -d: -f2)
        
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  ✅ $name available"
        else
            echo "  ❌ $name not found"
        fi
    done
    
    echo ""
    echo "${YELLOW}Mode Override:${NC}"
    echo "  Environment: FKS_MODE=${FKS_MODE:-not set}"
    echo "  Command line: Use --dev or --server to override"
    echo ""
}

echo "📦 Loaded mode detection module (v$MODE_DETECTION_MODULE_VERSION)"