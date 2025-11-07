#!/bin/bash

# Enhanced Linode StackScript: Modular NGINX Setup - Orchestrator
# Version: 3.0.0
# Repository: https://github.com/nuniesmith/nginx.git

# ============================================================================
# STACKSCRIPT UDF - User Defined Fields
# ============================================================================
# <UDF name="tailscale_auth_key" label="Tailscale Auth Key (REQUIRED)" example="tskey-auth-..." />
# <UDF name="hostname" label="Server Hostname" default="nginx" example="my-nginx-server" />
# <UDF name="timezone" label="Timezone" default="UTC" example="America/New_York" />
# <UDF name="ssh_key" label="SSH Public Key" />
# <UDF name="domain_name" label="Domain Name" default="7gram.xyz" example="yourdomain.com" />
# <UDF name="ssl_email" label="SSL Certificate Email" default="admin@7gram.xyz" example="admin@yourdomain.com" />
# <UDF name="enable_ssl" label="Enable SSL Certificates" default="true" oneof="true,false" />
# <UDF name="ssl_staging" label="Use SSL Staging Environment (for testing)" default="false" oneof="true,false" />
# <UDF name="cloudflare_api_token" label="Cloudflare API Token (for DNS updates)" />
# <UDF name="cloudflare_zone_id" label="Cloudflare Zone ID" />
# <UDF name="update_dns" label="Automatically update DNS records" default="true" oneof="true,false" />
# <UDF name="github_repo" label="GitHub Repository (owner/repo)" default="nuniesmith/nginx" example="username/repo-name" />
# <UDF name="github_token" label="GitHub Personal Access Token (for deploy key)" />
# <UDF name="enable_github_actions" label="Setup GitHub Actions Integration" default="true" oneof="true,false" />
# <UDF name="enable_monitoring" label="Enable Monitoring Stack" default="true" oneof="true,false" />
# <UDF name="enable_backup" label="Enable Automated Backups" default="true" oneof="true,false" />
# <UDF name="discord_webhook" label="Discord Webhook URL" />
# <UDF name="github_branch" label="GitHub Branch" default="main" example="main" />

set -euo pipefail

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================
readonly SCRIPT_VERSION="3.0.0"
readonly GITHUB_REPO="${GITHUB_REPO:-nuniesmith/nginx}"
readonly GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
readonly LOG_DIR="/var/log/linode-setup"
readonly CONFIG_DIR="/etc/nginx-automation"
readonly REPO_DIR="/opt/nginx-deployment"

# Create directories
mkdir -p "$LOG_DIR" "$CONFIG_DIR"
chmod 755 "$LOG_DIR" "$CONFIG_DIR"

# ============================================================================
# LOGGING AND UTILITIES
# ============================================================================
readonly LOG_FILE="$LOG_DIR/setup-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    send_notification "success" "$1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    send_notification "error" "$1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# ============================================================================
# NOTIFICATION SYSTEM
# ============================================================================
send_notification() {
    local level="$1"
    local message="$2"
    local hostname=$(hostname)
    
    if [ -n "${DISCORD_WEBHOOK:-}" ]; then
        local color
        case "$level" in
            success) color="3066993" ;;
            error) color="15158332" ;;
            warning) color="16776960" ;;
            *) color="3447003" ;;
        esac
        
        curl -s -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"StackScript - $hostname\",\"description\":\"$message\",\"color\":$color}]}" \
            "$DISCORD_WEBHOOK" || true
    fi
}

# ============================================================================
# ERROR HANDLING
# ============================================================================
cleanup() {
    log "Performing cleanup..."
    # Keep the repository for later use
}

trap cleanup EXIT

handle_error() {
    local exit_code="$1"
    local line_number="$2"
    error "Script failed with exit code $exit_code at line $line_number"
    
    # Save error state
    cat > "$CONFIG_DIR/error-state.json" << EOF
{
    "error": true,
    "exit_code": $exit_code,
    "line": $line_number,
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "log_file": "$LOG_FILE",
    "script_version": "$SCRIPT_VERSION",
    "github_repo": "$GITHUB_REPO",
    "github_branch": "$GITHUB_BRANCH"
}
EOF
    
    cleanup
    exit "$exit_code"
}

trap 'handle_error $? $LINENO' ERR

# ============================================================================
# SYSTEM PREPARATION
# ============================================================================
update_system() {
    log "Updating system packages..."
    
    # Initialize pacman
    pacman-key --init
    pacman-key --populate archlinux
    
    # Update mirrors for better performance
    pacman -S --noconfirm reflector
    reflector --latest 10 --sort rate --save /etc/pacman.d/mirrorlist --protocol https
    
    # Fix NVIDIA firmware conflicts BEFORE system update
    log "Resolving potential package conflicts..."
    if [[ -d "/usr/lib/firmware/nvidia" ]]; then
        warning "Removing conflicting NVIDIA firmware files..."
        rm -rf /usr/lib/firmware/nvidia/ad10* 2>/dev/null || true
        rm -rf /usr/lib/firmware/nvidia/* 2>/dev/null || true
    fi
    
    # Also remove other common conflict sources
    rm -rf /usr/lib/firmware/mediatek/mt7921* 2>/dev/null || true
    
    # System update with aggressive conflict resolution
    log "Performing system update..."
    if pacman -Syyu --noconfirm --overwrite="*"; then
        success "System update completed successfully"
    else
        warning "System update failed, attempting recovery..."
        
        # Try to update keyring first
        pacman -S --noconfirm archlinux-keyring || true
        pacman-key --refresh-keys || true
        
        # More aggressive retry with specific overwrite patterns
        if pacman -Syyu --noconfirm --overwrite="/usr/lib/firmware/*" --overwrite="/usr/share/*" --overwrite="/etc/*"; then
            success "System update completed after conflict resolution"
        else
            # Final attempt - nuclear option
            warning "Attempting final recovery with full overwrite..."
            if pacman -Syyu --noconfirm --overwrite="*"; then
                success "System update completed with full overwrite"
            else
                # Don't fail completely, just warn and continue
                warning "System update had issues, but continuing setup..."
                warning "You may need to run 'pacman -Syyu --overwrite=\"*\"' manually later"
            fi
        fi
    fi
}

install_prerequisites() {
    log "Installing prerequisite packages..."
    
    # Essential packages for our setup
    local packages=(
        "git"
        "curl" 
        "wget"
        "jq"
        "base-devel"
        "vim"
        "nano"
        "htop"
        "tree"
        "bind-tools"
        "net-tools"
        "openssh"
    )
    
    for package in "${packages[@]}"; do
        log "Installing: $package"
        if pacman -S --needed --noconfirm "$package"; then
            success "Installed: $package"
        else
            warning "Failed to install: $package"
        fi
    done
    
    success "Prerequisites installed"
}

# ============================================================================
# REPOSITORY MANAGEMENT
# ============================================================================
clone_repository() {
    log "Cloning repository: $GITHUB_REPO"
    
    # Remove existing directory if it exists
    if [[ -d "$REPO_DIR" ]]; then
        log "Removing existing repository directory..."
        rm -rf "$REPO_DIR"
    fi
    
    # Create parent directory
    mkdir -p "$(dirname "$REPO_DIR")"
    
    # Clone repository with retries
    local retries=3
    for ((i=1; i<=retries; i++)); do
        log "Clone attempt $i/$retries..."
        
        if git clone --branch "$GITHUB_BRANCH" --single-branch \
            "https://github.com/${GITHUB_REPO}.git" "$REPO_DIR"; then
            success "Repository cloned successfully"
            return 0
        else
            warning "Clone attempt $i/$retries failed"
            if [[ $i -eq $retries ]]; then
                error "Failed to clone repository after $retries attempts"
                return 1
            fi
            sleep 5
        fi
    done
}

verify_repository() {
    log "Verifying repository structure..."
    
    # Check if scripts directory exists
    if [[ ! -d "$REPO_DIR/scripts" ]]; then
        error "Scripts directory not found in repository"
        log "Repository contents:"
        ls -la "$REPO_DIR/" || true
        return 1
    fi
    
    # Check for essential scripts
    local required_scripts=(
        "setup-base.sh"
        "setup-tailscale.sh"
        "setup-nginx.sh"
        "post-reboot.sh"
        "utils/common.sh"
    )
    
    local missing_scripts=()
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$REPO_DIR/scripts/$script" ]]; then
            missing_scripts+=("$script")
        fi
    done
    
    if [[ ${#missing_scripts[@]} -gt 0 ]]; then
        error "Missing required scripts: ${missing_scripts[*]}"
        log "Available scripts:"
        find "$REPO_DIR/scripts" -name "*.sh" -type f 2>/dev/null | sed 's|.*/||' || true
        return 1
    fi
    
    # Make all scripts executable
    find "$REPO_DIR/scripts" -name "*.sh" -type f -exec chmod +x {} \;
    
    success "Repository structure verified"
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================
execute_script() {
    local script_name="$1"
    local script_path="$REPO_DIR/scripts/$script_name"
    
    if [[ ! -f "$script_path" ]]; then
        error "Script not found: $script_path"
        return 1
    fi
    
    log "Executing script: $script_name"
    
    # Export environment variables for the script
    export TAILSCALE_AUTH_KEY HOSTNAME TIMEZONE SSH_KEY DOMAIN_NAME SSL_EMAIL
    export ENABLE_SSL SSL_STAGING CLOUDFLARE_API_TOKEN CLOUDFLARE_ZONE_ID UPDATE_DNS
    export GITHUB_REPO GITHUB_TOKEN ENABLE_GITHUB_ACTIONS ENABLE_MONITORING
    export ENABLE_BACKUP DISCORD_WEBHOOK LOG_DIR CONFIG_DIR REPO_DIR
    export SCRIPT_BASE_URL="$REPO_DIR/scripts"
    
    # Change to scripts directory for relative imports
    cd "$REPO_DIR/scripts"
    
    if bash "$script_path"; then
        success "Completed: $script_name"
        return 0
    else
        error "Failed: $script_name"
        return 1
    fi
}

# ============================================================================
# VALIDATION
# ============================================================================
validate_prerequisites() {
    log "Validating prerequisites..."
    
    # Check required parameters
    if [[ -z "${TAILSCALE_AUTH_KEY:-}" ]]; then
        error "Tailscale Auth Key is required!"
        exit 1
    fi
    
    # Check system requirements
    local min_memory_mb=1024
    local actual_memory_mb=$(free -m | awk '/^Mem:/{print $2}')
    
    if [[ "$actual_memory_mb" -lt "$min_memory_mb" ]]; then
        error "Insufficient memory: ${actual_memory_mb}MB (minimum: ${min_memory_mb}MB)"
        exit 1
    fi
    
    success "Prerequisites validated"
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================
save_configuration() {
    log "Saving configuration..."
    
    cat > "$CONFIG_DIR/deployment-config.json" << EOF
{
    "version": "$SCRIPT_VERSION",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "${HOSTNAME:-nginx}",
    "domain": "${DOMAIN_NAME:-7gram.xyz}",
    "github": {
        "repository": "$GITHUB_REPO",
        "branch": "$GITHUB_BRANCH"
    },
    "services": {
        "nginx": true,
        "tailscale": true,
        "ssl": ${ENABLE_SSL:-true},
        "monitoring": ${ENABLE_MONITORING:-true},
        "backup": ${ENABLE_BACKUP:-true},
        "github_actions": ${ENABLE_GITHUB_ACTIONS:-true}
    },
    "paths": {
        "repository": "$REPO_DIR",
        "config": "$CONFIG_DIR",
        "logs": "$LOG_DIR"
    }
}
EOF
    
    success "Configuration saved"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "7gram Dashboard Modular Setup v$SCRIPT_VERSION"
    log "Repository: $GITHUB_REPO@$GITHUB_BRANCH"
    log "Deployment Directory: $REPO_DIR"
    log "=================================================="
    
    # Phase 0: System preparation
    log "PHASE 0: System Preparation"
    validate_prerequisites
    update_system
    install_prerequisites
    save_configuration
    
    # Phase 1: Repository setup
    log "PHASE 1: Repository Setup"
    clone_repository
    verify_repository
    
    # Phase 2: Core system setup
    log "PHASE 2: Core System Setup"
    execute_script "setup-base.sh"
    execute_script "setup-tailscale.sh"
    
    # Phase 3: Application setup
    log "PHASE 3: Application Setup"
    execute_script "setup-nginx.sh"
    
    if [[ "${ENABLE_SSL:-true}" == "true" ]]; then
        execute_script "setup-ssl.sh"
    fi
    
    if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        execute_script "setup-dns.sh"
    fi
    
    # Phase 4: DevOps setup
    log "PHASE 4: DevOps Setup"
    
    if [[ "${ENABLE_GITHUB_ACTIONS:-true}" == "true" ]]; then
        execute_script "setup-github.sh"
    fi
    
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]]; then
        execute_script "setup-monitoring.sh"
    fi
    
    if [[ "${ENABLE_BACKUP:-true}" == "true" ]]; then
        execute_script "setup-backup.sh"
    fi
    
    # Phase 5: Post-reboot setup preparation
    log "PHASE 5: Post-Reboot Setup Preparation"
    
    # Copy post-reboot script to system location
    cp "$REPO_DIR/scripts/post-reboot.sh" "/root/post-reboot-setup.sh"
    chmod +x "/root/post-reboot-setup.sh"
    
    # Create systemd service for post-reboot
    cat > /etc/systemd/system/post-reboot-setup.service << 'EOF'
[Unit]
Description=Post-reboot setup continuation for 7gram Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/post-reboot-setup.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable post-reboot-setup.service
    
    # Install management script globally
    cp "$REPO_DIR/scripts/7gram-status.sh" "/usr/local/bin/7gram-status"
    chmod +x "/usr/local/bin/7gram-status"
    
    success "Phase 1-4 complete - system will reboot for Phase 5"
    
    # Show summary
    echo ""
    log "Setup Summary:"
    echo "  [OK] System packages updated"
    echo "  [OK] Prerequisites installed"
    echo "  [OK] Repository cloned: $REPO_DIR"
    echo "  [OK] Base system configured"
    echo "  [OK] Tailscale installed"
    echo "  [OK] NGINX configured"
    [[ "${ENABLE_SSL:-true}" == "true" ]] && echo "  [OK] SSL prerequisites configured"
    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] && echo "  [OK] DNS management configured"
    [[ "${ENABLE_GITHUB_ACTIONS:-true}" == "true" ]] && echo "  [OK] GitHub Actions configured"
    [[ "${ENABLE_MONITORING:-true}" == "true" ]] && echo "  [OK] Monitoring configured"
    [[ "${ENABLE_BACKUP:-true}" == "true" ]] && echo "  [OK] Backup configured"
    
    echo ""
    log "After reboot, the system will complete final setup automatically"
    log "Repository location: $REPO_DIR"
    log "Management commands: 7gram-status"
    log "Deployment info: $REPO_DIR/deployment-info.txt (after reboot)"
    
    # Schedule reboot
    shutdown -r +2 "System will reboot in 2 minutes for final setup phase"
}

# Start main execution
main "$@"