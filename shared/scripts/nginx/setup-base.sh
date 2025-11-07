#!/bin/bash
# setup-base.sh - Base system setup for 7gram Dashboard
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-base"
readonly SCRIPT_VERSION="3.0.0"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    # Download common utilities if not present
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# BASE SYSTEM SETUP
# ============================================================================
setup_pacman() {
    log "Configuring package manager..."
    
    # Initialize pacman
    pacman-key --init
    pacman-key --populate archlinux
    
    # Update mirrors for better performance
    pacman -S --noconfirm reflector
    reflector --latest 10 --sort rate --save /etc/pacman.d/mirrorlist --protocol https
    
    # Enable parallel downloads
    sed -i 's/#ParallelDownloads = 5/ParallelDownloads = 5/' /etc/pacman.conf
    
    # Enable multilib if needed
    if ! grep -q "^\[multilib\]" /etc/pacman.conf; then
        echo -e "\n[multilib]\nInclude = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
    fi
    
    success "Package manager configured"
}

install_base_packages() {
    log "Installing base system packages..."
    
    # Fix potential package conflicts
    resolve_package_conflicts
    
    # System update with conflict resolution
    log "Performing system update..."
    if ! pacman -Syyu --noconfirm --overwrite="*"; then
        warning "System update encountered issues, attempting recovery..."
        
        # Try to update keyring first
        pacman -S --noconfirm archlinux-keyring
        pacman-key --refresh-keys
        
        # Retry update with more aggressive conflict resolution
        pacman -Syyu --noconfirm --overwrite="/usr/lib/firmware/*" || {
            error "System update failed even after recovery attempts"
            return 1
        }
    fi
    
    # Install packages in logical groups
    local package_groups=(
        "base-devel git curl wget"
        "vim nano htop tree"
        "nginx"
        "certbot certbot-nginx"
        "ufw fail2ban"
        "cronie openssl jq"
        "python python-pip"
        "rsync borgbackup"
        "bind-tools net-tools"
    )
    
    for packages in "${package_groups[@]}"; do
        install_package_group "$packages"
    done
    
    success "Base packages installed"
}

resolve_package_conflicts() {
    log "Resolving potential package conflicts..."
    
    # Remove conflicting nvidia firmware files if they exist
    if [[ -d "/usr/lib/firmware/nvidia" ]]; then
        warning "Removing conflicting nvidia firmware files..."
        rm -rf /usr/lib/firmware/nvidia/ad10* 2>/dev/null || true
    fi
    
    # Handle other common conflicts
    # Remove conflicting bluetooth firmware
    rm -f /usr/lib/firmware/mediatek/mt7921* 2>/dev/null || true
}

install_package_group() {
    local packages="$1"
    log "Installing: $packages"
    
    if pacman -S --needed --noconfirm $packages; then
        success "Installed: $packages"
    else
        warning "Some packages failed in group: $packages"
        # Try installing packages one by one
        for pkg in $packages; do
            if ! pacman -S --needed --noconfirm "$pkg"; then
                warning "Failed to install package: $pkg"
            fi
        done
    fi
}

configure_system() {
    log "Configuring system settings..."
    
    # Set timezone
    if [[ -n "${TIMEZONE:-}" ]]; then
        log "Setting timezone to $TIMEZONE..."
        if timedatectl set-timezone "$TIMEZONE"; then
            success "Timezone set to $TIMEZONE"
        else
            warning "Failed to set timezone to $TIMEZONE"
        fi
    fi
    
    # Set hostname
    local hostname="${HOSTNAME:-nginx}"
    log "Setting hostname to $hostname..."
    hostnamectl set-hostname "$hostname"
    
    # Update hosts file
    if ! grep -q "127.0.0.1 $hostname" /etc/hosts; then
        echo "127.0.0.1 $hostname" >> /etc/hosts
    fi
    
    # Configure locale if not set
    if [[ ! -f /etc/locale.conf ]]; then
        echo "LANG=en_US.UTF-8" > /etc/locale.conf
    fi
    
    success "System configuration completed"
}

setup_users() {
    log "Setting up user accounts..."
    
    # Create nginx user if it doesn't exist (Arch uses 'http')
    if ! id nginx &>/dev/null; then
        if id http &>/dev/null; then
            # Create nginx as alias to http user
            ln -sf /home/http /home/nginx 2>/dev/null || true
        fi
    fi
    
    # Add SSH key if provided
    if [[ -n "${SSH_KEY:-}" ]]; then
        log "Adding SSH key for root user..."
        mkdir -p /root/.ssh
        echo "$SSH_KEY" >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
        success "SSH key added"
    fi
    
    success "User accounts configured"
}

setup_firewall() {
    log "Configuring firewall..."
    
    # Check if iptables modules are available
    if ! lsmod | grep -q ip_tables; then
        warning "iptables kernel modules not loaded, attempting to load them..."
        modprobe ip_tables 2>/dev/null || true
        modprobe iptable_filter 2>/dev/null || true
        modprobe ip6_tables 2>/dev/null || true
        modprobe ip6table_filter 2>/dev/null || true
    fi
    
    # Try to configure UFW, but don't fail if it doesn't work
    log "Attempting UFW configuration..."
    if ufw --force reset && \
       ufw default deny incoming && \
       ufw default allow outgoing && \
       ufw allow ssh && \
       ufw allow 80/tcp && \
       ufw allow 443/tcp; then
        
        # Try to enable firewall
        if echo "y" | ufw enable 2>/dev/null; then
            success "Firewall configured successfully"
        else
            warning "Firewall rules set but enable failed - will retry after reboot"
            # Save firewall setup for post-reboot
            echo "ufw_setup_needed=true" >> "$CONFIG_DIR/post-reboot-tasks"
        fi
    else
        warning "UFW configuration failed - kernel modules not ready"
        warning "Firewall will be configured after reboot when modules are loaded"
        
        # Save firewall setup for post-reboot
        mkdir -p "$CONFIG_DIR"
        echo "ufw_setup_needed=true" >> "$CONFIG_DIR/post-reboot-tasks"
    fi
}

setup_fail2ban() {
    log "Configuring fail2ban..."
    
    # Create fail2ban configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 6

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 6
bantime = 7200
EOF
    
    # Create custom nginx filters
    create_fail2ban_filters
    
    # Enable and start fail2ban
    systemctl enable fail2ban
    
    success "Fail2ban configured"
}

create_fail2ban_filters() {
    # Create nginx-botsearch filter
    cat > /etc/fail2ban/filter.d/nginx-botsearch.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*/(phpMyAdmin|phpmyadmin|admin|wp-admin|wordpress).*HTTP.*"
ignoreregex =
EOF
    
    # Create nginx-badbots filter
    cat > /etc/fail2ban/filter.d/nginx-badbots.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scgi).*HTTP.*"
ignoreregex =
EOF
}

optimize_system() {
    log "Applying system optimizations..."
    
    # Increase file limits
    cat >> /etc/security/limits.conf << 'EOF'

# Nginx optimizations
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
nginx soft nofile 65535
nginx hard nofile 65535
http soft nofile 65535
http hard nofile 65535
EOF
    
    # Optimize kernel parameters
    cat >> /etc/sysctl.d/99-nginx-optimizations.conf << 'EOF'
# Network optimizations for nginx
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.tcp_tw_reuse = 1

# Memory optimizations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# File system optimizations
fs.file-max = 2097152
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-nginx-optimizations.conf
    
    success "System optimizations applied"
}

setup_logging() {
    log "Configuring log rotation..."
    
    # Create logrotate configuration for setup logs
    cat > /etc/logrotate.d/nginx-automation << 'EOF'
/var/log/linode-setup/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}

/var/log/nginx-automation/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    success "Log rotation configured"
}

enable_services() {
    log "Enabling system services..."
    
    # Enable and start cronie for cron jobs
    systemctl enable cronie
    systemctl start cronie
    
    # Enable systemd-timesyncd for time synchronization
    systemctl enable systemd-timesyncd
    systemctl start systemd-timesyncd
    
    success "System services enabled"
}

install_yay() {
    log "Installing yay AUR helper..."
    
    # Create builder user for AUR packages
    if ! id builder &>/dev/null; then
        useradd -m -G wheel builder
        echo "builder ALL=(ALL) NOPASSWD: /usr/bin/pacman, /usr/bin/makepkg" >> /etc/sudoers.d/builder
        chmod 440 /etc/sudoers.d/builder
    fi
    
    # Install yay
    if ! command -v yay &>/dev/null; then
        sudo -u builder bash << 'EOF'
cd /tmp
rm -rf yay
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si --noconfirm
EOF
        if command -v yay &>/dev/null; then
            success "yay AUR helper installed"
        else
            warning "yay installation failed, continuing without AUR support"
        fi
    else
        log "yay already installed"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting base system setup..."
    
    # Core system setup
    setup_pacman
    install_base_packages
    configure_system
    setup_users
    
    # Security setup (non-critical - can be done post-reboot)
    if setup_firewall; then
        log "Firewall setup completed"
    else
        warning "Firewall setup deferred to post-reboot phase"
    fi
    
    if setup_fail2ban; then
        log "Fail2ban setup completed"
    else
        warning "Fail2ban setup had issues but continuing..."
    fi
    
    # System optimizations
    optimize_system
    setup_logging
    enable_services
    
    # Install AUR helper
    install_yay
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "Base system setup completed successfully"
}

# Execute main function
main "$@"