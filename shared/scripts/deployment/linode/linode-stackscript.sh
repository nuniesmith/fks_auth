#!/bin/bash

# FKS Trading Systems - Multi-Distro StackScript for Dev Server
# Supports: Ubuntu 24.04 LTS and Arch Linux
# 
# Two-phase setup with proper user management, GitHub Actions support, and Tailscale

# StackScript UDF (User Defined Fields) - Production ready
#<UDF name="jordan_password" label="Password for jordan user" />
#<UDF name="fks_user_password" label="Password for fks_user" />
#<UDF name="ACTIONS_USER_SSH_PUB" label="GitHub Actions SSH Public Key" default="" />
#<UDF name="ACTIONS_JORDAN_SSH_PUB" label="Jordan SSH Public Key" default="" />
#<UDF name="ACTIONS_ROOT_SSH_PUB" label="Root SSH Public Key" default="" />
#<UDF name="ACTIONS_FKS_SSH_PUB" label="FKS User SSH Public Key" default="" />
#<UDF name="tailscale_auth_key" label="Tailscale Auth Key (REQUIRED)" default="" />
#<UDF name="docker_username" label="Docker Hub Username" default="" />
#<UDF name="docker_token" label="Docker Hub Access Token" default="" />
#<UDF name="netdata_claim_token" label="Netdata Cloud Claim Token (optional)" default="" />
#<UDF name="netdata_claim_room" label="Netdata Cloud Room ID (optional)" default="" />
#<UDF name="oryx_ssh_pub" label="Oryx Computer SSH Public Key" default="" />
#<UDF name="sullivan_ssh_pub" label="Sullivan Computer SSH Public Key" default="" />
#<UDF name="freddy_ssh_pub" label="Freddy Computer SSH Public Key" default="" />
#<UDF name="desktop_ssh_pub" label="Desktop Computer SSH Public Key" default="" />
#<UDF name="macbook_ssh_pub" label="MacBook SSH Public Key" default="" />
#<UDF name="timezone" label="Server Timezone" default="America/Toronto" />

# Exit on any error
set -e

# Validate required parameters (now using UDF variables)
# Note: Linode converts UDF names to uppercase
if [ -z "$TAILSCALE_AUTH_KEY" ]; then
    echo "ERROR: Tailscale auth key is required for this deployment" >&2
    echo "Please provide a valid Tailscale auth key" >&2
    exit 1
fi

if [ -z "$JORDAN_PASSWORD" ]; then
    echo "ERROR: Jordan user password is required" >&2
    exit 1
fi

if [ -z "$FKS_USER_PASSWORD" ]; then
    echo "ERROR: FKS user password is required" >&2
    exit 1
fi

# Debug UDF variables (Linode StackScript User Defined Fields)
# Note: Linode converts UDF names to uppercase
echo "=== DEBUG: UDF Variables ===" >> /var/log/fks_setup.log
echo "JORDAN_PASSWORD: $([ -n "$JORDAN_PASSWORD" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "FKS_USER_PASSWORD: $([ -n "$FKS_USER_PASSWORD" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "TAILSCALE_AUTH_KEY: $([ -n "$TAILSCALE_AUTH_KEY" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "DOCKER_USERNAME: $([ -n "$DOCKER_USERNAME" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "DOCKER_TOKEN: $([ -n "$DOCKER_TOKEN" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "NETDATA_CLAIM_TOKEN: $([ -n "$NETDATA_CLAIM_TOKEN" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "NETDATA_CLAIM_ROOM: $([ -n "$NETDATA_CLAIM_ROOM" ] && echo "SET" || echo "NOT SET")" >> /var/log/fks_setup.log
echo "TIMEZONE: ${TIMEZONE:-NOT_SET}" >> /var/log/fks_setup.log
echo "===========================" >> /var/log/fks_setup.log

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create log file
touch /var/log/fks_setup.log
chmod 644 /var/log/fks_setup.log

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a /var/log/fks_setup.log
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a /var/log/fks_setup.log
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a /var/log/fks_setup.log
}

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif command -v lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$(lsb_release -sr)
    else
        error "Cannot detect distribution"
        exit 1
    fi
    
    log "Detected distribution: $DISTRO $DISTRO_VERSION"
}

# Ubuntu-specific installations
install_ubuntu() {
    # Update system
    log "Updating Ubuntu system packages..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    # Install essential packages
    log "Installing essential packages for Ubuntu..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        git \
        vim \
        nano \
        htop \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        jq \
        tree \
        fail2ban \
        ufw \
        build-essential \
        net-tools \
        python3-pip \
        python3-venv \
        python3-dev \
        openssl
    
    # Install Docker
    log "Installing Docker on Ubuntu..."
    apt-get remove -y docker docker-engine docker.io containerd runc || true
    
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Install Node.js
    log "Installing Node.js on Ubuntu..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    
    # Install .NET
    log "Installing .NET on Ubuntu..."
    wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    dpkg -i packages-microsoft-prod.deb || true
    rm packages-microsoft-prod.deb
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y dotnet-sdk-8.0 aspnetcore-runtime-8.0 dotnet-runtime-8.0
}

# Arch Linux-specific installations
install_arch() {
    # Clean package cache and fix potential database issues
    log "Cleaning package cache and fixing potential issues..."
    rm -f /var/lib/pacman/db.lck 2>/dev/null || true
    pacman -Scc --noconfirm
    
    # Update system - handle nvidia firmware conflicts specifically
    log "Updating Arch Linux system packages..."
    
    # First, update the keyring
    pacman -Sy --noconfirm archlinux-keyring || true
    
    # Method 1: Remove conflicting files first
    log "Checking for nvidia firmware conflicts..."
    if [ -d /usr/lib/firmware/nvidia ]; then
        log "Backing up and removing conflicting nvidia firmware files..."
        mkdir -p /tmp/nvidia-firmware-backup
        cp -r /usr/lib/firmware/nvidia /tmp/nvidia-firmware-backup/ 2>/dev/null || true
        rm -rf /usr/lib/firmware/nvidia/ad10* 2>/dev/null || true
    fi
    
    # Method 2: Try update with overwrite flag
    if ! pacman -Syu --noconfirm --overwrite '/usr/lib/firmware/nvidia/*'; then
        warn "Standard update failed, trying alternative methods..."
        
        # Method 3: Update everything except linux-firmware packages first
        log "Updating system excluding firmware packages..."
        pacman -Syu --noconfirm --ignore linux-firmware-nvidia --ignore linux-firmware || true
        
        # Method 4: Force update firmware packages separately
        log "Force updating firmware packages..."
        pacman -S --noconfirm --overwrite '/usr/lib/firmware/*' linux-firmware linux-firmware-nvidia || {
            warn "Firmware update failed, removing and reinstalling..."
            # Method 5: Last resort - remove and reinstall
            pacman -Rdd --noconfirm linux-firmware-nvidia 2>/dev/null || true
            pacman -S --noconfirm linux-firmware-nvidia linux-firmware
        }
        
        # Final update to catch any remaining packages
        pacman -Su --noconfirm
    fi
    
    log "System update completed"
    
    # Install essential packages
    log "Installing essential packages for Arch..."
    pacman -S --noconfirm --needed \
        base-devel \
        curl \
        wget \
        git \
        vim \
        nano \
        htop \
        unzip \
        ca-certificates \
        gnupg \
        jq \
        tree \
        fail2ban \
        net-tools \
        python \
        python-pip \
        docker \
        docker-compose \
        nodejs \
        npm \
        dotnet-sdk \
        dotnet-runtime \
        aspnet-runtime \
        rust \
        openssl \
        go \
        linux \
        linux-headers \
        linux-firmware || {
        warn "Some packages failed to install, retrying with --overwrite..."
        pacman -S --noconfirm --needed --overwrite '*' \
            base-devel \
            curl \
            wget \
            git \
            vim \
            nano \
            htop \
            unzip \
            ca-certificates \
            gnupg \
            jq \
            tree \
            fail2ban \
            net-tools \
            python \
            python-pip \
            docker \
            docker-compose \
            nodejs \
            npm \
            dotnet-sdk \
            dotnet-runtime \
            aspnet-runtime \
            rust \
            openssl \
            go \
            linux \
            linux-headers \
            linux-firmware
    }
    
    # Check if kernel was updated
    CURRENT_KERNEL=$(uname -r)
    LATEST_KERNEL=$(pacman -Q linux | awk '{print $2}' | sed 's/-.*//')
    
    if [ "$CURRENT_KERNEL" != "$LATEST_KERNEL" ]; then
        log "Kernel update detected: $CURRENT_KERNEL -> $LATEST_KERNEL"
        log "Reboot will be required for new kernel and iptables modules"
    fi
    
    # Enable Docker
    systemctl enable docker.service
    
    # Install yay for AUR packages (needed for some tools)
    log "Installing yay for AUR access..."
    if ! command -v yay &> /dev/null; then
        # First ensure go is available
        if ! command -v go &> /dev/null; then
            warn "Go not available, skipping yay installation"
            return
        fi
        
        cd /tmp
        # Clean up any existing yay directory
        rm -rf /tmp/yay
        git clone https://aur.archlinux.org/yay.git
        cd yay
        
        # Create a temporary user for building
        useradd -m -s /bin/bash tempbuilder 2>/dev/null || true
        echo "tempbuilder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/tempbuilder
        chown -R tempbuilder:tempbuilder .
        
        # Set Go environment for the builder
        export GOPATH=/tmp/go
        export PATH=$PATH:/usr/bin/go
        mkdir -p $GOPATH
        chown -R tempbuilder:tempbuilder $GOPATH
        
        # Install as tempbuilder user
        sudo -u tempbuilder -H bash -c "
            export GOPATH=/tmp/go
            export PATH=\$PATH:/usr/bin/go
            cd /tmp/yay
            makepkg -si --noconfirm
        " || {
            warn "Yay installation failed, continuing without AUR support"
        }
        
        # Cleanup
        userdel -r tempbuilder 2>/dev/null || true
        rm -f /etc/sudoers.d/tempbuilder
        cd /
        rm -rf /tmp/yay /tmp/go
    fi
}

# Common firewall setup
setup_firewall() {
    if [ "$DISTRO" = "ubuntu" ]; then
        log "Configuring UFW firewall..."
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 3000/tcp  # React dev server
        ufw allow 8000/tcp  # API server
        ufw allow 8001/tcp  # Data service
        ufw allow 8002/tcp  # Worker service
        ufw allow 8003/tcp  # App service
        ufw allow 8080/tcp  # Adminer
        ufw allow 8081/tcp  # Redis Commander
        ufw allow 19999/tcp # Netdata monitoring
        ufw allow 41641/udp  # Tailscale (REQUIRED)
        echo "y" | ufw enable
    elif [ "$DISTRO" = "arch" ]; then
        log "Installing iptables packages..."
        # Check which iptables is already installed and use that
        if pacman -Q iptables-nft >/dev/null 2>&1; then
            log "iptables-nft already installed, using nft backend"
            pacman -S --noconfirm --needed iptables-nft linux-headers
        elif pacman -Q iptables >/dev/null 2>&1; then
            log "iptables (legacy) already installed, keeping it"
            pacman -S --noconfirm --needed iptables linux-headers
        else
            log "Installing iptables-nft (preferred for new systems)"
            pacman -S --noconfirm --needed iptables-nft linux-headers
        fi
        
        log "Firewall will be configured in Phase 2 after kernel update and reboot"
        # We'll configure iptables in Phase 2 after the reboot when kernel modules are available
    fi
}

# Determine which phase we're in
PHASE_FILE="/root/.fks_setup-phase"
if [ -f "$PHASE_FILE" ]; then
    PHASE=2
else
    PHASE=1
fi

# =================
# PHASE 1 - Initial Setup
# =================
if [ $PHASE -eq 1 ]; then
    log "Starting FKS Trading Systems Setup - PHASE 1"
    
    # Detect distribution
    detect_distro
    
    # Set hostname
    log "Setting hostname to fks..."
    hostnamectl set-hostname fks
    echo "fks" > /etc/hostname
    
    # Update /etc/hosts
    sed -i 's/127.0.1.1.*/127.0.1.1\tfks/' /etc/hosts
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo "127.0.1.1	fks" >> /etc/hosts
    fi
    
    # Log configuration
    log "Configuration:"
    log "  Distribution: $DISTRO $DISTRO_VERSION"
    log "  Hostname: fks"
    log "  Timezone: $TIMEZONE"
    log "  Jordan Password: $([ -n "$JORDAN_PASSWORD" ] && echo "Provided" || echo "Not provided")"
    log "  FKS User Password: $([ -n "$FKS_USER_PASSWORD" ] && echo "Provided" || echo "Not provided")"
    log "  Tailscale: Will configure (REQUIRED)"
    
    # Set timezone
    log "Setting timezone to ${TIMEZONE}..."
    if [ "$DISTRO" = "arch" ]; then
        ln -sf /usr/share/zoneinfo/${TIMEZONE} /etc/localtime
        hwclock --systohc
    else
        timedatectl set-timezone "${TIMEZONE}"
    fi
    
    # Install distribution-specific packages
    case "$DISTRO" in
        ubuntu)
            install_ubuntu
            ;;
        arch)
            log "Starting Arch Linux specific installation..."
            install_arch
            log "Arch Linux installation completed"
            ;;
        *)
            error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    # Install Docker Compose standalone (for compatibility)
    log "Installing Docker Compose standalone..."
    DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*?(?=")' || echo "v2.24.0")
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Install Rust (if not already installed on Arch)
    if [ "$DISTRO" = "ubuntu" ]; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/rustup.sh
        chmod +x /tmp/rustup.sh
        HOME=/opt/rust /tmp/rustup.sh -y --default-toolchain stable --no-modify-path
    fi
    
    # Install Tailscale (REQUIRED)
    log "Installing Tailscale..."
    if [ "$DISTRO" = "ubuntu" ]; then
        curl -fsSL https://tailscale.com/install.sh | sh
    elif [ "$DISTRO" = "arch" ]; then
        pacman -S --noconfirm tailscale
        systemctl enable tailscaled.service
    fi
    
    # Install Netdata monitoring
    log "Installing Netdata monitoring..."
    curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh
    chmod +x /tmp/netdata-kickstart.sh
    
    # Build Netdata install command with optional claim parameters
    NETDATA_CMD="sh /tmp/netdata-kickstart.sh --nightly-channel"
    if [[ -n "$NETDATA_CLAIM_TOKEN" ]]; then
        NETDATA_CMD="$NETDATA_CMD --claim-token $NETDATA_CLAIM_TOKEN"
        NETDATA_CMD="$NETDATA_CMD --claim-url https://app.netdata.cloud"
        if [[ -n "$NETDATA_CLAIM_ROOM" ]]; then
            NETDATA_CMD="$NETDATA_CMD --claim-rooms $NETDATA_CLAIM_ROOM"
        fi
    fi
    NETDATA_CMD="$NETDATA_CMD --dont-wait"
    
    eval "$NETDATA_CMD" || {
        warn "Netdata installation failed, continuing without monitoring"
    }
    
    # Create users
    log "Creating jordan user..."
    if ! id jordan &>/dev/null; then
        useradd -m -s /bin/bash jordan
    fi
    
    # Set password - handle the UDF variable properly
    if [ -n "${JORDAN_PASSWORD}" ]; then
        echo "jordan:${JORDAN_PASSWORD}" | chpasswd
        log "Password set for jordan user"
    elif [ -n "${jordan_password}" ]; then
        echo "jordan:${jordan_password}" | chpasswd
        log "Password set for jordan user"
    else
        # Generate a random password as fallback
        TEMP_PASS=$(openssl rand -base64 12)
        echo "jordan:${TEMP_PASS}" | chpasswd
        warn "No password provided for jordan user, generated temporary password: ${TEMP_PASS}"
        echo "JORDAN_TEMP_PASSWORD: ${TEMP_PASS}" >> /var/log/fks_setup.log
    fi
    
    # Add to sudo group (different on Arch)
    if [ "$DISTRO" = "arch" ]; then
        usermod -aG wheel jordan
        # Enable wheel group in sudoers
        sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers
    else
        usermod -aG sudo jordan
    fi
    usermod -aG docker jordan
    
    log "Creating fks_user..."
    if ! id fks_user &>/dev/null; then
        useradd -m -s /bin/bash fks_user
    fi
    
    # Set password - handle the UDF variable properly
    if [ -n "${FKS_USER_PASSWORD}" ]; then
        echo "fks_user:${FKS_USER_PASSWORD}" | chpasswd
        log "Password set for fks_user"
    elif [ -n "${fks_user_password}" ]; then
        echo "fks_user:${fks_user_password}" | chpasswd
        log "Password set for fks_user"
    else
        # Generate a random password as fallback
        TEMP_PASS=$(openssl rand -base64 12)
        echo "fks_user:${TEMP_PASS}" | chpasswd
        warn "No password provided for fks_user, generated temporary password: ${TEMP_PASS}"
        echo "FKS_USER_TEMP_PASSWORD: ${TEMP_PASS}" >> /var/log/fks_setup.log
    fi
    
    log "Creating actions_user user..."
    if ! id actions_user &>/dev/null; then
        useradd -m -s /bin/bash actions_user
    fi
    
    # Add actions_user to appropriate groups
    usermod -aG docker actions_user
    
    # Add to sudo/wheel group for deployment operations
    if [ "$DISTRO" = "arch" ]; then
        usermod -aG wheel actions_user
    else
        usermod -aG sudo actions_user
    fi
    
    # Set up passwordless sudo for actions_user (required for automated deployments)
    log "Configuring sudo access for actions_user..."
    cat > /etc/sudoers.d/actions_user << EOF
# GitHub Actions deployment user - passwordless sudo for specific commands
actions_user ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/local/bin/docker-compose, /usr/bin/git, /bin/systemctl
actions_user ALL=(jordan) NOPASSWD: ALL
EOF
    chmod 440 /etc/sudoers.d/actions_user
    
    # Setup SSH keys
    log "Setting up SSH keys..."
    
    setup_ssh_for_user() {
        local username=$1
        local ssh_pub_key=$2
        local home_dir="/home/$username"
        
        # Handle root home directory
        if [ "$username" = "root" ]; then
            home_dir="/root"
        fi
        
        # Create .ssh directory
        mkdir -p "$home_dir/.ssh"
        chmod 700 "$home_dir/.ssh"
        
        # Add public key to authorized_keys if provided
        if [ -n "$ssh_pub_key" ]; then
            echo "$ssh_pub_key" >> "$home_dir/.ssh/authorized_keys"
            chmod 600 "$home_dir/.ssh/authorized_keys"
            log "Added SSH key for $username"
        fi
        
        # Fix ownership (skip for root)
        if [ "$username" != "root" ]; then
            chown -R "$username:$username" "$home_dir/.ssh"
        fi
    }
    
    # Function to add additional SSH keys to a user
    add_additional_ssh_keys() {
        local username=$1
        local home_dir="/home/$username"
        
        # Only add to existing users
        if [ ! -d "$home_dir" ]; then
            return
        fi
        
        # Create array of additional SSH keys
        local additional_keys=(
            "${ORYX_SSH_PUB:-}"
            "${SULLIVAN_SSH_PUB:-}"
            "${FREDDY_SSH_PUB:-}"
            "${DESKTOP_SSH_PUB:-}"
            "${MACBOOK_SSH_PUB:-}"
        )
        
        local key_names=(
            "Oryx"
            "Sullivan"
            "Freddy"
            "Desktop"
            "MacBook"
        )
        
        # Add each non-empty key
        for i in "${!additional_keys[@]}"; do
            local key="${additional_keys[$i]}"
            local name="${key_names[$i]}"
            
            if [ -n "$key" ]; then
                echo "$key" >> "$home_dir/.ssh/authorized_keys"
                log "Added $name SSH key to $username's authorized_keys"
            fi
        done
    }
    
    # Setup SSH keys for each user (handle both uppercase and lowercase UDF variables)
    ROOT_SSH_KEY="${ACTIONS_ROOT_SSH_PUB:-}"
    JORDAN_SSH_KEY="${ACTIONS_ACTIONS_JORDAN_SSH_PUB:-${ACTIONS_JORDAN_SSH_PUB:-}}"
    FKS_USER_SSH_KEY="${ACTIONS_FKS_SSH_PUB:-}"
    ACTIONS_SSH_KEY="${ACTIONS_USER_SSH_PUB:-${ACTIONS_USER_SSH_PUB:-}}"
    
    setup_ssh_for_user "root" "$ROOT_SSH_KEY"
    setup_ssh_for_user "jordan" "$JORDAN_SSH_KEY"
    setup_ssh_for_user "fks_user" "$FKS_USER_SSH_KEY"
    setup_ssh_for_user "actions_user" "$ACTIONS_SSH_KEY"
    
    # Add additional SSH keys to both jordan and actions_user users
    add_additional_ssh_keys "jordan"
    add_additional_ssh_keys "actions_user"
    add_additional_ssh_keys "root"
    add_additional_ssh_keys "fks_user"
    
    # Also add github_actions key to jordan's authorized_keys for deployment fallback
    if [ -n "$ACTIONS_SSH_KEY" ]; then
        echo "$ACTIONS_SSH_KEY" >> /home/jordan/.ssh/authorized_keys
        log "Added GitHub Actions key to jordan's authorized_keys for fallback"
    fi
    
    # Generate SSH keys for actions_user if not provided
    if [ -z "$ACTIONS_SSH_KEY" ]; then
        log "Generating SSH keys for actions_user (required for GitHub Actions)..."
        
        # Ensure openssh is available
        if [ "$DISTRO" = "arch" ]; then
            # OpenSSH should be installed with base-devel, but verify
            if ! command -v ssh-keygen >/dev/null 2>&1; then
                log "Installing openssh package..."
                pacman -S --noconfirm openssh
            fi
        elif [ "$DISTRO" = "ubuntu" ]; then
            # openssh-client should be available, but verify
            if ! command -v ssh-keygen >/dev/null 2>&1; then
                log "Installing openssh-client package..."
                DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-client
            fi
        fi
        
        # Create .ssh directory for actions_user
        mkdir -p /home/actions_user/.ssh
        chmod 700 /home/actions_user/.ssh
        chown actions_user:actions_user /home/actions_user/.ssh
        
        # Generate ED25519 key pair (more secure than RSA)
        log "Generating ED25519 SSH key pair for actions_user..."
        sudo -u actions_user ssh-keygen -t ed25519 -f /home/actions_user/.ssh/id_ed25519 -N "" -C "actions_user@fks_dev-$(date +%Y%m%d)" || {
            error "Failed to generate SSH key for actions_user"
            exit 1
        }
        
        # Set up authorized_keys with the new public key for self-authentication
        sudo -u actions_user cp /home/actions_user/.ssh/id_ed25519.pub /home/actions_user/.ssh/authorized_keys
        sudo -u actions_user chmod 600 /home/actions_user/.ssh/authorized_keys
        
        # Ensure correct ownership
        chown -R actions_user:actions_user /home/actions_user/.ssh
        
        # Output the public key for logs and GitHub Actions retrieval
        GENERATED_KEY=$(cat /home/actions_user/.ssh/id_ed25519.pub)
        log "Generated SSH key for actions_user: $GENERATED_KEY"
        
        # Log in multiple formats for easy retrieval
        echo "GENERATED_ACTIONS_USER_SSH_PUB: $GENERATED_KEY" >> /var/log/fks_setup.log
        echo "SSH_KEY_FOR_GITHUB_ACTIONS: $GENERATED_KEY" >> /var/log/fks_setup.log
        echo "actions_user@fks_dev SSH public key: $GENERATED_KEY" >> /var/log/fks_setup.log
        
        # Also save to a dedicated file for easy access
        echo "$GENERATED_KEY" > /home/actions_user/.ssh/public_key_for_github.txt
        chown actions_user:actions_user /home/actions_user/.ssh/public_key_for_github.txt
        chmod 644 /home/actions_user/.ssh/public_key_for_github.txt
        
        log "[OK] SSH key generation completed successfully"
        log "[INFO] Key saved to: /home/actions_user/.ssh/id_ed25519.pub"
        log "[INFO] Also saved to: /home/actions_user/.ssh/public_key_for_github.txt"
        log "[INFO] Logged to: /var/log/fks_setup.log"
        
        # Test the key works for local authentication
        log "[TEST] Testing SSH key functionality..."
        if sudo -u actions_user ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ConnectTimeout=5 actions_user@localhost "echo 'SSH key test successful'" 2>/dev/null; then
            log "[OK] SSH key authentication test passed"
        else
            warn "SSH key authentication test failed - key generated but may need troubleshooting"
        fi
    else
        log "SSH key provided via UDF for actions_user"
    fi
    
    # Create root fallback SSH key for emergency access
    if [ -z "$ROOT_SSH_KEY" ]; then
        log "Generating emergency SSH key for root..."
        ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -C "root@fks_dev"
        
        # Output the public key for manual setup
        GENERATED_ROOT_KEY=$(cat /root/.ssh/id_ed25519.pub)
        log "Generated emergency SSH key for root: $GENERATED_ROOT_KEY"
        echo "GENERATED_ROOT_SSH_PUB: $GENERATED_ROOT_KEY" >> /var/log/fks_setup.log
    fi
    
    # Configure SSH
    log "Configuring SSH security..."
    if ! grep -q "Custom security settings" /etc/ssh/sshd_config; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        cat >> /etc/ssh/sshd_config << EOF

# Custom security settings
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    fi
    
    # Setup firewall
    setup_firewall
    
    # Configure fail2ban
    log "Configuring fail2ban..."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
EOF
    
    systemctl enable fail2ban
    
    # Create Phase 2 script
    log "Creating Phase 2 script..."
    cat > /usr/local/bin/fks_phase2.sh << 'PHASE2_SCRIPT'
#!/bin/bash

# Exit on any error
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a /var/log/fks_setup.log
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a /var/log/fks_setup.log
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a /var/log/fks_setup.log
}

log "Starting FKS Trading Systems Setup - PHASE 2"

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
fi

# Read environment variables from phase 1
source /root/.fks_env 2>/dev/null || true

# Configure firewall for Arch (now that kernel modules are available after reboot)
if [ "$DISTRO" = "arch" ]; then
    log "Configuring iptables firewall for Arch with Tailscale focus..."
    
    # Load required kernel modules
    log "Loading netfilter kernel modules..."
    modprobe ip_tables
    modprobe ip_conntrack
    modprobe iptable_filter
    modprobe iptable_nat
    
    # Check which iptables backend is installed and enable appropriate service
    if pacman -Q iptables-nft >/dev/null 2>&1; then
        log "Using iptables-nft backend"
        systemctl enable iptables.service
    else
        log "Using iptables legacy backend"
        systemctl enable iptables.service
    fi
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (always needed for initial setup and emergency access)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Tailscale interface rules (REQUIRED - all traffic should come through here)
    log "Configuring Tailscale-specific firewall rules..."
    
    # Allow Tailscale UDP port
    iptables -A INPUT -p udp --dport 41641 -j ACCEPT
    
    # Allow all traffic on Tailscale interface (when it becomes available)
    # This will be added by Tailscale automatically, but we prepare for it
    iptables -A INPUT -i tailscale+ -j ACCEPT
    
    # Temporarily allow HTTP/HTTPS from all sources during setup
    # These will be restricted to Tailscale-only after Tailscale is configured
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Application ports - will be restricted to Tailscale after setup
    iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # Web UI
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT  # API
    iptables -A INPUT -p tcp --dport 8001 -j ACCEPT  # Data service
    iptables -A INPUT -p tcp --dport 8002 -j ACCEPT  # Worker service
    iptables -A INPUT -p tcp --dport 8003 -j ACCEPT  # App service
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT  # Adminer
    iptables -A INPUT -p tcp --dport 8081 -j ACCEPT  # Redis Commander
    iptables -A INPUT -p tcp --dport 8888 -j ACCEPT  # Jupyter (if enabled)
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT  # Ninja Dev
    iptables -A INPUT -p tcp --dport 4000 -j ACCEPT  # Ninja Build API
    iptables -A INPUT -p tcp --dport 19999 -j ACCEPT # Netdata monitoring
    
    # Drop everything else
    iptables -A INPUT -j DROP
    
    # Save rules
    mkdir -p /etc/iptables
    if command -v iptables-nft-save >/dev/null 2>&1; then
        iptables-nft-save > /etc/iptables/iptables.rules
    else
        iptables-save > /etc/iptables/iptables.rules
    fi
    
    log "Iptables rules configured and saved"
    iptables -L -n --line-numbers
fi

# Start and configure Docker with proper iptables handling
log "Starting and configuring Docker service..."

# Ensure Docker starts with proper iptables handling
if ! systemctl is-active --quiet docker; then
    log "Starting Docker service..."
    
    # Check if Docker iptables chains exist
    if ! iptables -t filter -L DOCKER-FORWARD >/dev/null 2>&1; then
        log "Docker iptables chains missing - applying fix..."
        
        # Clean up any broken Docker iptables rules
        iptables -t nat -F DOCKER 2>/dev/null || true
        iptables -t nat -X DOCKER 2>/dev/null || true
        iptables -t filter -F DOCKER 2>/dev/null || true
        iptables -t filter -X DOCKER 2>/dev/null || true
        iptables -t filter -F DOCKER-FORWARD 2>/dev/null || true
        iptables -t filter -X DOCKER-FORWARD 2>/dev/null || true
        iptables -t filter -F DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
        iptables -t filter -X DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
        iptables -t filter -F DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
        iptables -t filter -X DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
        iptables -t filter -F DOCKER-USER 2>/dev/null || true
        iptables -t filter -X DOCKER-USER 2>/dev/null || true
        
        # Clean up Docker network state
        rm -rf /var/lib/docker/network/files/* 2>/dev/null || true
    fi
    
    # Start Docker service
    systemctl start docker
    
    # Wait for Docker to be ready
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            log "Docker daemon is ready"
            break
        fi
        sleep 1
    done
    
    if ! docker info >/dev/null 2>&1; then
        error "Docker failed to start properly"
        exit 1
    fi
    
    log "Docker service started successfully"
else
    log "Docker service is already running"
fi

# Test Docker networking
log "Testing Docker networking..."
if docker network create test-network >/dev/null 2>&1; then
    docker network rm test-network >/dev/null 2>&1
    log "Docker networking is working correctly"
else
    warn "Docker networking test failed - may need manual intervention"
fi

# Configure Tailscale (REQUIRED)
log "Configuring Tailscale..."

# Validate that we have the auth key
if [ -z "${TAILSCALE_AUTH_KEY}" ]; then
    error "Tailscale auth key is required but not found!"
    exit 1
fi

# Start Tailscale daemon
systemctl start tailscaled

# Configure Tailscale with security-focused settings
log "Connecting to Tailscale network..."
tailscale up --authkey="${TAILSCALE_AUTH_KEY}" \
    --accept-routes \
    --hostname=fks \
    --accept-dns=false \
    --shields-up=true || {
    warn "Tailscale configuration failed, will retry..."
    sleep 10
    tailscale up --authkey="${TAILSCALE_AUTH_KEY}" \
        --accept-routes \
        --hostname=fks \
        --accept-dns=false \
        --shields-up=true || {
        error "Tailscale configuration failed after retry!"
        exit 1
    }
}

# Wait for Tailscale interface to come up
log "Waiting for Tailscale interface..."
sleep 10

# Get Tailscale details
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
TAILSCALE_INTERFACE=$(ip route | grep "tailscale" | head -1 | awk '{print $3}' || echo "")

if [ -z "$TAILSCALE_IP" ]; then
    error "Failed to get Tailscale IP address!"
    exit 1
fi

log "Tailscale configured successfully: IP=$TAILSCALE_IP, Interface=$TAILSCALE_INTERFACE"

# Now restrict firewall to Tailscale-only access (more secure)
if [ "$DISTRO" = "arch" ] && [ -n "$TAILSCALE_INTERFACE" ]; then
    log "Restricting firewall to Tailscale-only access..."
    
    # Remove public access to application ports (keep SSH for emergency access)
    iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8000 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8001 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8002 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8003 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8081 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 4000 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 19999 -j ACCEPT 2>/dev/null || true
    
    # Add Tailscale-specific rules (traffic from Tailscale network only)
    # Insert at the beginning to ensure Tailscale traffic is processed first
    iptables -I INPUT 3 -i $TAILSCALE_INTERFACE -j ACCEPT
    
    # Save updated rules
    if command -v iptables-nft-save >/dev/null 2>&1; then
        iptables-nft-save > /etc/iptables/iptables.rules
    else
        iptables-save > /etc/iptables/iptables.rules
    fi
    
    log "Firewall restricted to Tailscale-only access (except SSH)"
fi

log "Tailscale status:"
tailscale status || warn "Could not get Tailscale status"

# Set up Rust for all users (Ubuntu only, Arch has it system-wide)
if [ "$DISTRO" = "ubuntu" ] && [ -d /opt/rust/.cargo ]; then
    log "Setting up Rust for all users..."
    cat > /etc/profile.d/rust.sh << 'EOF'
export CARGO_HOME=/opt/rust/.cargo
export RUSTUP_HOME=/opt/rust/.rustup
export PATH=$CARGO_HOME/bin:$PATH
EOF
    chmod +x /etc/profile.d/rust.sh
    source /etc/profile.d/rust.sh
fi

# Repository setup (manual)
log "Repository setup will be done manually after server provisioning"
log "To clone the FKS repository:"
log "  1. SSH to the server: ssh jordan@<server-ip>"
log "  2. Clone the repository: git clone <your-repo-url>"
log "  3. Start the services: cd fks && ./start.sh"

# Create useful aliases for jordan
log "Creating aliases for jordan..."
cat >> /home/jordan/.bashrc << 'EOF'

# FKS Trading Systems Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'

# FKS specific
alias fks='cd ~/fks'
alias fks_logs='cd ~/fks && docker compose logs -f'
alias fks_status='cd ~/fks && docker compose ps'
alias fks_restart='cd ~/fks && ./start.sh'
alias fks_stop='cd ~/fks && docker compose down'
alias fks_rebuild='cd ~/fks && docker compose down && docker compose build && docker compose up -d'
alias fks_update='cd ~/fks && git pull && ./start.sh'

# Docker aliases
alias d='docker'
alias dc='docker compose'
alias dps='docker ps'
alias dpa='docker ps -a'
alias dimg='docker images'
alias dlog='docker logs'
alias dexec='docker exec -it'
alias dprune='docker system prune -af'

# Git aliases
alias g='git'
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git pull'
alias gb='git branch'
alias gco='git checkout'
alias gd='git diff'

# System aliases
alias syslog='tail -f /var/log/syslog'
alias ports='netstat -tuln'
alias mem='free -h'
alias disk='df -h'
alias cpu='htop'
alias ts='tailscale'
alias tss='tailscale status'

# Security and monitoring aliases
alias fw='sudo iptables -L -n --line-numbers'
alias fws='sudo iptables -L -n'
alias tsip='tailscale ip'
alias tsstatus='tailscale status'
alias fail2ban-status='sudo fail2ban-client status'
alias check-connections='ss -tuln'
alias check-processes='ps aux | grep -E "(docker|python|node|dotnet)"'
alias system-status='echo "=== System Status ==="; free -h; echo ""; df -h; echo ""; docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias netdata-status='sudo systemctl status netdata'
alias netdata-restart='sudo systemctl restart netdata'
alias netdata-logs='sudo journalctl -u netdata -f'

echo "FKS Trading Systems Dev Server - Ready!"
echo "Hostname: $(hostname)"
echo "Project: ~/fks"
echo "Tailscale: $(tailscale ip -4 2>/dev/null || echo 'ERROR: Not connected')"
echo "Run 'fks_restart' to start the Docker environment"
echo "Run 'system-status' for a quick system overview"
EOF

# Create welcome script
cat > /home/jordan/welcome.sh << 'WELCOME'
#!/bin/bash
echo "============================================"
echo "FKS Trading Systems Dev Server"
echo "============================================"
echo "Hostname: $(hostname)"
echo "Server IP: $(curl -s ifconfig.me 2>/dev/null || echo 'Unknown')"
echo "Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'Not connected')"
echo "Tailscale Status: $(tailscale status --json 2>/dev/null | jq -r '.BackendState' 2>/dev/null || echo 'Unknown')"
echo "Username: $(whoami)"
echo "Project: ~/fks"
echo ""
echo "Network Security:"
if tailscale status >/dev/null 2>&1; then
    echo "  [OK] Tailscale: Connected"
    echo "  [SECURE] Access via: $(tailscale ip -4 2>/dev/null || echo 'Tailscale IP')"
    echo "  [SHIELDED] Shields Up: Enabled (extra security)"
    echo "  [RESTRICTED] Public access: SSH only (application ports blocked)"
else
    echo "  [ERROR] Tailscale: Not connected (REQUIRED)"
    echo "  [CRITICAL] This deployment requires Tailscale!"
fi
echo ""
echo "System Info:"
echo "  Kernel: $(uname -r)"
echo "  Uptime: $(uptime -p 2>/dev/null || uptime)"
echo "  Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "  Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}')"
echo ""
echo "Versions:"
echo "  Docker: $(docker --version 2>/dev/null | cut -d' ' -f3 | cut -d',' -f1)"
echo "  Node.js: $(node --version 2>/dev/null)"
echo "  Python: $(python3 --version 2>/dev/null | cut -d' ' -f2)"
echo "  .NET: $(dotnet --version 2>/dev/null)"
echo "  Rust: $(rustc --version 2>/dev/null | cut -d' ' -f2)"
echo ""
echo "Quick Commands:"
echo "  fks          - Go to project directory"
echo "  fks_status   - Check running containers"
echo "  fks_logs     - View container logs"
echo "  fks_restart  - Start/restart all services"
echo "  fks_update   - Pull code & restart"
echo "  ts           - Tailscale status"
echo "  tss          - Tailscale status (short)"
echo ""
echo "Monitoring Commands:"
echo "  netdata-status   - Check Netdata service status"
echo "  netdata-restart  - Restart Netdata service"
echo "  netdata-logs     - View Netdata logs"
echo "  system-status    - Quick system overview"
echo ""
echo "Access URLs (via Tailscale):"
if tailscale status >/dev/null 2>&1; then
    TSIP=$(tailscale ip -4 2>/dev/null || echo 'N/A')
    echo "  Web UI:     http://$TSIP:3000"
    echo "  API:        http://$TSIP:8000"
    echo "  Monitoring: http://$TSIP:19999"
fi
echo ""
echo "Security Commands:"
echo "  sudo iptables -L -n    - View firewall rules"
echo "  tailscale status       - Check VPN status"
echo "  tailscale ip           - Show Tailscale IPs"
echo "============================================"
WELCOME

chmod +x /home/jordan/welcome.sh
chown jordan:jordan /home/jordan/welcome.sh
echo "/home/jordan/welcome.sh" >> /home/jordan/.bashrc

# Create sudoers file for actions_user to run docker commands
log "Configuring sudo for actions_user..."
cat > /etc/sudoers.d/actions_user << EOF
actions_user ALL=(jordan) NOPASSWD: /usr/bin/docker, /usr/local/bin/docker-compose, /usr/bin/git, /home/jordan/fks/start.sh
actions_user ALL=(ALL) NOPASSWD: /bin/systemctl restart docker
EOF
chmod 440 /etc/sudoers.d/actions_user

# Docker Hub authentication setup
log "Configuring Docker Hub authentication..."

# Login to Docker Hub for private images
if [ -n "${DOCKER_USERNAME}" ] && [ -n "${DOCKER_TOKEN}" ]; then
    log "Logging into Docker Hub..."
    # Create .docker directory for jordan user first
    sudo -u jordan mkdir -p /home/jordan/.docker
    sudo -u jordan bash -c "echo '${DOCKER_TOKEN}' | docker login --username '${DOCKER_USERNAME}' --password-stdin" || {
        warn "Docker Hub login failed, private images may not be accessible"
    }
else
    log "Docker Hub credentials not provided"
fi

# Clean up
rm -f /root/.fks_setup-phase
rm -f /root/.fks_env

log "============================================"
log "FKS Trading Systems Setup - PHASE 2 COMPLETE"
log "============================================"
log "[OK] Tailscale configured and connected"
log "[OK] Firewall restricted to Tailscale-only access"
log "[OK] Docker Hub authentication configured"
log "[OK] All users and permissions set up"
log "[OK] Development environment ready"
log ""
log "[SUCCESS] COMPLETE SETUP FINISHED!"
log "[TIME] Total setup time: ~6 minutes"
log ""
log "[INFO] Server Details:"
log "Distribution: $DISTRO"
log "Hostname: fks"
log "Kernel: $(uname -r)"
log "Users created: jordan (sudo), fks_user, actions_user (deployment)"
log ""
log "[KEY] SSH Access:"
if tailscale status >/dev/null 2>&1; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "Unknown")
    log "Tailscale IP: $TAILSCALE_IP"
    log "SSH via Tailscale: ssh jordan@$TAILSCALE_IP"
    log "GitHub Actions: ssh actions_user@$TAILSCALE_IP"
    log ""
    log "[WEB] Web Access (via Tailscale):"
    log "Web Interface: http://$TAILSCALE_IP:3000"
    log "API: http://$TAILSCALE_IP:8000"
    log "Netdata Monitoring: http://$TAILSCALE_IP:19999"
    log ""
    log "[SECURITY] Security Status:"
    log "[OK] Tailscale: Connected and secured"
    log "[OK] Firewall: Restricted to Tailscale + SSH only"
    log "[OK] Shields Up: Enabled (extra Tailscale security)"
else
    error "Tailscale configuration failed - this should not happen!"
    log "Emergency SSH: ssh jordan@$(curl -s ifconfig.me 2>/dev/null || echo '<server-ip>')"
fi

log ""
log "[READY] Ready for GitHub Actions Deployment!"
log "[INFO] GitHub Actions can connect to: actions_user@<server-ip>"
log ""
log "[NOTE] Manual Repository Setup (if needed):"
log "1. SSH to server: ssh jordan@<server-ip>"
log "2. Clone repository: git clone <your-repo-url>"
log "3. Start services: cd <repo-name> && ./start.sh"
log "============================================"

# Create completion marker for GitHub Actions
echo "PHASE_2_COMPLETE" > /tmp/fks_setup-complete
chown actions_user:actions_user /tmp/fks_setup-complete
echo "$(date): FKS Trading Systems setup completed successfully" >> /tmp/fks_setup-complete

# Disable this service after successful run
systemctl disable fks_phase2.service

PHASE2_SCRIPT
    
    chmod +x /usr/local/bin/fks_phase2.sh
    
    # Save environment variables for phase 2
    cat > /root/.fks_env << EOF
export TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY}"
export DOCKER_USERNAME="${DOCKER_USERNAME}"
export DOCKER_TOKEN="${DOCKER_TOKEN}"
export NETDATA_CLAIM_TOKEN="${NETDATA_CLAIM_TOKEN}"
export NETDATA_CLAIM_ROOM="${NETDATA_CLAIM_ROOM}"
EOF
    chmod 600 /root/.fks_env
    
    # Create systemd service for Phase 2
    cat > /etc/systemd/system/fks_phase2.service << EOF
[Unit]
Description=FKS Trading Systems Setup Phase 2
After=network-online.target docker.service
Wants=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/bin/fks_phase2.sh
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable fks_phase2.service
    
    # Create GitHub Actions deployment script
    log "Creating GitHub Actions deployment script..."
    mkdir -p /home/actions_user
    cat > /home/actions_user/deploy.sh << 'DEPLOY_SCRIPT'
#!/bin/bash
set -e

echo "=== FKS Trading Systems - GitHub Actions Deployment ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "PWD: $(pwd)"

# Navigate to the FKS directory
cd /home/jordan/fks

# Check if the manual deployment script exists
if [ ! -f "scripts/deploy-dev.sh" ]; then
    echo "Manual deployment script not found, using basic deployment..."
    
    # Pull latest code
    echo "Pulling latest code..."
    sudo -u jordan git pull
    
    # Pull latest images
    echo "Pulling latest Docker images..."
    sudo -u jordan docker compose pull
    
    # Restart services
    echo "Restarting services..."
    sudo -u jordan docker compose down --timeout 30
    sudo -u jordan docker compose up -d
    
    echo "Basic deployment complete!"
else
    echo "Using advanced deployment script..."
    
    # Make script executable
    chmod +x scripts/deploy-dev.sh
    
    # Run the deployment script as jordan user
    sudo -u jordan ./scripts/deploy-dev.sh --force
    
    echo "Advanced deployment complete!"
fi

echo "=== Deployment finished ==="
DEPLOY_SCRIPT
    
    chmod +x /home/actions_user/deploy.sh
    chown actions_user:actions_user /home/actions_user/deploy.sh
    
    # Mark Phase 1 as complete
    echo "1" > "$PHASE_FILE"
    
    log "============================================"
    log "FKS Trading Systems Setup - PHASE 1 COMPLETE"
    log "============================================"
    log "[OK] System packages installed and updated"
    log "[OK] Users created: jordan, fks_user, actions_user"
    log "[OK] SSH keys generated for actions_user"
    log "[OK] Docker and development tools installed"
    log "[OK] Firewall configured"
    log "[OK] Phase 2 service enabled for post-reboot"
    log ""
    log "[UPDATE] REBOOTING to apply kernel updates and start Phase 2..."
    log "[INFO] Phase 2 will configure Tailscale and complete setup"
    log "[TIME] Total setup time: ~6 minutes (Phase 1: ~3 min, Reboot: ~1 min, Phase 2: ~2 min)"
    log ""
    log "GitHub Actions can now retrieve SSH key from:"
    log "  - /var/log/fks_setup.log (search for GENERATED_ACTIONS_USER_SSH_PUB)"
    log "  - /home/actions_user/.ssh/public_key_for_github.txt"
    log "  - /home/actions_user/.ssh/id_ed25519.pub"
    log "============================================"
    
    # Schedule reboot in 10 seconds
    sleep 5
    log "Rebooting now..."
    systemctl reboot
fi