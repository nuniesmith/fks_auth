#!/bin/bash

# FKS Trading Systems - Stage 1: Initial Setup
# Based on the working StackScript Phase 1
# Installs packages, creates users, configures SSH, and prepares for reboot
# 
# *** ARCH LINUX ONLY ***
# This script only supports Arch Linux servers. Ubuntu/Debian support has been removed.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    if [ -w /var/log/fks_setup.log ] 2>/dev/null; then
        echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a /var/log/fks_setup.log
    else
        echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    fi
}

warn() {
    if [ -w /var/log/fks_setup.log ] 2>/dev/null; then
        echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a /var/log/fks_setup.log
    else
        echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
    fi
}

error() {
    if [ -w /var/log/fks_setup.log ] 2>/dev/null; then
        echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a /var/log/fks_setup.log
    else
        echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    fi
}

# Default values
TARGET_HOST=""
FKS_DEV_ROOT_PASSWORD=""
JORDAN_PASSWORD=""
FKS_USER_PASSWORD=""
TAILSCALE_AUTH_KEY=""
DOCKER_USERNAME=""
DOCKER_TOKEN=""
NETDATA_CLAIM_TOKEN=""
NETDATA_CLAIM_ROOM=""
TIMEZONE="America/Toronto"
ACTIONS_JORDAN_SSH_PUB=""
ACTIONS_USER_SSH_PUB=""
ACTIONS_ROOT_SSH_PUB=""
ACTIONS_FKS_SSH_PUB=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --root-password)
            FKS_DEV_ROOT_PASSWORD="$2"
            shift 2
            ;;
        --jordan-password)
            JORDAN_PASSWORD="$2"
            shift 2
            ;;
        --fks_user-password)
            FKS_USER_PASSWORD="$2"
            shift 2
            ;;
        --tailscale-auth-key)
            TAILSCALE_AUTH_KEY="$2"
            shift 2
            ;;
        --docker-username)
            DOCKER_USERNAME="$2"
            shift 2
            ;;
        --docker-token)
            DOCKER_TOKEN="$2"
            shift 2
            ;;
        --netdata-claim-token)
            NETDATA_CLAIM_TOKEN="$2"
            shift 2
            ;;
        --netdata-claim-room)
            NETDATA_CLAIM_ROOM="$2"
            shift 2
            ;;
        --timezone)
            TIMEZONE="$2"
            shift 2
            ;;
        --jordan-ssh-pub)
            ACTIONS_JORDAN_SSH_PUB="$2"
            shift 2
            ;;
        --actions_user-ssh-pub)
            ACTIONS_USER_SSH_PUB="$2"
            shift 2
            ;;
        --root-ssh-pub)
            ACTIONS_ROOT_SSH_PUB="$2"
            shift 2
            ;;
        --fks_user-ssh-pub)
            ACTIONS_FKS_SSH_PUB="$2"
            shift 2
            ;;
        --env-file)
            if [ -f "$2" ]; then
                source "$2"
            else
                error "Environment file not found: $2"
                exit 1
            fi
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --target-host <host>           Target server host/IP"
            echo "  --root-password <pass>         Root password for SSH (REQUIRED for remote)"
            echo "  --jordan-password <pass>       Password for jordan user"
            echo "  --fks_user-password <pass>     Password for fks_user"
            echo "  --tailscale-auth-key <key>     Tailscale auth key (REQUIRED)"
            echo "  --docker-username <user>    Docker Hub username"
            echo "  --docker-token <token>      Docker Hub access token"
            echo "  --netdata-claim-token <token>  Netdata claim token"
            echo "  --netdata-claim-room <room>    Netdata room ID"
            echo "  --timezone <tz>                Server timezone (default: America/Toronto)"
            echo "  --jordan-ssh-pub <key>         Jordan's SSH public key"
            echo "  --actions_user-ssh-pub <key> GitHub Actions SSH public key"
            echo "  --root-ssh-pub <key>           Root SSH public key"
            echo "  --fks_user-ssh-pub <key>       FKS User SSH public key"
            echo "  --env-file <file>              Load environment from file"
            echo "  --help                         Show this help message"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load server details if available
if [ -f "server-details.env" ]; then
    source server-details.env
fi

# Validate required parameters
if [ -z "$TARGET_HOST" ]; then
    error "Target host is required (--target-host or TARGET_HOST environment variable)"
    exit 1
fi

if [ -z "$TAILSCALE_AUTH_KEY" ]; then
    error "Tailscale auth key is required (--tailscale-auth-key)"
    exit 1
fi

if [ -z "$JORDAN_PASSWORD" ]; then
    error "Jordan password is required (--jordan-password)"
    exit 1
fi

if [ -z "$FKS_USER_PASSWORD" ]; then
    error "FKS user password is required (--fks_user-password)"
    exit 1
fi

log "Starting FKS Trading Systems - Stage 1: Initial Setup"
log "Target Host: $TARGET_HOST"

# Always use remote connection to root@public_ip for initial setup
log "Connecting to root@$TARGET_HOST for initial setup"
RUN_LOCAL=false

# Validate root password for remote connection
if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
    error "Root password is required for initial connection (--root-password or FKS_DEV_ROOT_PASSWORD environment variable)"
    exit 1
fi

# Check if sshpass is available
if ! command -v sshpass >/dev/null 2>&1; then
    log "Installing sshpass for password-based SSH..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y sshpass
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm sshpass
    else
        error "Cannot install sshpass - unsupported package manager"
        exit 1
    fi
fi

# Test SSH connectivity to root@public_ip with robust retry logic
log "Testing SSH connectivity to root@$TARGET_HOST with password authentication..."
SSH_TIMEOUT=180  # 3 minutes total timeout
SSH_ATTEMPTS=18  # 10 second intervals = 18 attempts
SSH_SUCCESS=false

for i in $(seq 1 $SSH_ATTEMPTS); do
    log "SSH attempt $i/$SSH_ATTEMPTS to root@$TARGET_HOST..."
    
    if timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
        log "SSH connection to root@$TARGET_HOST successful!"
        SSH_SUCCESS=true
        break
    else
        warn "SSH attempt $i failed, waiting 10 seconds before retry..."
        sleep 10
    fi
done

if [ "$SSH_SUCCESS" = "false" ]; then
    error "Failed to connect to root@$TARGET_HOST after $SSH_ATTEMPTS attempts"
    error "Please verify:"
    error "  1. Server is fully booted and ready"
    error "  2. Root password is correct"
    error "  3. SSH service is running on the server"
    error "  4. Network connectivity to $TARGET_HOST"
    exit 1
fi

# Create the setup script
SETUP_SCRIPT=$(mktemp)
cat > "$SETUP_SCRIPT" << 'EOF'
#!/bin/bash

# FKS Trading Systems - Stage 1 Setup Script
# This script runs on the target server

set -e

# Parameters passed from main script
JORDAN_PASSWORD="$1"
FKS_USER_PASSWORD="$2"
TAILSCALE_AUTH_KEY="$3"
DOCKER_USERNAME="$4"
DOCKER_TOKEN="$5"
NETDATA_CLAIM_TOKEN="$6"
NETDATA_CLAIM_ROOM="$7"
TIMEZONE="$8"
ACTIONS_JORDAN_SSH_PUB="$9"
ACTIONS_USER_SSH_PUB="${10}"
ACTIONS_ROOT_SSH_PUB="${11}"
ACTIONS_FKS_SSH_PUB="${12}"

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

# Detect distribution - Arch Linux only
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    else
        error "Cannot detect distribution from /etc/os-release"
        exit 1
    fi
    
    if [ "$DISTRO" != "arch" ]; then
        error "This script only supports Arch Linux. Detected: $DISTRO"
        log "For migration from other distributions, manually set up an Arch Linux server."
        exit 1
    fi
    
    log "Confirmed Arch Linux distribution: $DISTRO $DISTRO_VERSION"
}

# Arch Linux package installation
install_arch() {
    log "Cleaning package cache and fixing potential issues..."
    rm -f /var/lib/pacman/db.lck 2>/dev/null || true
    pacman -Scc --noconfirm
    
    log "Updating Arch Linux system packages..."
    pacman -Sy --noconfirm archlinux-keyring || true
    
    # Handle nvidia firmware conflicts
    if [ -d /usr/lib/firmware/nvidia ]; then
        log "Backing up and removing conflicting nvidia firmware files..."
        mkdir -p /tmp/nvidia-firmware-backup
        cp -r /usr/lib/firmware/nvidia /tmp/nvidia-firmware-backup/ 2>/dev/null || true
        rm -rf /usr/lib/firmware/nvidia/ad10* 2>/dev/null || true
    fi
    
    if ! pacman -Syu --noconfirm --overwrite '/usr/lib/firmware/nvidia/*'; then
        warn "Standard update failed, trying alternative methods..."
        pacman -Syu --noconfirm --ignore linux-firmware-nvidia --ignore linux-firmware || true
        pacman -S --noconfirm --overwrite '/usr/lib/firmware/*' linux-firmware linux-firmware-nvidia || {
            warn "Firmware update failed, removing and reinstalling..."
            pacman -Rdd --noconfirm linux-firmware-nvidia 2>/dev/null || true
            pacman -S --noconfirm linux-firmware-nvidia linux-firmware
        }
        pacman -Su --noconfirm
    fi
    
    log "Installing essential packages for Arch Linux..."
    
    # Install packages in groups to handle conflicts better
    log "Installing base development and system packages..."
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
        net-tools \
        python \
        python-pip \
        openssl \
        linux \
        linux-headers \
        linux-firmware || {
        warn "Some base packages failed, continuing..."
    }
    
    log "Installing development tools..."
    pacman -S --noconfirm --needed \
        nodejs \
        npm \
        dotnet-sdk \
        dotnet-runtime \
        aspnet-runtime \
        rust \
        go || {
        warn "Some development tools failed, continuing..."
    }
    
    log "Installing Docker and related services..."
    pacman -S --noconfirm --needed \
        docker \
        docker-compose \
        tailscale || {
        warn "Some service packages failed, continuing..."
    }
    
    log "Installing security and firewall packages..."
    pacman -S --noconfirm --needed \
        fail2ban || {
        warn "fail2ban installation failed, continuing..."
    }
    
    # Handle iptables conflict explicitly
    log "Handling iptables installation..."
    
    # First check what's currently installed
    if pacman -Q iptables-nft >/dev/null 2>&1; then
        log "iptables-nft is already installed"
    elif pacman -Q iptables >/dev/null 2>&1; then
        log "Legacy iptables is installed, removing to avoid conflicts..."
        if ! pacman -Rdd --noconfirm iptables 2>/dev/null; then
            warn "Could not remove legacy iptables, trying to work with it"
        else
            log "Successfully removed legacy iptables"
        fi
    fi
    
    # Try to install iptables-nft
    if ! pacman -Q iptables-nft >/dev/null 2>&1; then
        log "Installing iptables-nft..."
        if pacman -S --noconfirm --needed iptables-nft; then
            log "Successfully installed iptables-nft"
        else
            warn "iptables-nft installation failed, trying legacy iptables..."
            if pacman -S --noconfirm --needed iptables; then
                log "Fallback to legacy iptables successful"
            else
                error "Failed to install any iptables variant - this may cause firewall issues"
                error "The system will still function but firewall configuration may fail"
            fi
        fi
    fi
    
    # Enable services (Docker and Tailscale will be started in Phase 2)
    # Note: Not enabling Docker here as it will be handled in Phase 2 after kernel reboot
    systemctl enable tailscaled.service
    
    # Docker iptables fix will be handled in Phase 2 after kernel reboot
    log "Docker iptables fix logic moved to Phase 2 (after reboot with updated kernel)"
}

# Firewall setup for Arch Linux with iptables
setup_firewall() {
    log "Setting up firewall packages for Arch Linux..."
    
    # Check what's already installed and handle conflicts
    if pacman -Q iptables-nft >/dev/null 2>&1; then
        log "iptables-nft already installed, using nft backend"
    elif pacman -Q iptables >/dev/null 2>&1; then
        log "iptables (legacy) is installed, this is fine for basic functionality"
    else
        warn "No iptables variant found - this should not happen after package installation"
    fi
    
    # Ensure we have linux-headers for iptables modules
    pacman -S --noconfirm --needed linux-headers || {
        warn "linux-headers installation failed, firewall modules may not work properly"
    }
    
    log "Firewall packages configured. Rules will be set up in Stage 2 after reboot when kernel modules are available"
}

log "Starting FKS Trading Systems Setup - Stage 1"

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

# Set timezone for Arch Linux
log "Setting timezone to ${TIMEZONE}..."
ln -sf /usr/share/zoneinfo/${TIMEZONE} /etc/localtime
hwclock --systohc

# Install packages for Arch Linux only
log "Installing packages for Arch Linux..."
install_arch

# Install Docker Compose standalone
log "Installing Docker Compose standalone..."
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*?(?=")' || echo "v2.24.0")
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Tailscale for Arch Linux
log "Installing Tailscale for Arch Linux..."
# Tailscale already installed via pacman in install_arch function
systemctl enable tailscaled.service

# Install Netdata monitoring
log "Installing Netdata monitoring..."
curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh
chmod +x /tmp/netdata-kickstart.sh

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

# Create users and set up SSH keys
log "Creating users and setting up SSH keys..."

# Create jordan user (admin user)
log "Creating jordan user for admin access..."
if ! id jordan &>/dev/null; then
    useradd -m -s /bin/bash jordan
fi

if [ -n "${JORDAN_PASSWORD}" ]; then
    echo "jordan:${JORDAN_PASSWORD}" | chpasswd
    log "Password set for jordan user"
fi

# Add jordan to wheel group for sudo access on Arch
usermod -aG wheel jordan
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers
usermod -aG docker jordan

# Create fks_user (service account for Docker)
log "Creating fks_user (service account for Docker)..."
if ! id fks_user &>/dev/null; then
    useradd -m -s /bin/bash fks_user
fi

if [ -n "${FKS_USER_PASSWORD}" ]; then
    echo "fks_user:${FKS_USER_PASSWORD}" | chpasswd
    log "Password set for fks_user"
fi

# Add fks_user to docker group for running containers
usermod -aG docker fks_user

# Create actions_user user (GitHub Actions deployment user)
# Using hyphen for consistency with StackScript
log "Creating actions_user user (GitHub Actions deployment user)..."
if ! id actions_user &>/dev/null; then
    useradd -m -s /bin/bash actions_user
fi

# Add actions_user to docker group and sudo for deployment operations
usermod -aG docker actions_user
usermod -aG wheel actions_user

# Generate SSH keys for actions_user (for GitHub repository access)
log "Generating SSH keys for actions_user (for GitHub repository access)..."
mkdir -p /home/actions_user/.ssh
chmod 700 /home/actions_user/.ssh

# Remove existing keys if they exist to avoid overwrite prompts
rm -f /home/actions_user/.ssh/id_ed25519 /home/actions_user/.ssh/id_ed25519.pub

# Generate Ed25519 key for GitHub repository access
ssh-keygen -t ed25519 -f /home/actions_user/.ssh/id_ed25519 -N "" -C "actions_user@fks_$(date +%Y%m%d)"

# Set proper ownership
chown -R actions_user:actions_user /home/actions_user/.ssh
chmod 600 /home/actions_user/.ssh/id_ed25519
chmod 644 /home/actions_user/.ssh/id_ed25519.pub

# Store the public key for display later
GITHUB_ACTIONS_SSH_PUB=$(cat /home/actions_user/.ssh/id_ed25519.pub)
log "SSH key generated for actions_user repository access"

# Setup SSH authorized_keys for remote access
log "Setting up SSH authorized_keys for all users..."

setup_ssh_for_user() {
    local username=$1
    local ssh_pub_key=$2
    local home_dir="/home/$username"
    
    if [ "$username" = "root" ]; then
        home_dir="/root"
    fi
    
    mkdir -p "$home_dir/.ssh"
    chmod 700 "$home_dir/.ssh"
    
    # Clear any existing authorized_keys to avoid duplicates
    > "$home_dir/.ssh/authorized_keys"
    
    if [ -n "$ssh_pub_key" ]; then
        echo "$ssh_pub_key" >> "$home_dir/.ssh/authorized_keys"
        chmod 600 "$home_dir/.ssh/authorized_keys"
        log "Added SSH key for $username"
    else
        warn "No SSH public key provided for $username"
    fi
    
    if [ "$username" != "root" ]; then
        chown -R "$username:$username" "$home_dir/.ssh"
    fi
}

# Set up SSH keys for all 4 users
# Note: All users get ACTIONS_USER_SSH_PUB for GitHub Actions access
setup_ssh_for_user "root" "$ACTIONS_USER_SSH_PUB"
setup_ssh_for_user "jordan" "$ACTIONS_USER_SSH_PUB"
setup_ssh_for_user "fks_user" "$ACTIONS_USER_SSH_PUB"
setup_ssh_for_user "actions_user" "$ACTIONS_USER_SSH_PUB"

log "SSH keys configured for all users"

# Add device-specific SSH keys to jordan's authorized_keys
log "Adding device-specific SSH keys to jordan's authorized_keys..."
[ -n "$DESKTOP_SSH_PUB" ] && echo "$DESKTOP_SSH_PUB" >> /home/jordan/.ssh/authorized_keys && log "Added Desktop SSH key"
[ -n "$MACBOOK_SSH_PUB" ] && echo "$MACBOOK_SSH_PUB" >> /home/jordan/.ssh/authorized_keys && log "Added MacBook SSH key"
[ -n "$ORYX_SSH_PUB" ] && echo "$ORYX_SSH_PUB" >> /home/jordan/.ssh/authorized_keys && log "Added Oryx SSH key"
[ -n "$FREDDY_SSH_PUB" ] && echo "$FREDDY_SSH_PUB" >> /home/jordan/.ssh/authorized_keys && log "Added Freddy SSH key"
[ -n "$SULLIVAN_SSH_PUB" ] && echo "$SULLIVAN_SSH_PUB" >> /home/jordan/.ssh/authorized_keys && log "Added Sullivan SSH key"

# Also add device keys to fks_user for convenience
log "Adding device-specific SSH keys to fks_user's authorized_keys..."
[ -n "$DESKTOP_SSH_PUB" ] && echo "$DESKTOP_SSH_PUB" >> /home/fks_user/.ssh/authorized_keys && log "Added Desktop SSH key to fks_user"
[ -n "$MACBOOK_SSH_PUB" ] && echo "$MACBOOK_SSH_PUB" >> /home/fks_user/.ssh/authorized_keys && log "Added MacBook SSH key to fks_user"
[ -n "$ORYX_SSH_PUB" ] && echo "$ORYX_SSH_PUB" >> /home/fks_user/.ssh/authorized_keys && log "Added Oryx SSH key to fks_user"
[ -n "$FREDDY_SSH_PUB" ] && echo "$FREDDY_SSH_PUB" >> /home/fks_user/.ssh/authorized_keys && log "Added Freddy SSH key to fks_user"
[ -n "$SULLIVAN_SSH_PUB" ] && echo "$SULLIVAN_SSH_PUB" >> /home/fks_user/.ssh/authorized_keys && log "Added Sullivan SSH key to fks_user"

# Fix permissions
chmod 600 /home/jordan/.ssh/authorized_keys 2>/dev/null || true
chmod 600 /home/fks_user/.ssh/authorized_keys 2>/dev/null || true
chown jordan:jordan /home/jordan/.ssh/authorized_keys 2>/dev/null || true
chown fks_user:fks_user /home/fks_user/.ssh/authorized_keys 2>/dev/null || true

# Configure Git for actions_user
log "Configuring Git for actions_user..."
sudo -u actions_user bash << 'GIT_CONFIG_EOF'
cd /home/actions_user

# Set Git configuration
git config --global user.name "nuniesmith"
git config --global user.email "nunie.smith01@gmail.com"
git config --global init.defaultBranch main
git config --global pull.rebase false

# Configure SSH for GitHub
cat >> /home/actions_user/.ssh/config << 'SSH_CONFIG_EOF'
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
SSH_CONFIG_EOF

chmod 600 /home/actions_user/.ssh/config
GIT_CONFIG_EOF

# Create repository management script
log "Creating repository management script..."
cat > /home/actions_user/manage-repo.sh << 'REPO_SCRIPT_EOF'
#!/bin/bash

# FKS Repository Management Script
# Handles cloning, updating, and permission management for the FKS repository

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR: $1${NC}"
}

# Default values
REPO_URL=""
TARGET_DIR="/home/fks_user/fks"
BRANCH="main"
FORCE_CLONE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        --target-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        --force)
            FORCE_CLONE=true
            shift
            ;;
        --help)
            echo "FKS Repository Management Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --repo-url <url>     Repository URL (SSH or HTTPS)"
            echo "  --target-dir <dir>   Target directory (default: /home/fks_user/fks)"
            echo "  --branch <branch>    Branch to checkout (default: main)"
            echo "  --force              Force re-clone if directory exists"
            echo "  --help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --repo-url git@github.com:user/fks.git"
            echo "  $0 --repo-url https://github.com/user/fks.git --branch develop"
            echo "  $0 --repo-url git@github.com:user/fks.git --force"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$REPO_URL" ]; then
    error "Repository URL is required (--repo-url)"
    echo "Use --help for usage information"
    exit 1
fi

log "🔄 FKS Repository Management"
log "Repository: $REPO_URL"
log "Target: $TARGET_DIR"
log "Branch: $BRANCH"

# Check if target directory exists
if [ -d "$TARGET_DIR" ]; then
    if [ "$FORCE_CLONE" = "true" ]; then
        log "Force clone requested, removing existing directory..."
        sudo rm -rf "$TARGET_DIR"
    else
        log "Directory exists, attempting to update..."
        if [ -d "$TARGET_DIR/.git" ]; then
            log "Git repository detected, pulling latest changes..."
            cd "$TARGET_DIR"
            
            # Check if we can access the remote
            if git remote get-url origin >/dev/null 2>&1; then
                # Update the repository
                git fetch origin
                git checkout "$BRANCH"
                git pull origin "$BRANCH"
                log "✅ Repository updated successfully"
                
                # Fix permissions
                log "Fixing permissions for fks_user..."
                sudo chown -R fks_user:fks_user "$TARGET_DIR"
                
                exit 0
            else
                warn "Cannot access remote, will re-clone..."
                sudo rm -rf "$TARGET_DIR"
            fi
        else
            warn "Directory exists but is not a Git repository, will re-clone..."
            sudo rm -rf "$TARGET_DIR"
        fi
    fi
fi

# Create target directory parent if needed
TARGET_PARENT=$(dirname "$TARGET_DIR")
if [ ! -d "$TARGET_PARENT" ]; then
    log "Creating parent directory: $TARGET_PARENT"
    sudo mkdir -p "$TARGET_PARENT"
fi

# Clone the repository
log "Cloning repository..."
if git clone "$REPO_URL" "$TARGET_DIR"; then
    log "✅ Repository cloned successfully"
    
    # Checkout specific branch if not main
    if [ "$BRANCH" != "main" ]; then
        log "Checking out branch: $BRANCH"
        cd "$TARGET_DIR"
        git checkout "$BRANCH"
    fi
    
    # Fix permissions for fks_user
    log "Setting permissions for fks_user..."
    sudo chown -R fks_user:fks_user "$TARGET_DIR"
    
    # Make scripts executable
    if [ -f "$TARGET_DIR/start.sh" ]; then
        chmod +x "$TARGET_DIR/start.sh"
        log "Made start.sh executable"
    fi
    
    if [ -d "$TARGET_DIR/scripts" ]; then
        find "$TARGET_DIR/scripts" -name "*.sh" -exec chmod +x {} \;
        log "Made scripts executable"
    fi
    
    log "🎉 Repository setup complete!"
    echo ""
    echo "Next steps:"
    echo "  sudo su - fks_user"
    echo "  cd /home/fks_user/fks"
    echo "  ./start.sh"
    
else
    error "❌ Failed to clone repository"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check if SSH key is added to GitHub:"
    echo "   cat ~/.ssh/id_ed25519.pub"
    echo "2. Test SSH connection:"
    echo "   ssh -T git@github.com"
    echo "3. Check repository URL:"
    echo "   $REPO_URL"
    exit 1
fi
REPO_SCRIPT_EOF

chmod +x /home/actions_user/manage-repo.sh
chown actions_user:actions_user /home/actions_user/manage-repo.sh

# Create quick access script for fks_user
log "Creating FKS startup script for fks_user..."
cat > /home/fks_user/start-fks.sh << 'FKS_START_EOF'
#!/bin/bash

# FKS Quick Start Script for fks_user
# Checks for repository and starts the FKS trading system

set -e

FKS_DIR="/home/fks_user/fks"

if [ ! -d "$FKS_DIR" ]; then
    echo "❌ FKS repository not found at $FKS_DIR"
    echo ""
    echo "To set up the repository, run as actions_user:"
    echo "  su - actions_user"
    echo "  ./manage-repo.sh --repo-url git@github.com:YOUR_USERNAME/YOUR_REPO.git"
    echo ""
    echo "Or clone manually:"
    echo "  git clone YOUR_REPO_URL $FKS_DIR"
    echo "  sudo chown -R fks_user:fks_user $FKS_DIR"
    exit 1
fi

if [ ! -f "$FKS_DIR/start.sh" ]; then
    echo "❌ start.sh not found in $FKS_DIR"
    echo "Make sure the FKS repository is properly cloned"
    exit 1
fi

echo "🚀 Starting FKS Trading Systems..."
cd "$FKS_DIR"
./start.sh "$@"
FKS_START_EOF

chmod +x /home/fks_user/start-fks.sh
chown fks_user:fks_user /home/fks_user/start-fks.sh

# Configure SSH
log "Configuring SSH security for deployment..."
if ! grep -q "Custom security settings" /etc/ssh/sshd_config; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    cat >> /etc/ssh/sshd_config << 'SSH_EOF'

# Custom security settings for FKS deployment
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2

# Allow specific users for deployment
AllowUsers root jordan actions_user fks_user

# Security hardening
Protocol 2
X11Forwarding no
PrintMotd no
UsePAM yes
SSH_EOF

    # Restart SSH service to apply changes
    log "Restarting SSH service to apply configuration..."
    systemctl restart sshd
    systemctl enable sshd
    
    # Wait a moment for SSH to fully restart
    sleep 3
    
    log "SSH service restarted and enabled"
    log "SSH Configuration Summary:"
    log "  - Root login: enabled (for deployment reliability)"
    log "  - Password auth: enabled (for fallback)"
    log "  - Key auth: enabled (primary method)"
    log "  - Allowed users: root, jordan, actions_user, fks_user"
    log "  - GitHub Actions will connect as: actions_user@public_ip"
fi

# Setup firewall
setup_firewall

# Configure fail2ban
log "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'FAIL2BAN_EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
FAIL2BAN_EOF

systemctl enable fail2ban

# Create Stage 2 script (matching StackScript logic)
log "Creating Stage 2 auto-run script..."
cat > /usr/local/bin/fks_stage2.sh << 'STAGE2_SCRIPT'
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

log "Starting FKS Trading Systems Setup - Stage 2 (Auto-run)"

# Read environment variables from stage 1
source /root/.fks_env 2>/dev/null || true

# This script is deprecated - the functionality has been moved to fks_phase2.sh
log "Stage 2 functionality has been moved to fks_phase2.sh"
log "This script is a placeholder for compatibility"

log "Stage 2 placeholder complete"
STAGE2_SCRIPT

chmod +x /usr/local/bin/fks_stage2.sh
log "Firewall will be configured in Stage 2 after reboot when kernel modules are available"

# Debug: Show environment variables
log "Debug: Environment variables:"
log "SKIP_IPTABLES=${SKIP_IPTABLES:-not_set}"
log "DEV_MODE=${DEV_MODE:-not_set}"
log "ARCH_DEFER_FIREWALL=${ARCH_DEFER_FIREWALL:-not_set}"
log "DISABLE_FIREWALL=${DISABLE_FIREWALL:-not_set}"

# Fallback: Try to read from deployment.env if variables are not set
if [[ "${SKIP_IPTABLES:-not_set}" == "not_set" ]] && [[ "${DEV_MODE:-not_set}" == "not_set" ]]; then
    log "Environment variables not set, trying to read from deployment.env"
    if [ -f "deployment.env" ]; then
        log "Found deployment.env, sourcing it"
        source deployment.env
        log "After sourcing deployment.env:"
        log "SKIP_IPTABLES=${SKIP_IPTABLES:-still_not_set}"
        log "DEV_MODE=${DEV_MODE:-still_not_set}"
        log "ARCH_DEFER_FIREWALL=${ARCH_DEFER_FIREWALL:-still_not_set}"
    else
        log "deployment.env not found"
    fi
fi

# Check if we should skip iptables configuration (dev mode or explicit skip)
if [[ "${SKIP_IPTABLES:-false}" == "true" ]] || [[ "${DEV_MODE:-false}" == "true" ]] || [[ "${ARCH_DEFER_FIREWALL:-false}" == "true" ]]; then
    log "Skipping iptables configuration in Stage 1 (dev mode or explicit skip)"
    log "Firewall rules will be configured in Stage 2 after reboot when kernel modules are available"
    
    # Still enable the service for Stage 2
    if pacman -Q iptables-nft >/dev/null 2>&1; then
        log "iptables-nft service will be enabled in Stage 2"
    else
        log "iptables service will be enabled in Stage 2"
    fi
else
    log "Configuring iptables rules in Stage 1 (production mode)"
    
    # Enable iptables service
    if pacman -Q iptables-nft >/dev/null 2>&1; then
        log "Using iptables-nft backend"
        systemctl enable iptables.service
    else
        log "Using iptables legacy backend"
        systemctl enable iptables.service
    fi

    # Load required kernel modules for iptables/netfilter
    log "Loading required netfilter kernel modules..."
    modprobe nf_tables 2>/dev/null || warn "Could not load nf_tables module"
    modprobe nf_conntrack 2>/dev/null || warn "Could not load nf_conntrack module"
    modprobe iptable_filter 2>/dev/null || warn "Could not load iptable_filter module"
    modprobe iptable_nat 2>/dev/null || warn "Could not load iptable_nat module"
    
    # Wait a moment for modules to initialize
    sleep 2
    
    # Test if iptables is working before configuring rules
    if ! iptables -L >/dev/null 2>&1; then
        warn "iptables not ready - deferring firewall configuration to Stage 2"
        log "Creating firewall configuration for Stage 2..."
        
        # Create the firewall rules script for Stage 2
        cat > /root/configure-firewall.sh << 'EOF'
#!/bin/bash
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
log "Configuring iptables rules in Stage 2..."

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

# Allow SSH (always needed for emergency access)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Tailscale UDP port
iptables -A INPUT -p udp --dport 41641 -j ACCEPT

# Temporarily allow application ports during setup
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # Web UI
iptables -A INPUT -p tcp --dport 5432 -j ACCEPT  # PostgreSQL (temporary)
iptables -A INPUT -p tcp --dport 6379 -j ACCEPT  # Redis (temporary)
iptables -A INPUT -p tcp --dport 19999 -j ACCEPT # Netdata

# Allow ping
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Save rules
iptables-save > /etc/iptables/iptables.rules

log "Firewall configured successfully in Stage 2"
EOF
        chmod +x /root/configure-firewall.sh
        log "Firewall will be configured in Stage 2 after system restart"
        return
echo "Debug point"
