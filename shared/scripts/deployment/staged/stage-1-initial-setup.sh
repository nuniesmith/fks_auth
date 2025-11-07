#!/bin/bash

# FKS Trading Systems - Stage 1: Unified Initial Setup
# Combines SSH key generation with system setup for reliability

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Default values
TARGET_HOST=""
FKS_DEV_ROOT_PASSWORD=""
JORDAN_PASSWORD=""
FKS_USER_PASSWORD=""
ACTIONS_USER_PASSWORD=""
TAILSCALE_AUTH_KEY=""
DOCKER_USERNAME=""
DOCKER_TOKEN=""
NETDATA_CLAIM_TOKEN=""
NETDATA_CLAIM_ROOM=""
TIMEZONE="America/Toronto"

# SSH Keys (will be set from environment or parameters)
ORYX_SSH_PUB=""
SULLIVAN_SSH_PUB=""
FREDDY_SSH_PUB=""
DESKTOP_SSH_PUB=""
MACBOOK_SSH_PUB=""

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
        --actions-user-password)
            ACTIONS_USER_PASSWORD="$2"
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
        --oryx-ssh-pub)
            ORYX_SSH_PUB="$2"
            shift 2
            ;;
        --sullivan-ssh-pub)
            SULLIVAN_SSH_PUB="$2"
            shift 2
            ;;
        --freddy-ssh-pub)
            FREDDY_SSH_PUB="$2"
            shift 2
            ;;
        --desktop-ssh-pub)
            DESKTOP_SSH_PUB="$2"
            shift 2
            ;;
        --macbook-ssh-pub)
            MACBOOK_SSH_PUB="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "FKS Stage 1: Unified initial setup with SSH key generation"
            echo ""
            echo "Required options:"
            echo "  --target-host <IP>             Server IP address"
            echo "  --root-password <pass>         Root password for initial SSH"
            echo "  --jordan-password <pass>       Password for jordan user"
            echo "  --fks_user-password <pass>     Password for fks_user"
            echo "  --actions-user-password u003cpassu003e   Password for actions_user"
            echo "  --tailscale-auth-key <key>     Tailscale auth key (REQUIRED)"
            echo ""
            echo "Optional:"
            echo "  --docker-username <user>    Docker Hub username"
            echo "  --docker-token <token>      Docker Hub access token"
            echo "  --netdata-claim-token <token>  Netdata claim token"
            echo "  --netdata-claim-room <room>    Netdata room ID"
            echo "  --timezone <tz>                Server timezone"
            echo "  --oryx-ssh-pub <key>           Oryx SSH public key"
            echo "  --sullivan-ssh-pub <key>       Sullivan SSH public key"
            echo "  --freddy-ssh-pub <key>         Freddy SSH public key"
            echo "  --desktop-ssh-pub <key>        Desktop SSH public key"
            echo "  --macbook-ssh-pub <key>        MacBook SSH public key"
            exit 0
            ;;
        --github-token)
            GITHUB_TOKEN="$2"
            shift 2
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
        esac
done

# Load environment variables if not provided via command line
if [ -z "$ORYX_SSH_PUB" ]; then
    ORYX_SSH_PUB="${ORYX_SSH_PUB:-}"
fi
if [ -z "$SULLIVAN_SSH_PUB" ]; then
    SULLIVAN_SSH_PUB="${SULLIVAN_SSH_PUB:-}"
fi
if [ -z "$FREDDY_SSH_PUB" ]; then
    FREDDY_SSH_PUB="${FREDDY_SSH_PUB:-}"
fi
if [ -z "$DESKTOP_SSH_PUB" ]; then
    DESKTOP_SSH_PUB="${DESKTOP_SSH_PUB:-}"
fi
if [ -z "$MACBOOK_SSH_PUB" ]; then
    MACBOOK_SSH_PUB="${MACBOOK_SSH_PUB:-}"
fi

# Load server details if available
if [ -f "server-details.env" ]; then
    source server-details.env
fi

# Validate required parameters
if [ -z "$TARGET_HOST" ]; then
    error "Target host is required (--target-host)"
    exit 1
fi

if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
    error "Root password is required (--root-password)"
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

if [ -z "$ACTIONS_USER_PASSWORD" ]; then
    error "Actions user password is required (--actions-user-password)"
    exit 1
fi

log "Starting FKS Trading Systems - Stage 1: Unified Setup"
log "Target Host: $TARGET_HOST"

# Install sshpass if needed
if ! command -v sshpass > /dev/null 2>&1; then
    log "Installing sshpass..."
    if command -v pacman > /dev/null 2>&1; then
        sudo -n pacman -S --noconfirm sshpass
    elif command -v apt-get > /dev/null 2>&1; then
        sudo -n apt-get update && sudo -n apt-get install -y sshpass
    fi
fi

# Test SSH connectivity
log "Testing SSH connectivity to root@$TARGET_HOST..."
if ! timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
    error "Cannot connect to root@$TARGET_HOST via SSH"
    exit 1
fi

log "✅ SSH connectivity confirmed"

# Create the unified setup script - using regular string with variable substitution
SETUP_SCRIPT=$(mktemp)
cat > "$SETUP_SCRIPT" << SETUP_EOF
#!/bin/bash

# FKS Trading Systems - Unified Setup Script (runs on target server)
set -e

# Parameters
JORDAN_PASSWORD="\$1"
FKS_USER_PASSWORD="\$2"
ACTIONS_USER_PASSWORD="\$3"
TAILSCALE_AUTH_KEY="\$4"
DOCKER_USERNAME="\$5"
DOCKER_TOKEN="\$6"
NETDATA_CLAIM_TOKEN="\$7"
NETDATA_CLAIM_ROOM="\$8"
TIMEZONE="\$9"
ORYX_SSH_PUB="\$10"
SULLIVAN_SSH_PUB="\${11}"
FREDDY_SSH_PUB="\${12}"
DESKTOP_SSH_PUB="\${13}"
MACBOOK_SSH_PUB="\${14}"

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

# Create log file
touch /var/log/fks_setup.log
chmod 644 /var/log/fks_setup.log

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] \$1\${NC}" | tee -a /var/log/fks_setup.log
}

warn() {
    echo -e "\${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: \$1\${NC}" | tee -a /var/log/fks_setup.log
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}" | tee -a /var/log/fks_setup.log
}

log "Starting FKS Trading Systems Setup - Stage 1 (Unified)"

# Detect distribution - Arch Linux only
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=\$ID
else
    error "Cannot detect distribution"
    exit 1
fi

if [ "\$DISTRO" != "arch" ]; then
    error "This script only supports Arch Linux. Detected: \$DISTRO"
    exit 1
fi

log "Confirmed Arch Linux distribution: \$DISTRO"

# Set hostname and timezone
log "Setting hostname to fks..."
hostnamectl set-hostname fks
echo "fks" > /etc/hostname
sed -i 's/127.0.1.1.*/127.0.1.1\\tfks/' /etc/hosts
if ! grep -q "127.0.1.1" /etc/hosts; then
    echo "127.0.1.1\tfks" >> /etc/hosts
fi

log "Setting timezone to \${TIMEZONE}..."
ln -sf /usr/share/zoneinfo/\${TIMEZONE} /etc/localtime
hwclock --systohc

# Update system (simplified for reliability)
log "Updating Arch Linux system packages..."
pacman -Sy --noconfirm archlinux-keyring || true

# Handle nvidia firmware conflicts
if [ -d /usr/lib/firmware/nvidia ]; then
    rm -rf /usr/lib/firmware/nvidia/ad10* 2>/dev/null || true
fi

# Update with overwrite flag for firmware conflicts
pacman -Syu --noconfirm --overwrite '/usr/lib/firmware/nvidia/*' || {
    warn "Standard update failed, trying alternative approach..."
    pacman -Syu --noconfirm --ignore linux-firmware-nvidia || true
    pacman -S --noconfirm --overwrite '*' linux-firmware-nvidia || true
}

# Install essential packages
log "Installing essential packages..."
pacman -S --noconfirm --needed \\
    base-devel \\
    curl \\
    wget \\
    git \\
    vim \\
    nano \\
    htop \\
    unzip \\
    ca-certificates \\
    gnupg \\
    jq \\
    tree \\
    python \\
    python-pip \\
    docker \\
    docker-compose \\
    tailscale \\
    fail2ban \\
    nodejs \\
    npm \\
    dotnet-sdk \\
    dotnet-runtime \\
    aspnet-runtime \\
    openssl \\
    linux-headers \\
    openssh || {
    warn "Some packages failed, continuing..."
}

# Install Docker Compose standalone
log "Installing Docker Compose standalone..."
DOCKER_COMPOSE_VERSION=\$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\\K.*?(?=")' || echo "v2.24.0")
curl -L "https://github.com/docker/compose/releases/download/\${DOCKER_COMPOSE_VERSION}/docker-compose-\$(uname -s)-\$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Netdata
log "Installing Netdata monitoring..."
curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh
chmod +x /tmp/netdata-kickstart.sh

NETDATA_CMD="sh /tmp/netdata-kickstart.sh --nightly-channel --dont-wait"
if [[ -n "\$NETDATA_CLAIM_TOKEN" ]]; then
    NETDATA_CMD="\$NETDATA_CMD --claim-token \$NETDATA_CLAIM_TOKEN --claim-url https://app.netdata.cloud"
    if [[ -n "\$NETDATA_CLAIM_ROOM" ]]; then
        NETDATA_CMD="\$NETDATA_CMD --claim-rooms \$NETDATA_CLAIM_ROOM"
    fi
fi

eval "\$NETDATA_CMD" || warn "Netdata installation failed"

# Create users
log "Creating users..."

# Jordan user (admin)
if ! id jordan &>/dev/null; then
    useradd -m -s /bin/bash jordan
fi
echo "jordan:\${JORDAN_PASSWORD}" | chpasswd
usermod -aG wheel jordan
usermod -aG docker jordan

# FKS user (service account)
if ! id fks_user &>/dev/null; then
    useradd -m -s /bin/bash fks_user
fi
echo "fks_user:\${FKS_USER_PASSWORD}" | chpasswd
usermod -aG docker fks_user

# Actions user (GitHub Actions)
if ! id actions_user &>/dev/null; then
    useradd -m -s /bin/bash actions_user
fi
usermod -aG wheel actions_user
usermod -aG docker actions_user
echo "actions_user:\${ACTIONS_USER_PASSWORD}" | chpasswd

# Enable wheel group for sudo
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

# Generate SSH keys for actions_user (CRITICAL for GitHub Actions)
log "Generating SSH keys for actions_user..."
mkdir -p /home/actions_user/.ssh
chmod 700 /home/actions_user/.ssh

# Remove any existing keys
rm -f /home/actions_user/.ssh/id_ed25519*

# Generate new Ed25519 key
ssh-keygen -t ed25519 -f /home/actions_user/.ssh/id_ed25519 -N "" -C "actions_user@fks_\$(date +%Y%m%d)"

# Set proper permissions
chmod 600 /home/actions_user/.ssh/id_ed25519
chmod 644 /home/actions_user/.ssh/id_ed25519.pub
chown -R actions_user:actions_user /home/actions_user/.ssh

# Set up authorized_keys
cp /home/actions_user/.ssh/id_ed25519.pub /home/actions_user/.ssh/authorized_keys
chmod 600 /home/actions_user/.ssh/authorized_keys

# Set up SSH for all users (using the generated key for all)
setup_ssh_for_user() {
    local username=\$1
    local home_dir="/home/\$username"
    
    if [ "\$username" = "root" ]; then
        home_dir="/root"
    fi
    
    mkdir -p "\$home_dir/.ssh"
    chmod 700 "\$home_dir/.ssh"
    
    if [ "\$username" != "root" ]; then
        chown -R "\$username:\$username" "\$home_dir/.ssh"
    fi
    
    # Count SSH keys added
    local keys_added=0
    
    # Add additional SSH keys if provided
    if [ -n "\$ORYX_SSH_PUB" ]; then
        echo "\$ORYX_SSH_PUB" >> "\$home_dir/.ssh/authorized_keys"
        log "  ✅ Added ORYX SSH key for \$username"
        keys_added=\$((keys_added + 1))
    else
        log "  ⚠️ ORYX_SSH_PUB not provided"
    fi
    
    if [ -n "\$SULLIVAN_SSH_PUB" ]; then
        echo "\$SULLIVAN_SSH_PUB" >> "\$home_dir/.ssh/authorized_keys"
        log "  ✅ Added SULLIVAN (Sull25) SSH key for \$username"
        keys_added=\$((keys_added + 1))
    else
        log "  ⚠️ SULLIVAN_SSH_PUB not provided"
    fi
    
    if [ -n "\$FREDDY_SSH_PUB" ]; then
        echo "\$FREDDY_SSH_PUB" >> "\$home_dir/.ssh/authorized_keys"
        log "  ✅ Added FREDDY SSH key for \$username"
        keys_added=\$((keys_added + 1))
    else
        log "  ⚠️ FREDDY_SSH_PUB not provided"
    fi
    
    if [ -n "\$DESKTOP_SSH_PUB" ]; then
        echo "\$DESKTOP_SSH_PUB" >> "\$home_dir/.ssh/authorized_keys"
        log "  ✅ Added DESKTOP SSH key for \$username"
        keys_added=\$((keys_added + 1))
    else
        log "  ⚠️ DESKTOP_SSH_PUB not provided"
    fi
    
    if [ -n "\$MACBOOK_SSH_PUB" ]; then
        echo "\$MACBOOK_SSH_PUB" >> "\$home_dir/.ssh/authorized_keys"
        log "  ✅ Added MACBOOK SSH key for \$username"
        keys_added=\$((keys_added + 1))
    else
        log "  ⚠️ MACBOOK_SSH_PUB not provided"
    fi
    
    # Set proper permissions on authorized_keys
    if [ -f "\$home_dir/.ssh/authorized_keys" ]; then
        chmod 600 "\$home_dir/.ssh/authorized_keys"
        if [ "\$username" != "root" ]; then
            chown "\$username:\$username" "\$home_dir/.ssh/authorized_keys"
        fi
    fi
    
    log "SSH key configuration complete for \$username (\$keys_added external keys added)"
}

# Set up SSH access for all users
setup_ssh_for_user "root"
setup_ssh_for_user "jordan"
setup_ssh_for_user "fks_user"
setup_ssh_for_user "actions_user"

# Configure Git for actions_user
log "Configuring Git for actions_user..."
sudo -u actions_user bash << 'GIT_CONFIG'
cd /home/actions_user
git config --global user.name "nuniesmith"
git config --global user.email "nunie.smith01@gmail.com"
git config --global init.defaultBranch main
git config --global pull.rebase false

# Configure SSH for GitHub
cat > /home/actions_user/.ssh/config << 'SSH_CONFIG'
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
SSH_CONFIG

chmod 600 /home/actions_user/.ssh/config
GIT_CONFIG

# Configure SSH daemon
log "Configuring SSH security..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
cat >> /etc/ssh/sshd_config << 'SSH_CONFIG'

# Custom security settings for FKS deployment
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers root jordan actions_user fks_user
Protocol 2
X11Forwarding no
PrintMotd no
UsePAM yes
SSH_CONFIG

systemctl restart sshd
systemctl enable sshd

# Configure sudo for actions_user
log "Configuring sudo for actions_user..."
cat > /etc/sudoers.d/actions_user << 'SUDO_CONFIG'
actions_user ALL=(ALL) NOPASSWD: ALL
actions_user ALL=(jordan) NOPASSWD: ALL
SUDO_CONFIG
chmod 440 /etc/sudoers.d/actions_user

# Docker Hub login
if [ -n "\${DOCKER_USERNAME}" ] && [ -n "\${DOCKER_TOKEN}" ]; then
    log "Configuring Docker Hub authentication..."
    sudo -u jordan bash -c "echo '\${DOCKER_TOKEN}' | docker login --username '\${DOCKER_USERNAME}' --password-stdin" || {
        warn "Docker Hub login failed"
    }
fi

# Save environment for Stage 2
cat > /root/.fks_env << ENV_EOF
export TAILSCALE_AUTH_KEY="\${TAILSCALE_AUTH_KEY}"
export DOCKER_USERNAME="\${DOCKER_USERNAME}"
export DOCKER_TOKEN="\${DOCKER_TOKEN}"
export NETDATA_CLAIM_TOKEN="\${NETDATA_CLAIM_TOKEN}"
export NETDATA_CLAIM_ROOM="\${NETDATA_CLAIM_ROOM}"
export GITHUB_TOKEN="${GITHUB_TOKEN}"
ENV_EOF
chmod 600 /root/.fks_env

# Create Stage 2 script with full deployment including Docker
cat > /usr/local/bin/fks_stage2.sh << 'STAGE2_SCRIPT'
#!/bin/bash
set -e

# Colors
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
RED='\\033[0;31m'
NC='\\033[0m'

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] \$1\${NC}" | tee -a /var/log/fks_stage2.log
}

warn() {
    echo -e "\${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: \$1\${NC}" | tee -a /var/log/fks_stage2.log
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}" | tee -a /var/log/fks_stage2.log
}

log "Starting FKS Trading Systems Setup - Stage 2 (Complete Deployment)"

# Read environment variables
source /root/.fks_env 2>/dev/null || true

# Fix Docker iptables if needed
fix_docker_iptables() {
    log "Checking Docker iptables configuration..."
    
    if ! systemctl is-active --quiet docker; then
        log "Starting Docker service..."
        systemctl start docker
        sleep 5
    fi
    
    if ! iptables -L DOCKER-FORWARD -n &>/dev/null; then
        warn "Docker iptables chains missing. Restarting Docker..."
        systemctl restart docker
        sleep 10
        
        if iptables -L DOCKER-FORWARD -n &>/dev/null; then
            log "✅ Docker iptables chains restored"
        else
            error "Failed to restore Docker iptables chains"
            return 1
        fi
    fi
}

# Setup Tailscale if configured
if [ -n "\$TAILSCALE_AUTH_KEY" ]; then
    log "Setting up Tailscale VPN..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-tailscale.conf
    sysctl -p /etc/sysctl.d/99-tailscale.conf
    
    # Authenticate with Tailscale
    tailscale up --authkey "\$TAILSCALE_AUTH_KEY" --ssh --accept-routes --accept-dns=false
    
    TAILSCALE_IP=\$(tailscale ip -4 2>/dev/null || echo "Not available")
    log "Tailscale configured. IP: \$TAILSCALE_IP"
else
    warn "Tailscale auth key not provided, skipping VPN setup"
fi

# Fix Docker iptables
fix_docker_iptables

# Setup FKS repository
log "Setting up FKS repository..."
FKS_DIR="/home/fks_user/fks"

if [ ! -d "\$FKS_DIR" ]; then
    log "Cloning FKS repository..."
    # Clone with authentication if available
    if [ -n "\$GITHUB_TOKEN" ]; then
        sudo -u fks_user git clone https://\$GITHUB_TOKEN@github.com/nuniesmith/fks.git "\$FKS_DIR"
    else
        sudo -u fks_user git clone https://github.com/nuniesmith/fks.git "\$FKS_DIR" 2>/dev/null || \
        sudo -u fks_user git clone git@github.com:nuniesmith/fks.git "\$FKS_DIR"
    fi
else
    log "Updating existing FKS repository..."
    sudo -u fks_user bash -c "cd \$FKS_DIR && git pull"
fi

# Set proper permissions
chmod -R 755 "\$FKS_DIR"
chown -R fks_user:fks_user "\$FKS_DIR"

# Setup Docker authentication
if [ -n "\$DOCKER_USERNAME" ] && [ -n "\$DOCKER_TOKEN" ]; then
    log "Setting up Docker Hub authentication..."
    echo "\$DOCKER_TOKEN" | docker login -u "\$DOCKER_USERNAME" --password-stdin
    
    sudo -u fks_user bash -c "mkdir -p ~/.docker && echo '\$DOCKER_TOKEN' | docker login -u '\$DOCKER_USERNAME' --password-stdin"
fi

# Deploy FKS application
log "Deploying FKS application..."
cd "\$FKS_DIR"

# Ensure .env exists
if [ ! -f "\$FKS_DIR/.env" ]; then
    if [ -f "\$FKS_DIR/.env.development" ]; then
        sudo -u fks_user cp "\$FKS_DIR/.env.development" "\$FKS_DIR/.env"
    elif [ -f "\$FKS_DIR/.env.example" ]; then
        sudo -u fks_user cp "\$FKS_DIR/.env.example" "\$FKS_DIR/.env"
    fi
fi

# Deploy using docker compose
sudo -u fks_user bash << 'DEPLOY'
cd /home/fks_user/fks

# Clean up any existing containers
docker compose down --remove-orphans 2>/dev/null || true

# Pull latest images
echo "Pulling latest images..."
docker compose pull

# Start services
echo "Starting services..."
docker compose up -d

# Wait for initialization
sleep 20

# Show status
docker compose ps
DEPLOY

log "Docker deployment completed"

# Configure firewall
log "Configuring firewall rules..."

# Basic security rules
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Docker services
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
iptables -A INPUT -p tcp --dport 9001 -j ACCEPT

# Tailscale
iptables -A INPUT -p udp --dport 41641 -j ACCEPT
iptables -A INPUT -i tailscale+ -j ACCEPT

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/iptables.rules

log "Firewall configured"

# Setup monitoring if configured
if [ -n "\$NETDATA_CLAIM_TOKEN" ] && [ -n "\$NETDATA_CLAIM_ROOM" ]; then
    log "Setting up Netdata monitoring..."
    if ! command -v netdata &>/dev/null; then
        bash <(curl -Ss https://get.netdata.cloud/kickstart.sh) --dont-wait --stable-channel
    fi
    netdata-claim.sh -token="\$NETDATA_CLAIM_TOKEN" -rooms="\$NETDATA_CLAIM_ROOM" -url="https://app.netdata.cloud" || true
fi

# Mark completion
touch /root/.fks_stage2-complete
echo "\$(date): Stage 2 completed successfully" >> /root/.fks_stage2-complete

# Disable this service
systemctl disable fks_stage2.service

log "✅ Stage 2 completed successfully!"
log "Server is fully deployed and ready!"

if [ -n "\$TAILSCALE_IP" ]; then
    log "Tailscale IP: \$TAILSCALE_IP"
fi

log "Web Interface: http://$(hostname -I | awk '{print $1}')"
log "API: http://$(hostname -I | awk '{print $1}'):8000"
STAGE2_SCRIPT

chmod +x /usr/local/bin/fks_stage2.sh


# Create systemd service for Stage 2
cat > /etc/systemd/system/fks_stage2.service << 'SERVICE'
[Unit]
Description=FKS Trading Systems Setup Stage 2
After=network-online.target
Wants=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 15
ExecStart=/usr/local/bin/fks_stage2.sh
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable fks_stage2.service

log "✅ Stage 1 completed successfully!"
# Enable services
systemctl enable docker.service
systemctl enable tailscaled.service
systemctl enable fail2ban.service

log "============================================"
log "Stage 1 Setup Complete!"
log "============================================"
log "✅ Users created: jordan, fks_user, actions_user"
log "✅ SSH keys generated for GitHub Actions"
log "✅ Stage 2 service configured for post-reboot"
log "✅ All packages installed"
log ""
log ""
log "System will reboot in 10 seconds to complete setup..."
sleep 5
systemctl reboot
SETUP_EOF

# Upload and execute the setup script
log "Uploading setup script to server..."
if ! sshpass -p "$FKS_DEV_ROOT_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SETUP_SCRIPT" root@"$TARGET_HOST":/tmp/stage1-setup.sh; then
    error "Failed to upload setup script"
    exit 1
fi

log "Executing setup script on server..."
if sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$TARGET_HOST" "
    chmod +x /tmp/stage1-setup.sh
    /tmp/stage1-setup.sh \\
        \"$JORDAN_PASSWORD\" \\
        \"$FKS_USER_PASSWORD\" \\
        \"$ACTIONS_USER_PASSWORD\" \\
        \"$TAILSCALE_AUTH_KEY\" \\
        \"$DOCKER_USERNAME\" \\
        \"$DOCKER_TOKEN\" \\
        \"$NETDATA_CLAIM_TOKEN\" \\
        \"$NETDATA_CLAIM_ROOM\" \\
        \"$TIMEZONE\" \\
        \"$ORYX_SSH_PUB\" \\
        \"$SULLIVAN_SSH_PUB\" \\
        \"$FREDDY_SSH_PUB\" \\
        \"$DESKTOP_SSH_PUB\" \\
        \"$MACBOOK_SSH_PUB\"
"; then
    log "✅ Stage 1 setup initiated successfully"
    
    # Extract SSH key from logs
    log "Retrieving generated SSH key..."
    if SSH_KEY=$(sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$TARGET_HOST" "grep 'ACTIONS_USER_SSH_PUBLIC_KEY:' /var/log/fks_setup.log | tail -1 | cut -d':' -f2-" 2>/dev/null | tr -d ' '); then
        if [ -n "$SSH_KEY" ]; then
            echo "$SSH_KEY" > generated-ssh-key.txt
            log "✅ SSH key saved to generated-ssh-key.txt"
            echo "ACTIONS_USER_SSH_PUB=$SSH_KEY"
        fi
    fi
else
    error "Failed to execute setup script"
    exit 1
fi

# Cleanup
rm -f "$SETUP_SCRIPT"

log "Stage 1 completed. Server is rebooting and Stage 2 will run automatically."
