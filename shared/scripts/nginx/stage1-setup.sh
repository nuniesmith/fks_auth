#!/bin/bash
set -e

echo "=== NGINX Server Setup - Stage 1: System Foundation ==="
echo "Following FKS project proven deployment pattern"

# Update system with conflict resolution (using proven ATS pattern)
echo "📦 Updating system packages..."
pacman-key --init
pacman-key --populate archlinux
pacman -Sy --noconfirm archlinux-keyring

# Handle known conflicts before system update (proven ATS approach)
echo "🔧 Resolving package conflicts..."
pacman -R --noconfirm linux-firmware-nvidia 2>/dev/null || echo "linux-firmware-nvidia not installed"
pacman -R --noconfirm gpgme 2>/dev/null || echo "gpgme conflict resolved"

# Remove conflicting nvidia firmware files if they exist
rm -rf /usr/lib/firmware/nvidia/ 2>/dev/null || echo "nvidia firmware directory cleaned"

# Now update system with overwrite flag (critical fix from ATS)
pacman -Syu --noconfirm --overwrite="*"

# Install essential packages with verification
echo "📦 Installing essential packages..."
PACKAGES=(curl wget git unzip nginx docker htop nano net-tools jq rsync)
for pkg in "${PACKAGES[@]}"; do
  echo "Installing $pkg..."
  pacman -S --noconfirm --needed "$pkg" || echo "Failed to install $pkg, continuing..."
done

# Configure system optimizations (from proven ATS pattern)
echo "⚙️ Configuring system optimizations..."
echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf
sysctl vm.overcommit_memory=1

# Enable memory overcommit for Redis (required for Docker)
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' >> /etc/rc.local

# Set timezone to EST (Toronto, Canada)
echo "🕐 Setting timezone to America/Toronto (EST)..."
timedatectl set-timezone America/Toronto
echo "✅ Timezone set to: $(timedatectl show --property=Timezone --value)"

# Set system hostname to 'nginx'
echo "🏷️ Setting system hostname to 'nginx'..."
hostnamectl set-hostname nginx
echo "nginx" > /etc/hostname
echo "127.0.0.1 localhost nginx" > /etc/hosts
echo "::1 localhost nginx" >> /etc/hosts
echo "✅ Hostname set to: $(hostname)"

# Create user accounts (FKS pattern)
echo "👥 Creating user accounts..."

# Create actions_user (for GitHub Actions deployment) - MATCHING FKS PATTERN
useradd -m -s /bin/bash actions_user || echo "actions_user user already exists"
echo "actions_user:$ACTIONS_USER_PASSWORD" | chpasswd
usermod -aG wheel actions_user

# Create jordan user (admin access)
useradd -m -s /bin/bash jordan || echo "jordan user already exists"
echo "jordan:$ACTIONS_USER_PASSWORD" | chpasswd
usermod -aG wheel jordan

# Create nginx_user (service account for nginx repo)
useradd -m -s /bin/bash nginx_user || echo "nginx_user already exists"
echo "nginx_user:$(openssl rand -base64 32)" | chpasswd

# Configure sudo for admin users
echo "actions_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
echo "jordan ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Setup SSH access
mkdir -p /home/actions_user/.ssh /home/jordan/.ssh /home/nginx_user/.ssh
chown -R actions_user:actions_user /home/actions_user/.ssh
chown -R jordan:jordan /home/jordan/.ssh
chown -R nginx_user:nginx_user /home/nginx_user/.ssh
chmod 700 /home/actions_user/.ssh /home/jordan/.ssh /home/nginx_user/.ssh

# Enable password authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd

# Docker setup (enable service for Stage 2)
echo "🐳 Preparing Docker for Stage 2..."
systemctl enable docker.service || echo "Docker enable failed, will retry in Stage 2"

# Create Docker daemon configuration directory
mkdir -p /etc/docker

# Create Docker daemon configuration for better compatibility
cat > /etc/docker/daemon.json << 'DOCKER_CONFIG'
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "data-root": "/var/lib/docker"
}
DOCKER_CONFIG

# Ensure Docker data directory exists with correct permissions
mkdir -p /var/lib/docker
chmod 755 /var/lib/docker

# Install Tailscale (enable for Stage 2)
echo "📡 Installing Tailscale..."
pacman -S --noconfirm tailscale || {
  echo "Installing Tailscale from official script..."
  curl -fsSL https://tailscale.com/install.sh | sh
}

# Enable Tailscale service for Stage 2
systemctl enable tailscaled || echo "Tailscale enable failed, will retry in Stage 2"

# Ensure TUN device is available
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
  chmod 666 /dev/net/tun
fi

# Load TUN kernel module
modprobe tun || echo "TUN module already loaded or not needed"
echo 'tun' >> /etc/modules-load.d/tun.conf

# Install Netdata (enable for Stage 2)
echo "📊 Installing Netdata..."
curl -L https://get.netdata.cloud/kickstart.sh | bash -s -- \
  --stable-channel \
  --disable-telemetry \
  --non-interactive \
  --dont-wait \
  --dont-start-it || echo "Netdata installation completed with warnings"

# Enable Netdata service for Stage 2
systemctl enable netdata || echo "Netdata enable failed, will retry in Stage 2"

# Create environment file for Stage 2 with secrets
cat > /root/stage2_env.sh << 'STAGE2_ENV'
#!/bin/bash
# Stage 2 environment variables
export NETDATA_CLAIM_TOKEN="$NETDATA_CLAIM_TOKEN"
export NETDATA_CLAIM_ROOM="$NETDATA_CLAIM_ROOM"
export TAILSCALE_AUTH_KEY="$TAILSCALE_AUTH_KEY"
STAGE2_ENV

chmod 600 /root/stage2_env.sh
chown root:root /root/stage2_env.sh

echo "=== Stage 1 Complete - Preparing for reboot ==="
echo "🔄 System will reboot to refresh kernel and networking"
echo "🔄 Stage 2 will execute after reboot"

# Stage 2 script should already be transferred to /root/stage2_setup.sh
if [ ! -f "/root/stage2_setup.sh" ]; then
  echo "⚠️ Stage 2 script not found at /root/stage2_setup.sh"
  echo "   It should have been transferred from GitHub Actions"
fi

# Schedule Stage 2 to run after reboot (using systemd)
cat > /etc/systemd/system/nginx-stage2.service << 'SYSTEMD_SERVICE'
[Unit]
Description=NGINX Server Stage 2 Setup - Post Reboot Configuration
After=network-online.target docker.service systemd-resolved.service
Wants=network-online.target docker.service
Requires=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
ExecStartPre=/bin/sleep 30
ExecStart=/bin/bash /root/stage2_setup.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=900
Restart=no

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

systemctl enable nginx-stage2.service

# Reboot the system (critical for kernel refresh and proper networking)
echo "🔄 Rebooting system for kernel refresh..."
sleep 5
reboot
