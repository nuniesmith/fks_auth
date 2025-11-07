#!/bin/bash
set -e

echo "=== NGINX Server Setup - Stage 1 (ATS-Proven Pattern) ==="

# Update system with conflict resolution (proven from ATS workflow)
echo "í³¦ Updating system packages..."
pacman-key --init
pacman-key --populate archlinux
pacman -Sy --noconfirm archlinux-keyring

# Handle known conflicts before system update (critical for Arch Linux)
echo "í´§ Resolving package conflicts..."
pacman -R --noconfirm linux-firmware-nvidia 2>/dev/null || echo "linux-firmware-nvidia not installed"
pacman -R --noconfirm gpgme 2>/dev/null || echo "gpgme conflict resolved"

# Now update system with overwrite flag
echo "í³¦ Performing system update..."
pacman -Syu --noconfirm --overwrite="*"

# Install essential packages with verification
echo "í³¦ Installing essential packages..."
PACKAGES=(curl wget git unzip nginx docker docker-compose htop nano net-tools)
for pkg in "${PACKAGES[@]}"; do
  echo "Installing $pkg..."
  pacman -S --noconfirm --needed "$pkg" || echo "Failed to install $pkg, continuing..."
done

# Install Tailscale with fallback
echo "í³¦ Installing Tailscale..."
pacman -S --noconfirm tailscale || {
  echo "Installing Tailscale from official script..."
  curl -fsSL https://tailscale.com/install.sh | sh
}

# Configure system optimizations
echo "âš™ï¸ Configuring system optimizations..."
echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf
sysctl vm.overcommit_memory=1

# Verify memory overcommit setting
echo "í´ Verifying memory overcommit configuration..."
OVERCOMMIT_VALUE=$(sysctl -n vm.overcommit_memory)
echo "   Current vm.overcommit_memory value: $OVERCOMMIT_VALUE"
if [ "$OVERCOMMIT_VALUE" = "1" ]; then
  echo "âœ… Memory overcommit properly configured"
else
  echo "âš ï¸ Memory overcommit not set correctly"
fi

# Set timezone to EST (Toronto, Canada)
echo "íµ Setting timezone to America/Toronto (EST)..."
timedatectl set-timezone America/Toronto
echo "âœ… Timezone set to: $(timedatectl show --property=Timezone --value)"

# Enable and start essential services
echo "í´§ Enabling services..."
systemctl enable docker
systemctl enable tailscaled
systemctl enable nginx

# Start Docker immediately
systemctl start docker

# Verify Docker installation
if systemctl list-unit-files | grep -q docker.service; then
  echo "âœ… Docker service found and enabled"
else
  echo "âŒ Docker service not found after installation"
  exit 1
fi

# Create actions user with proper permissions
echo "í±¤ Creating actions user..."
useradd -m -s /bin/bash actions
echo "actions:ACTIONS_PASSWORD_PLACEHOLDER" | chpasswd
usermod -aG docker actions
usermod -aG wheel actions

# Configure sudo for actions user
echo "actions ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Setup SSH configuration for password authentication
echo "ï¿½ï¿½ Configuring SSH for password authentication..."
mkdir -p /home/actions/.ssh
chown -R actions:actions /home/actions/.ssh
chmod 700 /home/actions/.ssh

# Enable password authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd

echo "âœ… Stage 1 Complete - Server ready for Tailscale and deployment"
