#!/bin/bash
set -euo pipefail

echo "🏗️ Starting Stage 1 complete setup..."

# Arch Linux package update and installation
echo "📦 Updating package database..."
pacman -Sy

echo "📦 Installing essential packages..."
# Install core packages first (without iptables to avoid conflicts)
CORE_PACKAGES="curl wget git openssh docker docker-compose tailscale base-devel"

for attempt in {1..3}; do
  echo "Package install attempt $attempt..."
  if timeout 300 pacman -S --noconfirm $CORE_PACKAGES; then
    echo "✅ Essential packages installed successfully"
    INSTALL_SUCCESS=true
    break
  else
    echo "⚠️ Package install attempt $attempt failed, retrying..."
    rm -f /var/lib/pacman/db.lck || true
    sleep 10
  fi
done

if [[ "${INSTALL_SUCCESS:-false}" != "true" ]]; then
  echo "❌ Failed to install essential packages after 3 attempts"
  echo "🔄 Trying to install packages individually..."
  for pkg in $CORE_PACKAGES; do
    echo "Installing $pkg..."
    timeout 120 pacman -S --noconfirm "$pkg" || echo "⚠️ Failed to install $pkg, continuing..."
  done
fi

echo "🔥 Handling iptables conflict (will be resolved in Stage 2 after reboot)..."
# Remove conflicting iptables package and install iptables-nft after reboot
# This avoids the interactive prompt during stage1
echo "ℹ️ Deferring iptables-nft and ufw installation to Stage 2 (post-reboot)"

echo "🐳 Skipping Docker start/config during Stage 1 (defer to deploy)..."
echo "ℹ️ Docker packages installed but not started or enabled in Stage 1"

echo " Creating users..."
useradd -m -s /bin/bash jordan || true
echo "jordan:JORDAN_PASSWORD_PLACEHOLDER" | chpasswd
usermod -aG wheel,docker jordan

useradd -m -s /bin/bash actions_user || true
echo "actions_user:ACTIONS_USER_PASSWORD_PLACEHOLDER" | chpasswd
usermod -aG wheel,docker actions_user

useradd -m -s /bin/bash SERVICE_NAME_PLACEHOLDER_user || true
usermod -aG docker SERVICE_NAME_PLACEHOLDER_user
echo "SERVICE_NAME_PLACEHOLDER_user:ACTIONS_USER_PASSWORD_PLACEHOLDER" | chpasswd

mkdir -p /home/SERVICE_NAME_PLACEHOLDER_user/.ssh
chmod 700 /home/SERVICE_NAME_PLACEHOLDER_user/.ssh
chown SERVICE_NAME_PLACEHOLDER_user:SERVICE_NAME_PLACEHOLDER_user /home/SERVICE_NAME_PLACEHOLDER_user/.ssh

echo "🔐 Configuring SSH..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

echo "🏷️ Setting hostname..."
hostnamectl set-hostname "SERVICE_NAME_PLACEHOLDER"

echo "⚙️ Enabling services for post-reboot..."
systemctl enable tailscaled

echo "📝 Creating systemd service for post-reboot setup..."
# Note: The stage2-post-reboot.sh script is uploaded by the workflow with placeholders already replaced
cat > /etc/systemd/system/stage2-setup.service << 'SERVICEEOF'
[Unit]
Description=Stage 2 Post-Reboot Setup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/stage2-post-reboot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl enable stage2-setup.service

echo "🔑 Creating backup auth key file for Stage 2..."
# This will be replaced by the workflow with the actual auth key
echo "TAILSCALE_AUTH_KEY_PLACEHOLDER" > /root/tailscale_auth_key
chmod 600 /root/tailscale_auth_key

echo "✅ Stage 1 complete - system ready for reboot"
echo "NEEDS_REBOOT" > /tmp/stage1_status
