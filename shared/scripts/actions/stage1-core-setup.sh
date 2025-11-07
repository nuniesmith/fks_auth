#!/bin/bash
set -euo pipefail

echo "🔄 Updating system..."
# Update package databases first
pacman -Sy --noconfirm

echo "🔧 Optimizing package mirrors for better download speeds..."
# Backup original mirrorlist
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup || true

# Use faster mirrors and optimize pacman configuration
{
  echo "## United States"
  echo "Server = https://america.mirror.pkgbuild.com/\$repo/os/\$arch"
  echo "Server = https://mirror.arizona.edu/archlinux/\$repo/os/\$arch"
  echo "Server = https://mirrors.ocf.berkeley.edu/archlinux/\$repo/os/\$arch"
  echo "Server = https://mirror.cs.pitt.edu/archlinux/\$repo/os/\$arch"
  echo "Server = https://mirrors.kernel.org/archlinux/\$repo/os/\$arch"
  echo "## Canada"
  echo "Server = https://archlinux.mirror.rafal.ca/\$repo/os/\$arch"
  echo "Server = https://mirror.csclub.uwaterloo.ca/archlinux/\$repo/os/\$arch"
} > /etc/pacman.d/mirrorlist

# Optimize pacman.conf for faster downloads
sed -i 's/#ParallelDownloads = 5/ParallelDownloads = 10/' /etc/pacman.conf
grep -q "ILoveCandy" /etc/pacman.conf || echo "ILoveCandy" >> /etc/pacman.conf

echo "💾 System upgrade with retry and conflict resolution..."
UPGRADE_SUCCESS=false
for attempt in {1..3}; do
  echo "Upgrade attempt $attempt/3..."
  if pacman -Su --noconfirm --overwrite='*' --overwrite='/usr/lib/firmware/nvidia/*' 2>/dev/null; then
    UPGRADE_SUCCESS=true
    break
  else
    echo "⚠️ Upgrade attempt $attempt failed, trying alternative approach..."
    # Clean up and try again
    rm -rf /usr/lib/firmware/nvidia || true
    rm -f /var/lib/pacman/db.lck || true
    sleep 5
  fi
done

if [[ "$UPGRADE_SUCCESS" != "true" ]]; then
  echo "⚠️ System upgrade failed after 3 attempts, proceeding with package installation..."
else
  echo "✅ System upgrade completed successfully"
fi

echo "📦 Installing core packages with retry logic..."
# Install essential packages first (most important ones) - using modern Docker with Compose plugin
CORE_PACKAGES="curl wget git docker docker-compose tailscale fail2ban sudo rsync"

echo "🔄 Installing essential packages: $CORE_PACKAGES"
INSTALL_SUCCESS=false
for attempt in {1..3}; do
  echo "Package install attempt $attempt/3..."
  if timeout 300 pacman -S --noconfirm $CORE_PACKAGES; then
    INSTALL_SUCCESS=true
    echo "✅ Essential packages installed successfully"
    break
  else
    echo "⚠️ Package install attempt $attempt failed, retrying..."
    # Clear any locks and try again
    rm -f /var/lib/pacman/db.lck || true
    sleep 10
  fi
done

if [[ "$INSTALL_SUCCESS" != "true" ]]; then
  echo "❌ Failed to install essential packages after 3 attempts"
  echo "🔄 Trying to install packages individually..."
  
  # Try installing packages one by one
  for pkg in $CORE_PACKAGES; do
    echo "Installing $pkg..."
    timeout 120 pacman -S --noconfirm "$pkg" || echo "⚠️ Failed to install $pkg, continuing..."
  done
fi
