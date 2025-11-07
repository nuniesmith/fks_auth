#!/bin/bash
set -euo pipefail

echo "🔧 Creating systemd service for stage 2..."
cat > /etc/systemd/system/stage2-setup.service << 'SERVICE_EOF'
[Unit]
Description=Stage 2 Post-Reboot Setup with Tailscale
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/systemd/system/stage2-setup.sh
Environment=SERVICE_NAME=SERVICE_NAME_PLACEHOLDER
Environment=TAILSCALE_AUTH_KEY=TAILSCALE_AUTH_KEY_PLACEHOLDER
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Enable the service to run on next boot
systemctl daemon-reload
systemctl enable stage2-setup.service

echo "🔄 Creating user and setting password if needed..."
# Create archuser if it doesn't exist (for some Arch images)
if ! id "archuser" &>/dev/null; then
  useradd -m -G wheel,docker -s /bin/bash archuser
fi

# Set password for archuser (for SSH fallback)
echo "archuser:$ACTIONS_USER_PASSWORD" | chpasswd

echo "💾 Syncing filesystem and preparing for reboot..."
sync

echo "✅ Stage 1 setup completed successfully"
echo "success" > /tmp/stage1_status

echo "🔄 Initiating system reboot for stage 2..."
# Schedule reboot in 5 seconds to allow script completion
(sleep 5 && reboot) &
