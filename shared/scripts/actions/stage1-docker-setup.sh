#!/bin/bash
set -euo pipefail

echo "🐳 Ensuring modern Docker Compose is available..."
# Install Docker Compose plugin for modern 'docker compose' command
if ! docker compose version &>/dev/null; then
  echo "Installing Docker Compose plugin..."
  mkdir -p ~/.docker/cli-plugins/
  COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
  curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o ~/.docker/cli-plugins/docker-compose
  chmod +x ~/.docker/cli-plugins/docker-compose
  
  # Also install standalone version and create symlink for backward compatibility
  curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  
  # Create symlink for compatibility
  ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose 2>/dev/null || true
fi

echo "🔧 Configuring services..."
# Start and enable Docker
systemctl start docker
systemctl enable docker

# Add archuser to docker group if exists
if id "archuser" &>/dev/null; then
  usermod -aG docker archuser
fi

# Start Tailscale service 
systemctl start tailscaled
systemctl enable tailscaled

# Enable and configure fail2ban
systemctl start fail2ban
systemctl enable fail2ban

echo "🔐 Setting up SSH security..."
# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup || true

# SSH security configuration
{
  echo "# SSH Security Configuration"
  echo "PermitRootLogin yes"
  echo "PasswordAuthentication yes"
  echo "PubkeyAuthentication yes"
  echo "Port 22"
  echo "MaxAuthTries 3"
  echo "ClientAliveInterval 60"
  echo "ClientAliveCountMax 3"
  echo "Protocol 2"
} >> /etc/ssh/sshd_config

# Restart SSH to apply changes
systemctl restart sshd

echo "⚙️ Creating stage 2 script..."
cat > /etc/systemd/system/stage2-setup.sh << 'STAGE2_EOF'
#!/bin/bash
set -euo pipefail

echo "🚀 Stage 2: Post-reboot Tailscale setup..."

# Wait for network to be ready
echo "⏳ Waiting for network connectivity..."
for i in {1..30}; do
  if ping -c 1 google.com &>/dev/null; then
    echo "✅ Network is ready"
    break
  fi
  echo "Waiting for network... attempt $i/30"
  sleep 2
done

echo "🔌 Setting up Tailscale with Docker subnet advertisement..."
# Determine Docker subnets to advertise
DOCKER_SUBNETS=""
case "${SERVICE_NAME}" in
  "fks")
    DOCKER_SUBNETS="172.20.0.0/16"
    ;;
  "ats")
    DOCKER_SUBNETS="172.21.0.0/16"
    ;;
  "nginx")
    DOCKER_SUBNETS="172.22.0.0/16"
    ;;
  *)
    DOCKER_SUBNETS="172.20.0.0/16"
    ;;
esac

echo "📡 Configuring Tailscale for service: ${SERVICE_NAME} with subnets: $DOCKER_SUBNETS"

# Create Docker networks with static IPs for this service
echo "🐳 Creating Docker networks for ${SERVICE_NAME}..."
docker network create --driver bridge --subnet="${DOCKER_SUBNETS}" "${SERVICE_NAME}_network" 2>/dev/null || echo "Network already exists"

# Configure iptables to allow Docker subnet traffic through Tailscale
echo "🔥 Configuring iptables for Docker subnet routing..."
iptables -A FORWARD -s "${DOCKER_SUBNETS}" -j ACCEPT || true
iptables -A FORWARD -d "${DOCKER_SUBNETS}" -j ACCEPT || true

# Authenticate and configure Tailscale
AUTH_KEY="${TAILSCALE_AUTH_KEY}"
if [[ -z "$AUTH_KEY" ]]; then
  echo "❌ TAILSCALE_AUTH_KEY not provided"
  exit 1
fi

echo "🔑 Authenticating with Tailscale..."
if tailscale up --authkey="$AUTH_KEY" --hostname="${SERVICE_NAME}" --accept-routes --advertise-routes="$DOCKER_SUBNETS" --timeout=180s; then
  echo "✅ Tailscale authentication successful"
else
  echo "⚠️ Standard auth failed, trying with tags..."
  if tailscale up --authkey="$AUTH_KEY" --hostname="${SERVICE_NAME}" --accept-routes --advertise-routes="$DOCKER_SUBNETS" --advertise-tags=tag:server --timeout=180s; then
    echo "✅ Tailscale authentication with tags successful"
  else
    echo "❌ Tailscale authentication failed"
    exit 1
  fi
fi

# Get and display Tailscale IP
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
echo "🌐 Tailscale IP: $TAILSCALE_IP"

# Save Tailscale IP for later use
echo "$TAILSCALE_IP" > /tmp/tailscale_ip

echo "✅ Stage 2 setup completed successfully"
echo "success" > /tmp/stage2_status
STAGE2_EOF

chmod +x /etc/systemd/system/stage2-setup.sh
