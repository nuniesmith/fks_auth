#!/bin/bash
set -e

# Source environment variables from Stage 1
if [ -f /root/stage2_env.sh ]; then
  source /root/stage2_env.sh
fi

echo "=== NGINX Server Setup - Stage 2: Service Configuration ==="
echo "Post-reboot configuration with fresh kernel and networking"
echo "$(date): Stage 2 starting..." >> /var/log/nginx-stage2.log

# Wait for system to settle after reboot
echo "⏳ Waiting for system to settle..."
sleep 20

# Ensure network is ready
echo "🌐 Waiting for network connectivity..."
for i in {1..30}; do
  if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Network is ready (attempt $i)"
    break
  fi
  echo "⏳ Waiting for network... (attempt $i/30)"
  sleep 5
done

# Start Docker with proper initialization
echo "🐳 Starting Docker daemon..."
if ! systemctl is-active --quiet docker; then
  systemctl start docker.service || {
    echo "🔧 Docker start failed, trying recovery..."
    systemctl reset-failed docker.service 2>/dev/null || true
    systemctl daemon-reload
    sleep 5
    systemctl start docker.service || {
      echo "🔧 Trying direct dockerd..."
      pkill -f dockerd || true
      sleep 5
      nohup dockerd --storage-driver=overlay2 --data-root=/var/lib/docker > /tmp/docker-stage2.log 2>&1 &
      sleep 20
    }
  }
fi

# Wait for Docker to be ready
echo "⏳ Waiting for Docker to be ready..."
for i in {1..30}; do
  if docker info >/dev/null 2>&1; then
    echo "✅ Docker is ready (attempt $i)"
    break
  fi
  echo "⏳ Waiting for Docker... (attempt $i/30)"
  sleep 3
done

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
DOCKER_COMPOSE_VERSION="v2.24.6"

# Install Docker Compose V2 as a plugin
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Also install legacy docker-compose for compatibility
curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Verify Docker Compose installation
echo "🔍 Verifying Docker Compose installation..."
if docker compose version >/dev/null 2>&1; then
  echo "✅ Docker Compose V2 plugin installed successfully"
  docker compose version
elif docker-compose version >/dev/null 2>&1; then
  echo "✅ Docker Compose V1 installed successfully"
  docker-compose version
else
  echo "❌ Docker Compose installation failed"
fi

# Add users to docker group
usermod -aG docker actions_user 2>/dev/null || echo "actions_user docker group already set"
usermod -aG docker nginx_user 2>/dev/null || echo "nginx_user docker group already set"

# Start Tailscale with enhanced error handling
echo "📡 Starting Tailscale..."

# Ensure Tailscale service is started
if ! systemctl is-active --quiet tailscaled; then
  systemctl start tailscaled || {
    echo "🔧 Starting tailscaled manually..."
    mkdir -p /var/lib/tailscale /run/tailscale
    nohup /usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --tun=userspace-networking > /tmp/tailscaled-stage2.log 2>&1 &
    sleep 10
  }
fi

# Wait for Tailscale daemon to be ready
echo "⏳ Waiting for Tailscale daemon..."
for i in {1..30}; do
  if tailscale status >/dev/null 2>&1; then
    echo "✅ Tailscale daemon is ready (attempt $i)"
    break
  fi
  echo "⏳ Waiting for Tailscale daemon... (attempt $i/30)"
  sleep 3
done

# Connect to Tailscale network with better error handling
echo "🔗 Connecting to Tailscale network..."
TAILSCALE_CONNECTED=false

# Try different connection methods with subnet advertising
for method in "with-routes-and-subnet" "with-routes" "without-routes" "basic"; do
  echo "Trying Tailscale connection method: $method"
  case $method in
    "with-routes-and-subnet")
      if timeout 180 tailscale up --authkey="$TAILSCALE_AUTH_KEY" --accept-routes --advertise-routes=172.18.0.0/16,10.0.0.0/8 --hostname="nginx" 2>/dev/null; then
        TAILSCALE_CONNECTED=true
        break
      fi
      ;;
    "with-routes")
      if timeout 180 tailscale up --authkey="$TAILSCALE_AUTH_KEY" --accept-routes --hostname="nginx" 2>/dev/null; then
        TAILSCALE_CONNECTED=true
        break
      fi
      ;;
    "without-routes")
      if timeout 180 tailscale up --authkey="$TAILSCALE_AUTH_KEY" --hostname="nginx" 2>/dev/null; then
        TAILSCALE_CONNECTED=true
        break
      fi
      ;;
    "basic")
      if timeout 180 tailscale up --authkey="$TAILSCALE_AUTH_KEY" 2>/dev/null; then
        TAILSCALE_CONNECTED=true
        break
      fi
      ;;
  esac
  echo "Method $method failed, trying next..."
  sleep 5
done

if [ "$TAILSCALE_CONNECTED" = "true" ]; then
  echo "✅ Tailscale connected successfully"
  
  # Get Tailscale IP with retries
  echo "🔍 Getting Tailscale IP..."
  TAILSCALE_IP=""
  for i in {1..15}; do
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
    if [ -n "$TAILSCALE_IP" ] && [ "$TAILSCALE_IP" != "" ]; then
      echo "✅ Tailscale IP: $TAILSCALE_IP"
      echo "$TAILSCALE_IP" > /tmp/tailscale_ip
      break
    fi
    echo "⏳ Waiting for Tailscale IP... (attempt $i/15)"
    sleep 5
  done
  
  if [ -z "$TAILSCALE_IP" ]; then
    echo "⚠️ Could not get Tailscale IP, but connection was successful"
    echo "unknown" > /tmp/tailscale_ip
  fi
else
  echo "❌ Tailscale connection failed after all attempts"
  echo "failed" > /tmp/tailscale_ip
fi

# Start Netdata with enhanced error handling
echo "📊 Starting Netdata..."
if ! systemctl is-active --quiet netdata; then
  systemctl start netdata || {
    echo "🔧 Netdata start failed, trying to enable and start..."
    systemctl enable netdata 2>/dev/null || true
    sleep 5
    systemctl start netdata || echo "❌ Netdata start failed completely"
  }
fi

# Wait for Netdata to be ready
echo "⏳ Waiting for Netdata to be ready..."
for i in {1..20}; do
  if curl -f -s http://localhost:19999/api/v1/info >/dev/null 2>&1; then
    echo "✅ Netdata is ready (attempt $i)"
    break
  fi
  echo "⏳ Waiting for Netdata... (attempt $i/20)"
  sleep 5
done

# Claim Netdata to cloud if tokens provided
if [ -n "$NETDATA_CLAIM_TOKEN" ] && [ -n "$NETDATA_CLAIM_ROOM" ]; then
  echo "🔗 Claiming Netdata to cloud..."
  echo "Using claim token: ${NETDATA_CLAIM_TOKEN:0:10}... (truncated)"
  echo "Using claim room: $NETDATA_CLAIM_ROOM"
  sleep 10
  
  # Modern claiming approach using configuration files
  echo "🔧 Using modern Netdata claiming configuration..."
  
  # Create claiming configuration directory
  mkdir -p /var/lib/netdata/cloud.d
  
  # Write claiming configuration
  cat > /var/lib/netdata/cloud.d/cloud.conf << 'CLOUD_CONFIG'
[global]
    enabled = yes

[connection]
    hostname = nginx.7gram.xyz
    
[claim]
    token = $NETDATA_CLAIM_TOKEN
    rooms = $NETDATA_CLAIM_ROOM
    url = https://app.netdata.cloud
CLOUD_CONFIG
  
  # Set proper ownership and permissions
  chown -R netdata:netdata /var/lib/netdata/cloud.d
  chmod 640 /var/lib/netdata/cloud.d/cloud.conf
  
  # Try claiming with direct netdata-claim command first
  echo "🔗 Attempting direct netdata-claim command..."
  if timeout 60 netdata-claim.sh -token=$NETDATA_CLAIM_TOKEN \
    -rooms=$NETDATA_CLAIM_ROOM \
    -url=https://app.netdata.cloud \
    -hostname=nginx.7gram.xyz 2>/dev/null; then
    echo "✅ Netdata successfully claimed via direct command"
  else
    echo "⚠️ Direct claim failed, trying with script locations..."
    
    # Fallback to script-based claiming
    CLAIM_SCRIPT=""
    for script_path in "/opt/netdata/bin/netdata-claim.sh" "/opt/netdata/usr/libexec/netdata/netdata-claim.sh" "/usr/libexec/netdata/netdata-claim.sh"; do
      if [ -f "$script_path" ]; then
        CLAIM_SCRIPT="$script_path"
        echo "Found claim script: $CLAIM_SCRIPT"
        break
      fi
    done
    
    if [ -n "$CLAIM_SCRIPT" ]; then
      echo "Running Netdata claim script..."
      if timeout 60 $CLAIM_SCRIPT -token=$NETDATA_CLAIM_TOKEN \
        -rooms=$NETDATA_CLAIM_ROOM \
        -url=https://app.netdata.cloud \
        -hostname=nginx.7gram.xyz; then
        echo "✅ Netdata successfully claimed via script"
      else
        echo "⚠️ Script-based claiming also failed"
        
        # Manual claiming fallback
        echo "🔧 Attempting manual claiming configuration..."
        echo "$NETDATA_CLAIM_TOKEN" > /var/lib/netdata/cloud.d/token
        echo "$NETDATA_CLAIM_ROOM" > /var/lib/netdata/cloud.d/rooms
        echo "https://app.netdata.cloud" > /var/lib/netdata/cloud.d/url
        chown netdata:netdata /var/lib/netdata/cloud.d/*
        chmod 640 /var/lib/netdata/cloud.d/*
        
        # Restart Netdata to pick up new configuration
        echo "🔄 Restarting Netdata to apply claiming configuration..."
        systemctl restart netdata
        sleep 15
        
        echo "✅ Manual claiming configuration applied, Netdata restarted"
      fi
    else
      echo "⚠️ No claim script found, using configuration-only approach"
      # Restart Netdata to pick up configuration
      systemctl restart netdata
      sleep 15
    fi
  fi
  
  # Verify claiming status
  echo "🔍 Verifying claim status..."
  sleep 5
  if [ -f /var/lib/netdata/cloud.d/claimed_id ]; then
    echo "✅ Netdata claiming verification: SUCCESS"
    echo "Claimed ID: $(cat /var/lib/netdata/cloud.d/claimed_id 2>/dev/null || echo 'ID file exists but unreadable')"
  else
    echo "⚠️ Claim verification: No claimed_id file found"
    echo "📋 Available claim files:"
    ls -la /var/lib/netdata/cloud.d/ 2>/dev/null || echo "No cloud.d directory"
  fi
else
  echo "ℹ️ No Netdata cloud tokens provided, skipping cloud claiming"
fi

# Create status summary
echo "=== Stage 2 Status Summary ===" >> /var/log/nginx-stage2.log
echo "Docker: $(systemctl is-active docker || echo 'failed')" >> /var/log/nginx-stage2.log
echo "Tailscale: $(systemctl is-active tailscaled || echo 'failed')" >> /var/log/nginx-stage2.log
echo "Netdata: $(systemctl is-active netdata || echo 'failed')" >> /var/log/nginx-stage2.log
echo "Tailscale IP: $(cat /tmp/tailscale_ip 2>/dev/null || echo 'unknown')" >> /var/log/nginx-stage2.log
echo "$(date): Stage 2 completed" >> /var/log/nginx-stage2.log

# Create completion marker for GitHub Actions workflow monitoring
echo "✅ Creating Stage 2 completion marker..."
touch /tmp/nginx-stage2-complete
echo "$(date): Stage 2 completion marker created" >> /var/log/nginx-stage2.log

echo "✅ Stage 2 Setup Complete"
