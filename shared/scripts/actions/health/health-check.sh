#!/bin/bash
set -euo pipefail

# Health check script
# Usage: ./health-check.sh <service_name> <server_ip> <tailscale_ip>

SERVICE_NAME="${1:-}"
SERVER_IP="${2:-}"
TAILSCALE_IP="${3:-}"

if [[ -z "$SERVICE_NAME" || -z "$SERVER_IP" ]]; then
  echo "❌ Missing required parameters"
  echo "Usage: $0 <service_name> <server_ip> [tailscale_ip]"
  exit 1
fi

echo "🏥 Running comprehensive health checks for $SERVICE_NAME..."

# Ensure SSH key exists
if [[ ! -f ~/.ssh/deployment_key ]]; then
  echo "❌ SSH deployment key not found"
  exit 1
fi

echo "🔍 1. Basic connectivity tests..."
# Basic connectivity test
if ping -c 3 "$SERVER_IP" >/dev/null 2>&1; then
  echo "✅ Server ping successful"
else
  echo "⚠️ Server ping failed"
fi

# SSH connectivity test
if ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$SERVER_IP" "echo 'SSH OK'"; then
  echo "✅ SSH connection successful"
else
  echo "❌ SSH connection failed"
  exit 1
fi

echo "🔍 2. Service health checks..."
# Check if Docker is running
DOCKER_STATUS=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" "systemctl is-active docker 2>/dev/null || echo 'inactive'")
if [[ "$DOCKER_STATUS" == "active" ]]; then
  echo "✅ Docker service is running"
else
  echo "❌ Docker service is not running: $DOCKER_STATUS"
fi

# Check if Tailscale is connected
TAILSCALE_STATUS=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" "tailscale status --self --peers=false 2>/dev/null | head -1" || echo "not connected")
if echo "$TAILSCALE_STATUS" | grep -q "online"; then
  echo "✅ Tailscale is connected"
else
  echo "⚠️ Tailscale status: $TAILSCALE_STATUS"
fi

echo "🔍 3. Service-specific health checks..."
# Check if service containers are running
RUNNING_CONTAINERS=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" "docker ps --format 'table {{.Names}}\t{{.Status}}' | grep '$SERVICE_NAME' || echo 'none'")
if [[ "$RUNNING_CONTAINERS" != "none" ]]; then
  echo "✅ Service containers are running:"
  echo "$RUNNING_CONTAINERS"
else
  echo "⚠️ No service containers found running"
fi

# Check network connectivity
echo "🔍 4. Network connectivity tests..."
# Test HTTP connectivity (if service exposes port 80)
if timeout 10 curl -s -o /dev/null -w "%{http_code}" "http://$SERVER_IP" | grep -E "^[2-3][0-9][0-9]$"; then
  echo "✅ HTTP service is responding"
else
  echo "ℹ️ HTTP service not responding on port 80 (may be normal)"
fi

# Test Tailscale IP connectivity if available
if [[ "$TAILSCALE_IP" != "pending" && -n "$TAILSCALE_IP" ]]; then
  if timeout 5 ping -c 1 "$TAILSCALE_IP" >/dev/null 2>&1; then
    echo "✅ Tailscale IP is reachable: $TAILSCALE_IP"
  else
    echo "⚠️ Tailscale IP not reachable: $TAILSCALE_IP"
  fi
fi

echo "🔍 5. Resource health checks..."
# Check system resources
SYSTEM_INFO=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@"$SERVER_IP" "
  echo 'CPU:' \$(nproc) 'cores'
  echo 'RAM:' \$(free -h | awk '/^Mem:/ {print \$2}' | head -1)
  echo 'Disk:' \$(df -h / | awk 'NR==2 {print \$4}' | head -1) 'free'
  echo 'Uptime:' \$(uptime -p)
")
echo "📊 System resources:"
echo "$SYSTEM_INFO"

echo "✅ Health checks completed for $SERVICE_NAME"
