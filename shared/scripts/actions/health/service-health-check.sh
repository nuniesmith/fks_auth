#!/bin/bash
# Health check script for deployed services

set -euo pipefail

SERVICE_NAME="${1:-}"
SERVER_IP="${2:-}"
TAILSCALE_IP="${3:-}"

log() {
    echo "🏥 [HEALTH] $*"
}

if [[ -z "$SERVICE_NAME" || -z "$SERVER_IP" ]]; then
    echo "❌ Missing required parameters"
    echo "Usage: $0 <service_name> <server_ip> [tailscale_ip]"
    exit 1
fi

log "Running health checks for $SERVICE_NAME..."
log "Server IP: $SERVER_IP"
log "Tailscale IP: ${TAILSCALE_IP:-not available}"

# Setup SSH key: if provided via env, decode it; otherwise assume it was installed by the workflow
mkdir -p ~/.ssh
if [[ -n "${SSH_PRIVATE_KEY:-}" ]]; then
    echo "$SSH_PRIVATE_KEY" | base64 -d > ~/.ssh/deployment_key 2>/dev/null || true
fi
chmod 600 ~/.ssh/deployment_key 2>/dev/null || true

# Basic connectivity test
log "Testing SSH connectivity..."
if ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$SERVER_IP "echo 'SSH connection successful'" 2>/dev/null; then
    log "✅ SSH connectivity verified"
else
    log "❌ SSH connectivity failed"
    exit 1
fi

# Docker health check
log "Checking Docker services..."
DOCKER_STATUS=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
    if systemctl is-active docker >/dev/null 2>&1; then
        echo 'active'
    else
        echo 'inactive'
    fi
" 2>/dev/null || echo "unknown")

if [[ "$DOCKER_STATUS" == "active" ]]; then
    log "✅ Docker service is running"
else
    log "⚠️ Docker service status: $DOCKER_STATUS"
fi

# Service-specific health checks
log "Checking $SERVICE_NAME service containers..."
CONTAINER_COUNT=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
    docker ps --filter name=$SERVICE_NAME --format 'table {{.Names}}' | wc -l
" 2>/dev/null || echo "0")

if [[ "$CONTAINER_COUNT" -gt 1 ]]; then
    log "✅ Service containers are running ($((CONTAINER_COUNT - 1)) containers)"
else
    log "⚠️ No service containers found running"
fi

# Tailscale connectivity test
if [[ -n "$TAILSCALE_IP" && "$TAILSCALE_IP" != "pending" ]]; then
    log "Testing Tailscale connectivity..."
    TAILSCALE_STATUS=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
        if tailscale ip -4 >/dev/null 2>&1; then
            echo 'connected'
        else
            echo 'disconnected'
        fi
    " 2>/dev/null || echo "unknown")
    
    if [[ "$TAILSCALE_STATUS" == "connected" ]]; then
        log "✅ Tailscale is connected"
    else
        log "⚠️ Tailscale status: $TAILSCALE_STATUS"
    fi
fi

# Network connectivity test
log "Testing outbound connectivity..."
NETWORK_TEST=$(ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
    if curl -s --connect-timeout 5 https://api.github.com >/dev/null 2>&1; then
        echo 'success'
    else
        echo 'failed'
    fi
" 2>/dev/null || echo "unknown")

if [[ "$NETWORK_TEST" == "success" ]]; then
    log "✅ Outbound network connectivity verified"
else
    log "⚠️ Outbound network test: $NETWORK_TEST"
fi

log "🎉 Health check completed for $SERVICE_NAME"
