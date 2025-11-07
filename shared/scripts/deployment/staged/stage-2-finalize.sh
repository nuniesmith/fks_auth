#!/bin/bash

# FKS Trading Systems - Stage 2: Finalize Setup Status Checker
# Checks the status of Stage 2 auto-setup and optionally runs it manually
# Stage 2 normally runs automatically via systemd service after Stage 1 reboot

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
FORCE_MANUAL=false
WAIT_FOR_COMPLETION=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --force-manual)
            FORCE_MANUAL=true
            shift
            ;;
        --wait)
            WAIT_FOR_COMPLETION=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "FKS Stage 2: Check status of automatic Stage 2 setup and optionally run manually"
            echo ""
            echo "Options:"
            echo "  --target-host <host>     Target server host/IP"
            echo "  --force-manual           Force manual Stage 2 execution (bypass auto-run)"
            echo "  --wait                   Wait for Stage 2 completion (up to 10 minutes)"
            echo "  --help                   Show this help message"
            echo ""
            echo "What Stage 2 does:"
            echo "  - Configures iptables firewall with proper kernel modules"
            echo "  - Sets up Tailscale VPN with 'shields up' security"
            echo "  - Restricts application ports to Tailscale-only access"
            echo "  - Creates user aliases and welcome scripts"
            echo "  - Completes system finalization"
            echo ""
            echo "Normal operation:"
            echo "  Stage 2 runs automatically via systemd service after Stage 1 reboot."
            echo "  This script is mainly for status checking and troubleshooting."
            echo ""
            echo "Examples:"
            echo "  # Check Stage 2 status"
            echo "  $0 --target-host 192.168.1.100"
            echo ""
            echo "  # Wait for Stage 2 to complete"
            echo "  $0 --target-host 192.168.1.100 --wait"
            echo ""
            echo "  # Force manual Stage 2 execution"
            echo "  $0 --target-host 192.168.1.100 --force-manual"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load server details if available
if [ -f "server-details.env" ]; then
    source server-details.env
    if [ -z "$TARGET_HOST" ] && [ -n "$TARGET_HOST" ]; then
        TARGET_HOST="$TARGET_HOST"
    fi
fi

# Validate required parameters
if [ -z "$TARGET_HOST" ]; then
    error "Target host is required (--target-host or TARGET_HOST environment variable)"
    exit 1
fi

log "FKS Trading Systems - Stage 2: Finalize Setup Status"
log "Target Host: $TARGET_HOST"

# Test SSH connectivity
log "Testing SSH connectivity..."
if ! timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
    error "Cannot connect to $TARGET_HOST via SSH"
    error "Please verify:"
    error "  1. Server is online and accessible"
    error "  2. SSH service is running"
    error "  3. 'jordan' user exists and SSH keys are configured"
    exit 1
fi

log "✅ SSH connectivity confirmed"

# Check Stage 2 systemd service status
log "Checking Stage 2 systemd service status..."

SERVICE_STATUS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
    if sudo systemctl is-enabled fks_stage2.service >/dev/null 2>&1; then
        if sudo systemctl is-active fks_stage2.service >/dev/null 2>&1; then
            echo 'running'
        elif sudo systemctl status fks_stage2.service 2>/dev/null | grep -q 'Deactivated successfully'; then
            echo 'completed'
        elif sudo systemctl status fks_stage2.service 2>/dev/null | grep -q 'failed'; then
            echo 'failed'
        else
            echo 'enabled-inactive'
        fi
    else
        echo 'not-enabled'
    fi
" 2>/dev/null || echo "unknown")

log "📊 Stage 2 service status: $SERVICE_STATUS"

case "$SERVICE_STATUS" in
    "completed")
        log "✅ Stage 2 has completed successfully!"
        
        # Verify key Stage 2 components
        log "Verifying Stage 2 components..."
        
        TAILSCALE_STATUS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
            if tailscale status >/dev/null 2>&1; then
                echo 'connected'
            else
                echo 'not-connected'
            fi
        " 2>/dev/null || echo "unknown")
        
        if [ "$TAILSCALE_STATUS" = "connected" ]; then
            TAILSCALE_IP=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "tailscale ip -4 2>/dev/null" || echo "unknown")
            log "✅ Tailscale: Connected ($TAILSCALE_IP)"
        else
            warn "⚠️ Tailscale: Not connected"
        fi
        
        # Check firewall
        FIREWALL_STATUS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
            if sudo iptables -L -n | grep -q 'tailscale'; then
                echo 'configured'
            else
                echo 'basic'
            fi
        " 2>/dev/null || echo "unknown")
        
        if [ "$FIREWALL_STATUS" = "configured" ]; then
            log "✅ Firewall: Configured with Tailscale rules"
        else
            warn "⚠️ Firewall: Basic configuration (may need Tailscale rules)"
        fi
        
        log ""
        log "🎉 Stage 2 is complete! Server is ready for use."
        if [ "$TAILSCALE_STATUS" = "connected" ]; then
            log "Access via Tailscale: ssh jordan@$TAILSCALE_IP"
        fi
        ;;
        
    "running")
        log "🔄 Stage 2 is currently running..."
        
        if [ "$WAIT_FOR_COMPLETION" = "true" ]; then
            log "Waiting for Stage 2 to complete (up to 10 minutes)..."
            
            TIMEOUT=600  # 10 minutes
            ELAPSED=0
            
            while [ $ELAPSED -lt $TIMEOUT ]; do
                CURRENT_STATUS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
                    if sudo systemctl is-active fks_stage2.service >/dev/null 2>&1; then
                        echo 'running'
                    elif sudo systemctl status fks_stage2.service 2>/dev/null | grep -q 'Deactivated successfully'; then
                        echo 'completed'
                    else
                        echo 'unknown'
                    fi
                " 2>/dev/null || echo "unknown")
                
                if [ "$CURRENT_STATUS" = "completed" ]; then
                    log "✅ Stage 2 completed successfully!"
                    break
                fi
                
                log "Stage 2 still running... ($ELAPSED/$TIMEOUT seconds)"
                sleep 20
                ELAPSED=$((ELAPSED + 20))
            done
            
            if [ $ELAPSED -ge $TIMEOUT ]; then
                warn "⚠️ Stage 2 did not complete within timeout"
            fi
        else
            log "Use --wait to wait for completion, or check manually:"
            log "  ssh jordan@$TARGET_HOST 'sudo journalctl -u fks_stage2.service -f'"
        fi
        ;;
        
    "failed")
        error "❌ Stage 2 systemd service has failed!"
        log "Getting failure details..."
        
        ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
            echo '=== Stage 2 Service Status ==='
            sudo systemctl status fks_stage2.service --no-pager || true
            echo ''
            echo '=== Recent Stage 2 Logs ==='
            sudo journalctl -u fks_stage2.service --no-pager -n 30 || true
        " 2>/dev/null || warn "Could not get failure details"
        
        if [ "$FORCE_MANUAL" = "true" ]; then
            warn "Attempting manual Stage 2 execution..."
        else
            error "Use --force-manual to attempt manual Stage 2 execution"
            exit 1
        fi
        ;;
        
    "enabled-inactive"|"not-enabled")
        warn "⚠️ Stage 2 service is not running"
        
        if [ "$SERVICE_STATUS" = "not-enabled" ]; then
            warn "Stage 2 service is not even enabled - this suggests Stage 1 did not complete properly"
        fi
        
        if [ "$FORCE_MANUAL" = "true" ]; then
            warn "Attempting manual Stage 2 execution..."
        else
            warn "Use --force-manual to attempt manual Stage 2 execution"
            exit 1
        fi
        ;;
        
    *)
        warn "⚠️ Cannot determine Stage 2 status: $SERVICE_STATUS"
        
        if [ "$FORCE_MANUAL" = "true" ]; then
            warn "Attempting manual Stage 2 execution..."
        else
            warn "Use --force-manual to attempt manual Stage 2 execution"
            exit 1
        fi
        ;;
esac

# Force manual execution if requested
if [ "$FORCE_MANUAL" = "true" ]; then
    log ""
    log "============================================"
    log "FORCE MANUAL Stage 2 Execution"
    log "============================================"
    
    warn "This will run Stage 2 setup manually, bypassing the systemd service"
    warn "This should only be done if the automatic Stage 2 failed or is stuck"
    
    log "Checking if Stage 2 script exists..."
    
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "test -f /usr/local/bin/fks_stage2.sh" 2>/dev/null; then
        log "✅ Stage 2 script found at /usr/local/bin/fks_stage2.sh"
        
        log "Executing Stage 2 script manually..."
        
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
            echo 'Starting manual Stage 2 execution...'
            sudo /usr/local/bin/fks_stage2.sh
        " 2>/dev/null; then
            log "✅ Manual Stage 2 execution completed successfully!"
        else
            error "❌ Manual Stage 2 execution failed"
            error "Check the logs for details:"
            error "  ssh jordan@$TARGET_HOST 'sudo journalctl -n 50'"
            exit 1
        fi
    else
        error "❌ Stage 2 script not found at /usr/local/bin/fks_stage2.sh"
        error "This suggests Stage 1 did not complete properly"
        error "You may need to re-run Stage 1 setup"
        exit 1
    fi
fi

log ""
log "============================================"
log "Stage 2 Status Check Complete"
log "============================================"

# Final status summary
FINAL_TAILSCALE=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
    if tailscale status >/dev/null 2>&1; then
        tailscale ip -4 2>/dev/null || echo 'connected-no-ip'
    else
        echo 'not-connected'
    fi
" 2>/dev/null || echo "unknown")

if [[ "$FINAL_TAILSCALE" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "🎉 Server is fully ready!"
    log "✅ Tailscale IP: $FINAL_TAILSCALE"
    log ""
    log "Access your server:"
    log "  SSH: ssh jordan@$FINAL_TAILSCALE"
    log "  Web UI: http://$FINAL_TAILSCALE:3000"
    log "  API: http://$FINAL_TAILSCALE:8000"
    log "  Monitoring: http://$FINAL_TAILSCALE:19999"
    log ""
    log "Next steps:"
    log "  1. Clone your repository: git clone <repo-url> ~/fks"
    log "  2. Start services: cd ~/fks && ./start.sh"
elif [ "$FINAL_TAILSCALE" = "not-connected" ]; then
    warn "⚠️ Tailscale is not connected"
    log "Emergency SSH access: ssh jordan@$TARGET_HOST"
    log "Check Tailscale status: ssh jordan@$TARGET_HOST 'tailscale status'"
else
    log "✅ Stage 2 status verified"
    log "SSH access: ssh jordan@$TARGET_HOST"
fi

log "============================================"