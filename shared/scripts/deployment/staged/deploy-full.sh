#!/bin/bash

# FKS Trading Systems - Full Deployment Orchestration
# Runs all stages in sequence: Stage 0 -> Stage 1 -> (reboot) -> Stage 2

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

# Helper function to validate environment file format
validate_env_file() {
    local env_file="$1"
    
    if [ ! -f "$env_file" ]; then
        error "Environment file not found: $env_file"
        return 1
    fi
    
    # Check for common syntax issues with SSH keys
    if grep -q '^[A-Z_]*=.*[^"]ssh-[a-z0-9]' "$env_file" 2>/dev/null; then
        error "Found unquoted SSH keys in $env_file"
        error "SSH keys must be quoted. Example:"
        error 'ACTIONS_JORDAN_SSH_PUB="ssh-ed25519 AAAAC3... user@host"'
        error ""
        error "To fix this automatically, run:"
        error "  ./fix-env-file.sh $env_file"
        return 1
    fi
    
    # Test syntax by trying to source it safely
    if ! (set -a; source "$env_file"; set +a) 2>/dev/null; then
        error "Environment file has syntax errors: $env_file"
        error ""
        error "Common issues:"
        error "- Unquoted values containing special characters"
        error "- Missing quotes around SSH keys"
        error "- Invalid variable names"
        error ""
        error "To fix this automatically, run:"
        error "  ./fix-env-file.sh $env_file"
        return 1
    fi
    
    return 0
}

# Default values
TARGET_SERVER="auto-detect"
CUSTOM_HOST=""
FORCE_NEW_SERVER=false
JORDAN_PASSWORD=""
FKS_USER_PASSWORD=""
TAILSCALE_AUTH_KEY=""
DOCKER_USERNAME=""
DOCKER_TOKEN=""
NETDATA_CLAIM_TOKEN=""
NETDATA_CLAIM_ROOM=""
TIMEZONE="America/Toronto"

ACTIONS_ROOT_PRIVATE_KEY=""
ACTIONS_FKS_SSH_PUB=""
ACTIONS_JORDAN_SSH_PUB=""
ACTIONS_USER_SSH_PUB=""
ACTIONS_ROOT_SSH_PUB=""

SKIP_STAGE_0=false
SKIP_STAGE_1=false
SKIP_STAGE_2=false
SKIP_TAILSCALE=false
ENV_FILE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-server)
            TARGET_SERVER="$2"
            shift 2
            ;;
        --custom-host)
            CUSTOM_HOST="$2"
            shift 2
            ;;
        --force-new)
            FORCE_NEW_SERVER=true
            shift
            ;;
        --jordan-password)
            JORDAN_PASSWORD="$2"
            shift 2
            ;;
        --fks_user-password)
            FKS_USER_PASSWORD="$2"
            shift 2
            ;;
        --tailscale-auth-key)
            TAILSCALE_AUTH_KEY="$2"
            shift 2
            ;;
        --docker-username)
            DOCKER_USERNAME="$2"
            shift 2
            ;;
        --docker-token)
            DOCKER_TOKEN="$2"
            shift 2
            ;;
        --netdata-claim-token)
            NETDATA_CLAIM_TOKEN="$2"
            shift 2
            ;;
        --netdata-claim-room)
            NETDATA_CLAIM_ROOM="$2"
            shift 2
            ;;
        --timezone)
            TIMEZONE="$2"
            shift 2
            ;;
        --jordan-ssh-pub)
            ACTIONS_JORDAN_SSH_PUB="$2"
            shift 2
            ;;
        --actions_user-ssh-pub)
            ACTIONS_USER_SSH_PUB="$2"
            shift 2
            ;;
        --root-ssh-pub)
            ACTIONS_ROOT_SSH_PUB="$2"
            shift 2
            ;;
        --fks_user-ssh-pub)
            ACTIONS_FKS_SSH_PUB="$2"
            shift 2
            ;;
        --env-file)
            ENV_FILE="$2"
            if validate_env_file "$ENV_FILE"; then
                # Source the environment file in a safe way
                set -a  # automatically export all variables
                source "$ENV_FILE"
                set +a  # turn off automatic export
                log "Loaded environment from: $ENV_FILE"
            else
                error "Failed to validate environment file: $ENV_FILE"
                error "Please check the file format and ensure all values are properly quoted"
                error ""
                error "Quick fix: Run the environment file fixer:"
                error "  ./$(dirname "${BASH_SOURCE[0]}")/fix-env-file.sh $ENV_FILE"
                error ""
                error "Or manually ensure SSH keys are quoted like:"
                error "  ACTIONS_JORDAN_SSH_PUB=\"ssh-ed25519 AAAAC3... user@host\""
                exit 1
            fi
            shift 2
            ;;
        --skip-stage-0)
            SKIP_STAGE_0=true
            shift
            ;;
        --skip-stage-1)
            SKIP_STAGE_1=true
            shift
            ;;
        --skip-stage-2)
            SKIP_STAGE_2=true
            shift
            ;;
        --skip-tailscale)
            SKIP_TAILSCALE=true
            shift
            ;;
        --help)
            echo "FKS Trading Systems - Full Deployment Orchestration"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Server Options:"
            echo "  --target-server <option>      Target server (auto-detect|fks.tailfef10.ts.net|custom)"
            echo "  --custom-host <host>          Custom host/IP (if target-server=custom)"
            echo "  --force-new                   Force creation of new server"
            echo ""
            echo "User Credentials:"
            echo "  --jordan-password <pass>      Password for jordan user (REQUIRED)"
            echo "  --fks_user-password <pass>    Password for fks_user (REQUIRED)"
            echo ""
            echo "Service Configuration:"
            echo "  --tailscale-auth-key <key>    Tailscale auth key (REQUIRED for VPN)"
            echo "  --docker-username <user>   Docker Hub username"
            echo "  --docker-token <token>     Docker Hub access token"
            echo "  --netdata-claim-token <token> Netdata claim token"
            echo "  --netdata-claim-room <room>   Netdata room ID"
            echo "  --timezone <tz>               Server timezone (default: America/Toronto)"
            echo ""
            echo "SSH Keys:"
            echo "  --jordan-ssh-pub <key>        Jordan's SSH public key"
            echo "  --actions_user-ssh-pub <key> GitHub Actions SSH public key"
            echo "  --root-ssh-pub <key>          Root SSH public key"
            echo "  --fks_user-ssh-pub <key>      FKS User SSH public key"
            echo ""
            echo "Execution Control:"
            echo "  --env-file <file>             Load environment from file"
            echo "  --skip-stage-0                Skip server creation"
            echo "  --skip-stage-1                Skip initial setup"
            echo "  --skip-stage-2                Skip Stage 2 waiting (let it run automatically)"
            echo "  --skip-tailscale              Skip Tailscale configuration"
            echo "  --help                        Show this help message"
            echo ""
            echo "Environment Variables (alternative to CLI args):"
            echo "  LINODE_CLI_TOKEN             Linode API token (REQUIRED for Stage 0)"
            echo "  FKS_DEV_ROOT_PASSWORD         Root password for new servers (REQUIRED for Stage 0)"
            echo ""
            echo "Examples:"
            echo "  # Full deployment with new server:"
            echo "  $0 --jordan-password mypass --fks_user-password mypass2 \\"
            echo "     --tailscale-auth-key tskey-xxx"
            echo ""
            echo "  # Use existing server:"
            echo "  $0 --target-server custom --custom-host 192.168.1.100 \\"
            echo "     --jordan-password mypass --fks_user-password mypass2 \\"
            echo "     --tailscale-auth-key tskey-xxx"
            echo ""
            echo "  # GitHub Actions mode (Stage 1 only, Stage 2 automatic):"
            echo "  $0 --skip-stage-2 --env-file deployment.env"
            echo ""
            echo "Environment File Format:"
            echo "  All values in the environment file must be properly quoted:"
            echo "  JORDAN_PASSWORD=\"mypassword\""
            echo "  ACTIONS_JORDAN_SSH_PUB=\"ssh-ed25519 AAAAC3... user@host\""
            echo ""
            echo "Common Issues:"
            echo "  - SSH keys must be quoted with double quotes"
            echo "  - Passwords with special characters must be quoted"
            echo "  - No spaces around the = sign"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "============================================"
log "FKS Trading Systems - Full Deployment"
log "============================================"

# Validate environment file was properly loaded if specified
if [ -n "$ENV_FILE" ]; then
    log "Environment file: $ENV_FILE"
    
    # Check if SSH keys are properly set (not just starting with ssh-)
    if [ -n "$ACTIONS_JORDAN_SSH_PUB" ] && [[ ! "$ACTIONS_JORDAN_SSH_PUB" =~ ^ssh- ]]; then
        error "ACTIONS_JORDAN_SSH_PUB appears to be malformed. SSH keys should start with 'ssh-'"
        error "Current value: ${ACTIONS_JORDAN_SSH_PUB:0:50}..."
        error "Please ensure SSH keys are properly quoted in your environment file"
        exit 1
    fi
    
    if [ -n "$ACTIONS_USER_SSH_PUB" ] && [[ ! "$ACTIONS_USER_SSH_PUB" =~ ^ssh- ]]; then
        error "ACTIONS_USER_SSH_PUB appears to be malformed. SSH keys should start with 'ssh-'"
        error "Current value: ${ACTIONS_USER_SSH_PUB:0:50}..."
        error "Please ensure SSH keys are properly quoted in your environment file"
        exit 1
    fi
    
    if [ -n "$ACTIONS_ROOT_SSH_PUB" ] && [[ ! "$ACTIONS_ROOT_SSH_PUB" =~ ^ssh- ]]; then
        error "ACTIONS_ROOT_SSH_PUB appears to be malformed. SSH keys should start with 'ssh-'"
        error "Current value: ${ACTIONS_ROOT_SSH_PUB:0:50}..."
        error "Please ensure SSH keys are properly quoted in your environment file"
        exit 1
    fi
    
    if [ -n "$ACTIONS_FKS_SSH_PUB" ] && [[ ! "$ACTIONS_FKS_SSH_PUB" =~ ^ssh- ]]; then
        error "ACTIONS_FKS_SSH_PUB appears to be malformed. SSH keys should start with 'ssh-'"
        error "Current value: ${ACTIONS_FKS_SSH_PUB:0:50}..."
        error "Please ensure SSH keys are properly quoted in your environment file"
        exit 1
    fi
    
    log "Environment validation passed"
fi

# Validate required parameters for stages we're running
if [ "$SKIP_STAGE_0" = "false" ]; then
    if [ -z "$LINODE_CLI_TOKEN" ]; then
        error "LINODE_CLI_TOKEN environment variable is required for Stage 0"
        exit 1
    fi
    
    if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then
        error "FKS_DEV_ROOT_PASSWORD environment variable is required for Stage 0"
        exit 1
    fi
fi

if [ "$SKIP_STAGE_1" = "false" ]; then
    if [ -z "$JORDAN_PASSWORD" ]; then
        error "Jordan password is required for Stage 1 (--jordan-password)"
        exit 1
    fi
    
    if [ -z "$FKS_USER_PASSWORD" ]; then
        error "FKS user password is required for Stage 1 (--fks_user-password)"
        exit 1
    fi
    
    if [ "$SKIP_TAILSCALE" = "false" ] && [ -z "$TAILSCALE_AUTH_KEY" ]; then
        error "Tailscale auth key is required unless --skip-tailscale is used"
        exit 1
    fi
fi

# Stage 0: Server Creation
if [ "$SKIP_STAGE_0" = "false" ]; then
    log ""
    log "================================================"
    log "STAGE 0: Server Creation"
    log "================================================"
    
    STAGE_0_ARGS="--target-server $TARGET_SERVER"
    
    if [ -n "$CUSTOM_HOST" ]; then
        STAGE_0_ARGS="$STAGE_0_ARGS --custom-host $CUSTOM_HOST"
    fi
    
    if [ "$FORCE_NEW_SERVER" = "true" ]; then
        STAGE_0_ARGS="$STAGE_0_ARGS --force-new"
    fi
    
    log "Running: $SCRIPT_DIR/stage-0-create-server.sh $STAGE_0_ARGS"
    
    if ! "$SCRIPT_DIR/stage-0-create-server.sh" $STAGE_0_ARGS; then
        error "Stage 0 failed"
        exit 1
    fi
    
    # Load server details from Stage 0
    if [ -f "server-details.env" ]; then
        source server-details.env
        log "Server details loaded: TARGET_HOST=$TARGET_HOST, IS_NEW_SERVER=$IS_NEW_SERVER"
    else
        error "Stage 0 did not create server-details.env file"
        exit 1
    fi
else
    log "Skipping Stage 0 (Server Creation)"
    
    # If we're skipping Stage 0, we need a target host
    if [ -n "$CUSTOM_HOST" ]; then
        TARGET_HOST="$CUSTOM_HOST"
        IS_NEW_SERVER=false
        log "Using provided target host: $TARGET_HOST"
    else
        error "When skipping Stage 0, you must provide --custom-host"
        exit 1
    fi
fi

# Stage 1: Initial Setup
if [ "$SKIP_STAGE_1" = "false" ]; then
    log ""
    log "================================================"
    log "STAGE 1: Initial Setup"
    log "================================================"
    
    STAGE_1_ARGS="--target-host $TARGET_HOST"
    
    # Add root password for password-based SSH
    if [ -n "$FKS_DEV_ROOT_PASSWORD" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --root-password '$FKS_DEV_ROOT_PASSWORD'"
    fi
    
    STAGE_1_ARGS="$STAGE_1_ARGS --jordan-password '$JORDAN_PASSWORD'"
    STAGE_1_ARGS="$STAGE_1_ARGS --fks_user-password '$FKS_USER_PASSWORD'"
    STAGE_1_ARGS="$STAGE_1_ARGS --timezone '$TIMEZONE'"
    
    if [ -n "$TAILSCALE_AUTH_KEY" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --tailscale-auth-key '$TAILSCALE_AUTH_KEY'"
    fi
    
    if [ -n "$DOCKER_USERNAME" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --docker-username '$DOCKER_USERNAME'"
    fi
    
    if [ -n "$DOCKER_TOKEN" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --docker-token '$DOCKER_TOKEN'"
    fi
    
    if [ -n "$NETDATA_CLAIM_TOKEN" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --netdata-claim-token '$NETDATA_CLAIM_TOKEN'"
    fi
    
    if [ -n "$NETDATA_CLAIM_ROOM" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --netdata-claim-room '$NETDATA_CLAIM_ROOM'"
    fi
    
    if [ -n "$ACTIONS_JORDAN_SSH_PUB" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --jordan-ssh-pub '$ACTIONS_JORDAN_SSH_PUB'"
    fi
    
    if [ -n "$ACTIONS_USER_SSH_PUB" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --actions_user-ssh-pub '$ACTIONS_USER_SSH_PUB'"
    fi
    
    if [ -n "$ACTIONS_ROOT_SSH_PUB" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --root-ssh-pub '$ACTIONS_ROOT_SSH_PUB'"
    fi
    
    if [ -n "$ACTIONS_FKS_SSH_PUB" ]; then
        STAGE_1_ARGS="$STAGE_1_ARGS --fks_user-ssh-pub '$ACTIONS_FKS_SSH_PUB'"
    fi
    
    log "Running Stage 1 setup..."
    
    if ! eval "$SCRIPT_DIR/stage-1-initial-setup.sh $STAGE_1_ARGS"; then
        error "Stage 1 failed"
        exit 1
    fi
    
    log ""
    log "Stage 1 complete. Server is rebooting..."
    log "Stage 2 will run AUTOMATICALLY via systemd service after reboot"
    
    if [ "$SKIP_STAGE_2" = "false" ]; then
        log "Waiting for server to come back online and Stage 2 to complete..."
    else
        log "Waiting for server to come back online (Stage 2 will complete automatically)..."
    fi
    
    # Wait for server to reboot and come back online
    sleep 30  # Initial wait for reboot to start
    
    # Optimized reboot waiting strategy:
    # Check at 2, 4, and 6 minute intervals (server typically reboots in ~2 minutes)
    server_online=false
    for attempt in 1 2; do
        log "Reboot wait attempt $attempt/2..."
        
        # Check at key intervals: 2min, 4min, 6min
        for check_time in 120 240 360; do
            check_minutes=$((check_time / 60))
            log "⏰ Checking server status at ${check_minutes} minute mark..."
            
            # Wait until we reach this check time
            elapsed=0
            while [ $elapsed -lt $check_time ]; do
                # Test connectivity every 30 seconds as we approach the check time
                if [ $((check_time - elapsed)) -le 30 ]; then
                    if timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "echo 'Server is back online'" 2>/dev/null; then
                        log "✅ Server is back online after reboot (attempt $attempt, ${elapsed}s / ${check_minutes}min mark)"
                        server_online=true
                        break 2  # Break out of both loops
                    fi
                fi
                
                # Show progress less frequently to reduce log noise
                if [ $((elapsed % 30)) -eq 0 ]; then
                    log "Waiting for ${check_minutes}min check... (${elapsed}/${check_time}s)"
                fi
                sleep 15
                elapsed=$((elapsed + 15))
            done
            
            # Final check at the exact interval
            log "📡 Testing connectivity at ${check_minutes} minute mark..."
            if timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "echo 'Server is back online'" 2>/dev/null; then
                log "✅ Server is back online at ${check_minutes} minute mark (attempt $attempt)"
                server_online=true
                break
            else
                warn "❌ Server not ready at ${check_minutes} minute mark"
            fi
        done
        
        if [ "$server_online" = "true" ]; then
            break
        fi
        
        if [ $attempt -eq 1 ]; then
            warn "⚠️ Attempt $attempt failed. Server not responding after 6 minutes. Trying once more..."
            log "Waiting 30 seconds before next attempt..."
            sleep 30
        fi
    done
    
    if [ "$server_online" != "true" ]; then
        error "❌ Server failed to come back online after 2 attempts (checked at 2min, 4min, 6min intervals)"
        error "This suggests a more serious issue with the server or reboot process."
        error ""
        error "Troubleshooting options:"
        error "1. Check Linode console: https://cloud.linode.com/linodes"
        error "2. Try manual SSH: ssh jordan@$TARGET_HOST"
        error "3. Check Stage 2 status manually: $SCRIPT_DIR/stage-2-finalize.sh --target-host $TARGET_HOST"
        error "4. Check system logs via Linode console"
        error "5. Server might be stuck in reboot - check console for kernel messages"
        exit 1
    fi
    
    # Check if we should wait for Stage 2 completion
    if [ "$SKIP_STAGE_2" = "false" ]; then
        # Wait for Stage 2 systemd service to complete
        log "✅ Server is online! Now waiting for Stage 2 systemd service to complete..."
        sleep 30  # Give Stage 2 service time to start
        
        # Wait for Stage 2 completion (up to 8 minutes - should be plenty since server is online)
        stage2_timeout=480  # 8 minutes
        stage2_elapsed=0
        stage2_completed=false
        
        while [ $stage2_elapsed -lt $stage2_timeout ]; do
            # Check multiple indicators that Stage 2 completed
            if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
                # Check for completion message
                sudo journalctl -u fks_stage2.service --no-pager -n 20 | grep -q 'FKS Trading Systems Setup Complete' ||
                # Check if service finished successfully
                systemctl is-active fks_stage2.service | grep -q 'inactive' ||
                # Check if Tailscale is configured (key Stage 2 task)
                tailscale status >/dev/null 2>&1
            " 2>/dev/null; then
                log "✅ Stage 2 completed successfully!"
                stage2_completed=true
                break
            fi
            
            # Show some progress info
            stage2_status=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
                if systemctl is-active fks_stage2.service >/dev/null 2>&1; then
                    echo 'running'
                elif systemctl status fks_stage2.service | grep -q 'inactive'; then
                    echo 'finished'
                else
                    echo 'pending'
                fi
            " 2>/dev/null || echo "unknown")
            
            log "Stage 2 status: $stage2_status - waiting... ($stage2_elapsed/$stage2_timeout seconds)"
            sleep 20
            stage2_elapsed=$((stage2_elapsed + 20))
        done
        
        if [ "$stage2_completed" != "true" ]; then
            warn "⚠️ Stage 2 auto-setup may not have completed within timeout"
            log "Checking final Stage 2 status..."
            
            # Try to get more detailed status
            ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
                echo '=== Stage 2 Service Status ==='
                sudo systemctl status fks_stage2.service --no-pager || true
                echo ''
                echo '=== Recent Stage 2 Logs ==='
                sudo journalctl -u fks_stage2.service --no-pager -n 20 || true
                echo ''
                echo '=== Tailscale Status ==='
                tailscale status || echo 'Tailscale not configured'
            " 2>/dev/null || warn "Could not get Stage 2 status"
            
            log "Stage 2 may need manual completion. Continuing with deployment verification..."
        fi
    else
        # Skip Stage 2 waiting - just verify it's set up correctly
        log "✅ Server is online! Verifying Stage 2 systemd service is configured..."
        
        # Check that Stage 2 service is enabled and ready to run
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
            sudo systemctl is-enabled fks_stage2.service >/dev/null 2>&1
        " 2>/dev/null; then
            log "✅ Stage 2 systemd service is enabled and will run automatically"
            
            # Check current status
            stage2_status=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no jordan@"$TARGET_HOST" "
                if sudo systemctl is-active fks_stage2.service >/dev/null 2>&1; then
                    echo 'running'
                elif sudo systemctl status fks_stage2.service 2>/dev/null | grep -q 'Deactivated successfully'; then
                    echo 'completed'
                else
                    echo 'pending'
                fi
            " 2>/dev/null || echo "unknown")
            
            log "📊 Stage 2 status: $stage2_status"
            
            if [ "$stage2_status" = "completed" ]; then
                log "🎉 Stage 2 has already completed successfully!"
            elif [ "$stage2_status" = "running" ]; then
                log "🔄 Stage 2 is currently running automatically"
            else
                log "⏳ Stage 2 will start automatically (may take a few minutes)"
            fi
            
            log "🚀 Deployment workflow complete! Stage 2 will finish automatically via systemd."
        else
            warn "⚠️ Stage 2 service may not be properly configured"
            warn "You may need to run Stage 2 manually later"
        fi
    fi
else
    log "Skipping Stage 1 (Initial Setup)"
fi

# Stage 2: Check Status (and manual run if needed)
if [ "$SKIP_STAGE_2" = "false" ]; then
    log ""
    log "================================================"
    log "STAGE 2: Check Auto-Setup Status"
    log "================================================"
    
    STAGE_2_ARGS="--target-host $TARGET_HOST"
    
    log "Checking Stage 2 auto-setup status..."
    
    if ! "$SCRIPT_DIR/stage-2-finalize.sh" $STAGE_2_ARGS; then
        warn "Stage 2 status check indicated issues"
        log "You may need to troubleshoot or run manual Stage 2"
        log "Check systemd service: ssh jordan@$TARGET_HOST 'journalctl -u fks_stage2.service -f'"
        log "Or run manual Stage 2: $SCRIPT_DIR/stage-2-finalize.sh --target-host $TARGET_HOST --force-manual"
    fi
else
    log "Skipping Stage 2 waiting (will complete automatically via systemd)"
fi

log ""
log "============================================"
if [ "$SKIP_STAGE_2" = "false" ]; then
    log "DEPLOYMENT COMPLETE!"
    log "============================================"
    log "Server: $TARGET_HOST"
    log "Status: Ready for use"
    log ""
    log "The FKS deployment follows the proven StackScript approach:"
    log "- Stage 0: Server creation (if needed)"
    log "- Stage 1: Initial setup, user creation, package installation"
    log "- Auto-reboot and Stage 2: Tailscale, firewall, finalization"
    log ""
    log "Next steps:"
    log "1. SSH to server: ssh jordan@$TARGET_HOST"
    log "2. Clone your repository: git clone <your-repo-url> ~/fks"
    log "3. Start services: cd ~/fks && ./start.sh"
    log ""
    log "Access via Tailscale (if configured):"
    if [ "$SKIP_TAILSCALE" = "false" ]; then
        log "  SSH: ssh jordan@<tailscale-ip>"
        log "  Web UI: http://<tailscale-ip>:3000"
        log "  API: http://<tailscale-ip>:8000"
        log "  Monitoring: http://<tailscale-ip>:19999"
    else
        log "  Tailscale was skipped"
    fi
    log ""
    log "Troubleshooting:"
    log "  Check Stage 2 logs: ssh jordan@$TARGET_HOST 'journalctl -u fks_stage2.service -f'"
    log "  Manual Stage 2: $SCRIPT_DIR/stage-2-finalize.sh --target-host $TARGET_HOST --force-manual"
else
    log "STAGE 0 + STAGE 1 DEPLOYMENT COMPLETE!"
    log "============================================"
    log "Server: $TARGET_HOST"
    log "Status: Stage 1 complete, Stage 2 running automatically"
    log ""
    log "Deployment progress:"
    log "✅ Stage 0: Server creation (if needed)"
    log "✅ Stage 1: Initial setup, user creation, package installation, reboot"
    log "🔄 Stage 2: Tailscale, firewall, finalization (running automatically via systemd)"
    log ""
    log "What happens next:"
    log "- Stage 2 will complete automatically in 5-10 minutes"
    log "- Tailscale will be configured and secured"
    log "- Firewall will be locked down to Tailscale-only access"
    log "- Server will be fully ready for deployment"
    log ""
    log "Monitor Stage 2 progress:"
    log "  SSH: ssh jordan@$TARGET_HOST"
    log "  Logs: ssh jordan@$TARGET_HOST 'sudo journalctl -u fks_stage2.service -f'"
    log "  Status: ssh jordan@$TARGET_HOST 'sudo systemctl status fks_stage2.service'"
    log ""
    log "After Stage 2 completes (~5-10 minutes):"
    log "1. Get Tailscale IP: ssh jordan@$TARGET_HOST 'tailscale ip'"
    log "2. Clone your repository: git clone <your-repo-url> ~/fks"
    log "3. Start services: cd ~/fks && ./start.sh"
    log ""
    log "Access will be via Tailscale:"
    log "  SSH: ssh jordan@<tailscale-ip>"
    log "  Web UI: http://<tailscale-ip>:3000"
    log "  API: http://<tailscale-ip>:8000"
    log "  Monitoring: http://<tailscale-ip>:19999"
    log ""
    log "Emergency troubleshooting:"
    log "  Manual Stage 2: $SCRIPT_DIR/stage-2-finalize.sh --target-host $TARGET_HOST --force-manual"
fi
log ""
log "Server details saved in: server-details.env"
log "============================================"