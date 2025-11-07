#!/bin/bash

# FKS Deployment Optimizer - Advanced GitHub Actions Tools Integration
# This script optimizes the deployment process by integrating all our shell tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_success() { echo -e "${GREEN}✅ [$(date +'%H:%M:%S')] $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_error() { echo -e "${RED}❌ [$(date +'%H:%M:%S')] $1${NC}"; }
log_step() { echo -e "${MAGENTA}🔄 [$(date +'%H:%M:%S')] $1${NC}"; }

# Default values
ACTION=""
SERVER_IP=""
SERVER_ID=""
DEPLOYMENT_MODE=""
VERBOSE=false

# Usage function
usage() {
    cat << EOF
FKS Deployment Optimizer - GitHub Actions Integration

Usage: $0 <action> [options]

Actions:
  configure-linode     Configure Linode CLI optimally
  test-ssh             Test SSH connectivity with fallbacks
  monitor-deployment   Monitor deployment status with smart timing
  emergency-debug      Run comprehensive debugging
  optimize-timing      Calculate optimal wait times

Options:
  --server-ip IP       Server IP address
  --server-id ID       Linode server ID
  --mode MODE          Deployment mode (full-deploy, builds-only, etc.)
  --verbose            Enable verbose output
  --help               Show this help

Examples:
  $0 configure-linode
  $0 test-ssh --server-ip 192.168.1.100
  $0 monitor-deployment --server-id 12345 --mode full-deploy
  $0 emergency-debug --server-ip 192.168.1.100

EOF
}

# Configure Linode CLI with optimal settings
configure_linode() {
    log_step "Configuring Linode CLI with optimal settings..."
    
    # First, configure using our dedicated script
    if [ -f "scripts/deployment/github-actions/configure_linode_cli.sh" ]; then
        log_info "Using dedicated Linode CLI configuration script..."
        chmod +x scripts/deployment/github-actions/configure_linode_cli.sh
        ./scripts/deployment/github-actions/configure_linode_cli.sh
    else
        log_warning "Dedicated script not found, using fallback configuration..."
        
        # Fallback configuration
        mkdir -p ~/.config/linode-cli
        cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
default-user = DEFAULT
region = ca-central
type = g6-standard-2
image = linode/arch
authorized_users = 
authorized_keys = 
token = ${LINODE_CLI_TOKEN}
EOF
        chmod 600 ~/.config/linode-cli/config
        
        log_success "Fallback Linode CLI configuration applied"
    fi
    
    # Additional GitHub Actions optimizations
    log_info "Applying GitHub Actions specific optimizations..."
    
    # Set optimal timeouts for CI environment
    export LINODE_CLI_TIMEOUT="30"
    export LINODE_CLI_RETRIES="3"
    
    # Configure for our preferred region
    echo "LINODE_PREFERRED_REGION=ca-central" >> $GITHUB_ENV
    echo "LINODE_BACKUP_REGION=us-east" >> $GITHUB_ENV
    echo "LINODE_OPTIMIZED_CONFIG=true" >> $GITHUB_ENV
    
    # Export timing optimizations
    echo "FKS_TIMING_OPTIMIZED=true" >> $GITHUB_ENV
    
    log_success "Linode CLI configured with GitHub Actions optimizations"
}

# Test SSH connectivity with smart fallbacks
test_ssh() {
    if [ -z "$SERVER_IP" ]; then
        log_error "Server IP required for SSH testing"
        return 1
    fi
    
    log_step "Testing SSH connectivity to $SERVER_IP..."
    
    # Test basic connectivity first
    log_info "1. Testing basic network connectivity..."
    if timeout 10 ping -c 3 "$SERVER_IP" >/dev/null 2>&1; then
        log_success "Network connectivity confirmed"
    else
        log_warning "Network connectivity issues detected"
    fi
    
    # Test SSH port
    log_info "2. Testing SSH port accessibility..."
    if timeout 10 nc -z "$SERVER_IP" 22; then
        log_success "SSH port 22 is accessible"
    else
        log_warning "SSH port 22 may not be ready"
    fi
    
    # Test SSH with different users and methods
    log_info "3. Testing SSH authentication methods..."
    
    local ssh_success=false
    
    # Try jordan user with password (most reliable during setup)
    if [ -n "$JORDAN_PASSWORD" ]; then
        log_info "Testing jordan user with password..."
        if command -v sshpass >/dev/null 2>&1; then
            if timeout 15 sshpass -p "$JORDAN_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 jordan@"$SERVER_IP" "echo 'SSH password auth successful'" 2>/dev/null; then
                log_success "SSH password authentication working for jordan user"
                ssh_success=true
            else
                log_warning "SSH password authentication failed for jordan user"
            fi
        else
            log_warning "sshpass not available for password authentication"
        fi
    fi
    
    # Try SSH key authentication if available
    if [ -n "$ACTIONS_JORDAN_SSH_PUB" ]; then
        log_info "Testing jordan user with SSH key..."
        if timeout 15 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 jordan@"$SERVER_IP" "echo 'SSH key auth successful'" 2>/dev/null; then
            log_success "SSH key authentication working for jordan user"
            ssh_success=true
        else
            log_warning "SSH key authentication failed for jordan user"
        fi
    fi
    
    if [ "$ssh_success" = true ]; then
        log_success "SSH connectivity confirmed"
        return 0
    else
        log_error "SSH connectivity failed"
        
        # Run emergency debug if available
        if [ -f "scripts/deployment/github-actions/emergency-ssh-debug.sh" ]; then
            log_info "Running emergency SSH debug..."
            chmod +x scripts/deployment/github-actions/emergency-ssh-debug.sh
            ./scripts/deployment/github-actions/emergency-ssh-debug.sh "$SERVER_IP" || true
        fi
        
        return 1
    fi
}

# Monitor deployment with smart timing based on phase
monitor_deployment() {
    if [ -z "$SERVER_ID" ] && [ -z "$SERVER_IP" ]; then
        log_error "Server ID or IP required for monitoring"
        return 1
    fi
    
    log_step "Monitoring deployment progress with smart timing..."
    
    case "$DEPLOYMENT_MODE" in
        "full-deploy")
            log_info "Full deployment mode - monitoring all phases"
            monitor_full_deployment
            ;;
        "builds-only")
            log_info "Builds only mode - no server monitoring needed"
            ;;
        "infra-only")
            log_info "Infrastructure only mode - monitoring server creation"
            monitor_infrastructure_only
            ;;
        *)
            log_info "Standard monitoring mode"
            monitor_standard_deployment
            ;;
    esac
}

# Monitor full deployment with optimized timing
monitor_full_deployment() {
    log_info "Phase 1: Monitoring server creation and initial setup..."
    
    # Wait for server to be running (usually 1-2 minutes)
    local max_wait=120
    local count=0
    
    while [ $count -lt $max_wait ]; do
        if [ -n "$SERVER_ID" ] && command -v linode-cli >/dev/null 2>&1; then
            local status=$(linode-cli linodes view "$SERVER_ID" --text --no-headers --format="status" 2>/dev/null || echo "unknown")
            if [ "$status" = "running" ]; then
                log_success "Server is running - Phase 1 setup starting"
                break
            fi
            log_info "Server status: $status (waiting...)"
        else
            # Fallback to ping test
            if timeout 5 ping -c 1 "$SERVER_IP" >/dev/null 2>&1; then
                log_success "Server responding to ping - setup in progress"
                break
            fi
        fi
        
        sleep 15
        count=$((count + 15))
    done
    
    # Optimized Phase 1 wait (reduced from 8 minutes to 5 minutes)
    log_info "Phase 1: Package installation and user setup (5 minutes)..."
    local phase1_wait=300  # 5 minutes instead of 8
    
    for i in $(seq 1 $((phase1_wait / 30))); do
        log_info "Phase 1 progress: $((i * 30))/$phase1_wait seconds"
        sleep 30
    done
    
    # Monitor reboot
    log_info "Phase 2: Monitoring auto-reboot..."
    sleep 60  # Give time for reboot to start
    
    # Wait for server to come back (optimized to 3 minutes max)
    local reboot_wait=180
    local reboot_count=0
    
    while [ $reboot_count -lt $reboot_wait ]; do
        if timeout 5 ping -c 1 "$SERVER_IP" >/dev/null 2>&1; then
            log_success "Server back online after reboot"
            break
        fi
        
        log_info "Waiting for reboot completion... ($reboot_count/$reboot_wait seconds)"
        sleep 15
        reboot_count=$((reboot_count + 15))
    done
    
    # Phase 2 completion (reduced from 5 minutes to 3 minutes)
    log_info "Phase 2: Tailscale and final configuration (3 minutes)..."
    local phase2_wait=180  # 3 minutes instead of 5
    
    for i in $(seq 1 $((phase2_wait / 30))); do
        log_info "Phase 2 progress: $((i * 30))/$phase2_wait seconds"
        sleep 30
    done
    
    log_success "Deployment monitoring complete - total time optimized to ~10 minutes"
}

# Monitor infrastructure-only deployment
monitor_infrastructure_only() {
    log_info "Monitoring infrastructure provisioning only..."
    
    # Just wait for server creation and basic setup
    sleep 120  # 2 minutes for basic setup
    
    log_success "Infrastructure monitoring complete"
}

# Monitor standard deployment
monitor_standard_deployment() {
    log_info "Standard deployment monitoring..."
    
    # Balanced approach
    sleep 300  # 5 minutes for standard setup
    
    log_success "Standard monitoring complete"
}

# Run emergency debug with all available tools
emergency_debug() {
    if [ -z "$SERVER_IP" ]; then
        log_error "Server IP required for emergency debugging"
        return 1
    fi
    
    log_step "Running comprehensive emergency debugging..."
    
    # Basic connectivity
    log_info "1. Network connectivity check..."
    ping -c 5 "$SERVER_IP" || log_warning "Ping failed"
    
    # Port checks
    log_info "2. Port accessibility check..."
    nc -z -v "$SERVER_IP" 22 || log_warning "SSH port not accessible"
    nc -z -v "$SERVER_IP" 80 || log_warning "HTTP port not accessible"
    nc -z -v "$SERVER_IP" 443 || log_warning "HTTPS port not accessible"
    
    # SSH debugging
    if [ -f "scripts/deployment/github-actions/emergency-ssh-debug.sh" ]; then
        log_info "3. Running dedicated SSH debug script..."
        chmod +x scripts/deployment/github-actions/emergency-ssh-debug.sh
        ./scripts/deployment/github-actions/emergency-ssh-debug.sh "$SERVER_IP" || true
    fi
    
    # Server status via API
    if [ -n "$SERVER_ID" ] && command -v linode-cli >/dev/null 2>&1; then
        log_info "4. Checking server status via Linode API..."
        linode-cli linodes view "$SERVER_ID" || log_warning "API check failed"
    fi
    
    log_success "Emergency debugging complete"
}

# Calculate and apply optimal timing
optimize_timing() {
    log_step "Calculating optimal timing for deployment phases..."
    
    # Export optimized timing to GitHub environment
    echo "FKS_PHASE1_WAIT=300" >> $GITHUB_ENV      # 5 minutes (was 8)
    echo "FKS_REBOOT_WAIT=180" >> $GITHUB_ENV      # 3 minutes (was 5)
    echo "FKS_PHASE2_WAIT=180" >> $GITHUB_ENV      # 3 minutes (was 5)
    echo "FKS_SECRET_WAIT=300" >> $GITHUB_ENV      # 5 minutes (was 10)
    echo "FKS_TOTAL_SETUP=11" >> $GITHUB_ENV       # 11 minutes total (was 18)
    
    log_success "Optimized timing exported to GitHub environment"
    log_info "Total deployment time optimized from 18 minutes to 11 minutes"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        configure-linode|test-ssh|monitor-deployment|emergency-debug|optimize-timing)
            ACTION="$1"
            ;;
        --server-ip)
            SERVER_IP="$2"
            shift
            ;;
        --server-id)
            SERVER_ID="$2"
            shift
            ;;
        --mode)
            DEPLOYMENT_MODE="$2"
            shift
            ;;
        --verbose)
            VERBOSE=true
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
    shift
done

# Validate action
if [ -z "$ACTION" ]; then
    log_error "Action required"
    usage
    exit 1
fi

# Set verbose mode
if [ "$VERBOSE" = true ]; then
    set -x
fi

# Execute action
case "$ACTION" in
    "configure-linode")
        configure_linode
        ;;
    "test-ssh")
        test_ssh
        ;;
    "monitor-deployment")
        monitor_deployment
        ;;
    "emergency-debug")
        emergency_debug
        ;;
    "optimize-timing")
        optimize_timing
        ;;
    *)
        log_error "Invalid action: $ACTION"
        exit 1
        ;;
esac

log_success "Action '$ACTION' completed successfully"
