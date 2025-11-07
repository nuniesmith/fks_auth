#!/bin/bash

# FKS Trading Systems - Docker iptables Fix
# Resolves common Docker networking issues related to iptables chains
# Supports both Arch Linux and Ubuntu/Debian systems

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
FORCE_RESTART=false
SKIP_BACKUP=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force-restart)
            FORCE_RESTART=true
            shift
            ;;
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Fix Docker iptables networking issues"
            echo ""
            echo "Options:"
            echo "  --force-restart    Force Docker daemon restart even if not needed"
            echo "  --skip-backup      Skip iptables rules backup"
            echo "  --verbose          Enable verbose output"
            echo "  --help             Show this help message"
            echo ""
            echo "Common Docker iptables errors this fixes:"
            echo "  - 'No chain/target/match by that name'"
            echo "  - 'Failed to Setup IP tables: Unable to enable DROP INCOMING rule'"
            echo "  - Network creation failures during docker-compose up"
            echo ""
            echo "This script will:"
            echo "  1. Backup current iptables rules (if not skipped)"
            echo "  2. Stop Docker daemon gracefully"
            echo "  3. Clean up broken iptables chains"
            echo "  4. Reset Docker networking state"
            echo "  5. Restart Docker daemon"
            echo "  6. Verify Docker networking is functional"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
    error "Run with: sudo $0"
    exit 1
fi

# Detect OS
if [ -f /etc/arch-release ]; then
    OS="arch"
    DOCKER_SERVICE="docker.service"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    DOCKER_SERVICE="docker.service"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    DOCKER_SERVICE="docker.service"
else
    warn "Unknown OS detected, assuming systemd-based system"
    OS="unknown"
    DOCKER_SERVICE="docker.service"
fi

log "Detected OS: $OS"

# Function to check if Docker is running
is_docker_running() {
    systemctl is-active --quiet $DOCKER_SERVICE
}

# Function to check Docker chains
check_docker_chains() {
    if [ "$VERBOSE" = "true" ]; then
        log "Checking existing Docker iptables chains..."
        iptables -L | grep -i docker || echo "No Docker chains found"
    fi
    
    # Check for problematic chain states
    if iptables -L DOCKER-ISOLATION-STAGE-1 -n >/dev/null 2>&1; then
        if [ "$VERBOSE" = "true" ]; then
            log "DOCKER-ISOLATION-STAGE-1 chain exists"
        fi
        return 0
    else
        if [ "$VERBOSE" = "true" ]; then
            warn "DOCKER-ISOLATION-STAGE-1 chain missing or broken"
        fi
        return 1
    fi
}

# Function to backup iptables rules
backup_iptables() {
    if [ "$SKIP_BACKUP" = "true" ]; then
        log "Skipping iptables backup (--skip-backup specified)"
        return 0
    fi
    
    local backup_dir="/var/lib/fks_backups/iptables"
    local backup_file="$backup_dir/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
    
    log "Creating iptables backup..."
    mkdir -p "$backup_dir"
    
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$backup_file"
        log "Iptables rules backed up to: $backup_file"
    else
        warn "iptables-save not available, skipping backup"
    fi
}

# Function to clean Docker iptables chains
clean_docker_chains() {
    log "Cleaning Docker iptables chains..."
    
    # List of Docker-related chains to clean
    DOCKER_CHAINS=(
        "DOCKER"
        "DOCKER-ISOLATION-STAGE-1"
        "DOCKER-ISOLATION-STAGE-2"
        "DOCKER-USER"
    )
    
    # Flush and delete Docker chains in filter table
    for chain in "${DOCKER_CHAINS[@]}"; do
        if iptables -L "$chain" -n >/dev/null 2>&1; then
            log "Flushing chain: $chain"
            iptables -F "$chain" 2>/dev/null || warn "Failed to flush chain $chain"
            
            log "Deleting chain: $chain"
            iptables -X "$chain" 2>/dev/null || warn "Failed to delete chain $chain"
        fi
    done
    
    # Clean NAT table rules
    log "Cleaning Docker NAT table rules..."
    iptables -t nat -F DOCKER 2>/dev/null || true
    iptables -t nat -X DOCKER 2>/dev/null || true
    
    # Clean MANGLE table rules
    log "Cleaning Docker MANGLE table rules..."
    iptables -t mangle -F DOCKER 2>/dev/null || true
    iptables -t mangle -X DOCKER 2>/dev/null || true
}

# Function to remove Docker bridge interfaces
clean_docker_interfaces() {
    log "Cleaning Docker network interfaces..."
    
    # Remove docker0 bridge if it exists
    if ip link show docker0 >/dev/null 2>&1; then
        log "Removing docker0 bridge interface"
        ip link set docker0 down 2>/dev/null || true
        ip link delete docker0 2>/dev/null || true
    fi
    
    # Remove any other Docker-created bridges
    for bridge in $(ip link show | grep 'br-' | awk -F': ' '{print $2}' | awk '{print $1}'); do
        log "Removing Docker bridge: $bridge"
        ip link set "$bridge" down 2>/dev/null || true
        ip link delete "$bridge" 2>/dev/null || true
    done
}

# Function to restart Docker daemon
restart_docker() {
    log "Stopping Docker daemon..."
    systemctl stop $DOCKER_SERVICE
    
    # Wait a moment for clean shutdown
    sleep 3
    
    log "Starting Docker daemon..."
    systemctl start $DOCKER_SERVICE
    
    # Wait for Docker to initialize
    log "Waiting for Docker to initialize..."
    local timeout=30
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if is_docker_running; then
            log "Docker daemon is running"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    if ! is_docker_running; then
        error "Docker daemon failed to start within $timeout seconds"
        return 1
    fi
    
    # Additional wait for Docker to fully initialize
    sleep 5
}

# Function to verify Docker networking
verify_docker_networking() {
    log "Verifying Docker networking..."
    
    # Check if Docker can create basic networks
    local test_network="fks_test-network-$$"
    
    if docker network create "$test_network" >/dev/null 2>&1; then
        log "✅ Docker network creation test passed"
        docker network rm "$test_network" >/dev/null 2>&1
    else
        error "❌ Docker network creation test failed"
        return 1
    fi
    
    # Check if Docker chains are properly created
    if check_docker_chains; then
        log "✅ Docker iptables chains are properly configured"
    else
        warn "⚠️ Docker iptables chains may still have issues"
    fi
    
    # Test basic Docker functionality
    if docker run --rm alpine:latest echo "Docker test successful" >/dev/null 2>&1; then
        log "✅ Docker container execution test passed"
    else
        warn "⚠️ Docker container execution test failed"
    fi
}

# Function to show Docker network status
show_docker_status() {
    log "Current Docker status:"
    
    if [ "$VERBOSE" = "true" ]; then
        echo "=== Docker Service Status ==="
        systemctl status $DOCKER_SERVICE --no-pager -l
        
        echo "=== Docker Networks ==="
        docker network ls
        
        echo "=== Docker Iptables Chains ==="
        iptables -L | grep -A 10 -B 2 -i docker || echo "No Docker chains found"
        
        echo "=== Docker Bridge Interfaces ==="
        ip link show | grep -E "(docker|br-)" || echo "No Docker interfaces found"
    else
        systemctl is-active $DOCKER_SERVICE >/dev/null && echo "Docker service: ✅ Running" || echo "Docker service: ❌ Not running"
        docker network ls >/dev/null 2>&1 && echo "Docker networks: ✅ Accessible" || echo "Docker networks: ❌ Not accessible"
        check_docker_chains >/dev/null 2>&1 && echo "Docker iptables: ✅ Configured" || echo "Docker iptables: ⚠️ Issues detected"
    fi
}

# Main execution
main() {
    log "Starting Docker iptables fix..."
    log "OS: $OS, Docker service: $DOCKER_SERVICE"
    
    # Show initial status
    if [ "$VERBOSE" = "true" ]; then
        log "Initial Docker status:"
        show_docker_status
        echo ""
    fi
    
    # Check if we need to fix anything
    local needs_fix=false
    
    if is_docker_running; then
        if ! check_docker_chains; then
            log "Docker is running but iptables chains are broken"
            needs_fix=true
        elif [ "$FORCE_RESTART" = "true" ]; then
            log "Force restart requested"
            needs_fix=true
        else
            log "Docker appears to be working correctly"
            verify_docker_networking
            if [ $? -eq 0 ]; then
                log "✅ Docker networking is functional - no fix needed"
                return 0
            else
                log "Docker networking tests failed - fix needed"
                needs_fix=true
            fi
        fi
    else
        log "Docker daemon is not running"
        needs_fix=true
    fi
    
    if [ "$needs_fix" = "false" ]; then
        log "No Docker iptables fix needed"
        return 0
    fi
    
    # Perform the fix
    log "Performing Docker iptables fix..."
    
    # Backup current rules
    backup_iptables
    
    # Stop Docker if running
    if is_docker_running; then
        log "Stopping Docker daemon for cleanup..."
        systemctl stop $DOCKER_SERVICE
        sleep 3
    fi
    
    # Clean up broken state
    clean_docker_chains
    clean_docker_interfaces
    
    # Restart Docker
    restart_docker
    
    # Verify the fix worked
    if verify_docker_networking; then
        log "✅ Docker iptables fix completed successfully"
        
        # Show final status
        if [ "$VERBOSE" = "true" ]; then
            echo ""
            log "Final Docker status:"
            show_docker_status
        fi
        
        return 0
    else
        error "❌ Docker iptables fix failed"
        return 1
    fi
}

# Run main function
main "$@"
