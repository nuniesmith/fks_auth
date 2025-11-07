#!/bin/bash

# FKS Trading Systems - Server Cleanup Script
# Comprehensive cleanup of FKS servers including Tailscale and Netdata

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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Default values
DRY_RUN=false
FORCE=false
CLEANUP_ALL=false
SPECIFIC_SERVER_ID=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --all)
            CLEANUP_ALL=true
            shift
            ;;
        --server-id)
            SPECIFIC_SERVER_ID="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run           Show what would be cleaned up without doing it"
            echo "  --force             Skip confirmation prompts"
            echo "  --all               Cleanup all FKS servers"
            echo "  --server-id <id>    Cleanup specific server by ID"
            echo "  --help              Show this help message"
            echo ""
            echo "Environment Variables Required:"
            echo "  LINODE_CLI_TOKEN           Linode API token"
            echo "  FKS_DEV_ROOT_PASSWORD      Root password for server access"
            echo ""
            echo "Environment Variables Optional:"
            echo "  TAILSCALE_AUTH_KEY         For Tailscale cleanup verification"
            echo "  NETDATA_CLAIM_TOKEN        For Netdata cleanup verification"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

log "🗑️ FKS Trading Systems - Server Cleanup Tool"
echo ""

# Validate required environment variables
if [ -z "$LINODE_CLI_TOKEN" ]; then
    error "LINODE_CLI_TOKEN environment variable is required"
    exit 1
fi

if [ -z "$FKS_DEV_ROOT_PASSWORD" ] && [ "$DRY_RUN" = "false" ]; then
    warn "FKS_DEV_ROOT_PASSWORD not set - Tailscale/Netdata cleanup may fail"
fi

# Install dependencies if needed
if ! command -v sshpass > /dev/null 2>&1 && [ "$DRY_RUN" = "false" ]; then
    log "Installing sshpass for SSH operations..."
    if command -v pacman > /dev/null 2>&1; then
        sudo -n pacman -S --noconfirm sshpass
    elif command -v apt-get > /dev/null 2>&1; then
        sudo -n apt-get update && sudo -n apt-get install -y sshpass
    fi
fi

# Ensure Linode CLI is available
if ! command -v linode-cli > /dev/null 2>&1; then
    log "Installing Linode CLI..."
    pip3 install --user linode-cli --quiet
    export PATH="$HOME/.local/bin:$PATH"
fi

# Function to cleanup a single server
cleanup_server() {
    local server_id="$1"
    local server_ip="$2"
    local server_label="$3"
    
    log "🔍 Processing server: $server_label (ID: $server_id, IP: $server_ip)"
    
    if [ "$DRY_RUN" = "true" ]; then
        echo "  [DRY RUN] Would cleanup Tailscale on $server_ip"
        echo "  [DRY RUN] Would cleanup Netdata on $server_ip"
        echo "  [DRY RUN] Would delete Linode server $server_id"
        return 0
    fi
    
    # 1. Tailscale Cleanup
    if [ -n "$server_ip" ] && command -v sshpass >/dev/null 2>&1; then
        log "🔗 Attempting Tailscale cleanup on $server_ip..."
        if timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "tailscale logout 2>/dev/null; systemctl stop tailscaled 2>/dev/null" 2>/dev/null; then
            log "✅ Tailscale logout successful"
        else
            warn "⚠️ Tailscale cleanup failed (server may be unreachable)"
        fi
        
        info "📋 Manual Tailscale cleanup:"
        info "   Visit: https://login.tailscale.com/admin/machines"
        info "   Remove node: $server_label or $server_ip"
    fi
    
    # 2. Netdata Cleanup
    if [ -n "$server_ip" ] && command -v sshpass >/dev/null 2>&1; then
        log "📊 Attempting Netdata cleanup on $server_ip..."
        if timeout 10 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$server_ip" "netdata-claim.sh -token= -rooms= -url= 2>/dev/null; systemctl stop netdata 2>/dev/null" 2>/dev/null; then
            log "✅ Netdata unclaim attempt completed"
        else
            warn "⚠️ Netdata cleanup failed (server may be unreachable)"
        fi
        
        info "📋 Manual Netdata cleanup:"
        info "   Visit: https://app.netdata.cloud/"
        info "   Remove node: $server_label or $server_ip from your Space"
    fi
    
    # 3. Linode Server Cleanup
    log "🖥️ Deleting Linode server $server_id..."
    if linode-cli linodes delete "$server_id" 2>/dev/null; then
        log "✅ Server $server_id deleted successfully"
    else
        error "❌ Failed to delete server $server_id"
        info "🔧 Manual cleanup required:"
        info "   Visit: https://cloud.linode.com/linodes"
        info "   Delete server: $server_label ($server_id)"
        return 1
    fi
    
    return 0
}

# Get list of FKS servers
log "🔍 Searching for FKS servers..."
FKS_SERVERS=""
if linode-cli linodes list --json > /dev/null 2>&1; then
    FKS_SERVERS=$(linode-cli linodes list --json | jq -r '.[] | select(.label | test("fks"; "i")) | "\(.id)|\(.ipv4[0])|\(.label)"' 2>/dev/null || echo "")
fi

if [ -z "$FKS_SERVERS" ]; then
    log "✅ No FKS servers found"
    exit 0
fi

# Display found servers
log "📋 Found FKS servers:"
echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_ip server_label; do
    echo "  - $server_label (ID: $server_id, IP: $server_ip)"
done
echo ""

# Handle specific server cleanup
if [ -n "$SPECIFIC_SERVER_ID" ]; then
    SERVER_FOUND=false
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_ip server_label; do
        if [ "$server_id" = "$SPECIFIC_SERVER_ID" ]; then
            SERVER_FOUND=true
            
            if [ "$FORCE" != "true" ] && [ "$DRY_RUN" != "true" ]; then
                echo "⚠️ This will permanently delete server: $server_label (ID: $server_id)"
                read -p "Are you sure? (y/N): " confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                    log "❌ Cleanup cancelled"
                    exit 0
                fi
            fi
            
            cleanup_server "$server_id" "$server_ip" "$server_label"
            exit $?
        fi
    done
    
    if [ "$SERVER_FOUND" = "false" ]; then
        error "Server ID $SPECIFIC_SERVER_ID not found"
        exit 1
    fi
fi

# Handle cleanup all servers
if [ "$CLEANUP_ALL" = "true" ]; then
    SERVER_COUNT=$(echo "$FKS_SERVERS" | wc -l)
    
    if [ "$FORCE" != "true" ] && [ "$DRY_RUN" != "true" ]; then
        echo "⚠️ This will permanently delete $SERVER_COUNT FKS server(s)"
        read -p "Are you sure? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log "❌ Cleanup cancelled"
            exit 0
        fi
    fi
    
    FAILED_COUNT=0
    SUCCESS_COUNT=0
    
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_ip server_label; do
        if cleanup_server "$server_id" "$server_ip" "$server_label"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
        echo ""
    done
    
    log "📊 Cleanup Summary:"
    log "   Successful: $SUCCESS_COUNT"
    if [ $FAILED_COUNT -gt 0 ]; then
        warn "   Failed: $FAILED_COUNT"
    fi
    
    exit 0
fi

# If no specific action, show interactive menu
if [ "$DRY_RUN" != "true" ]; then
    echo "🎯 Select cleanup action:"
    echo "1) Cleanup all FKS servers"
    echo "2) Cleanup specific server"
    echo "3) Dry run (show what would be cleaned)"
    echo "4) Exit"
    echo ""
    read -p "Choice (1-4): " choice
    
    case $choice in
        1)
            exec "$0" --all --force
            ;;
        2)
            read -p "Enter server ID: " server_id
            exec "$0" --server-id "$server_id"
            ;;
        3)
            exec "$0" --dry-run --all
            ;;
        4)
            log "👋 Cleanup cancelled"
            exit 0
            ;;
        *)
            error "Invalid choice"
            exit 1
            ;;
    esac
else
    log "📋 Dry run completed - no changes made"
fi
