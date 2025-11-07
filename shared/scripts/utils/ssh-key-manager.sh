#!/bin/bash

# SSH Key GitHub Secret Updater Helper
# This script helps you update the ACTIONS_ROOT_PRIVATE_KEY secret in your GitHub repository

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

# Configuration
DEFAULT_SERVER="fks.tailfef10.ts.net"
DEFAULT_USER="jordan"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --server HOST    Server hostname or IP (default: $DEFAULT_SERVER)"
    echo "  -u, --user USER      SSH username (default: $DEFAULT_USER)"
    echo "  -g, --generate       Generate new SSH key on server"
    echo "  -d, --display        Display public key and instructions"
    echo "  -t, --test           Test SSH connection"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --display                    # Show public key from default server"
    echo "  $0 -s 192.168.1.100 --generate # Generate new key on specific server"
    echo "  $0 --test                       # Test SSH connection"
}

# Default values
SERVER="$DEFAULT_SERVER"
USER="$DEFAULT_USER"
ACTION=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--server)
            SERVER="$2"
            shift 2
            ;;
        -u|--user)
            USER="$2"
            shift 2
            ;;
        -g|--generate)
            ACTION="generate"
            shift
            ;;
        -d|--display)
            ACTION="display"
            shift
            ;;
        -t|--test)
            ACTION="test"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Default action if none specified
if [ -z "$ACTION" ]; then
    ACTION="display"
fi

# SSH connection string
SSH_TARGET="$USER@$SERVER"

log "SSH Key Management for $SSH_TARGET"
echo ""

# Test SSH connectivity
test_ssh() {
    log "Testing SSH connection to $SSH_TARGET..."
    
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_TARGET" "echo 'Connection successful'" 2>/dev/null; then
        log "✅ SSH connection successful"
        return 0
    else
        error "❌ SSH connection failed"
        echo ""
        echo "Troubleshooting:"
        echo "1. Verify server is running and accessible"
        echo "2. Check SSH key permissions (chmod 600 ~/.ssh/id_rsa)"
        echo "3. Ensure user '$USER' exists on the server"
        echo "4. Try manual connection: ssh $SSH_TARGET"
        return 1
    fi
}

# Display public key and instructions
display_key() {
    log "Retrieving SSH key information from $SSH_TARGET..."
    echo ""
    
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_TARGET" "test -f ~/.ssh/id_rsa.pub" 2>/dev/null; then
        echo -e "${BLUE}📋 Public Key:${NC}"
        echo "=============="
        ssh "$SSH_TARGET" "cat ~/.ssh/id_rsa.pub"
        echo ""
        
        echo -e "${BLUE}🔐 Key Fingerprint:${NC}"
        echo "==================="
        ssh "$SSH_TARGET" "ssh-keygen -lf ~/.ssh/id_rsa.pub"
        echo ""
        
        echo -e "${YELLOW}📋 To update GitHub ACTIONS_ROOT_PRIVATE_KEY secret:${NC}"
        echo ""
        echo "1. Copy the private key:"
        echo "   ssh $SSH_TARGET"
        echo "   cat ~/.ssh/id_rsa"
        echo ""
        echo "2. Go to your GitHub repository"
        echo "3. Navigate to: Settings → Secrets and variables → Actions"
        echo "4. Find 'ACTIONS_ROOT_PRIVATE_KEY' and click 'Update'"
        echo "5. Paste the entire private key content (including BEGIN/END lines)"
        echo ""
        echo -e "${GREEN}💡 Tip: You can also use GitHub CLI to update secrets:${NC}"
        echo "   gh secret set ACTIONS_ROOT_PRIVATE_KEY < private_key_file"
        
    else
        warn "⚠️  No SSH key found on server"
        echo ""
        echo "To generate a new SSH key, run:"
        echo "  $0 --server $SERVER --generate"
    fi
}

# Generate new SSH key
generate_key() {
    log "Generating new SSH key on $SSH_TARGET..."
    echo ""
    
    # Backup existing key if it exists
    ssh "$SSH_TARGET" "
        if [ -f ~/.ssh/id_rsa ]; then
            echo 'Backing up existing key...'
            cp ~/.ssh/id_rsa ~/.ssh/id_rsa.backup.\$(date +%Y%m%d_%H%M%S)
            cp ~/.ssh/id_rsa.pub ~/.ssh/id_rsa.pub.backup.\$(date +%Y%m%d_%H%M%S)
            echo 'Backup created'
        fi
    "
    
    # Generate new key
    ssh "$SSH_TARGET" "
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N '' -C 'fks_\$(hostname)-\$(date +%Y%m%d)'
        chmod 600 ~/.ssh/id_rsa
        chmod 644 ~/.ssh/id_rsa.pub
        echo 'New SSH key generated successfully'
    "
    
    log "✅ New SSH key generated"
    echo ""
    
    # Display the new key
    display_key
}

# Main execution
case "$ACTION" in
    "test")
        test_ssh
        ;;
    "display")
        if test_ssh; then
            echo ""
            display_key
        fi
        ;;
    "generate")
        if test_ssh; then
            echo ""
            generate_key
        fi
        ;;
    *)
        error "Unknown action: $ACTION"
        usage
        exit 1
        ;;
esac

echo ""
log "SSH key management completed"
