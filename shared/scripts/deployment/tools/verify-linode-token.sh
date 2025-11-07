#!/bin/bash

# FKS Trading Systems - Linode Token Verification
# This script helps verify that your Linode CLI token is properly configured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

echo "==========================================="
echo "FKS Trading Systems - Linode Token Verification"
echo "==========================================="
echo ""

# Check if linode-cli is installed
if ! command -v linode-cli &> /dev/null; then
    warn "Linode CLI not found. Installing..."
    pip install linode-cli
fi

# Check for token from command line argument or environment
LINODE_CLI_TOKEN=""
if [ $# -gt 0 ]; then
    LINODE_CLI_TOKEN="$1"
elif [ -n "$LINODE_CLI_TOKEN" ]; then
    LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"
else
    echo "Usage: $0 <linode_token>"
    echo "   OR: LINODE_CLI_TOKEN=<token> $0"
    echo ""
    echo "Get your token from: https://cloud.linode.com/profile/tokens"
    exit 1
fi

info "Testing Linode API token..."

# Configure CLI with the token
export LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"

# Create minimal config to avoid interactive setup
mkdir -p ~/.config/linode-cli
cat > ~/.config/linode-cli/linode-cli << EOF
[DEFAULT]
default-user = DEFAULT

[DEFAULT]  
token = $LINODE_CLI_TOKEN
region = ca-central
type = g6-standard-2
image = linode/ubuntu22.04
EOF

# Test basic API connectivity
echo ""
info "Testing basic API connectivity..."
if linode-cli regions list > /dev/null 2>&1; then
    log "✅ Basic API connection successful"
else
    error "❌ Failed to connect to Linode API"
    echo ""
    echo "This could mean:"
    echo "1. The token is invalid or expired"
    echo "2. Network connectivity issues"
    echo "3. Linode API is down"
    echo ""
    echo "Please verify your token at: https://cloud.linode.com/profile/tokens"
    exit 1
fi

# Test Linodes permission (read)
echo ""
info "Testing Linodes read permission..."
if linode-cli linodes list > /dev/null 2>&1; then
    log "✅ Linodes read permission verified"
else
    error "❌ Cannot read Linodes list"
    echo "The token needs 'Linodes: Read/Write' permission"
    exit 1
fi

# Test StackScripts permission (read)
echo ""
info "Testing StackScripts read permission..."
if linode-cli stackscripts list > /dev/null 2>&1; then
    log "✅ StackScripts read permission verified"
else
    error "❌ Cannot read StackScripts list"
    echo "The token needs 'StackScripts: Read/Write' permission"
    exit 1
fi

# Test Images permission (read)
echo ""
info "Testing Images read permission..."
if linode-cli images list > /dev/null 2>&1; then
    log "✅ Images read permission verified"
else
    error "❌ Cannot read Images list"
    echo "The token needs 'Images: Read Only' permission"
    exit 1
fi

# Show token info (without revealing the token)
echo ""
info "Token verification summary:"
TOKEN_PREFIX="${LINODE_CLI_TOKEN:0:8}"
TOKEN_SUFFIX="${LINODE_CLI_TOKEN: -4}"
echo "Token: ${TOKEN_PREFIX}...${TOKEN_SUFFIX}"

# Test account info
ACCOUNT_INFO=$(linode-cli account view --json 2>/dev/null || echo "[]")
if [ "$ACCOUNT_INFO" != "[]" ]; then
    COMPANY=$(echo "$ACCOUNT_INFO" | jq -r '.[0].company // "N/A"')
    EMAIL=$(echo "$ACCOUNT_INFO" | jq -r '.[0].email // "N/A"')
    echo "Account: $COMPANY ($EMAIL)"
fi

# Show current Linodes
echo ""
info "Current Linodes in your account:"
LINODES=$(linode-cli linodes list --text --no-headers --format="label,status,type,region" 2>/dev/null || echo "")
if [ -n "$LINODES" ]; then
    echo "$LINODES"
else
    echo "No Linodes found"
fi

echo ""
log "🎉 All tests passed! Your Linode token is properly configured."
echo ""
echo "To use this token in GitHub Actions:"
echo "1. Go to your repository → Settings → Secrets and variables → Actions"
echo "2. Add a new secret named: LINODE_CLI_TOKEN"
echo "3. Set the value to your token"
echo ""
echo "Required permissions for this token:"
echo "- Linodes: Read/Write"
echo "- StackScripts: Read/Write"
echo "- Images: Read Only"
