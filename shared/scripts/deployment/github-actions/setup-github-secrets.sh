#!/bin/bash

# FKS Trading Systems - GitHub Secrets Setup Helper
# This script helps you set up the required GitHub secrets for Linode automation

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

echo "============================================"
echo "FKS Trading Systems - GitHub Secrets Setup"
echo "============================================"
echo ""
echo "🔍 If you need help with Linode token issues, see:"
echo "   docs/LINODE_TOKEN_TROUBLESHOOTING.md"
echo ""

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    error "GitHub CLI (gh) is required but not installed"
    echo ""
    echo "Install GitHub CLI:"
    echo "  macOS: brew install gh"
    echo "  Ubuntu: sudo apt install gh"
    echo "  Windows: Download from https://cli.github.com/"
    echo ""
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    error "Not authenticated with GitHub CLI"
    echo ""
    echo "Please authenticate first:"
    echo "  gh auth login"
    echo ""
    exit 1
fi

# Get repository info
REPO_INFO=$(gh repo view --json owner,name)
REPO_OWNER=$(echo "$REPO_INFO" | jq -r '.owner.login')
REPO_NAME=$(echo "$REPO_INFO" | jq -r '.name')

log "Repository: $REPO_OWNER/$REPO_NAME"
echo ""

# Function to set a secret
set_secret() {
    local secret_name="$1"
    local description="$2"
    local example="$3"
    local required="$4"
    
    echo "----------------------------------------"
    if [ "$required" = "true" ]; then
        echo "🔑 REQUIRED: $secret_name"
    else
        echo "⚠️  OPTIONAL: $secret_name"
    fi
    echo "Description: $description"
    echo "Example: $example"
    echo ""
    
    # Check if secret already exists
    if gh secret list | grep -q "^$secret_name"; then
        warn "Secret '$secret_name' already exists"
        read -p "Do you want to update it? (y/N): " update_choice
        if [ "$update_choice" != "y" ] && [ "$update_choice" != "Y" ]; then
            log "Skipping $secret_name"
            return
        fi
    fi
    
    # Prompt for secret value
    echo "Enter value for $secret_name:"
    if [[ "$secret_name" == *"PASSWORD"* ]] || [[ "$secret_name" == *"TOKEN"* ]] || [[ "$secret_name" == *"KEY"* ]]; then
        read -s secret_value
    else
        read secret_value
    fi
    
    if [ -z "$secret_value" ]; then
        if [ "$required" = "true" ]; then
            error "Required secret cannot be empty"
            return 1
        else
            warn "Skipping empty optional secret"
            return
        fi
    fi
    
    # Set the secret
    echo "$secret_value" | gh secret set "$secret_name"
    log "Secret '$secret_name' set successfully"
}

echo "Setting up GitHub secrets for Linode automation..."
echo ""
echo "You'll be prompted for each secret value."
echo "For passwords/tokens, your input will be hidden."
echo ""

# Required secrets
log "REQUIRED SECRETS:"
echo ""

set_secret "LINODE_CLI_TOKEN" \
    "Linode API Personal Access Token (needs Linodes + StackScripts read/write)" \
    "abcdef123456789..." \
    "true"

set_secret "FKS_DEV_ROOT_PASSWORD" \
    "Root password for the Linode server" \
    "MySecureRootPass123!" \
    "true"

set_secret "JORDAN_PASSWORD" \
    "Password for the jordan user (main user account)" \
    "MyJordanPass123!" \
    "true"

set_secret "FKS_USER_PASSWORD" \
    "Password for the fks_user account" \
    "MyFksPass123!" \
    "true"

set_secret "TAILSCALE_AUTH_KEY" \
    "Tailscale authentication key (REQUIRED for secure networking)" \
    "tskey-auth-..." \
    "true"

echo ""
echo "----------------------------------------"
echo ""
log "OPTIONAL SECRETS (but recommended):"
echo ""

read -p "Do you want to set up optional secrets? (Y/n): " setup_optional
if [ "$setup_optional" != "n" ] && [ "$setup_optional" != "N" ]; then
    
    set_secret "DOCKER_USERNAME" \
        "Docker Hub username for private image access" \
        "yourusername" \
        "false"
    
    set_secret "DOCKER_TOKEN" \
        "Docker Hub access token for private image access" \
        "dckr_pat_..." \
        "false"
    
    set_secret "ACTIONS_ROOT_PRIVATE_KEY" \
        "SSH private key for deployment (paste the entire key including headers)" \
        "-----BEGIN OPENSSH PRIVATE KEY-----..." \
        "false"
    
    set_secret "NETDATA_CLAIM_TOKEN" \
        "Netdata Cloud claim token for monitoring" \
        "claim-token-here" \
        "false"
    
    set_secret "NETDATA_CLAIM_ROOM" \
        "Netdata Cloud room ID for monitoring" \
        "room-id-here" \
        "false"
    
    set_secret "DISCORD_WEBHOOK_SERVERS" \
        "Discord webhook URL for deployment notifications" \
        "https://discord.com/api/webhooks/..." \
        "false"
fi

echo ""
echo "============================================"
log "GitHub Secrets Setup Complete!"
echo "============================================"
echo ""

# List all secrets to verify
log "Current secrets in your repository:"
gh secret list

echo ""
log "Next steps:"
echo "1. Go to GitHub Actions tab in your repository"
echo "2. Run 'Create Linode Server with Arch Linux' workflow"
echo "3. Configure your server settings and create the server"
echo "4. Use 'Deploy to Linode Server' workflow for deployments"
echo ""

info "Documentation: docs/LINODE_AUTOMATION_GUIDE.md"
info "Repository: https://github.com/$REPO_OWNER/$REPO_NAME"

echo ""
log "Setup completed successfully! 🎉"
