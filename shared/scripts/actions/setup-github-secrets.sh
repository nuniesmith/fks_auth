#!/bin/bash
# setup-github-secrets.sh - Interactive GitHub Secrets Setup
# This script helps configure all required GitHub secrets for standardized deployments

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

# Check if GitHub CLI is installed
check_requirements() {
    if ! command -v gh &> /dev/null; then
        error "GitHub CLI (gh) is required but not installed."
        echo "Install it from: https://cli.github.com/"
        exit 1
    fi
    
    if ! gh auth status &> /dev/null; then
        error "GitHub CLI is not authenticated."
        echo "Run: gh auth login"
        exit 1
    fi
    
    success "GitHub CLI is ready"
}

# Generate secure password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Set a GitHub secret
set_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local repo="${3:-}"
    
    if [[ -n "$repo" ]]; then
        gh secret set "$secret_name" --repo "$repo" --body "$secret_value"
    else
        gh secret set "$secret_name" --body "$secret_value"
    fi
}

# Main setup function
main() {
    echo "🚀 Standardized GitHub Actions Secrets Setup"
    echo "=============================================="
    echo
    
    check_requirements
    
    # Get repository information
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
    if [[ -z "$REPO" ]]; then
        error "Not in a GitHub repository or repository not found"
        exit 1
    fi
    
    info "Setting up secrets for repository: $REPO"
    echo
    
    # Core Infrastructure Secrets
    echo "🏗️ Core Infrastructure Secrets"
    echo "==============================="
    
    read -p "Enter your Linode API Token: " -s LINODE_CLI_TOKEN
    echo
    if [[ -n "$LINODE_CLI_TOKEN" ]]; then
        set_secret "LINODE_CLI_TOKEN" "$LINODE_CLI_TOKEN"
        success "LINODE_CLI_TOKEN set"
    fi
    
    echo
    read -p "Generate random root password? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ROOT_PASSWORD=$(generate_password)
        echo "Generated root password: $ROOT_PASSWORD"
        set_secret "SERVICE_ROOT_PASSWORD" "$ROOT_PASSWORD"
        success "SERVICE_ROOT_PASSWORD set"
    else
        read -p "Enter root password for servers: " -s ROOT_PASSWORD
        echo
        set_secret "SERVICE_ROOT_PASSWORD" "$ROOT_PASSWORD"
        success "SERVICE_ROOT_PASSWORD set"
    fi
    
    # User Account Secrets
    echo
    echo "👥 User Account Secrets"
    echo "======================="
    
    read -p "Generate random password for jordan user? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        JORDAN_PASSWORD=$(generate_password)
        echo "Generated jordan password: $JORDAN_PASSWORD"
        set_secret "JORDAN_PASSWORD" "$JORDAN_PASSWORD"
        success "JORDAN_PASSWORD set"
    else
        read -p "Enter password for jordan user: " -s JORDAN_PASSWORD
        echo
        set_secret "JORDAN_PASSWORD" "$JORDAN_PASSWORD"
        success "JORDAN_PASSWORD set"
    fi
    
    read -p "Generate random password for actions_user? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ACTIONS_PASSWORD=$(generate_password)
        echo "Generated actions_user password: $ACTIONS_PASSWORD"
        set_secret "ACTIONS_USER_PASSWORD" "$ACTIONS_PASSWORD"
        success "ACTIONS_USER_PASSWORD set"
    else
        read -p "Enter password for actions_user: " -s ACTIONS_PASSWORD
        echo
        set_secret "ACTIONS_USER_PASSWORD" "$ACTIONS_PASSWORD"
        success "ACTIONS_USER_PASSWORD set"
    fi
    
    # VPN & Networking
    echo
    echo "🔗 VPN & Networking Secrets"
    echo "==========================="
    
    read -p "Enter Tailscale Auth Key: " -s TAILSCALE_AUTH_KEY
    echo
    if [[ -n "$TAILSCALE_AUTH_KEY" ]]; then
        set_secret "TAILSCALE_AUTH_KEY" "$TAILSCALE_AUTH_KEY"
        success "TAILSCALE_AUTH_KEY set"
    fi
    
    # Optional Tailscale OAuth (for advanced features)
    echo
    read -p "Do you have Tailscale OAuth credentials? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter Tailscale OAuth Client ID: " TAILSCALE_CLIENT_ID
        read -p "Enter Tailscale OAuth Secret: " -s TAILSCALE_SECRET
        echo
        
        if [[ -n "$TAILSCALE_CLIENT_ID" && -n "$TAILSCALE_SECRET" ]]; then
            set_secret "TAILSCALE_OAUTH_CLIENT_ID" "$TAILSCALE_CLIENT_ID"
            set_secret "TAILSCALE_OAUTH_SECRET" "$TAILSCALE_SECRET"
            success "Tailscale OAuth credentials set"
        fi
    fi
    
    # DNS Management (Optional)
    echo
    echo "🌐 DNS Management Secrets (Optional)"
    echo "===================================="
    
    read -p "Do you have Cloudflare credentials for DNS management? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter Cloudflare API Token: " -s CLOUDFLARE_TOKEN
        echo
        read -p "Enter Cloudflare Zone ID: " CLOUDFLARE_ZONE
        
        if [[ -n "$CLOUDFLARE_TOKEN" ]]; then
            set_secret "CLOUDFLARE_API_TOKEN" "$CLOUDFLARE_TOKEN"
            success "CLOUDFLARE_API_TOKEN set"
        fi
        
        if [[ -n "$CLOUDFLARE_ZONE" ]]; then
            set_secret "CLOUDFLARE_ZONE_ID" "$CLOUDFLARE_ZONE"
            success "CLOUDFLARE_ZONE_ID set"
        fi
    fi
    
    # Container Registry (Optional)
    echo
    echo "🐳 Container Registry Secrets (Optional)"
    echo "========================================"
    
    read -p "Do you have Docker Hub credentials? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter Docker Hub username: " DOCKER_USERNAME
        read -p "Enter Docker Hub token/password: " -s DOCKER_TOKEN
        echo
        
        if [[ -n "$DOCKER_USERNAME" ]]; then
            set_secret "DOCKER_USERNAME" "$DOCKER_USERNAME"
            success "DOCKER_USERNAME set"
        fi
        
        if [[ -n "$DOCKER_TOKEN" ]]; then
            set_secret "DOCKER_TOKEN" "$DOCKER_TOKEN"
            success "DOCKER_TOKEN set"
        fi
    fi
    
    # Notifications (Optional)
    echo
    echo "📢 Notification Secrets (Optional)"
    echo "=================================="
    
    read -p "Do you have a Discord webhook for notifications? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter Discord webhook URL: " DISCORD_WEBHOOK
        
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            set_secret "DISCORD_WEBHOOK" "$DISCORD_WEBHOOK"
            success "DISCORD_WEBHOOK set"
        fi
    fi
    
    # Service-specific secrets
    echo
    echo "🎯 Service-Specific Secrets (Optional)"
    echo "======================================"
    
    read -p "Do you need JWT secrets for authentication? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
        set_secret "JWT_SECRET" "$JWT_SECRET"
        success "JWT_SECRET generated and set"
    fi
    
    # Summary
    echo
    echo "🎉 Setup Complete!"
    echo "=================="
    success "All secrets have been configured for repository: $REPO"
    echo
    info "Next steps:"
    echo "1. Test your deployment with: gh workflow run deploy-service.yml"
    echo "2. Monitor deployment in the Actions tab of your repository"
    echo "3. Access your services via Tailscale VPN"
    echo
    warning "Important: Save the generated passwords in a secure location!"
    
    # Show generated passwords summary
    echo
    echo "Generated Passwords Summary:"
    echo "============================"
    [[ -n "${ROOT_PASSWORD:-}" ]] && echo "Root Password: $ROOT_PASSWORD"
    [[ -n "${JORDAN_PASSWORD:-}" ]] && echo "Jordan Password: $JORDAN_PASSWORD"
    [[ -n "${ACTIONS_PASSWORD:-}" ]] && echo "Actions User Password: $ACTIONS_PASSWORD"
}

# Run main function
main "$@"
