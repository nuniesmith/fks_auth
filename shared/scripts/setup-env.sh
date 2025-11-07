#!/bin/bash

# FKS Trading Systems - Environment Setup Script
# Creates a .env file with required environment variables for deployment

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
#!/usr/bin/env bash
# Shim: setup-env moved to preflight/setup-env.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/preflight/setup-env.sh"
if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
}

# Check if .env file already exists
if [ -f "$ENV_FILE" ]; then
    log_warning "Environment file $ENV_FILE already exists"
    echo -n "Do you want to overwrite it? (y/N): "
    read overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        log_info "Cancelled. To use existing file: source $ENV_FILE"
        exit 0
    fi
fi

log "Setting up FKS Trading Systems environment variables"
echo ""

# Linode Configuration
log_info "=== Linode Configuration ==="
echo ""
echo "Get your Linode API token from: https://cloud.linode.com/profile/tokens"
echo "Required scopes: Linodes (Read/Write)"
echo ""
prompt_with_default "Linode CLI Token" "" "LINODE_CLI_TOKEN" true

echo ""
echo "Server configuration:"
prompt_with_default "Server Region" "ca-central" "SERVER_REGION"
prompt_with_default "Server Type" "g6-standard-2" "SERVER_TYPE"
prompt_with_default "Server Image" "linode/arch" "SERVER_IMAGE"

# Password Configuration
echo ""
log_info "=== Password Configuration ==="
echo ""
echo "Setting up secure passwords for server users..."
echo ""

# Generate random passwords by default
DEFAULT_ROOT_PASS=$(generate_password)
DEFAULT_JORDAN_PASS=$(generate_password)
DEFAULT_FKS_PASS=$(generate_password)
DEFAULT_ACTIONS_PASS=$(generate_password)

prompt_with_default "Root Password" "$DEFAULT_ROOT_PASS" "FKS_DEV_ROOT_PASSWORD" true
prompt_with_default "Jordan User Password" "$DEFAULT_JORDAN_PASS" "JORDAN_PASSWORD" true
prompt_with_default "FKS User Password" "$DEFAULT_FKS_PASS" "FKS_USER_PASSWORD" true
prompt_with_default "Actions User Password" "$DEFAULT_ACTIONS_PASS" "ACTIONS_USER_PASSWORD" true

# Tailscale Configuration
echo ""
log_info "=== Tailscale Configuration ==="
echo ""
echo "Get your Tailscale auth key from: https://login.tailscale.com/admin/settings/keys"
echo "Make sure to check 'Reusable' and set an appropriate expiration."
echo ""
prompt_with_default "Tailscale Auth Key" "" "TAILSCALE_AUTH_KEY" true

# Optional Docker Configuration
echo ""
log_info "=== Docker Configuration (Optional) ==="
echo ""
echo "Docker Hub credentials for private repositories (leave blank to skip):"
prompt_with_default "Docker Username" "" "DOCKER_USERNAME"
if [ -n "$DOCKER_USERNAME" ]; then
    prompt_with_default "Docker Token/Password" "" "DOCKER_TOKEN" true
fi

# Optional Monitoring Configuration
echo ""
log_info "=== Monitoring Configuration (Optional) ==="
echo ""
echo "Netdata monitoring (leave blank to skip):"
prompt_with_default "Netdata Claim Token" "" "NETDATA_CLAIM_TOKEN" true
if [ -n "$NETDATA_CLAIM_TOKEN" ]; then
    prompt_with_default "Netdata Room ID" "" "NETDATA_CLAIM_ROOM"
fi

# Domain Configuration
echo ""
log_info "=== Domain Configuration ==="
echo ""
prompt_with_default "Domain Name" "fkstrading.xyz" "DOMAIN_NAME"

# Create .env file
log "Creating environment file: $ENV_FILE"
cat > "$ENV_FILE" << EOF
# FKS Trading Systems - Environment Configuration
# Generated on $(date)

# Linode Configuration
LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"
SERVER_REGION="$SERVER_REGION"
SERVER_TYPE="$SERVER_TYPE"
SERVER_IMAGE="$SERVER_IMAGE"

# User Passwords
FKS_DEV_ROOT_PASSWORD="$FKS_DEV_ROOT_PASSWORD"
JORDAN_PASSWORD="$JORDAN_PASSWORD"
FKS_USER_PASSWORD="$FKS_USER_PASSWORD"
ACTIONS_USER_PASSWORD="$ACTIONS_USER_PASSWORD"

# Tailscale Configuration
TAILSCALE_AUTH_KEY="$TAILSCALE_AUTH_KEY"

# Docker Configuration (Optional)
DOCKER_USERNAME="$DOCKER_USERNAME"
DOCKER_TOKEN="$DOCKER_TOKEN"

# Monitoring Configuration (Optional)
NETDATA_CLAIM_TOKEN="$NETDATA_CLAIM_TOKEN"
NETDATA_CLAIM_ROOM="$NETDATA_CLAIM_ROOM"

# Domain Configuration
DOMAIN_NAME="$DOMAIN_NAME"

# Build Configuration
FORCE_CPU_BUILDS="false"
FORCE_GPU_BUILDS="false"
EOF

chmod 600 "$ENV_FILE"

log "✅ Environment file created: $ENV_FILE"
log "🔒 File permissions set to 600 (owner read/write only)"

echo ""
log_info "📋 Next Steps:"
echo ""
echo "1. Load the environment variables:"
echo "   source $ENV_FILE"
echo ""
echo "2. Run the deployment script:"
echo "   ./scripts/deploy-fks.sh --mode full"
echo ""
echo "3. For other deployment modes:"
echo "   ./scripts/deploy-fks.sh --help"
echo ""

# Security reminder
log_warning "🛡️  Security Reminder:"
echo "- Keep the $ENV_FILE file secure and never commit it to version control"
echo "- Consider using a password manager to store these credentials"
echo "- Regularly rotate your API tokens and passwords"
echo ""

# Quick validation
log_info "🧪 Quick Validation:"
missing_required=()

if [ -z "$LINODE_CLI_TOKEN" ]; then missing_required+=("LINODE_CLI_TOKEN"); fi
if [ -z "$FKS_DEV_ROOT_PASSWORD" ]; then missing_required+=("FKS_DEV_ROOT_PASSWORD"); fi
if [ -z "$JORDAN_PASSWORD" ]; then missing_required+=("JORDAN_PASSWORD"); fi
if [ -z "$FKS_USER_PASSWORD" ]; then missing_required+=("FKS_USER_PASSWORD"); fi
if [ -z "$ACTIONS_USER_PASSWORD" ]; then missing_required+=("ACTIONS_USER_PASSWORD"); fi
if [ -z "$TAILSCALE_AUTH_KEY" ]; then missing_required+=("TAILSCALE_AUTH_KEY"); fi

if [ ${#missing_required[@]} -gt 0 ]; then
    log_error "Missing required variables:"
    for var in "${missing_required[@]}"; do
        echo "  - $var"
    done
    echo ""
    log_warning "Please edit $ENV_FILE to add the missing values"
else
    log "✅ All required environment variables are set"
    echo ""
    log_info "Ready for deployment! Run: source $ENV_FILE && ./scripts/deploy-fks.sh --mode full"
fi
