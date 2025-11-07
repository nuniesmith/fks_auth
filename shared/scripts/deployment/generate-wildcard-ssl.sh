#!/bin/bash
#
# FKS Trading Systems - Generate Wildcard SSL
# Generates a wildcard SSL certificate using Cloudflare DNS challenge
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Default values
DOMAIN_NAME=""
ADMIN_EMAIL=""
CLOUDFLARE_API_TOKEN=""
INCLUDE_WWW="false"

# Usage function
usage() {
    echo "Usage: $0 --domain DOMAIN --email EMAIL --api-token TOKEN [options]"
    echo ""
    echo "Required parameters:"
    echo "  --domain DOMAIN          Domain name (e.g., fkstrading.xyz)"
    echo "  --email EMAIL           Admin email for Let's Encrypt"
    echo "  --api-token TOKEN       Cloudflare API token"
    echo ""
    echo "Optional parameters:"
    echo "  --include-www           Include www subdomain in SSL certificate"
    echo "  --help                  Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --email)
            ADMIN_EMAIL="$2"
            shift 2
            ;;
        --api-token)
            CLOUDFLARE_API_TOKEN="$2"
            shift 2
            ;;
        --include-www)
            INCLUDE_WWW="true"
            shift
            ;;
        --help)
            usage
            ;;
        *)
            log_error "Unknown parameter: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$DOMAIN_NAME" || -z "$ADMIN_EMAIL" || -z "$CLOUDFLARE_API_TOKEN" ]]; then
    log_error "Missing required parameters"
    usage
fi

log_info "Generating wildcard SSL certificate for $DOMAIN_NAME"
log_info "Admin Email: $ADMIN_EMAIL"

# Install required package
if ! command -v certbot 2&> /dev/null; then
    log_info "Installing certbot..."
    pacman -Sy --noconfirm certbot certbot-dns-cloudflare
fi

log_success "Certbot installed"

# Create Cloudflare credentials file for certbot
log_info "Setting up Cloudflare credentials for certbot..."
CLOUDFLARE_CREDS_FILE="/root/.cloudflare-credentials"
cat > "$CLOUDFLARE_CREDS_FILE" << EOF
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
chmod 600 "$CLOUDFLARE_CREDS_FILE"
log_success "Cloudflare credentials configured"

# Generate wildcard SSL certificate
log_info "Running certbot for wildcard certificate..."
STAGING_FLAG=""
CERT_DOMAINS="-d *.$DOMAIN_NAME -d $DOMAIN_NAME"
if [[ "$INCLUDE_WWW" == "true" ]]; then
    CERT_DOMAINS="$CERT_DOMAINS -d www.$DOMAIN_NAME"
fi

if certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CLOUDFLARE_CREDS_FILE" \
    --email "$ADMIN_EMAIL" \
    --agree-tos \
    --non-interactive \
    --expand \
    $STAGING_FLAG \
    $CERT_DOMAINS; then
    log_success "Wildcard SSL certificate generated successfully"
else
    log_error "Failed to generate wildcard SSL certificate"
    exit 1
fi

# Clean up credentials file for security
rm -f "$CLOUDFLARE_CREDS_FILE"
log_info "Cleaned up temporary credentials file"

log_success "Wildcard SSL certificate generation script completed!"
