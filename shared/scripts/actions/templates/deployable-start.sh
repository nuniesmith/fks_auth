#!/bin/bash

# Service Startup Script - Configured via Environment Variables
# This script downloads and uses the universal template from the actions repository

set -e  # Exit on any error

# Service Configuration - Will be set by deployment workflow environment variables
SERVICE_NAME="${SERVICE_NAME:-nginx}"
SERVICE_DISPLAY_NAME="${SERVICE_DISPLAY_NAME:-Nginx Reverse Proxy}"
DEFAULT_HTTP_PORT="${DEFAULT_HTTP_PORT:-80}"
DEFAULT_HTTPS_PORT="${DEFAULT_HTTPS_PORT:-443}"

# Feature Configuration - Will be set by deployment workflow
SUPPORTS_GPU="${SUPPORTS_GPU:-false}"
SUPPORTS_MINIMAL="${SUPPORTS_MINIMAL:-false}"
SUPPORTS_DEV="${SUPPORTS_DEV:-false}"
HAS_NETDATA="${HAS_NETDATA:-true}"
HAS_SSL="${HAS_SSL:-true}"

# Download universal template if not available locally
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIVERSAL_TEMPLATE="$SCRIPT_DIR/universal-start.sh"

if [ ! -f "$UNIVERSAL_TEMPLATE" ]; then
    echo "📥 Downloading universal startup template..."
    curl -s https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/templates/universal-start.sh -o "$UNIVERSAL_TEMPLATE"
    chmod +x "$UNIVERSAL_TEMPLATE"
fi

# Source and run the universal template
source "$UNIVERSAL_TEMPLATE"
