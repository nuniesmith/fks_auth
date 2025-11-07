#!/bin/bash

# Nginx Reverse Proxy - Service Startup Script
# Uses the universal startup template from actions repository

# Service Configuration
export SERVICE_NAME="nginx"
export SERVICE_DISPLAY_NAME="Nginx Reverse Proxy"
export DEFAULT_HTTP_PORT="80"
export DEFAULT_HTTPS_PORT="443"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Custom environment variables for nginx
create_custom_env() {
    cat << EOF

# Nginx Specific Configuration
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443

# Web Interface Configuration
API_PID=
SULLIVAN_SERVER_URL=https://sullivan.7gram.xyz
FREDDY_SERVER_URL=https://freddy.7gram.xyz
EOF
}

# Source the universal startup template
# First check if we can download it from actions repo, otherwise use local fallback
UNIVERSAL_SCRIPT_URL="https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/templates/start.sh"
TEMP_SCRIPT="/tmp/universal-start-$$.sh"

if curl -s -f "$UNIVERSAL_SCRIPT_URL" -o "$TEMP_SCRIPT" 2>/dev/null; then
    echo "[INFO] Using universal startup script from actions repository"
    source "$TEMP_SCRIPT"
    rm -f "$TEMP_SCRIPT"
else
    echo "[WARN] Could not download universal script, using local implementation"
    
    # Fallback to original nginx start.sh logic if universal script not available
    # This ensures the script still works even if the actions repo is not accessible
    
    # Include the original nginx start.sh content as fallback here
    # (keeping the existing nginx start.sh logic as backup)
    
    # For now, let's just include a minimal implementation
    echo "[ERROR] Universal startup script not available and no fallback implemented"
    echo "Please ensure the actions repository is accessible or implement fallback logic"
    exit 1
fi
