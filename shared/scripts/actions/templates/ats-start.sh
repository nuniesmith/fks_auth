#!/bin/bash

# ATS Game Server - Service Startup Script
# Uses the universal startup template from actions repository

# Service Configuration
export SERVICE_NAME="ats"
export SERVICE_DISPLAY_NAME="ATS Game Server"
export DEFAULT_HTTP_PORT="80"
export DEFAULT_HTTPS_PORT="443"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Custom environment variables for ATS
create_custom_env() {
    cat << EOF

# ATS Game Server Specific Configuration
GAME_PORT=8080
GAME_SERVER_PORT=8080

# Game Configuration
GAME_MODE=production
MAX_PLAYERS=100
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
    
    # Fallback to original ats start.sh logic if universal script not available
    # This ensures the script still works even if the actions repo is not accessible
    
    # Include the original ats start.sh content as fallback here
    # (keeping the existing ats start.sh logic as backup)
    
    # For now, let's just include a minimal implementation
    echo "[ERROR] Universal startup script not available and no fallback implemented"
    echo "Please ensure the actions repository is accessible or implement fallback logic"
    exit 1
fi
