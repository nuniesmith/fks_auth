#!/bin/bash

# FKS Trading System - Service Startup Script
# Uses the universal startup template from actions repository

# Service Configuration
export SERVICE_NAME="fks"
export SERVICE_DISPLAY_NAME="FKS Trading System"
export DEFAULT_HTTP_PORT="80"
export DEFAULT_HTTPS_PORT="443"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Custom environment variables for FKS
create_custom_env() {
    cat << EOF

# FKS Trading System Specific Configuration
API_PORT=3000
WEB_PORT=3001
AUTH_PORT=3002

# Trading Configuration
TRADING_MODE=production
MAX_CONCURRENT_TRADES=1000

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
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
    
    # Fallback to original fks start.sh logic if universal script not available
    # This ensures the script still works even if the actions repo is not accessible
    
    # Include the original fks start.sh content as fallback here
    # (keeping the existing fks start.sh logic as backup)
    
    # For now, let's just include a minimal implementation
    echo "[ERROR] Universal startup script not available and no fallback implemented"
    echo "Please ensure the actions repository is accessible or implement fallback logic"
    exit 1
fi
