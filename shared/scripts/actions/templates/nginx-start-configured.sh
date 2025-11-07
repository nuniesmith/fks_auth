#!/bin/bash

# Nginx Service Startup Script
# Uses universal template with nginx-specific configuration

# Service Configuration
export SERVICE_NAME="nginx"
export SERVICE_DISPLAY_NAME="Nginx Reverse Proxy"
export DEFAULT_HTTP_PORT="80"
export DEFAULT_HTTPS_PORT="443"

# Feature Configuration
export SUPPORTS_GPU="false"
export SUPPORTS_MINIMAL="false"
export SUPPORTS_DEV="false"
export HAS_MULTIPLE_COMPOSE_FILES="false"
export HAS_NETDATA="true"
export HAS_SSL="true"

# Custom environment creation for nginx
create_custom_env() {
    log "INFO" "Creating Nginx environment file..."
    
    # Find available port for Netdata (starting from 19999)
    NETDATA_PORT=19999
    while netstat -tlnp 2>/dev/null | grep -q ":${NETDATA_PORT} "; do
        NETDATA_PORT=$((NETDATA_PORT + 1))
        if [ $NETDATA_PORT -gt 20010 ]; then
            log "WARN" "Could not find available port for Netdata, using 19999 anyway"
            NETDATA_PORT=19999
            break
        fi
    done
    
    if [ $NETDATA_PORT -ne 19999 ]; then
        log "INFO" "Port 19999 is in use, using port $NETDATA_PORT for Netdata"
    fi
    
    cat > "$ENV_FILE" << EOF
# Nginx Reverse Proxy Environment
COMPOSE_PROJECT_NAME=nginx
ENVIRONMENT=production
APP_ENV=production
NODE_ENV=production

# Nginx Configuration
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
HTTP_PORT=80
HTTPS_PORT=443

# Web Interface Configuration
API_PID=
SULLIVAN_SERVER_URL=https://sullivan.7gram.xyz
FREDDY_SERVER_URL=https://freddy.7gram.xyz

# Monitoring Configuration
NETDATA_PORT=$NETDATA_PORT

# SSL Configuration
SSL_EMAIL=admin@7gram.xyz
DOMAIN_NAME=nginx.7gram.xyz
LETSENCRYPT_EMAIL=admin@7gram.xyz

# Docker Hub
DOCKER_NAMESPACE=$DOCKER_NAMESPACE
DOCKER_REGISTRY=$DOCKER_REGISTRY

# Timezone
TZ=America/Toronto
EOF
    
    log "INFO" "Environment file created"
}

# Custom connectivity test for nginx
test_connectivity() {
    log "INFO" "🔌 Testing connectivity..."
    
    # Test HTTP port
    if curl -s -f http://localhost >/dev/null 2>&1; then
        log "INFO" "✅ Nginx HTTP is accessible at http://localhost"
    else
        log "WARN" "⚠️ Nginx HTTP not yet accessible (may still be starting)"
    fi
    
    # Test HTTPS port
    if curl -s -k -f https://localhost >/dev/null 2>&1; then
        log "INFO" "✅ Nginx HTTPS is accessible at https://localhost"
    else
        log "WARN" "⚠️ Nginx HTTPS not yet accessible (SSL may still be configuring)"
    fi
}

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Download and source the universal template
if [ -f "$SCRIPT_DIR/universal-start.sh" ]; then
    source "$SCRIPT_DIR/universal-start.sh"
else
    # Download from GitHub if not found locally
    echo "📥 Downloading universal startup template..."
    curl -s https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/templates/universal-start.sh -o /tmp/universal-start.sh
    source /tmp/universal-start.sh
fi
