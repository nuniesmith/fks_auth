#!/bin/bash
#
# FKS Trading Systems - Enhanced Nginx Entrypoint with Authentication
#
set -euo pipefail

# Logging functions
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
log_success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $*"; }

log_info "Starting nginx entrypoint script..."

# Create required directories
mkdir -p /etc/nginx/conf.d /etc/nginx/sites-enabled /var/log/nginx /var/cache/nginx /var/www/certbot

# Setup basic authentication if enabled
if [[ "${ENABLE_AUTH:-false}" == "true" ]]; then
    log_info "Setting up basic authentication..."
    
    # Check if credentials are provided
    if [[ -z "${AUTH_USER:-}" ]] || [[ -z "${AUTH_PASS:-}" ]]; then
        log_error "Authentication enabled but AUTH_USER or AUTH_PASS not set!"
        exit 1
    fi
    
    # Install htpasswd if not available
    if ! command -v htpasswd &> /dev/null; then
        log_info "Installing apache2-utils for htpasswd..."
        apk add --no-cache apache2-utils
    fi
    
    # Create htpasswd file
    htpasswd -bc /etc/nginx/.htpasswd "$AUTH_USER" "$AUTH_PASS"
    chmod 644 /etc/nginx/.htpasswd
    log_success "Basic authentication configured for user: $AUTH_USER"
else
    log_info "Basic authentication disabled"
    # Create empty htpasswd file to avoid nginx errors
    touch /etc/nginx/.htpasswd
fi

# Process nginx configuration templates
log_info "Processing nginx configuration templates..."

# Determine which template to use
if [[ "${ENABLE_SSL:-false}" == "true" ]] && [[ -f "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" ]]; then
    TEMPLATE_FILE="/etc/nginx/templates/default-ssl-auth.conf.template"
    log_info "Using SSL configuration template"
else
    TEMPLATE_FILE="/etc/nginx/templates/default.conf.template"
    log_info "Using non-SSL configuration template"
fi

# Set default values for environment variables
export API_HOST="${API_HOST:-api}"
export API_PORT="${API_PORT:-8000}"
export WEB_HOST="${WEB_HOST:-web}"
export WEB_PORT="${WEB_PORT:-3000}"
export DOMAIN_NAME="${DOMAIN_NAME:-localhost}"
export CLIENT_MAX_BODY_SIZE="${CLIENT_MAX_BODY_SIZE:-100M}"
export PROXY_CONNECT_TIMEOUT="${PROXY_CONNECT_TIMEOUT:-60s}"
export PROXY_SEND_TIMEOUT="${PROXY_SEND_TIMEOUT:-60s}"
export PROXY_READ_TIMEOUT="${PROXY_READ_TIMEOUT:-60s}"

# Process main configuration template
if [[ -f "$TEMPLATE_FILE" ]]; then
    log_info "Processing template: $TEMPLATE_FILE"
    envsubst '${API_HOST} ${API_PORT} ${WEB_HOST} ${WEB_PORT} ${DOMAIN_NAME} ${CLIENT_MAX_BODY_SIZE} ${PROXY_CONNECT_TIMEOUT} ${PROXY_SEND_TIMEOUT} ${PROXY_READ_TIMEOUT}' \
        < "$TEMPLATE_FILE" > /etc/nginx/conf.d/default.conf
    log_success "Nginx configuration processed"
else
    log_error "Template file not found: $TEMPLATE_FILE"
    exit 1
fi

# Process nginx.conf template if it exists
if [[ -f "/etc/nginx/templates/nginx.conf.template" ]]; then
    log_info "Processing nginx.conf template..."
    envsubst < /etc/nginx/templates/nginx.conf.template > /etc/nginx/nginx.conf
fi

# Copy SSL parameters if SSL is enabled
if [[ "${ENABLE_SSL:-false}" == "true" ]] && [[ -f "/etc/nginx/ssl-params.conf" ]]; then
    log_info "SSL enabled, copying SSL parameters..."
    cp /etc/nginx/ssl-params.conf /etc/nginx/
fi

# Test nginx configuration
log_info "Testing nginx configuration..."
if nginx -t; then
    log_success "Nginx configuration test passed"
else
    log_error "Nginx configuration test failed!"
    exit 1
fi

# Create a simple index.html if it doesn't exist
if [[ ! -f /usr/share/nginx/html/index.html ]]; then
    cat > /usr/share/nginx/html/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>FKS Trading Systems</title>
</head>
<body>
    <h1>FKS Trading Systems</h1>
    <p>Welcome to the FKS Trading Systems. Services are protected with authentication.</p>
</body>
</html>
EOF
fi

# Start nginx
log_info "Starting nginx..."
exec nginx -g "daemon off;"
