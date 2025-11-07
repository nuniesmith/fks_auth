#!/bin/bash
# =================================================================
# Nginx Docker Entrypoint Script - Improved Version
# =================================================================
# This script processes nginx configuration templates with environment
# variables before starting nginx

set -uo pipefail

# Enable debug mode
DEBUG="${DEBUG:-false}"

# Logging functions
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ℹ️  $*"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $*" >&2
}

log_debug() {
    if [ "$DEBUG" = "true" ]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] 🔍 $*"
    fi
}
    # If optional upstream hosts aren't resolvable yet, map them to 127.0.0.1 to avoid nginx -t failures
    safe_host_var() {
        local var_name="$1"
        local host_value="${!var_name:-}"
        if [ -n "$host_value" ]; then
            if getent hosts "$host_value" >/dev/null 2>&1; then
                log_debug "Host $var_name=$host_value is resolvable"
            else
                log_info "Upstream host '$host_value' (from $var_name) not resolvable; using 127.0.0.1 placeholder"
                export "$var_name=127.0.0.1"
            fi
        fi
    }

    # Apply safety for known upstreams (some are optional in dev)
    safe_host_var API_HOST
    safe_host_var WEB_HOST
    safe_host_var DATA_HOST
    safe_host_var TRANSFORMER_HOST
    safe_host_var ENGINE_HOST
    safe_host_var AUTHELIA_HOST
    safe_host_var PROMETHEUS_HOST
    safe_host_var GRAFANA_HOST


log_info "Starting Nginx configuration..."

# Configuration dump in debug mode
if [ "$DEBUG" = "true" ]; then
    log_debug "Environment configuration:"
    env | grep -E '^(DOMAIN_NAME|ENABLE_SSL|API_|WEB_|WORKER_|CLIENT_|NGINX_|PROXY_|GZIP_|REAL_IP_)' | sort
fi

# Function to validate required environment variables
validate_env() {
    local required_vars=(
        "DOMAIN_NAME"
        "API_HOST"
        "API_PORT"
        "WEB_HOST"
        "WEB_PORT"
    )
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            log_error "Required environment variable not set: $var"
            return 1
        fi
    done
    
    log_debug "All required environment variables validated"
    return 0
}

# Function to process templates with improved envsubst
process_template() {
    local template=$1
    local output=$2
    
    # Check if template exists
    if [ ! -f "$template" ]; then
        log_error "Template file not found: $template"
        return 1
    fi
    
    # Remove existing output file if it exists (avoid backup due to permissions)
    if [ -f "$output" ]; then
        rm -f "$output"
        log_debug "Removed existing config: $output"
    fi
    
    log_info "Processing template: $(basename "$template") -> $(basename "$output")"
    
    # Minimal whitelist for dev templates to avoid touching nginx runtime $vars
    # Include NGINX_* so nginx.conf gets proper worker settings
    local export_vars='$BASE_DOMAIN $DOMAIN_NAME $API_HOST $API_PORT $WEB_HOST $WEB_PORT $DATA_HOST $DATA_PORT $TRANSFORMER_HOST $TRANSFORMER_PORT $ENGINE_HOST $ENGINE_PORT $AUTHELIA_HOST $AUTHELIA_PORT $PROMETHEUS_HOST $PROMETHEUS_PORT $GRAFANA_HOST $GRAFANA_PORT $PROXY_CONNECT_TIMEOUT $PROXY_SEND_TIMEOUT $PROXY_READ_TIMEOUT $NGINX_WORKER_PROCESSES $NGINX_WORKER_CONNECTIONS $KEEPALIVE_TIMEOUT $CLIENT_MAX_BODY_SIZE $GZIP_ENABLED $GZIP_COMP_LEVEL'
    # Process template using only the whitelisted variables
    if envsubst "$export_vars" < "$template" > "$output"; then
        log_debug "Successfully processed template"
        # No-op
    else
        log_error "Failed to process template: $template"
        return 1
    fi
    
    return 0
}

# Validate environment variables
if ! validate_env; then
    log_error "Environment validation failed"
    exit 1
fi

# Create required directories
directories=(
    "/etc/nginx/ssl"
    "/var/log/nginx"
    "/var/cache/nginx"
    "/var/run/nginx"
)

for dir in "${directories[@]}"; do
    if ! mkdir -p "$dir"; then
        log_error "Failed to create directory: $dir"
        exit 1
    fi
done

# Process main nginx.conf if template exists
if [ -f "/etc/nginx/templates/nginx.conf.template" ]; then
    if ! process_template "/etc/nginx/templates/nginx.conf.template" "/etc/nginx/nginx.conf"; then
        log_error "Failed to process main nginx configuration"
        exit 1
    fi
fi

DEV_MULTI_PRESENT=false
if [ -f "/etc/nginx/templates/dev-multi.conf.template" ]; then
    DEV_MULTI_PRESENT=true
fi

# Process all configuration templates
template_count=0
for template in /etc/nginx/templates/*.conf.template; do
    if [ -f "$template" ]; then
        filename=$(basename "$template" .template)
        
        # Skip nginx.conf.template as it's already processed above
        if [ "$(basename "$template")" = "nginx.conf.template" ]; then
            log_info "Skipping nginx.conf.template (already processed)"
            continue
        fi
        
        # Skip SSL config if SSL is disabled
        if [ "$(basename "$template" .conf.template)" = "ssl" ] && [ "$ENABLE_SSL" != "true" ]; then
            log_info "Skipping SSL configuration (SSL disabled)"
            continue
        fi
        
        # Skip HTTPS config if SSL is disabled
        if [ "$(basename "$template" .conf.template)" = "https" ] && [ "$ENABLE_SSL" != "true" ]; then
            log_info "Skipping HTTPS configuration (SSL disabled)"
            continue
        fi
        
        # Skip SSL auth config if SSL is disabled
        if [ "$(basename "$template" .conf.template)" = "default-ssl-auth" ] && [ "$ENABLE_SSL" != "true" ]; then
            log_info "Skipping SSL auth configuration (SSL disabled)"
            continue
        fi
        
        # Skip default config if SSL is enabled (use default-ssl-auth instead)
        if [ "$(basename "$template" .conf.template)" = "default" ] && [ "$ENABLE_SSL" = "true" ]; then
            log_info "Skipping default configuration (using SSL auth config instead)"
            continue
        fi
    # If dev-multi is present, skip default.conf.template to prevent conflicts
        if [ "$DEV_MULTI_PRESENT" = "true" ] && [ "$(basename "$template")" = "default.conf.template" ]; then
            log_info "Skipping default.conf.template (dev-multi present)"
            continue
        fi
        # Prefer dev-multi when present for local dev routing
        if [ "$(basename "$template")" = "dev-multi.conf.template" ]; then
            log_info "Including dev multi-domain config (BASE_DOMAIN=$BASE_DOMAIN)"
        fi
        
        if process_template "$template" "/etc/nginx/conf.d/$filename"; then
            template_count=$((template_count + 1))
            log_debug "Successfully processed template: $template"
        else
            log_error "Failed to process template: $template"
            exit 1
        fi
    fi
done

log_info "Processed $template_count configuration templates"

# Remove the packaged default.conf when using dev-multi to ensure our server blocks are used
if [ "$DEV_MULTI_PRESENT" = "true" ] && [ -f "/etc/nginx/conf.d/default.conf" ]; then
    log_info "Removing packaged default.conf to avoid server_name conflicts"
    rm -f /etc/nginx/conf.d/default.conf || true
fi

# Handle SSL configuration
if [ "$ENABLE_SSL" = "true" ]; then
    log_info "SSL is enabled, checking certificates..."
    
    # Check for Let's Encrypt certificates first
    if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" ]; then
        log_info "✅ Using Let's Encrypt certificates for $DOMAIN_NAME"
        cert_path="/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
        key_path="/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"
    else
        # Fall back to default SSL certificate paths
        cert_path="/etc/nginx/ssl/cert.pem"
        key_path="/etc/nginx/ssl/key.pem"
    fi
    
    # Check if certificates exist
    if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
        log_info "SSL certificates not found, generating self-signed certificates..."
        
        # Create SSL directory if it doesn't exist
        mkdir -p "/etc/nginx/ssl"
        
        # Generate self-signed certificate with timeout
        if timeout 30 openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_path" \
            -out "$cert_path" \
            -subj "/C=US/ST=State/L=City/O=FKS Trading Systems/CN=$DOMAIN_NAME" \
            2>/dev/null; then
            
            log_info "✅ Self-signed certificates generated"
            chmod 600 "$key_path" "$cert_path"
        else
            log_error "Failed to generate self-signed certificates"
            log_info "⚠️ Disabling SSL and falling back to HTTP-only mode"
            export ENABLE_SSL="false"
            # Remove SSL configuration if it exists
            rm -f /etc/nginx/conf.d/ssl.conf 2>/dev/null || true
        fi
    else
        log_info "✅ SSL certificates found"
        # Validate certificate
        if openssl x509 -in "$cert_path" -noout -checkend 86400 > /dev/null 2>&1; then
            log_debug "Certificate is valid for at least 24 hours"
        else
            log_info "⚠️  Certificate expires within 24 hours"
        fi
    fi
    
    # Only check SSL configuration if SSL is still enabled
    if [ "$ENABLE_SSL" = "true" ]; then
        # Ensure SSL configuration exists
        if [ ! -f "/etc/nginx/conf.d/ssl.conf" ]; then
            log_error "SSL configuration file not found after template processing"
            log_info "⚠️ Disabling SSL and falling back to HTTP-only mode"
            export ENABLE_SSL="false"
        fi
    fi
else
    log_info "SSL is disabled"
fi

# Remove SSL configuration if SSL is disabled
if [ "$ENABLE_SSL" != "true" ]; then
    rm -f /etc/nginx/conf.d/ssl.conf 2>/dev/null || true
fi

# Test nginx configuration
log_info "Validating nginx configuration..."
if nginx -t 2>&1 | tee /tmp/nginx-test.log; then
    log_info "✅ Nginx configuration is valid"
else
    log_error "Nginx configuration validation failed"
    cat /tmp/nginx-test.log >&2
    exit 1
fi

# Create a simple health check file
echo "OK" > /usr/share/nginx/html/health.txt

# Log startup information
log_info "Nginx configuration complete"
log_info "Domain: $DOMAIN_NAME"
log_info "SSL: $ENABLE_SSL"
log_info "Upstream servers:"
log_info "  - API: $API_HOST:$API_PORT"
log_info "  - Web: $WEB_HOST:$WEB_PORT"

if [ "$DEBUG" = "true" ]; then
    log_debug "Configuration files:"
    ls -la /etc/nginx/conf.d/
fi

log_info "🚀 Starting nginx..."

# Execute the CMD (nginx)
exec "$@"