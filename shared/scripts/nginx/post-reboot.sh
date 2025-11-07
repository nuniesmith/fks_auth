#!/bin/bash
# post-reboot.sh - Post-reboot setup completion
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="post-reboot"
readonly SCRIPT_VERSION="3.0.0"

# Configuration
CONFIG_DIR="/etc/nginx-automation"
LOG_FILE="/var/log/linode-setup/post-reboot-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"

# Logging setup
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

# ============================================================================
# LOAD CONFIGURATION AND UTILITIES
# ============================================================================
load_configuration() {
    if [[ -f "$CONFIG_DIR/deployment-config.json" ]]; then
        # Extract key configuration values
        DOMAIN_NAME=$(jq -r '.domain // "7gram.xyz"' "$CONFIG_DIR/deployment-config.json")
        ENABLE_SSL=$(jq -r '.services.ssl // true' "$CONFIG_DIR/deployment-config.json")
        GITHUB_REPO=$(jq -r '.github.repository // "nuniesmith/nginx"' "$CONFIG_DIR/deployment-config.json")
        SCRIPT_BASE_URL=$(jq -r '.script_base_url // "https://raw.githubusercontent.com/nuniesmith/nginx/main/scripts"' "$CONFIG_DIR/deployment-config.json")
        
        # Export for use by other scripts
        export DOMAIN_NAME ENABLE_SSL GITHUB_REPO SCRIPT_BASE_URL
        
        log "Configuration loaded successfully"
    else
        warning "Configuration file not found, using defaults"
        DOMAIN_NAME="7gram.xyz"
        ENABLE_SSL="true"
        GITHUB_REPO="nuniesmith/nginx"
        SCRIPT_BASE_URL="https://raw.githubusercontent.com/nuniesmith/nginx/main/scripts"
    fi
}

# Load common utilities
download_and_source_utils() {
    local utils_url="${SCRIPT_BASE_URL}/utils/common.sh"
    
    if ! curl -fsSL "$utils_url" -o /tmp/common.sh; then
        echo "❌ Failed to download common utilities, creating minimal functions..."
        create_minimal_utils
    else
        source /tmp/common.sh
    fi
}

create_minimal_utils() {
    # Minimal logging functions if download fails
    log() { echo -e "\033[0;34m[$(date +'%Y-%m-%d %H:%M:%S')]\033[0m $1"; }
    success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }
    error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }
    warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }
}

# ============================================================================
# TAILSCALE CONNECTION
# ============================================================================
connect_tailscale() {
    if [[ -f "$CONFIG_DIR/tailscale-auth.key" ]]; then
        log "Connecting to Tailscale network..."
        local auth_key=$(cat "$CONFIG_DIR/tailscale-auth.key")
        
        local retries=3
        for ((i=1; i<=retries; i++)); do
            if tailscale up --authkey="$auth_key" --accept-routes --accept-dns=false; then
                success "Connected to Tailscale network"
                
                # Clean up auth key
                rm -f "$CONFIG_DIR/tailscale-auth.key"
                
                # Wait for IP assignment
                local ts_ip
                if ts_ip=$(get_tailscale_ip); then
                    save_config_value "tailscale_ip" "$ts_ip"
                    log "Tailscale IP: $ts_ip"
                    echo "$ts_ip"
                    return 0
                else
                    warning "Could not get Tailscale IP"
                fi
                return 0
            else
                warning "Tailscale connection attempt $i/$retries failed"
                if [[ $i -lt $retries ]]; then
                    sleep 10
                fi
            fi
        done
        
        error "Failed to connect to Tailscale after $retries attempts"
        return 1
    else
        warning "No Tailscale auth key found"
        return 1
    fi
}

get_tailscale_ip() {
    local retries=10
    for ((i=1; i<=retries; i++)); do
        local ts_ip=$(tailscale ip -4 2>/dev/null | head -n1)
        if [[ -n "$ts_ip" ]] && [[ "$ts_ip" =~ ^100\. ]]; then
            echo "$ts_ip"
            return 0
        fi
        sleep 3
    done
    return 1
}

# ============================================================================
# DNS MANAGEMENT
# ============================================================================
update_dns_records() {
    local ip_address="$1"
    
    if [[ -x "/usr/local/bin/update-cloudflare-dns" ]]; then
        log "Updating DNS records..."
        if /usr/local/bin/update-cloudflare-dns "$ip_address" all; then
            success "DNS records updated to point to $ip_address"
        else
            warning "Some DNS updates failed"
        fi
        
        # Wait for DNS propagation
        log "Waiting for DNS propagation..."
        sleep 30
    else
        log "DNS update script not found, skipping DNS updates"
    fi
}

# ============================================================================
# REPOSITORY AND DEPLOYMENT
# ============================================================================
setup_repository() {
    local deploy_dir="/opt/nginx-deployment"
    
    if [[ ! -d "$deploy_dir/.git" ]] && [[ -n "$GITHUB_REPO" ]]; then
        log "Cloning repository: $GITHUB_REPO"
        if sudo -u github-deploy git clone "https://github.com/$GITHUB_REPO.git" "$deploy_dir"; then
            success "Repository cloned successfully"
        else
            warning "Failed to clone repository, will use existing configuration"
            return 1
        fi
    elif [[ -d "$deploy_dir/.git" ]]; then
        log "Repository already exists, pulling latest changes"
        cd "$deploy_dir"
        if sudo -u github-deploy git pull origin main 2>/dev/null || \
           sudo -u github-deploy git pull origin master 2>/dev/null; then
            success "Repository updated"
        else
            warning "Failed to pull latest changes"
        fi
    else
        log "No repository configured or deployment directory missing"
        return 1
    fi
}

perform_initial_deployment() {
    log "Performing initial deployment..."
    
    # Ensure deployment directory exists
    mkdir -p /opt/nginx-deployment
    chown -R github-deploy:github-deploy /opt/nginx-deployment
    
    # Setup repository
    setup_repository
    
    # Run deployment script if available
    if [[ -x "/opt/nginx-deployment/deploy.sh" ]]; then
        log "Running deployment script..."
        if sudo -u github-deploy /opt/nginx-deployment/deploy.sh deploy; then
            success "Initial deployment completed"
        else
            warning "Initial deployment failed, continuing with basic setup"
        fi
    else
        log "Deployment script not found, using existing configuration"
    fi
}

# ============================================================================
# SSL CERTIFICATE SETUP
# ============================================================================
setup_ssl_certificates() {
    if [[ "$ENABLE_SSL" != "true" ]] || [[ "$DOMAIN_NAME" == "localhost" ]]; then
        log "SSL disabled or localhost domain, skipping certificate setup"
        return 0
    fi
    
    log "Setting up SSL certificates..."
    
    # Wait for DNS to propagate
    log "Waiting for DNS propagation before requesting certificates..."
    sleep 60
    
    # Determine SSL method
    local ssl_args=""
    if [[ -f "/etc/letsencrypt/cloudflare.ini" ]]; then
        ssl_args="--dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini"
        log "Using Cloudflare DNS challenge"
    else
        ssl_args="--webroot --webroot-path=/var/www/certbot"
        log "Using HTTP challenge"
        
        # Create webroot directory
        mkdir -p /var/www/certbot
        chown http:http /var/www/certbot
    fi
    
    # Add staging flag if requested
    if [[ "${SSL_STAGING:-false}" == "true" ]]; then
        ssl_args="$ssl_args --staging"
        log "Using Let's Encrypt staging environment"
    fi
    
    # Request certificate
    local ssl_email="${SSL_EMAIL:-admin@$DOMAIN_NAME}"
    if certbot certonly $ssl_args \
        --email "$ssl_email" \
        --agree-tos \
        --no-eff-email \
        --non-interactive \
        -d "$DOMAIN_NAME" \
        -d "www.$DOMAIN_NAME"; then
        
        success "SSL certificate obtained successfully"
        
        # Update nginx configuration for SSL
        create_ssl_nginx_config
        
        # Test and reload nginx
        if nginx -t; then
            systemctl reload nginx
            success "NGINX reloaded with SSL configuration"
        else
            error "NGINX configuration test failed with SSL"
            return 1
        fi
        
        # Setup certificate renewal
        setup_ssl_renewal
        
    else
        warning "SSL certificate request failed, continuing with HTTP only"
        return 1
    fi
}

create_ssl_nginx_config() {
    log "Creating SSL-enabled NGINX configuration..."
    
    cat > /etc/nginx/sites-available/default-ssl << EOF
# HTTP redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    # Let's Encrypt challenge location
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }
    
    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    # Include SSL settings
    include /etc/nginx/conf.d/ssl.conf;
    
    # Security: Only allow Tailscale network and localhost
    allow 100.64.0.0/10;  # Tailscale network
    allow 127.0.0.1;      # Localhost
    deny all;
    
    root /var/www/html;
    index index.html index.htm;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    
    # Main location
    location / {
        try_files \$uri \$uri/ =404;
        
        # Cache static assets
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # Health check endpoint
    location = /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
    
    # Status endpoint for monitoring
    location = /status {
        access_log off;
        return 200 '{"status":"ok","server":"$hostname","timestamp":"$time_iso8601","ssl":true}';
        add_header Content-Type application/json;
    }
    
    # Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
    
    # Enable SSL config and disable HTTP-only config
    ln -sf /etc/nginx/sites-available/default-ssl /etc/nginx/sites-enabled/default-ssl
    rm -f /etc/nginx/sites-enabled/default
    
    success "SSL NGINX configuration created"
}

setup_ssl_renewal() {
    log "Setting up SSL certificate auto-renewal..."
    
    # Add renewal to cron
    (crontab -l 2>/dev/null; echo "0 12 * * * certbot renew --quiet && systemctl reload nginx") | \
        crontab -
    
    success "SSL auto-renewal configured"
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================
start_services() {
    log "Starting and enabling services..."
    
    # Start NGINX
    if systemctl start nginx && systemctl is-active --quiet nginx; then
        success "NGINX started successfully"
    else
        error "Failed to start NGINX"
        systemctl status nginx
        return 1
    fi
    
    # Start monitoring services if available
    local monitoring_services=("prometheus" "prometheus-node-exporter" "webhook-receiver")
    for service in "${monitoring_services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            if systemctl start "$service"; then
                success "Started monitoring service: $service"
            else
                warning "Failed to start monitoring service: $service"
            fi
        fi
    done
}

# ============================================================================
# HEALTH CHECKS
# ============================================================================
perform_health_checks() {
    log "Performing health checks..."
    
    local failed_checks=0
    
    # Check NGINX status
    if systemctl is-active --quiet nginx; then
        success "✅ NGINX is running"
    else
        error "❌ NGINX is not running"
        ((failed_checks++))
    fi
    
    # Check HTTP endpoint
    local retries=5
    for ((i=1; i<=retries; i++)); do
        if curl -sf http://localhost/health >/dev/null 2>&1; then
            success "✅ HTTP health check passed"
            break
        elif [[ $i -eq $retries ]]; then
            error "❌ HTTP health check failed after $retries attempts"
            ((failed_checks++))
        else
            warning "HTTP health check attempt $i/$retries failed, retrying..."
            sleep 5
        fi
    done
    
    # Check HTTPS endpoint if SSL is enabled
    if [[ "$ENABLE_SSL" == "true" ]] && [[ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]]; then
        if curl -sf "https://$DOMAIN_NAME/health" >/dev/null 2>&1; then
            success "✅ HTTPS health check passed"
        else
            warning "⚠️ HTTPS health check failed"
            # Don't increment failed_checks as HTTPS might still be propagating
        fi
    fi
    
    # Check Tailscale connectivity
    if command -v tailscale &>/dev/null && tailscale ip >/dev/null 2>&1; then
        success "✅ Tailscale is connected"
    else
        warning "⚠️ Tailscale connection issue"
    fi
    
    return $failed_checks
}

# ============================================================================
# NOTIFICATIONS
# ============================================================================
send_completion_notification() {
    local status="$1"
    local ts_ip="$2"
    local public_ip=$(curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || echo "unknown")
    
    local emoji="✅"
    local color="3066993"
    if [[ "$status" != "success" ]]; then
        emoji="⚠️"
        color="16776960"
    fi
    
    local message="$emoji 7gram Dashboard Setup Complete!

**Status:** $status
**Tailscale IP:** $ts_ip
**Public IP:** $public_ip
**Domain:** $DOMAIN_NAME
**SSL:** $([ "$ENABLE_SSL" == "true" ] && echo "Enabled" || echo "Disabled")

**Management Commands:**
• \`7gram-status\` - Check system status
• \`/opt/nginx-deployment/deployment-info.txt\` - Deployment info

**Access:** https://$DOMAIN_NAME"

    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        curl -s -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"Setup Complete - $(hostname)\",\"description\":\"$message\",\"color\":$color}]}" \
            "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
    fi
    
    echo "$message"
}

# ============================================================================
# CLEANUP
# ============================================================================
cleanup_post_reboot() {
    log "Performing post-reboot cleanup..."
    
    # Disable and remove the post-reboot service
    systemctl disable post-reboot-setup.service 2>/dev/null || true
    rm -f /etc/systemd/system/post-reboot-setup.service
    systemctl daemon-reload
    
    # Clean up temporary files
    rm -f /tmp/common.sh /tmp/*.template
    
    # Save final status
    save_config_value "setup_completed" "true"
    save_config_value "completion_time" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    success "Cleanup completed"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting post-reboot setup Phase 2..."
    
    # Initialize
    load_configuration
    download_and_source_utils
    
    # Wait for system to fully initialize
    log "Waiting for system initialization..."
    sleep 15
    
    # Connect to Tailscale and get IP
    local ts_ip="unknown"
    if connect_tailscale; then
        if ts_ip=$(get_tailscale_ip); then
            log "Tailscale IP obtained: $ts_ip"
            
            # Setup firewall if it was deferred
setup_deferred_firewall() {
    if [[ -f "$CONFIG_DIR/post-reboot-tasks" ]] && grep -q "ufw_setup_needed=true" "$CONFIG_DIR/post-reboot-tasks"; then
        log "Setting up deferred firewall configuration..."
        
        # Load kernel modules
        modprobe ip_tables 2>/dev/null || true
        modprobe iptable_filter 2>/dev/null || true
        modprobe ip6_tables 2>/dev/null || true
        modprobe ip6table_filter 2>/dev/null || true
        
        # Configure UFW
        if ufw --force reset && \
           ufw default deny incoming && \
           ufw default allow outgoing && \
           ufw allow ssh && \
           ufw allow 80/tcp && \
           ufw allow 443/tcp && \
           ufw allow in on tailscale0; then
            
            if echo "y" | ufw enable; then
                success "Deferred firewall setup completed"
                # Remove the task flag
                sed -i '/ufw_setup_needed=true/d' "$CONFIG_DIR/post-reboot-tasks"
            else
                warning "Firewall enable still failed after reboot"
            fi
        else
            warning "Firewall configuration still having issues"
        fi
    fi
} if configured
            update_dns_records "$ts_ip"
        else
            warning "Could not get Tailscale IP"
        fi
    else
        warning "Tailscale connection failed"
    fi
    
    # Perform deployment
    perform_initial_deployment
    
    # Start services
    start_services
    
    # Setup SSL if enabled and we have a proper domain
    if [[ "$ENABLE_SSL" == "true" ]] && [[ "$DOMAIN_NAME" != "localhost" ]]; then
        setup_ssl_certificates
    fi
    
    # Perform health checks
    local health_status="success"
    if ! perform_health_checks; then
        health_status="warning"
        warning "Some health checks failed, but deployment may still be functional"
    fi
    
    # Send completion notification
    send_completion_notification "$health_status" "$ts_ip"
    
    # Cleanup
    cleanup_post_reboot
    
    # Final status
    if [[ "$health_status" == "success" ]]; then
        success "🎉 Post-reboot setup completed successfully!"
        success "Dashboard available at: https://$DOMAIN_NAME"
        success "Use '7gram-status' to check system status"
    else
        warning "⚠️ Post-reboot setup completed with warnings"
        warning "Check logs and run '7gram-status' for details"
    fi
    
    log "Post-reboot setup finished at $(date)"
}

# Execute main function
main "$@"