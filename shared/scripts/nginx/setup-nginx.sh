#!/bin/bash
# setup-nginx.sh - NGINX installation and configuration
# Part of the modular StackScript system
# Version: 3.0.1 - Fixed template URLs and variable issues

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-nginx"
readonly SCRIPT_VERSION="3.0.1"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# VARIABLES AND CONFIGURATION  
# ============================================================================
# Set variables with defaults
readonly SERVER_HOSTNAME="${HOSTNAME:-$(hostname)}"
readonly SERVER_DOMAIN="${DOMAIN_NAME:-7gram.xyz}"
readonly SSL_ENABLED="${ENABLE_SSL:-true}"
readonly GITHUB_REPO_URL="${GITHUB_REPO:-nuniesmith/nginx}"
readonly GITHUB_BRANCH_NAME="${GITHUB_BRANCH:-main}"
readonly REPO_DIR="${REPO_DIR:-/opt/nginx-deployment}"

# ============================================================================
# NGINX INSTALLATION
# ============================================================================
install_nginx() {
    log "Installing NGINX..."
    
    # Check if already installed
    if command -v nginx &>/dev/null; then
        log "NGINX already installed, checking version..."
        nginx -v
        return 0
    fi
    
    # Install NGINX
    if pacman -S --needed --noconfirm nginx; then
        success "NGINX installed successfully"
        nginx -v
    else
        error "Failed to install NGINX"
        return 1
    fi
}

# ============================================================================
# NGINX CONFIGURATION
# ============================================================================
configure_nginx() {
    log "Configuring NGINX..."
    
    # Create necessary directories
    mkdir -p /etc/nginx/{sites-available,sites-enabled,conf.d,ssl,includes}
    mkdir -p /var/www/html
    mkdir -p /var/log/nginx
    mkdir -p /var/cache/nginx
    mkdir -p /var/www/certbot
    
    # Set proper permissions
    chown -R http:http /var/www/html
    chown -R http:http /var/log/nginx
    chown -R http:http /var/cache/nginx
    chown -R http:http /var/www/certbot
    
    success "NGINX directories created"
}

create_nginx_config() {
    log "Creating main NGINX configuration..."
    
    # Try to download template from repository
    local template_url="https://raw.githubusercontent.com/${GITHUB_REPO_URL}/${GITHUB_BRANCH_NAME}/config/nginx/nginx.conf"
    
    if download_template_safe "$template_url" "/tmp/nginx.conf.template"; then
        log "Downloaded NGINX template from repository"
        # Use downloaded template with variable substitution
        substitute_template "/tmp/nginx.conf.template" "/etc/nginx/nginx.conf"
        rm -f "/tmp/nginx.conf.template"
    else
        warning "Template download failed, creating inline configuration..."
        create_inline_nginx_config
    fi
    
    # Validate configuration
    if nginx -t; then
        success "NGINX configuration is valid"
    else
        error "NGINX configuration validation failed"
        return 1
    fi
}

download_template_safe() {
    local url="$1"
    local output="$2"
    local retries=3
    
    for ((i=1; i<=retries; i++)); do
        log "Download attempt $i/$retries: $(basename "$url")"
        if curl -fsSL "$url" -o "$output" 2>/dev/null; then
            return 0
        else
            warning "Download attempt $i/$retries failed for $(basename "$url")"
            if [[ $i -lt $retries ]]; then
                sleep 2
            fi
        fi
    done
    
    return 1
}

substitute_template() {
    local template_file="$1"
    local output_file="$2"
    
    log "Processing template variables and cleaning up config..."
    
    # More precise removal of the duplicate template section
    # The main config ends with "include /etc/nginx/conf.d/*.conf;" and "}"
    # The template starts after that with another "user nginx;" line
    
    # Find the line number where the template section starts (second occurrence of "user nginx;")
    local template_start=$(grep -n "^user nginx;" "$template_file" | tail -1 | cut -d: -f1)
    
    if [[ -n "$template_start" && "$template_start" -gt 50 ]]; then
        # Remove everything from the second "user nginx;" onwards
        head -n "$((template_start - 1))" "$template_file" > "/tmp/nginx_clean.conf"
        log "Removed template section starting at line $template_start"
    else
        # Fallback: use the original method
        sed '/^user nginx;$/,$d' "$template_file" > "/tmp/nginx_clean.conf"
        log "Used fallback template removal method"
    fi
    
    # Process the cleaned file with variable substitution and OS fixes
    sed -e "s/{{SERVER_NAME}}/$SERVER_HOSTNAME/g" \
        -e "s/{{DOMAIN_NAME}}/$SERVER_DOMAIN/g" \
        -e "s/{{HOSTNAME}}/$SERVER_HOSTNAME/g" \
        -e "s/\${NGINX_WORKER_PROCESSES}/auto/g" \
        -e "s/\${NGINX_WORKER_CONNECTIONS}/4096/g" \
        -e "s/user nginx;/user http;/g" \
        -e "s/user www-data;/user http;/g" \
        -e "s/sullivan.7gram.xyz/127.0.0.1/g" \
        -e "s/100.121.199.80/127.0.0.1/g" \
        -e "s/sullivan.tailfef10.ts.net/127.0.0.1/g" \
        "/tmp/nginx_clean.conf" > "/tmp/nginx_processed.conf"
    
    # Comment out SSL-dependent configurations until certificates are available
    # But preserve the sophisticated structure
    sed -e 's/^[[:space:]]*listen 443 ssl/listen 443 #ssl/g' \
        -e 's/^[[:space:]]*ssl_certificate/#ssl_certificate/g' \
        -e 's/^[[:space:]]*ssl_certificate_key/#ssl_certificate_key/g' \
        -e 's/^[[:space:]]*ssl_dhparam/#ssl_dhparam/g' \
        -e 's/^[[:space:]]*include.*ssl_params\.conf/#include \/etc\/nginx\/includes\/ssl_params.conf/g' \
        "/tmp/nginx_processed.conf" > "$output_file"
    
    # Add a comment explaining the configuration state
    cat >> "$output_file" << 'EOF'

# ============================================================================
# CONFIGURATION STATUS - 7GRAM NGINX SETUP
# ============================================================================
# This is your comprehensive production nginx.conf with:
# - Advanced maps system for service-aware configurations
# - Sophisticated upstream definitions for all your services  
# - Health proxy server on port 8081 for dashboard integration
# - Dynamic security headers and CORS policies
# - Service-specific rate limiting and caching
# - SSL configurations temporarily disabled until certificates available
#
# The template section has been removed to prevent conflicts.
# All server blocks from default.conf will provide the actual service routing.
# The health check server on port 8080 and health proxy on port 8081 are active.
# The default server returns 444 for undefined hosts.
#
# Service routing will be handled by:
# - /etc/nginx/conf.d/default.conf (main service definitions)
# - /etc/nginx/conf.d/maps.conf (advanced variable mappings)
# - /etc/nginx/includes/*.conf (proxy parameters, security headers, etc.)
EOF
    
    # Clean up temporary files
    rm -f "/tmp/nginx_clean.conf" "/tmp/nginx_processed.conf"
}

create_inline_nginx_config() {
    log "Creating inline NGINX configuration..."
    
    cat > /etc/nginx/nginx.conf << 'EOF'
user http;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';
    
    log_format detailed '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" '
                       '"$http_user_agent" "$http_x_forwarded_for" '
                       'rt=$request_time uct="$upstream_connect_time" '
                       'uht="$upstream_header_time" urt="$upstream_response_time"';
    
    access_log /var/log/nginx/access.log main;
    
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 75s;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 100M;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    # Buffer settings
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    output_buffers 1 32k;
    postpone_output 1460;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
    gzip_min_length 1000;

    # Security headers (default)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
    limit_req_zone $binary_remote_addr zone=general:10m rate=30r/m;

    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    limit_conn conn_limit_per_ip 20;

    # Include additional configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    success "Inline NGINX configuration created"
}

create_simple_bootstrap_site() {
    log "Preparing for sophisticated site configurations from repository..."
    
    # The main nginx.conf already has:
    # - Default server block (returns 444)
    # - Health check server on port 8080
    # - Health proxy server on port 8081
    # - Include statement for conf.d/*.conf
    
    # The default.conf from repository will provide the actual service routing
    # We just need to ensure the document root exists and has content
    
    # Remove any existing conflicting default site
    rm -f "$SITES_ENABLED/default"
    
    # Create the dashboard content for the repository's default.conf to serve
    create_dashboard_content
    
    log "The sophisticated server configurations from default.conf will handle routing"
    log "Main nginx.conf provides: default server (444), health check (8080), health proxy (8081)"
    log "Repository default.conf will provide: dashboard, service routing, SSL configurations"
    
    success "Bootstrap preparation complete (repository configurations will take over)"
}

create_monitoring_config() {
    log "Creating monitoring configuration..."
    
    cat > /etc/nginx/conf.d/monitoring.conf << 'EOF'
# Monitoring and status endpoints
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    
    access_log off;
    
    # NGINX status for monitoring
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        deny all;
    }
    
    # Basic metrics endpoint
    location /metrics {
        access_log off;
        return 200 "# NGINX Metrics\nnginx_up 1\n";
        add_header Content-Type text/plain;
        allow 127.0.0.1;
        deny all;
    }
}
EOF
    
    success "Monitoring configuration created"
}

create_security_config() {
    log "Creating security configuration..."
    
    cat > /etc/nginx/conf.d/security.conf << 'EOF'
# Security configuration

# Hide NGINX version
server_tokens off;

# Block common exploit attempts
map $request_uri $block_exploits {
    default 0;
    ~*(\.|%2e)(\.|%2e)(%2f|/) 1;
    ~*(etc|proc|sys)/ 1;
    ~*\.(htaccess|htpasswd|ini|log|sh|sql|conf)$ 1;
}

# Block bad user agents
map $http_user_agent $block_ua {
    default 0;
    ~*(bot|crawler|spider|scraper) 1;
    ~*(curl|wget|python|perl|java) 1;
    "" 1;
}

# Geographic blocking (example - adjust as needed)
geo $block_country {
    default 0;
    # Add specific countries to block if needed
    # CN 1;  # China
    # RU 1;  # Russia
}

# Rate limiting for different endpoint types
limit_req_zone $binary_remote_addr zone=admin:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=search:10m rate=20r/m;
limit_req_zone $binary_remote_addr zone=static:10m rate=100r/m;
EOF
    
    success "Security configuration created"
}

create_ssl_config() {
    log "Creating SSL configuration template..."
    
    cat > /etc/nginx/conf.d/ssl.conf << 'EOF'
# SSL/TLS configuration
# This file provides SSL settings that can be included in server blocks

# Modern SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# SSL session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Security headers for HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;" always;
EOF
    
    success "SSL configuration template created"
}

create_dashboard_content() {
    log "Creating dashboard content..."
    
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>7gram Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 3rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 800px;
            width: 100%;
        }
        
        h1 {
            color: #333;
            margin-bottom: 1rem;
            font-size: 3rem;
            font-weight: 700;
        }
        
        .status {
            color: #28a745;
            font-weight: bold;
            margin: 2rem 0;
            font-size: 1.2rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .info-card {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 15px;
            border-left: 4px solid #667eea;
        }
        
        .info-card h3 {
            color: #495057;
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }
        
        .info-card p {
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .commands {
            background: #2d3748;
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 10px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            text-align: left;
            margin: 2rem 0;
            overflow-x: auto;
        }
        
        .commands code {
            display: block;
            margin: 0.5rem 0;
            color: #81e6d9;
        }
        
        .services {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .service-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            text-decoration: none;
            transition: transform 0.3s ease;
        }
        
        .service-card:hover {
            transform: translateY(-5px);
            text-decoration: none;
            color: white;
        }
        
        .service-card h4 {
            margin-bottom: 0.5rem;
        }
        
        .footer {
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 2rem;
                margin: 1rem;
            }
            
            h1 {
                font-size: 2rem;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 7gram Dashboard</h1>
        <div class="status">✅ System is operational!</div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3>🖥️ Server Info</h3>
                <p><strong>Hostname:</strong> $SERVER_HOSTNAME</p>
                <p><strong>Domain:</strong> $SERVER_DOMAIN</p>
                <p><strong>Setup:</strong> $(date)</p>
            </div>
            
            <div class="info-card">
                <h3>🔧 Management</h3>
                <p><strong>Status:</strong> <code>7gram-status</code></p>
                <p><strong>Logs:</strong> <code>journalctl -f</code></p>
                <p><strong>NGINX:</strong> <code>systemctl status nginx</code></p>
            </div>
            
            <div class="info-card">
                <h3>🚀 Deployment</h3>
                <p><strong>Deploy:</strong> Auto via GitHub</p>
                <p><strong>Manual:</strong> <code>/opt/nginx-deployment/deploy.sh</code></p>
                <p><strong>Rollback:</strong> Available via script</p>
            </div>
            
            <div class="info-card">
                <h3>🔒 Security</h3>
                <p><strong>Firewall:</strong> UFW enabled</p>
                <p><strong>SSL:</strong> Let's Encrypt</p>
                <p><strong>Access:</strong> Tailscale only</p>
            </div>
        </div>
        
        <div class="services">
            <a href="https://emby.$SERVER_DOMAIN" class="service-card">
                <h4>📺 Emby</h4>
                <p>Media Server</p>
            </a>
            <a href="https://jellyfin.$SERVER_DOMAIN" class="service-card">
                <h4>🎬 Jellyfin</h4>
                <p>Media Platform</p>
            </a>
            <a href="https://ai.$SERVER_DOMAIN" class="service-card">
                <h4>🤖 AI Services</h4>
                <p>LLM & Tools</p>
            </a>
        </div>
        
        <div class="commands">
            <h3 style="color: #81e6d9; margin-bottom: 1rem;">Quick Commands</h3>
            <code># Check overall status</code>
            <code>7gram-status</code>
            <code></code>
            <code># Deploy latest changes</code>
            <code>sudo -u github-deploy /opt/nginx-deployment/deploy.sh</code>
            <code></code>
            <code># View NGINX logs</code>
            <code>tail -f /var/log/nginx/access.log</code>
            <code></code>
            <code># Check SSL certificates</code>
            <code>certbot certificates</code>
        </div>
        
        <div class="footer">
            <p>7gram Dashboard • Powered by NGINX • Deployed via GitHub Actions</p>
            <p>For support, check <code>/opt/nginx-deployment/deployment-info.txt</code></p>
        </div>
    </div>
    
    <script>
        // Auto-refresh status every 30 seconds
        setInterval(() => {
            fetch('/status')
                .then(response => response.json())
                .then(data => {
                    console.log('Status check:', data);
                })
                .catch(err => console.log('Status check failed:', err));
        }, 30000);
        
        // Add click handlers for service cards
        document.querySelectorAll('.service-card').forEach(card => {
            card.addEventListener('click', (e) => {
                // Optional: Add analytics or logging here
                console.log('Service accessed:', card.href);
            });
        });
    </script>
</body>
</html>
EOF
    
    # Set proper permissions
    chown -R http:http /var/www/html
    chmod -R 755 /var/www/html
    
    success "Dashboard content created"
}

create_nginx_management_scripts() {
    log "Creating NGINX management scripts..."
    
    cat > /usr/local/bin/nginx-status << 'EOF'
#!/bin/bash
# NGINX status and management script

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

show_status() {
    echo "=== NGINX Status ==="
    echo ""
    
    # Service status
    if systemctl is-active --quiet nginx; then
        success "NGINX service is running"
    else
        error "NGINX service is not running"
        echo "  Status: $(systemctl is-active nginx)"
    fi
    
    # Configuration test
    echo ""
    echo "Configuration Test:"
    if nginx -t 2>/dev/null; then
        success "Configuration is valid"
    else
        error "Configuration has errors"
        nginx -t
    fi
    
    # Listen ports
    echo ""
    echo "Listen Ports:"
    ss -tlnp | grep nginx || echo "No listening ports found"
}

case "${1:-status}" in
    status|"")
        show_status
        ;;
    logs)
        echo "=== NGINX Logs ==="
        journalctl -u nginx --no-pager -n 20
        ;;
    test)
        nginx -t
        ;;
    reload)
        log "Reloading NGINX configuration..."
        systemctl reload nginx
        ;;
    restart)
        log "Restarting NGINX service..."
        systemctl restart nginx
        ;;
    *)
        echo "Usage: $0 [status|logs|test|reload|restart]"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/nginx-status
    success "NGINX management script created"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting NGINX setup..."
    
    # Install NGINX first
    install_nginx
    
    # Configure NGINX
    configure_nginx
    create_nginx_config
    create_default_site
    create_monitoring_config
    create_security_config
    create_ssl_config
    
copy_additional_configs() {
    log "Copying additional configuration files from repository..."
    
    # Copy conf.d files from repository
    if [[ -d "$REPO_DIR/config/nginx/conf.d" ]]; then
        log "Copying conf.d files from repository..."
        cp -r "$REPO_DIR/config/nginx/conf.d/"* "/etc/nginx/conf.d/" 2>/dev/null || true
        success "Repository conf.d files copied"
    else
        warning "No conf.d directory found in repository"
    fi
    
    # Copy includes files from repository - PRIORITY over generated ones
    if [[ -d "$REPO_DIR/config/nginx/includes" ]]; then
        log "Copying sophisticated includes files from repository..."
        mkdir -p /etc/nginx/includes
        cp -r "$REPO_DIR/config/nginx/includes/"* "/etc/nginx/includes/" 2>/dev/null || true
        success "Repository includes files copied (overriding generated ones)"
        
        # Log what was copied
        log "Copied include files:"
        ls -la /etc/nginx/includes/ | grep "\.conf$" | while read -r line; do
            log "  $(echo "$line" | awk '{print $9}')"
        done
    else
        warning "No includes directory found in repository, using generated includes"
    fi
    
    # Ensure proper permissions
    chown -R root:root /etc/nginx/conf.d /etc/nginx/includes 2>/dev/null || true
    chmod -R 644 /etc/nginx/conf.d/* /etc/nginx/includes/* 2>/dev/null || true
}

create_fallback_includes() {
    log "Creating fallback include files only if missing..."
    
    # Only create basic includes if they don't exist (repository didn't provide them)
    
    # Create SSL parameters include if missing
    if [[ ! -f "/etc/nginx/includes/ssl_params.conf" ]]; then
        cat > /etc/nginx/includes/ssl_params.conf << 'EOF'
# Basic SSL configuration fallback
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
EOF
        log "Created fallback ssl_params.conf"
    fi
    
    # Create basic security headers if missing
    if [[ ! -f "/etc/nginx/includes/security_headers.conf" ]]; then
        cat > /etc/nginx/includes/security_headers.conf << 'EOF'
# Basic security headers fallback
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:;" always;
EOF
        log "Created fallback security_headers.conf"
    fi
    
    # Create basic proxy params if missing
    if [[ ! -f "/etc/nginx/includes/proxy_params.conf" ]]; then
        cat > /etc/nginx/includes/proxy_params.conf << 'EOF'
# Basic proxy parameters fallback
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;

proxy_connect_timeout 30s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

proxy_buffering on;
proxy_buffer_size 8k;
proxy_buffers 16 8k;
proxy_busy_buffers_size 16k;
EOF
        log "Created fallback proxy_params.conf"
    fi
    
    # Create other essential fallbacks if missing
    local fallback_files=(
        "caching.conf"
        "rate_limiting.conf"
        "media_proxy_params.conf"
        "websocket_proxy_params.conf"
    )
    
    for file in "${fallback_files[@]}"; do
        if [[ ! -f "/etc/nginx/includes/$file" ]]; then
            create_simple_fallback "$file"
        fi
    done
    
    success "Fallback include files created where needed"
}

create_simple_fallback() {
    local filename="$1"
    
    case "$filename" in
        "caching.conf")
            cat > "/etc/nginx/includes/$filename" << 'EOF'
# Basic caching fallback
expires 5m;
add_header Cache-Control "public, max-age=300" always;
add_header Vary "Accept-Encoding" always;
EOF
            ;;
        "rate_limiting.conf")
            cat > "/etc/nginx/includes/$filename" << 'EOF'
# Basic rate limiting fallback
limit_req zone=general burst=20 nodelay;
limit_conn conn_limit_per_ip 10;
EOF
            ;;
        "media_proxy_params.conf")
            cat > "/etc/nginx/includes/$filename" << 'EOF'
# Basic media proxy fallback
include /etc/nginx/includes/proxy_params.conf;
proxy_buffering off;
proxy_request_buffering off;
client_max_body_size 0;
proxy_read_timeout 300s;
EOF
            ;;
        "websocket_proxy_params.conf")
            cat > "/etc/nginx/includes/$filename" << 'EOF'
# Basic WebSocket proxy fallback  
include /etc/nginx/includes/proxy_params.conf;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_read_timeout 86400s;
proxy_send_timeout 86400s;
EOF
            ;;
    esac
    
    log "Created fallback $filename"
}
    
    # Enable NGINX service (don't start yet - will be started post-reboot)
    systemctl enable nginx
    
    # Update firewall for NGINX
    log "Updating firewall rules for NGINX..."
    if command -v ufw &>/dev/null; then
        # Remove the basic HTTP/HTTPS rules and add NGINX profile
        ufw delete allow 80/tcp 2>/dev/null || true
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw allow 'Nginx Full' || {
            # Fallback to manual port rules if profile doesn't work
            ufw allow 80/tcp
            ufw allow 443/tcp
        }
        success "Firewall rules updated for NGINX"
    fi
    
    # Validate final configuration with detailed error checking
    log "Validating NGINX configuration..."
    if nginx -t 2>/tmp/nginx_test_output; then
        success "NGINX configuration validation passed"
        
        # Check if maps are working
        if grep -q "maps.conf" /etc/nginx/nginx.conf; then
            if [[ -f "/etc/nginx/conf.d/maps.conf" ]]; then
                success "Maps configuration properly integrated"
            else
                warning "Maps referenced but maps.conf not found"
            fi
        fi
        
        # Check if includes are working
        local missing_includes=()
        while read -r include_file; do
            if [[ ! -f "$include_file" ]]; then
                missing_includes+=("$(basename "$include_file")")
            fi
        done < <(grep -o "include /etc/nginx/includes/[^;]*" /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | cut -d: -f2 | sed 's/include //' | sort -u)
        
        if [[ ${#missing_includes[@]} -gt 0 ]]; then
            warning "Some include files are missing: ${missing_includes[*]}"
            log "This is normal for initial setup - they may be created by other scripts"
        else
            success "All include files found"
        fi
        
    else
        error "NGINX configuration validation failed"
        log "Error details:"
        cat /tmp/nginx_test_output
        
        # Try to identify common issues
        if grep -q "maps.conf" /tmp/nginx_test_output; then
            warning "Issue with maps.conf - checking if file exists..."
            ls -la /etc/nginx/conf.d/maps.conf || warning "maps.conf not found"
        fi
        
        if grep -q "include.*not found" /tmp/nginx_test_output; then
            warning "Missing include files detected. Available files:"
            find /etc/nginx -name "*.conf" -type f | head -10
        fi
        
        if grep -q "upstream" /tmp/nginx_test_output; then
            warning "Upstream server issues detected (normal for initial setup)"
            log "Upstream servers will be available after network/Tailscale setup"
        fi
        
        rm -f /tmp/nginx_test_output
        return 1
    fi
    
    rm -f /tmp/nginx_test_output
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "NGINX setup completed successfully"
    log "NGINX is configured and ready to start after reboot"
    log "Management command: nginx-status"
    log ""
    log "Configuration summary:"
    log "  - Downloaded and processed comprehensive nginx.conf template"
    log "  - Repository conf.d files: $(ls /etc/nginx/conf.d/*.conf 2>/dev/null | wc -l) files"
    log "  - Repository includes files: $(ls /etc/nginx/includes/*.conf 2>/dev/null | wc -l) files"  
    log "  - Template section removed to prevent conflicts"
    log "  - SSL configurations commented until certificates available"
    log ""
    log "Active servers after configuration:"
    log "  - Default server: Returns 444 for undefined hosts"
    log "  - Health check: http://localhost:8080/health (monitoring)"
    log "  - Health proxy: http://localhost:8081/api/health-proxy (dashboard integration)"
    log "  - Dashboard: Will be served by default.conf configurations"
    log ""
    log "Next steps:"
    log "  - Tailscale will connect after reboot"
    log "  - SSL certificates will be configured"
    log "  - Full service routing will be activated via default.conf"
}

# Execute main function
main "$@"