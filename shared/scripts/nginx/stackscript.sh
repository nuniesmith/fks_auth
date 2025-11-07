#!/bin/bash

# Linode StackScript: NGINX Server with Tailscale, SSL/TLS, Cloudflare DNS, and GitHub Actions Integration
# This script sets up NGINX server with Tailscale-only access, SSL certificates, automatic DNS updates, and GitHub Actions deployment
# Repository: https://github.com/nuniesmith/nginx.git

# StackScript UDF (User Defined Fields)
# <UDF name="tailscale_auth_key" label="Tailscale Auth Key (REQUIRED)" example="tskey-auth-..." />
# <UDF name="hostname" label="Server Hostname" default="nginx" example="my-nginx-server" />
# <UDF name="timezone" label="Timezone" default="UTC" example="America/New_York" />
# <UDF name="ssh_key" label="SSH Public Key (optional)" />
# <UDF name="domain_name" label="Domain Name" default="7gram.xyz" example="yourdomain.com" />
# <UDF name="ssl_email" label="SSL Certificate Email" default="admin@7gram.xyz" example="admin@yourdomain.com" />
# <UDF name="enable_ssl" label="Enable SSL Certificates" default="true" oneof="true,false" />
# <UDF name="ssl_staging" label="Use SSL Staging Environment (for testing)" default="false" oneof="true,false" />
# <UDF name="cloudflare_api_token" label="Cloudflare API Token (for DNS updates)" />
# <UDF name="cloudflare_zone_id" label="Cloudflare Zone ID" />
# <UDF name="update_dns" label="Automatically update DNS records" default="true" oneof="true,false" />
# <UDF name="github_repo" label="GitHub Repository (owner/repo)" default="nuniesmith/nginx" example="username/repo-name" />
# <UDF name="github_token" label="GitHub Personal Access Token (for deploy key)" />
# <UDF name="enable_github_actions" label="Setup GitHub Actions Integration" default="true" oneof="true,false" />

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Validate required parameters
if [ -z "$TAILSCALE_AUTH_KEY" ]; then
    error "Tailscale Auth Key is required!"
    exit 1
fi

# Set defaults
HOSTNAME=${HOSTNAME:-"nginx"}
DOMAIN_NAME=${DOMAIN_NAME:-"7gram.xyz"}
SSL_EMAIL=${SSL_EMAIL:-"admin@7gram.xyz"}
ENABLE_SSL=${ENABLE_SSL:-"true"}
SSL_STAGING=${SSL_STAGING:-"false"}
UPDATE_DNS=${UPDATE_DNS:-"true"}
GITHUB_REPO=${GITHUB_REPO:-"nuniesmith/nginx"}
ENABLE_GITHUB_ACTIONS=${ENABLE_GITHUB_ACTIONS:-"true"}

log "Starting Enhanced NGINX + Tailscale + SSL + GitHub Actions Setup on Arch Linux"
log "PHASE 1: System preparation and package installation"
log "Hostname: $HOSTNAME"
log "Domain: $DOMAIN_NAME"
log "SSL Enabled: $ENABLE_SSL"
log "SSL Staging: $SSL_STAGING"
log "DNS Updates: $UPDATE_DNS"
log "GitHub Actions: $ENABLE_GITHUB_ACTIONS"
log "GitHub Repo: $GITHUB_REPO"
echo "=============================================="

# =============================================================================
# GITHUB ACTIONS USER AND SSH KEY SETUP
# =============================================================================

if [ "$ENABLE_GITHUB_ACTIONS" = "true" ]; then
    log "Setting up GitHub Actions deployment user and SSH keys..."
    
    # Create github-deploy user
    useradd -m -s /bin/bash github-deploy 2>/dev/null || log "User github-deploy already exists"
    usermod -aG wheel github-deploy
    
    # Create SSH directory for github-deploy user
    mkdir -p /home/github-deploy/.ssh
    chown github-deploy:github-deploy /home/github-deploy/.ssh
    chmod 700 /home/github-deploy/.ssh
    
    # Generate SSH key pair for GitHub Actions
    log "Generating SSH key pair for GitHub Actions..."
    sudo -u github-deploy ssh-keygen -t ed25519 -C "actions_user@$DOMAIN_NAME" -f /home/github-deploy/.ssh/github_deploy -N ""
    
    # Set proper permissions
    chown github-deploy:github-deploy /home/github-deploy/.ssh/github_deploy*
    chmod 600 /home/github-deploy/.ssh/github_deploy
    chmod 644 /home/github-deploy/.ssh/github_deploy.pub
    
    # Add public key to authorized_keys
    cat /home/github-deploy/.ssh/github_deploy.pub > /home/github-deploy/.ssh/authorized_keys
    chown github-deploy:github-deploy /home/github-deploy/.ssh/authorized_keys
    chmod 600 /home/github-deploy/.ssh/authorized_keys
    
    # Create sudo rules for GitHub Actions deployment
    cat > /etc/sudoers.d/github-deploy << 'EOF'
# Allow github-deploy to manage nginx and deployment without password
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl status nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/nginx
github-deploy ALL=(ALL) NOPASSWD: /bin/cp * /etc/nginx/*
github-deploy ALL=(ALL) NOPASSWD: /bin/mkdir -p /etc/nginx/*
github-deploy ALL=(ALL) NOPASSWD: /bin/chown -R * /var/www/html
github-deploy ALL=(ALL) NOPASSWD: /bin/chmod -R * /var/www/html
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/find /var/www/html -type d -exec chmod 755 {} \;
github-deploy ALL=(ALL) NOPASSWD: /bin/rm -rf /opt/nginx-deployment/*
github-deploy ALL=(ALL) NOPASSWD: /bin/rm -rf /opt/nginx-backups/*
EOF
    
    chmod 440 /etc/sudoers.d/github-deploy
    
    # Create deployment directories
    mkdir -p /opt/nginx-deployment /opt/nginx-backups
    chown -R github-deploy:github-deploy /opt/nginx-deployment /opt/nginx-backups
    chmod 755 /opt/nginx-deployment /opt/nginx-backups
    
    success "GitHub Actions user and SSH keys created"
    
    # Store public key for later use
    GITHUB_DEPLOY_PUBLIC_KEY=$(cat /home/github-deploy/.ssh/github_deploy.pub)
    GITHUB_DEPLOY_PRIVATE_KEY=$(cat /home/github-deploy/.ssh/github_deploy)
    
    info "GitHub deploy public key: $GITHUB_DEPLOY_PUBLIC_KEY"
fi

# =============================================================================
# SYSTEM UPDATE AND ESSENTIAL PACKAGES
# =============================================================================

log "Updating Arch Linux system..."

# Initialize pacman keyring
pacman-key --init
pacman-key --populate archlinux

# Update mirror list for better performance
log "Updating mirror list..."
pacman -S --noconfirm reflector
reflector --latest 10 --sort rate --save /etc/pacman.d/mirrorlist --protocol https

# Full system update
log "Performing full system update..."
pacman -Syyu --noconfirm

# Install essential packages including SSL tools and DNS utilities
log "Installing essential packages..."
pacman -S --needed --noconfirm \
    base-devel \
    git \
    nginx \
    curl \
    wget \
    vim \
    ufw \
    tree \
    certbot \
    certbot-nginx \
    cronie \
    openssl \
    jq \
    python-pip \
    python-setuptools \
    python-wheel \
    bind

success "System updated and essential packages installed"

# =============================================================================
# INSTALL YAY AUR HELPER
# =============================================================================

log "Installing yay AUR helper..."

# Create builder user for AUR
if ! id "builder" &>/dev/null; then
    useradd -m -G wheel builder
    echo "builder ALL=(ALL) NOPASSWD: /usr/bin/pacman, /usr/bin/makepkg, /usr/bin/yay" >> /etc/sudoers
    echo "builder:$(openssl rand -base64 32)" | chpasswd
fi

# Build and install yay
su - builder -c "
    cd /tmp
    rm -rf yay
    git clone https://aur.archlinux.org/yay.git
    cd yay
    makepkg -si --noconfirm
"

success "yay AUR helper installed"

# =============================================================================
# INSTALL CLOUDFLARE CERTBOT PLUGIN (PRE-REBOOT)
# =============================================================================

if [ "$ENABLE_SSL" = "true" ]; then
    log "Installing Cloudflare certbot plugin..."
    
    # Install via pip (more reliable than AUR for certbot plugins)
    pip install --break-system-packages certbot-dns-cloudflare
    
    success "Cloudflare certbot plugin installed"
fi

# =============================================================================
# INSTALL TAILSCALE (BUT DON'T CONNECT YET)
# =============================================================================

log "Installing Tailscale (connection will happen after reboot)..."

curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable tailscaled

success "Tailscale installed and enabled (will connect after reboot)"

# =============================================================================
# SET TIMEZONE AND HOSTNAME
# =============================================================================

if [ -n "$TIMEZONE" ]; then
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE"
fi

log "Setting hostname to $HOSTNAME..."
hostnamectl set-hostname "$HOSTNAME"
echo "127.0.0.1 $HOSTNAME" >> /etc/hosts

# =============================================================================
# GITHUB API INTEGRATION FUNCTION
# =============================================================================

if [ "$ENABLE_GITHUB_ACTIONS" = "true" ]; then
    log "Creating GitHub API integration script..."
    
    cat > /usr/local/bin/github-deploy-key << 'EOF'
#!/bin/bash

# GitHub Deploy Key Management Script
GITHUB_TOKEN="$1"
GITHUB_REPO="$2"
PUBLIC_KEY="$3"
KEY_TITLE="$4"

if [ -z "$GITHUB_TOKEN" ] || [ -z "$GITHUB_REPO" ] || [ -z "$PUBLIC_KEY" ]; then
    echo "Usage: $0 <github_token> <repo> <public_key> [title]"
    echo "Example: $0 ghp_xxx... owner/repo 'ssh-ed25519 AAAA...' 'Deploy Key'"
    exit 1
fi

KEY_TITLE=${KEY_TITLE:-"Linode Deploy Key - $(date +%Y%m%d)"}

# GitHub API endpoint
API_URL="https://api.github.com/repos/$GITHUB_REPO/keys"

# Create deploy key
response=$(curl -s -X POST "$API_URL" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -d "{
    \"title\": \"$KEY_TITLE\",
    \"key\": \"$PUBLIC_KEY\",
    \"read_only\": false
  }")

# Check if successful
if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
    echo "Deploy key added successfully to $GITHUB_REPO"
    echo "Key ID: $(echo "$response" | jq -r '.id')"
    echo "Key Title: $(echo "$response" | jq -r '.title')"
    exit 0
else
    echo "Failed to add deploy key to $GITHUB_REPO"
    echo "Response: $response"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/github-deploy-key
    success "GitHub API integration script created"
fi

# =============================================================================
# PREPARE POST-REBOOT CONTINUATION SCRIPT
# =============================================================================

log "Creating post-reboot continuation script..."

cat > /root/post-reboot-setup.sh << 'EOFPOSTSETUP'
#!/bin/bash

# Post-reboot continuation script
# PHASE 2: Tailscale connection, DNS updates, file deployment, SSL setup, NGINX start, GitHub integration

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

echo "=============================================="
log "PHASE 2: Post-reboot setup starting..."
log "Tailscale connection -> DNS updates -> File deployment -> SSL -> NGINX -> GitHub Integration"
echo "=============================================="

# Wait for system to fully boot
sleep 15

# =============================================================================
# STEP 1: CONNECT TO TAILSCALE
# =============================================================================

log "STEP 1: Connecting to Tailscale network..."

RETRY_COUNT=0
MAX_RETRIES=5

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if tailscale up --authkey="TAILSCALE_AUTH_KEY_PLACEHOLDER" --accept-routes; then
        success "Successfully connected to Tailscale"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        warning "Tailscale connection attempt $RETRY_COUNT failed, retrying in 15 seconds..."
        sleep 15
        
        if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
            error "Failed to connect to Tailscale after $MAX_RETRIES attempts"
            systemctl status tailscaled --no-pager
            journalctl -u tailscaled --no-pager -n 20
            exit 1
        fi
    fi
done

# =============================================================================
# STEP 2: GET TAILSCALE IP
# =============================================================================

log "STEP 2: Getting Tailscale IP address..."
sleep 10

TAILSCALE_IP=""
IP_RETRY_COUNT=0
MAX_IP_RETRIES=20

while [ $IP_RETRY_COUNT -lt $MAX_IP_RETRIES ] && [ -z "$TAILSCALE_IP" ]; do
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | head -n1)
    if [ -n "$TAILSCALE_IP" ]; then
        break
    else
        IP_RETRY_COUNT=$((IP_RETRY_COUNT + 1))
        log "Waiting for Tailscale IP... attempt $IP_RETRY_COUNT/$MAX_IP_RETRIES"
        sleep 5
    fi
done

if [ -z "$TAILSCALE_IP" ]; then
    error "Could not retrieve Tailscale IP after $MAX_IP_RETRIES attempts"
    error "Manual intervention required"
    exit 1
else
    success "Tailscale IP obtained: $TAILSCALE_IP"
fi

# Get public IP for GitHub Actions access
PUBLIC_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || curl -s icanhazip.com)
if [ -n "$PUBLIC_IP" ]; then
    success "Public IP obtained: $PUBLIC_IP"
else
    warning "Could not determine public IP"
    PUBLIC_IP="UNKNOWN"
fi

# =============================================================================
# STEP 3: UPDATE CLOUDFLARE DNS RECORDS
# =============================================================================

if [ "UPDATE_DNS_PLACEHOLDER" = "true" ] && [ -n "CLOUDFLARE_API_TOKEN_PLACEHOLDER" ] && [ -n "CLOUDFLARE_ZONE_ID_PLACEHOLDER" ]; then
    log "STEP 3: Updating Cloudflare DNS records..."
    log "Changing DNS records to point to Tailscale IP: $TAILSCALE_IP"
    
    # Create the DNS update script
    cat > /usr/local/bin/update-cloudflare-dns << 'EOFDNS'
#!/bin/bash

API_TOKEN="CLOUDFLARE_API_TOKEN_PLACEHOLDER"
ZONE_ID="CLOUDFLARE_ZONE_ID_PLACEHOLDER"
DOMAIN="DOMAIN_NAME_PLACEHOLDER"

# Update DNS record
update_dns_record() {
    local record_name="$1"
    local ip_address="$2"
    local record_type="${3:-A}"
    
    echo "Updating $record_name.$DOMAIN to $ip_address..."
    
    # Get existing record ID
    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$record_name.$DOMAIN&type=$record_type" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    
    local response
    if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
        # Update existing record
        response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$ip_address\",\"ttl\":3600}")
    else
        # Create new record
        response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$ip_address\",\"ttl\":3600}")
    fi
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        echo "Updated $record_name.$DOMAIN"
        return 0
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        echo "Failed to update $record_name.$DOMAIN: $errors"
        return 1
    fi
}

# Main function
main() {
    local ip_address="$1"
    
    if [ -z "$ip_address" ]; then
        echo "Usage: $0 <ip_address>"
        exit 1
    fi
    
    echo "Updating all DNS records to $ip_address..."
    
    # All subdomains from your zone file
    local subdomains=(
        "@" "www" "nginx" "sullivan" "freddy" "auth" "emby" "jellyfin" "plex"
        "music" "youtube" "nc" "abs" "calibre" "calibreweb" "mealie" "grocy"
        "wiki" "ai" "chat" "ollama" "sd" "comfy" "whisper" "code" "sonarr"
        "radarr" "lidarr" "audiobooks" "ebooks" "jackett" "qbt" "filebot"
        "duplicati" "home" "pihole" "dns" "grafana" "prometheus"
        "uptime" "watchtower" "portainer" "portainer-freddy" "portainer-sullivan"
        "sync-freddy" "sync-sullivan" "sync-desktop" "sync-oryx" "mail"
        "smtp" "imap" "api" "status" "vpn" "remote"
    )
    
    local updated=0
    local failed=0
    
    for subdomain in "${subdomains[@]}"; do
        if update_dns_record "$subdomain" "$ip_address"; then
            updated=$((updated + 1))
        else
            failed=$((failed + 1))
        fi
        sleep 0.5  # Rate limiting
    done
    
    echo ""
    echo "DNS update completed: $updated updated, $failed failed"
    
    if [ $failed -eq 0 ]; then
        echo "All DNS records updated successfully!"
        return 0
    else
        echo "Some DNS updates failed"
        return 1
    fi
}

main "$@"
EOFDNS

    # Replace placeholders in DNS script
    sed -i "s/CLOUDFLARE_API_TOKEN_PLACEHOLDER/$CLOUDFLARE_API_TOKEN_PLACEHOLDER/g" /usr/local/bin/update-cloudflare-dns
    sed -i "s/CLOUDFLARE_ZONE_ID_PLACEHOLDER/$CLOUDFLARE_ZONE_ID_PLACEHOLDER/g" /usr/local/bin/update-cloudflare-dns
    sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME_PLACEHOLDER/g" /usr/local/bin/update-cloudflare-dns
    
    chmod +x /usr/local/bin/update-cloudflare-dns
    
    # Run DNS update with Tailscale IP
    if /usr/local/bin/update-cloudflare-dns "$TAILSCALE_IP"; then
        success "DNS records updated successfully"
        info "All subdomains now point to: $TAILSCALE_IP"
    else
        warning "Some DNS updates failed - continuing anyway"
    fi
    
    # Wait for DNS propagation
    log "Waiting 30 seconds for DNS propagation..."
    sleep 30
else
    warning "DNS updates skipped (not configured or disabled)"
fi

# =============================================================================
# STEP 4: CLONE AND DEPLOY NGINX REPOSITORY
# =============================================================================

log "STEP 4: Cloning and deploying NGINX repository..."

NGINX_PATH="/opt/nginx-docker"
mkdir -p "$NGINX_PATH"
cd "$NGINX_PATH"

if git clone https://github.com/GITHUB_REPO_PLACEHOLDER.git .; then
    success "Repository cloned successfully"
else
    error "Failed to clone repository"
    exit 1
fi

# Deploy website files
log "Deploying website files..."

# Create web directory
mkdir -p /var/www/html

# Deploy files based on repository structure
if [ -d "config/nginx/html" ]; then
    log "Found config/nginx/html directory, deploying..."
    cp -r config/nginx/html/* /var/www/html/
elif [ -d "html" ]; then
    log "Found html directory, deploying..."
    cp -r html/* /var/www/html/
elif [ -d "public" ]; then
    log "Found public directory, deploying..."
    cp -r public/* /var/www/html/
else
    # Create default page
    log "No web files found, creating default page..."
    cat > /var/www/html/index.html << 'EOFHTML'
<!DOCTYPE html>
<html>
<head>
    <title>NGINX with SSL on Tailscale</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: rgba(255, 255, 255, 0.95); padding: 3rem; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); text-align: center; max-width: 800px; }
        h1 { color: #333; font-size: 2.5rem; margin-bottom: 1rem; }
        .status { background: #4CAF50; color: white; padding: 15px; border-radius: 10px; margin: 20px 0; font-weight: 600; }
        .info { background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 15px 0; text-align: left; border-left: 4px solid #667eea; }
        .github-info { background: #24292e; color: white; padding: 20px; border-radius: 10px; margin: 15px 0; }
        .ssh-key { background: #f6f8fa; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; word-break: break-all; border: 1px solid #e1e4e8; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>NGINX Server Ready!</h1>
        <div class="status">Server is running on Tailscale network with SSL support</div>
        <div class="info">
            <h3>Services Available</h3>
            <p>This server hosts 40+ services including Plex, Jellyfin, Home Assistant, and more.</p>
            <p><strong>Access:</strong> Via Tailscale network only</p>
            <p><strong>Domain:</strong> DOMAIN_NAME_PLACEHOLDER</p>
            <p><strong>Tailscale IP:</strong> TAILSCALE_IP_PLACEHOLDER</p>
            <p><strong>Public IP:</strong> PUBLIC_IP_PLACEHOLDER</p>
        </div>
        <div class="github-info">
            <h3>GitHub Actions Ready</h3>
            <p><strong>Repository:</strong> GITHUB_REPO_PLACEHOLDER</p>
            <p><strong>Deploy User:</strong> github-deploy</p>
            <p><strong>Deploy Key:</strong> DEPLOY_KEY_STATUS_PLACEHOLDER</p>
        </div>
    </div>
</body>
</html>
EOFHTML
fi

# Replace placeholders in HTML
sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME_PLACEHOLDER/g" /var/www/html/index.html
sed -i "s/TAILSCALE_IP_PLACEHOLDER/$TAILSCALE_IP/g" /var/www/html/index.html
sed -i "s/PUBLIC_IP_PLACEHOLDER/$PUBLIC_IP/g" /var/www/html/index.html
sed -i "s/GITHUB_REPO_PLACEHOLDER/$GITHUB_REPO_PLACEHOLDER/g" /var/www/html/index.html

# Set permissions
chown -R http:http /var/www/html
chmod -R 755 /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;

success "Website files deployed"

# =============================================================================
# STEP 5: SETUP SSL DIRECTORIES AND CONFIGURATION
# =============================================================================

log "STEP 5: Setting up SSL directories and configuration..."

# Create SSL directories
mkdir -p /etc/letsencrypt
mkdir -p /var/www/certbot
mkdir -p /etc/nginx/ssl
mkdir -p /var/log/letsencrypt

# Set proper permissions
chmod 755 /var/www/certbot
chmod 700 /etc/nginx/ssl

# Create Cloudflare credentials file if SSL is enabled
if [ "ENABLE_SSL_PLACEHOLDER" = "true" ] && [ -n "CLOUDFLARE_API_TOKEN_PLACEHOLDER" ]; then
    log "Creating Cloudflare credentials file for SSL..."
    cat > /etc/letsencrypt/cloudflare.ini << EOF
dns_cloudflare_api_token = CLOUDFLARE_API_TOKEN_PLACEHOLDER
EOF
    chmod 600 /etc/letsencrypt/cloudflare.ini
    success "Cloudflare credentials configured"
fi

# Generate self-signed certificates for initial NGINX start
log "Creating self-signed certificates for initial setup..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/privkey.pem \
    -out /etc/nginx/ssl/fullchain.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=DOMAIN_NAME_PLACEHOLDER"

# Generate DH parameters
log "Generating DH parameters..."
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048

success "SSL directories and initial certificates created"

# =============================================================================
# STEP 6: SETUP NGINX CONFIGURATION
# =============================================================================

log "STEP 6: Setting up NGINX configuration..."

# Create nginx directories
mkdir -p /etc/nginx/{sites-available,sites-enabled,conf.d,ssl}

# Deploy nginx configuration from repository if available
if [ -d "config/nginx" ]; then
    log "Deploying nginx configuration from repository..."
    
    # Copy configuration files
    if [ -d "config/nginx/conf.d" ]; then
        cp -r config/nginx/conf.d/* /etc/nginx/conf.d/
        success "Configuration files deployed from repository"
    fi
    
    if [ -d "config/nginx/includes" ]; then
        mkdir -p /etc/nginx/includes
        cp -r config/nginx/includes/* /etc/nginx/includes/
        success "Include files deployed from repository"
    fi
    
    if [ -f "config/nginx/nginx.conf" ]; then
        cp config/nginx/nginx.conf /etc/nginx/nginx.conf
        success "Main nginx.conf deployed from repository"
    fi
    
    # Replace domain placeholders in all config files
    find /etc/nginx -name "*.conf" -type f -exec sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME_PLACEHOLDER/g" {} \;
    
else
    log "No repository nginx config found, creating basic configuration..."
    
    # Create basic nginx.conf
    cat > /etc/nginx/nginx.conf << 'EOFNGINX'
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

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 75s;
    types_hash_max_size 2048;
    types_hash_bucket_size 64;
    server_tokens off;
    client_max_body_size 10G;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/conf.d/*.conf;
}
EOFNGINX

    # Create default server configuration
    if [ "ENABLE_SSL_PLACEHOLDER" = "true" ]; then
        cat > /etc/nginx/sites-available/default << 'EOFDEFAULT'
# HTTP server - redirect to HTTPS (except ACME challenges)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name DOMAIN_NAME_PLACEHOLDER _;
    
    # Only allow Tailscale network
    allow 100.64.0.0/10;
    deny all;
    
    # ACME challenge location
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }
    
    # Health check
    location = /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Redirect everything else to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name DOMAIN_NAME_PLACEHOLDER _;
    
    # Only allow Tailscale network
    allow 100.64.0.0/10;
    deny all;
    
    root /var/www/html;
    index index.html index.htm;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location = /health {
        access_log off;
        return 200 '{"status":"healthy","ssl":"enabled","timestamp":"$time_iso8601"}';
        add_header Content-Type application/json;
    }
}
EOFDEFAULT
    else
        # HTTP-only configuration
        cat > /etc/nginx/sites-available/default << 'EOFDEFAULT'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    # Only allow Tailscale network and public access for GitHub Actions
    allow 100.64.0.0/10;  # Tailscale
    allow all;            # Allow all for GitHub Actions access
    
    server_name DOMAIN_NAME_PLACEHOLDER _;
    root /var/www/html;
    index index.html index.htm;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location = /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOFDEFAULT
    fi

    # Replace domain placeholder
    sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME_PLACEHOLDER/g" /etc/nginx/sites-available/default

    # Enable the default site
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
fi

# Test nginx configuration
if nginx -t; then
    success "NGINX configuration test passed"
else
    error "NGINX configuration test failed"
    nginx -t
    exit 1
fi

# =============================================================================
# STEP 7: GET SSL CERTIFICATES (IF ENABLED)
# =============================================================================

if [ "ENABLE_SSL_PLACEHOLDER" = "true" ] && [ -n "CLOUDFLARE_API_TOKEN_PLACEHOLDER" ]; then
    log "STEP 7: Getting SSL certificates via DNS challenge..."
    
    # Determine staging flag
    STAGING_FLAG=""
    if [ "SSL_STAGING_PLACEHOLDER" = "true" ]; then
        STAGING_FLAG="--staging"
        log "Using Let's Encrypt staging environment"
    else
        log "Using Let's Encrypt production environment"
    fi
    
    # Get certificate using DNS challenge
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
        --email "SSL_EMAIL_PLACEHOLDER" \
        --agree-tos \
        --no-eff-email \
        $STAGING_FLAG \
        -d "DOMAIN_NAME_PLACEHOLDER" \
        -d "*.DOMAIN_NAME_PLACEHOLDER"; then
        
        success "SSL certificates obtained successfully!"
        
        # Update nginx configuration to use real certificates
        sed -i "s|ssl_certificate /etc/nginx/ssl/fullchain.pem;|ssl_certificate /etc/letsencrypt/live/DOMAIN_NAME_PLACEHOLDER/fullchain.pem;|g" /etc/nginx/sites-available/default
        sed -i "s|ssl_certificate_key /etc/nginx/ssl/privkey.pem;|ssl_certificate_key /etc/letsencrypt/live/DOMAIN_NAME_PLACEHOLDER/privkey.pem;|g" /etc/nginx/sites-available/default
        
        log "Updated NGINX to use real SSL certificates"
    else
        warning "Failed to get SSL certificates - using self-signed certificates"
    fi
else
    warning "SSL certificate generation skipped (disabled or no Cloudflare token)"
fi

# =============================================================================
# STEP 8: START NGINX
# =============================================================================

log "STEP 8: Starting NGINX..."

# Final configuration test
if nginx -t; then
    systemctl enable nginx
    systemctl start nginx
    
    if systemctl is-active --quiet nginx; then
        success "NGINX is running successfully!"
    else
        error "Failed to start NGINX"
        systemctl status nginx --no-pager
        exit 1
    fi
else
    error "NGINX configuration test failed - cannot start"
    nginx -t
    exit 1
fi

# =============================================================================
# STEP 9: SETUP FIREWALL
# =============================================================================

log "STEP 9: Configuring firewall..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow ssh
log "SSH access allowed"

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow Tailscale traffic
ufw allow in on tailscale0

# Setup SSH key if provided
if [ -n "SSH_KEY_PLACEHOLDER" ] && [ "SSH_KEY_PLACEHOLDER" != "" ]; then
    # Setup SSH key for root
    mkdir -p /root/.ssh
    echo "SSH_KEY_PLACEHOLDER" >> /root/.ssh/authorized_keys
    chmod 700 /root/.ssh
    chmod 600 /root/.ssh/authorized_keys
    success "SSH key configured for root"
fi

ufw --force enable

success "Firewall configured"

# =============================================================================
# STEP 10: GITHUB ACTIONS INTEGRATION
# =============================================================================

if [ "ENABLE_GITHUB_ACTIONS_PLACEHOLDER" = "true" ]; then
    log "STEP 10: Setting up GitHub Actions integration..."
    
    # Get the deploy key
    DEPLOY_PUBLIC_KEY=$(cat /home/github-deploy/.ssh/github_deploy.pub)
    DEPLOY_PRIVATE_KEY=$(cat /home/github-deploy/.ssh/github_deploy)
    
    # Try to add deploy key to GitHub repository if token is provided
    if [ -n "GITHUB_TOKEN_PLACEHOLDER" ] && [ "GITHUB_TOKEN_PLACEHOLDER" != "" ]; then
        log "Adding deploy key to GitHub repository..."
        
        if /usr/local/bin/github-deploy-key "GITHUB_TOKEN_PLACEHOLDER" "GITHUB_REPO_PLACEHOLDER" "$DEPLOY_PUBLIC_KEY" "Linode Auto-Deploy Key - $(date +%Y%m%d)"; then
            success "Deploy key added to GitHub repository automatically!"
            DEPLOY_KEY_STATUS="Automatically added"
        else
            warning "Failed to add deploy key automatically"
            DEPLOY_KEY_STATUS="Manual addition required"
        fi
    else
        warning "No GitHub token provided - deploy key must be added manually"
        DEPLOY_KEY_STATUS="Manual addition required"
    fi
    
    # Update HTML with deploy key status
    if [ -f "/var/www/html/index.html" ]; then
        sed -i "s/DEPLOY_KEY_STATUS_PLACEHOLDER/$DEPLOY_KEY_STATUS/g" /var/www/html/index.html
    fi
    
    # Create deployment info file
    cat > /opt/nginx-deployment/deployment-info.txt << EOF
=== GitHub Actions Deployment Information ===
Generated: $(date)

Server Information:
- Hostname: HOSTNAME_PLACEHOLDER
- Domain: DOMAIN_NAME_PLACEHOLDER
- Tailscale IP: $TAILSCALE_IP
- Public IP: $PUBLIC_IP

GitHub Repository: GITHUB_REPO_PLACEHOLDER
Deploy User: github-deploy
Deploy Key Status: $DEPLOY_KEY_STATUS

GitHub Repository Secrets to Add:
1. SSH_PRIVATE_KEY:
$DEPLOY_PRIVATE_KEY

2. SSH_USER: github-deploy

3. SSH_HOST: $PUBLIC_IP

Deploy Key (if manual addition needed):
$DEPLOY_PUBLIC_KEY

Instructions:
1. Add the above secrets to your GitHub repository:
   Go to: https://github.com/GITHUB_REPO_PLACEHOLDER/settings/secrets/actions
2. Copy the GitHub Actions workflow to .github/workflows/deploy-nginx.yml
3. Copy the deployment script to scripts/deploy.sh
4. Push changes to trigger deployment

Test SSH Connection:
ssh -i <private_key_file> github-deploy@$PUBLIC_IP "nginx -t"
EOF
    
    # Replace placeholders
    sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME_PLACEHOLDER/g" /opt/nginx-deployment/deployment-info.txt
    sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME_PLACEHOLDER/g" /opt/nginx-deployment/deployment-info.txt
    sed -i "s/GITHUB_REPO_PLACEHOLDER/$GITHUB_REPO_PLACEHOLDER/g" /opt/nginx-deployment/deployment-info.txt
    
    chmod 644 /opt/nginx-deployment/deployment-info.txt
    chown github-deploy:github-deploy /opt/nginx-deployment/deployment-info.txt
    
    success "GitHub Actions integration configured"
    info "Deployment information saved to: /opt/nginx-deployment/deployment-info.txt"
fi

# =============================================================================
# STEP 11: SETUP AUTOMATIC CERTIFICATE RENEWAL
# =============================================================================

if [ "ENABLE_SSL_PLACEHOLDER" = "true" ]; then
    log "STEP 11: Setting up automatic certificate renewal..."
    
    systemctl enable cronie
    systemctl start cronie
    
    # Create renewal script
    cat > /usr/local/bin/ssl-renew << 'EOFRENEWAL'
#!/bin/bash
LOG_FILE="/var/log/ssl-renewal.log"
echo "$(date): Starting certificate renewal check..." >> "$LOG_FILE"

if certbot renew --quiet --no-self-upgrade >> "$LOG_FILE" 2>&1; then
    echo "$(date): Certificate renewal check completed successfully" >> "$LOG_FILE"
    if nginx -t >> "$LOG_FILE" 2>&1; then
        systemctl reload nginx
        echo "$(date): NGINX reloaded successfully" >> "$LOG_FILE"
    fi
else
    echo "$(date): Certificate renewal failed" >> "$LOG_FILE"
fi
EOFRENEWAL
    
    chmod +x /usr/local/bin/ssl-renew
    
    # Add cron job for automatic renewal (twice daily)
    echo "0 */12 * * * /usr/local/bin/ssl-renew" | crontab -
    
    success "Automatic certificate renewal configured"
fi

# =============================================================================
# FINAL SETUP AND CLEANUP - CREATE MANAGEMENT SCRIPTS
# =============================================================================

log "Creating management scripts..."

# Create github-status script
cat > /usr/local/bin/github-status << 'EOFGITHUBSTATUS'
#!/bin/bash
echo "=== GitHub Actions Status ==="
echo "Deploy User: github-deploy"
echo "Deploy User Home: /home/github-deploy"
echo "Deployment Path: /opt/nginx-deployment"
echo ""

echo "SSH Key Status:"
if [ -f "/home/github-deploy/.ssh/github_deploy.pub" ]; then
    echo "SSH keys exist"
    echo "Public Key:"
    cat /home/github-deploy/.ssh/github_deploy.pub
else
    echo "SSH keys not found"
fi

echo ""
echo "Sudo Permissions:"
sudo -l -U github-deploy 2>/dev/null || echo "No sudo permissions found"

echo ""
echo "Deployment Info:"
if [ -f "/opt/nginx-deployment/deployment-info.txt" ]; then
    cat /opt/nginx-deployment/deployment-info.txt
else
    echo "No deployment info file found"
fi
EOFGITHUBSTATUS

chmod +x /usr/local/bin/github-status

echo ""
echo "=================================================="
success "SETUP COMPLETE!"
echo "=================================================="
echo ""
info "Server Information:"
echo "  Hostname: HOSTNAME_PLACEHOLDER"
echo "  Domain: DOMAIN_NAME_PLACEHOLDER"
echo "  Tailscale IP: $TAILSCALE_IP"
echo "  Public IP: $PUBLIC_IP"
echo "  NGINX Status: $(systemctl is-active nginx)"
echo ""

if [ "ENABLE_SSL_PLACEHOLDER" = "true" ]; then
    info "Access URLs:"
    echo "  HTTPS: https://DOMAIN_NAME_PLACEHOLDER/"
    echo "  HTTP (redirects): http://$TAILSCALE_IP/"
else
    info "Access URL:"
    echo "  HTTP: http://$TAILSCALE_IP/"
fi

echo ""
if [ "ENABLE_GITHUB_ACTIONS_PLACEHOLDER" = "true" ]; then
    info "GitHub Actions Integration:"
    echo "  Repository: GITHUB_REPO_PLACEHOLDER"
    echo "  Deploy User: github-deploy"
    echo "  Deploy Key Status: $DEPLOY_KEY_STATUS"
    echo "  SSH Command: ssh github-deploy@$PUBLIC_IP"
    echo ""
    echo "Next Steps for GitHub Actions:"
    echo "1. Add secrets to GitHub repository (see deployment-info.txt)"
    echo "2. Add workflow file to .github/workflows/deploy-nginx.yml"
    echo "3. Add deployment script to scripts/deploy.sh"
    echo "4. Push to repository to trigger deployment"
    echo ""
fi

info "Management Commands:"
echo "  nginx-status              - Check server status"
echo "  github-status             - Check GitHub Actions status"
echo "  ssl-status                - Check SSL status"
echo "  ssl-setup                 - Setup SSL certificates"
echo "  ssl-renew                 - Renew certificates"
echo "  update-cloudflare-dns IP  - Update DNS records"

echo ""
success "Your NGINX server with GitHub Actions is ready!"

# Clean up setup files
log "Cleaning up setup files..."
systemctl disable post-reboot-setup.service 2>/dev/null || true
rm -f /etc/systemd/system/post-reboot-setup.service
rm -f /root/post-reboot-setup.sh
systemctl daemon-reload

log "Setup completed successfully!"
EOFPOSTSETUP

# Replace all placeholders in the post-reboot script
sed -i "s/TAILSCALE_AUTH_KEY_PLACEHOLDER/$TAILSCALE_AUTH_KEY/g" /root/post-reboot-setup.sh
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /root/post-reboot-setup.sh
sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME/g" /root/post-reboot-setup.sh
sed -i "s/SSL_EMAIL_PLACEHOLDER/$SSL_EMAIL/g" /root/post-reboot-setup.sh
sed -i "s/ENABLE_SSL_PLACEHOLDER/$ENABLE_SSL/g" /root/post-reboot-setup.sh
sed -i "s/SSL_STAGING_PLACEHOLDER/$SSL_STAGING/g" /root/post-reboot-setup.sh
sed -i "s/UPDATE_DNS_PLACEHOLDER/$UPDATE_DNS/g" /root/post-reboot-setup.sh
sed -i "s/ENABLE_GITHUB_ACTIONS_PLACEHOLDER/$ENABLE_GITHUB_ACTIONS/g" /root/post-reboot-setup.sh
sed -i "s|GITHUB_REPO_PLACEHOLDER|$GITHUB_REPO|g" /root/post-reboot-setup.sh

if [ -n "$CLOUDFLARE_API_TOKEN" ]; then
    sed -i "s/CLOUDFLARE_API_TOKEN_PLACEHOLDER/$CLOUDFLARE_API_TOKEN/g" /root/post-reboot-setup.sh
else
    sed -i "s/CLOUDFLARE_API_TOKEN_PLACEHOLDER//g" /root/post-reboot-setup.sh
fi

if [ -n "$CLOUDFLARE_ZONE_ID" ]; then
    sed -i "s/CLOUDFLARE_ZONE_ID_PLACEHOLDER/$CLOUDFLARE_ZONE_ID/g" /root/post-reboot-setup.sh
else
    sed -i "s/CLOUDFLARE_ZONE_ID_PLACEHOLDER//g" /root/post-reboot-setup.sh
fi

if [ -n "$SSH_KEY" ]; then
    sed -i "s|SSH_KEY_PLACEHOLDER|$SSH_KEY|g" /root/post-reboot-setup.sh
else
    sed -i "s/SSH_KEY_PLACEHOLDER//g" /root/post-reboot-setup.sh
fi

if [ -n "$GITHUB_TOKEN" ]; then
    sed -i "s/GITHUB_TOKEN_PLACEHOLDER/$GITHUB_TOKEN/g" /root/post-reboot-setup.sh
else
    sed -i "s/GITHUB_TOKEN_PLACEHOLDER//g" /root/post-reboot-setup.sh
fi

chmod +x /root/post-reboot-setup.sh

# Create systemd service for post-reboot execution
cat > /etc/systemd/system/post-reboot-setup.service << 'EOFSERVICE'
[Unit]
Description=Post-reboot NGINX Tailscale SSL GitHub Setup
After=multi-user.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/post-reboot-setup.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSERVICE

systemctl enable post-reboot-setup.service

echo ""
echo "=================================================="
success "PHASE 1 COMPLETE - SYSTEM WILL REBOOT"
echo "=================================================="
echo ""
log "What happens next:"
echo "1. System packages installed and updated"
echo "2. Tailscale installed (not connected yet)"
echo "3. SSL tools and dependencies ready"
if [ "$ENABLE_GITHUB_ACTIONS" = "true" ]; then
    echo "4. GitHub deploy user and SSH keys created"
    echo "5. GitHub API integration configured"
fi
echo "6. System will reboot in 10 seconds..."
echo "7. After reboot: Tailscale -> DNS -> Files -> SSL -> NGINX -> GitHub"
echo ""
warning "The setup will continue automatically after reboot"
info "Monitor progress with: journalctl -u post-reboot-setup -f"

if [ "$ENABLE_GITHUB_ACTIONS" = "true" ]; then
    echo ""
    info "GitHub Actions Information:"
    echo "SSH Public Key: $GITHUB_DEPLOY_PUBLIC_KEY"
    echo "This will be added to your repository automatically if GitHub token is provided"
fi

echo ""

# Countdown
for i in {10..1}; do
    echo -ne "\rRebooting in $i seconds... "
    sleep 1
done
echo -e "\nRebooting now!"

reboot