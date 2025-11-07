#!/bin/bash
# upgrade-to-letsencrypt.sh - Upgrade from self-signed to Let's Encrypt certificates
# Run this script after the initial deployment is working with self-signed certs

set -euo pipefail

echo "🔒 Upgrading from self-signed to Let's Encrypt certificates..."

# Check if we're running as root or with sudo
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root or with sudo" 
   exit 1
fi

# Configuration
DOMAIN="7gram.xyz"
EMAIL="${ADMIN_EMAIL:-admin@7gram.xyz}"
NGINX_CONF_DIR="/home/actions_user/nginx-app/config/nginx/conf.d"
DOCKER_COMPOSE_DIR="/home/actions_user/nginx-app"

echo "📋 Configuration:"
echo "   Domain: $DOMAIN"
echo "   Email: $EMAIL"
echo "   NGINX Config: $NGINX_CONF_DIR"
echo "   Docker Compose: $DOCKER_COMPOSE_DIR"

# Install certbot if not already installed
if ! command -v certbot &> /dev/null; then
    echo "📦 Installing certbot..."
    
    # Detect package manager and install certbot
    if command -v pacman >/dev/null 2>&1; then
        echo "🐧 Detected Arch Linux - using pacman"
        pacman -Sy --noconfirm certbot certbot-nginx
    elif command -v apt-get >/dev/null 2>&1; then
        echo "🐧 Detected Ubuntu/Debian - using apt"
        apt-get update && apt-get install -y certbot python3-certbot-nginx
    else
        echo "❌ Unsupported package manager"
        exit 1
    fi
else
    echo "✅ certbot already installed"
fi

# Stop nginx container temporarily to release port 80
echo "🛑 Temporarily stopping NGINX container..."
cd "$DOCKER_COMPOSE_DIR"
docker compose down

# Create webroot directory
mkdir -p /var/www/certbot
chown -R www-data:www-data /var/www/certbot 2>/dev/null || chown -R http:http /var/www/certbot 2>/dev/null || true

# Obtain Let's Encrypt certificate using standalone mode
echo "📜 Obtaining Let's Encrypt certificate..."
certbot certonly \
    --standalone \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    --domains "$DOMAIN,www.$DOMAIN,*.$DOMAIN" \
    --keep-until-expiring \
    --non-interactive

# Check if certificate was successfully obtained
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "❌ Let's Encrypt certificate not found!"
    echo "🔧 Falling back to self-signed certificates..."
    
    # Restart with self-signed certs
    docker compose up -d
    exit 1
fi

echo "✅ Let's Encrypt certificate obtained successfully!"

# Update NGINX configuration to use Let's Encrypt certificates
echo "🔧 Updating NGINX configuration for Let's Encrypt..."

# Backup current HTTPS config
cp "$NGINX_CONF_DIR/7gram.https.conf" "$NGINX_CONF_DIR/7gram.https.conf.backup"

# Update SSL certificate paths in NGINX config
sed -i 's|ssl_certificate /etc/nginx/ssl/fullchain.pem;|ssl_certificate /etc/letsencrypt/live/7gram.xyz/fullchain.pem;|g' "$NGINX_CONF_DIR/7gram.https.conf"
sed -i 's|ssl_certificate_key /etc/nginx/ssl/privkey.pem;|ssl_certificate_key /etc/letsencrypt/live/7gram.xyz/privkey.pem;|g' "$NGINX_CONF_DIR/7gram.https.conf"

# Update health check message
sed -i 's|return 200 "OK - HTTPS (Self-Signed)\\n";|return 200 "OK - HTTPS (Let'\''s Encrypt)\\n";|g' "$NGINX_CONF_DIR/7gram.https.conf"

# Update docker-compose to mount Let's Encrypt certificates
echo "🐳 Updating Docker Compose for Let's Encrypt..."

# Create updated docker-compose file
if [ -f "$DOCKER_COMPOSE_DIR/docker-compose-ssl.yml" ]; then
    cp "$DOCKER_COMPOSE_DIR/docker-compose-ssl.yml" "$DOCKER_COMPOSE_DIR/docker-compose-letsencrypt.yml"
else
    cp "$DOCKER_COMPOSE_DIR/docker-compose.yml" "$DOCKER_COMPOSE_DIR/docker-compose-letsencrypt.yml"
fi

# Replace self-signed SSL mount with Let's Encrypt mount
sed -i 's|- /etc/nginx/ssl:/etc/nginx/ssl:ro|- /etc/letsencrypt:/etc/letsencrypt:ro|g' "$DOCKER_COMPOSE_DIR/docker-compose-letsencrypt.yml"

# Add certbot webroot mount if not present
if ! grep -q "/var/www/certbot" "$DOCKER_COMPOSE_DIR/docker-compose-letsencrypt.yml"; then
    sed -i '/- \/etc\/letsencrypt:\/etc\/letsencrypt:ro/a\      # Certbot webroot\n      - /var/www/certbot:/var/www/certbot' "$DOCKER_COMPOSE_DIR/docker-compose-letsencrypt.yml"
fi

# Start NGINX with Let's Encrypt certificates
echo "🚀 Starting NGINX with Let's Encrypt certificates..."
docker compose up -d

# Wait for startup
sleep 15

# Test HTTPS with Let's Encrypt certificate
echo "🔍 Testing Let's Encrypt certificate..."
if curl -f -s https://localhost >/dev/null 2>&1; then
    echo "✅ HTTPS is working with Let's Encrypt certificate!"
    
    # Show certificate details
    echo "📜 Certificate details:"
    echo | openssl s_client -connect localhost:443 -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "Could not retrieve certificate details"
else
    echo "❌ HTTPS not working with Let's Encrypt certificate"
    echo "🔧 Rolling back to self-signed certificates..."
    
    # Restore backup config
    cp "$NGINX_CONF_DIR/7gram.https.conf.backup" "$NGINX_CONF_DIR/7gram.https.conf"
    
    # Restart with self-signed certs
    docker compose up -d
    exit 1
fi

# Set up automatic renewal
echo "🔄 Setting up automatic certificate renewal..."
cat > /etc/systemd/system/certbot-renewal.service << 'EOF'
[Unit]
Description=Certbot Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "cd /home/actions_user/nginx-app && docker compose restart nginx"
EOF

cat > /etc/systemd/system/certbot-renewal.timer << 'EOF'
[Unit]
Description=Run certbot renewal twice daily
Requires=certbot-renewal.service

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable certbot-renewal.timer
systemctl start certbot-renewal.timer

echo "✅ Automatic renewal configured"

echo ""
echo "🎉 Successfully upgraded to Let's Encrypt certificates!"
echo "📋 Summary:"
echo "   ✅ Let's Encrypt certificate obtained for $DOMAIN"
echo "   ✅ NGINX configuration updated"
echo "   ✅ Docker Compose updated"
echo "   ✅ HTTPS is working"
echo "   ✅ Automatic renewal configured"
echo ""
echo "🔗 Your site is now available at: https://$DOMAIN"
echo "⚠️ Note: The wildcard certificate (*.$DOMAIN) requires DNS validation"
echo "   You may need to run certbot with --manual --preferred-challenges dns for wildcard support"
echo ""
echo "🔄 To test renewal: sudo systemctl start certbot-renewal.service"
echo "📊 To check renewal status: sudo systemctl status certbot-renewal.timer"
