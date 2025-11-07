#!/bin/bash

# Fixed SSL certificate generation
set -e

# Configuration
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
SSL_STAGING="${SSL_STAGING:-false}"
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"

echo "🔐 Generating SSL certificates for $DOMAIN_NAME..."

# SSH command to generate certificates
ssh -o StrictHostKeyChecking=no actions_user@${TARGET_HOST} << ENDSSH
set -e

echo "🔐 Installing certbot if not present..."
if ! command -v certbot >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y certbot python3-certbot-nginx python3-certbot-dns-cloudflare
fi

echo "🔐 Generating SSL certificate for $DOMAIN_NAME and www.$DOMAIN_NAME..."
if [ "$SSL_STAGING" = "true" ]; then
    echo "🧪 Using Let's Encrypt staging environment"
    sudo certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 60 \
        --staging \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        -d "$DOMAIN_NAME" \
        -d "www.$DOMAIN_NAME"
else
    echo "🏭 Using Let's Encrypt production environment"
    sudo certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 60 \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        -d "$DOMAIN_NAME" \
        -d "www.$DOMAIN_NAME"
fi

echo "🔐 Configuring nginx for SSL..."
sudo tee /etc/nginx/sites-available/fks_ssl > /dev/null << 'NGINXEOF'
server {
    listen 80;
    server_name fkstrading.xyz www.fkstrading.xyz;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name fkstrading.xyz www.fkstrading.xyz;

    ssl_certificate /etc/letsencrypt/live/fkstrading.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/fkstrading.xyz/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
NGINXEOF

echo "🔐 Enabling SSL site..."
sudo ln -sf /etc/nginx/sites-available/fks_ssl /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

echo "🔐 Testing nginx configuration..."
sudo nginx -t

echo "🔐 Reloading nginx..."
sudo systemctl reload nginx

echo "🔐 Setting up auto-renewal..."
sudo crontab -l 2>/dev/null | grep -v certbot > /tmp/crontab.tmp || true
echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" >> /tmp/crontab.tmp
sudo crontab /tmp/crontab.tmp
rm -f /tmp/crontab.tmp

echo "✅ SSL certificates generated and configured successfully!"
echo "🔐 Certificate details:"
sudo certbot certificates

echo "🌐 Testing HTTPS access..."
curl -I https://fkstrading.xyz/ || echo "⚠️ HTTPS test failed - may need a moment to propagate"

ENDSSH

echo "✅ SSL certificate generation complete!"
echo "🔗 Your site should now be available at: https://fkstrading.xyz"
