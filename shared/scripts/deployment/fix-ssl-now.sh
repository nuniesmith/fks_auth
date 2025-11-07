#!/bin/bash

# Quick fix for SSL certificates on running deployment
set -e

TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
SSL_STAGING="${SSL_STAGING:-false}"

echo "🔐 Fixing SSL certificates for Docker containers..."

sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no actions_user@"$TARGET_HOST" << 'ENDSSH'
set -e

echo "🔐 SSL Certificate Quick Fix..."

# Check if Let's Encrypt certificates exist
if [ -f "/etc/letsencrypt/live/fkstrading.xyz/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/fkstrading.xyz/privkey.pem" ]; then
    echo "✅ Let's Encrypt certificates found"
    
    # Create SSL directory for Docker
    sudo mkdir -p /home/fks_user/ssl
    
    # Copy certificates with correct names
    sudo cp -L /etc/letsencrypt/live/fkstrading.xyz/fullchain.pem /home/fks_user/ssl/cert.pem
    sudo cp -L /etc/letsencrypt/live/fkstrading.xyz/privkey.pem /home/fks_user/ssl/key.pem
    
    # Set permissions
    sudo chmod 644 /home/fks_user/ssl/cert.pem
    sudo chmod 600 /home/fks_user/ssl/key.pem
    sudo chown -R fks_user:fks_user /home/fks_user/ssl/
    
    echo "✅ SSL certificates prepared for Docker"
    
    # Update docker-compose.yml if needed
    if [ -f "/home/fks_user/fks/docker-compose.yml" ]; then
        cd /home/fks_user/fks
        sudo -u fks_user sed -i 's|./config/ssl:/etc/nginx/ssl:ro|/home/fks_user/ssl:/etc/nginx/ssl:ro|g' docker-compose.yml
        echo "✅ Updated docker-compose.yml SSL mount path"
    fi
    
    # Restart nginx container
    if sudo -u fks_user docker ps | grep -q fks_nginx; then
        echo "🔄 Restarting nginx container..."
        sudo -u fks_user docker restart fks_nginx
        
        # Wait and check status
        sleep 10
        if sudo -u fks_user docker ps | grep -q fks_nginx; then
            echo "✅ Nginx container restarted successfully"
        else
            echo "❌ Nginx container failed to restart"
            sudo -u fks_user docker logs fks_nginx --tail=20
        fi
    else
        echo "⚠️ Nginx container not found"
    fi
    
    echo "✅ SSL fix completed"
else
    echo "❌ Let's Encrypt certificates not found at /etc/letsencrypt/live/fkstrading.xyz/"
    echo "📋 Available certificates:"
    sudo ls -la /etc/letsencrypt/live/ || echo "No certificates found"
fi

ENDSSH

echo "✅ SSL fix script completed"
