#!/bin/bash
# setup-ssl.sh
# Script to set up SSL certificates and switch to HTTPS configuration

set -e

echo "🔒 Setting up SSL certificates and HTTPS configuration..."

# Move to repo root when invoked from scripts/ssl
cd "$(dirname "$0")/../.."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: Please run this script from the nginx project root directory"
    exit 1
fi

# Check for required environment variables
if [ -z "$ADMIN_EMAIL" ] || [ -z "$CLOUDFLARE_EMAIL" ] || [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "❌ Error: Please set ADMIN_EMAIL, CLOUDFLARE_EMAIL and CLOUDFLARE_API_TOKEN environment variables"
    echo "   export ADMIN_EMAIL=your-email@example.com"
    echo "   export CLOUDFLARE_EMAIL=your-cloudflare-email@example.com"
    echo "   export CLOUDFLARE_API_TOKEN=your-api-token"
    exit 1
fi

# Create cloudflare credentials file
echo "🔑 Creating Cloudflare credentials..."
mkdir -p config/certbot
cat > config/certbot/cloudflare.ini << EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
chmod 600 config/certbot/cloudflare.ini

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose down || true

# Remove the override file to enable SSL
if [ -f "docker-compose.override.yml" ]; then
    echo "🗑️  Removing HTTP-only override..."
    rm docker-compose.override.yml
fi

# Generate initial SSL certificate using DNS challenge
echo "📜 Obtaining SSL certificate..."
docker run --rm \
    -v "$(pwd)/config/certbot:/etc/letsencrypt/config" \
    -v "$(pwd)/ssl-certs:/etc/letsencrypt" \
    certbot/dns-cloudflare:latest \
    certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/config/cloudflare.ini \
    --dns-cloudflare-propagation-seconds 60 \
    --email "$ADMIN_EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "7gram.xyz" \
    -d "*.7gram.xyz"

if [ $? -eq 0 ]; then
    echo "✅ SSL certificate obtained successfully!"
else
    echo "❌ Failed to obtain SSL certificate"
    exit 1
fi

# Restore the SSL configuration
echo "🔄 Switching to HTTPS configuration..."
if [ -f "config/nginx/conf.d/default.conf.ssl-backup" ]; then
    cp config/nginx/conf.d/default.conf.ssl-backup config/nginx/conf.d/default.conf
    echo "✅ SSL configuration restored"
else
    echo "⚠️  No SSL backup found, using current configuration"
fi

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if docker run --rm \
    -v "$(pwd)/config/nginx:/etc/nginx" \
    -v "$(pwd)/ssl-certs:/etc/letsencrypt" \
    nginx:alpine nginx -t; then
    echo "✅ Nginx configuration is valid"
else
    echo "❌ Nginx configuration has errors"
    exit 1
fi

# Start all services with SSL
echo "🚀 Starting all services with SSL..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Test the HTTPS health endpoint
echo "🏥 Testing HTTPS health endpoint..."
if curl -k -s https://localhost/health | jq . > /dev/null 2>&1; then
    echo "✅ HTTPS health endpoint is working!"
    curl -k -s https://localhost/health | jq .
else
    echo "⚠️  HTTPS health endpoint test failed, check logs"
    echo "📋 Debug commands:"
    echo "   docker-compose logs nginx"
    echo "   docker-compose logs certbot"
fi

echo ""
echo "🎉 SSL setup complete!"
echo ""
echo "📋 Services should now be available at:"
echo "   Main dashboard: https://7gram.xyz (or https://localhost with host file entry)"
echo "   Health check: https://localhost/health"
echo ""
echo "🔍 To monitor certificate renewals:"
echo "   docker-compose logs -f certbot"
