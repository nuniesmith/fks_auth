#!/bin/bash
# setup-local-testing.sh
# Script to set up nginx for local testing without SSL

set -e

echo "🔧 Setting up nginx for local testing..."

# Move to repo root when invoked from scripts/local
cd "$(dirname "$0")/../.."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: Please run this script from the nginx project root directory"
    exit 1
fi

# Stop any running containers
echo "🛑 Stopping existing containers..."
docker-compose down 2>/dev/null || true

# Backup the SSL configuration
echo "📦 Backing up SSL configuration..."
if [ -f "config/nginx/conf.d/default.conf" ]; then
    cp config/nginx/conf.d/default.conf config/nginx/conf.d/default.conf.ssl-backup
    echo "✅ SSL config backed up to default.conf.ssl-backup"
fi

# Use the HTTP-only configuration for testing
echo "🔄 Switching to HTTP-only configuration..."
cp config/nginx/conf.d/temp-http.conf config/nginx/conf.d/default.conf

# Create a simple docker-compose override for testing
cat > docker-compose.override.yml << 'EOF'
services:
  nginx:
    ports:
      - "8080:80"
    volumes:
      # Comment out SSL-related volumes for HTTP-only testing
      # - ssl-certs:/etc/nginx/ssl
      # - letsencrypt-certs:/etc/letsencrypt
      - acme-challenge:/var/www/certbot
  
  # Disable certbot for HTTP-only testing
  certbot:
    profiles: ["ssl"]
EOF

echo "✅ Created docker-compose.override.yml for HTTP-only testing"

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if docker run --rm -v "$(pwd)/config/nginx:/etc/nginx" nginx:alpine nginx -t; then
    echo "✅ Nginx configuration is valid"
else
    echo "❌ Nginx configuration has errors"
    exit 1
fi

# Start the services
echo "🚀 Starting nginx in HTTP-only mode..."
docker-compose up -d nginx

# Wait for nginx to start
echo "⏳ Waiting for nginx to start..."
sleep 5

# Test the health endpoint
echo "🏥 Testing health endpoint..."
if curl -s http://localhost:8080/health | jq . > /dev/null 2>&1; then
    echo "✅ Health endpoint is working!"
    curl -s http://localhost:8080/health | jq .
else
    echo "⚠️  Health endpoint test failed, but nginx might still be working"
fi

echo ""
echo "🎉 Local testing setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Test the service: curl http://localhost:8080/health"
echo "   2. View logs: docker-compose logs -f nginx"
echo "   3. When ready for SSL: bash setup-ssl.sh"
echo "   4. Restore SSL config: cp config/nginx/conf.d/default.conf.ssl-backup config/nginx/conf.d/default.conf"
echo ""
echo "🔗 Access your service at: http://localhost:8080"
