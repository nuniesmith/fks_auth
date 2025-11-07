#!/bin/bash
# Emergency Docker Compose startup script for nginx
# This script provides a fallback when the main start.sh fails

set -e

echo "🚨 Emergency Docker Compose startup for nginx..."

# Change to the nginx directory
cd "$(dirname "$0")/.."

# Simple environment setup
cat > .env << 'EOF'
COMPOSE_PROJECT_NAME=nginx
NODE_ENV=production
API_PID=
DOMAIN_NAME=nginx.7gram.xyz
HTTP_PORT=80
HTTPS_PORT=443
TZ=America/Toronto
EOF

# Detect Docker Compose command
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    echo "✅ Using Docker Compose V2: docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
    echo "✅ Using Docker Compose V1: docker-compose"
else
    echo "❌ No Docker Compose available"
    exit 1
fi

# Clean start
echo "🧹 Cleaning up existing containers..."
$COMPOSE_CMD down --remove-orphans 2>/dev/null || true

# Start services
echo "🚀 Starting nginx services..."
$COMPOSE_CMD up -d

# Show status
echo "📊 Service status:"
$COMPOSE_CMD ps

echo "✅ Emergency startup complete!"
echo "🌐 HTTP: http://localhost"
echo "🔒 HTTPS: https://localhost (self-signed)"
