#!/bin/bash
echo "🔄 Restarting NGINX services with SSL support..."

# Ensure SSL certificates exist
if [ ! -f ssl/fullchain.pem ] || [ ! -f ssl/privkey.pem ]; then
    echo "❌ SSL certificates not found in ssl/ directory"
    echo "📍 Current directory: $(pwd)"
    echo "📍 Expected files: ssl/fullchain.pem, ssl/privkey.pem"
    ls -la ssl/ 2>/dev/null || echo "ssl/ directory not found"
    exit 1
fi

echo "✅ SSL certificates found"

# Check if we should use minimal or full configuration
USE_MINIMAL=false
if [ "$1" = "--minimal" ] || [ "$1" = "-m" ]; then
    USE_MINIMAL=true
    echo "🔧 Using minimal configuration (no upstream dependencies)"
elif [ "$1" = "--full" ] || [ "$1" = "-f" ]; then
    USE_MINIMAL=false
    echo "🔧 Using full configuration (with upstream servers)"
else
    # Auto-detect: use minimal if full config has issues
    if [ -f config/nginx/nginx.full.conf ]; then
        echo "🔍 Auto-detecting configuration to use..."
        # Test if we can resolve upstream hostnames
        if nslookup sullivan.tailfef10.ts.net >/dev/null 2>&1; then
            echo "✅ Upstream hostnames resolvable, using full configuration"
            USE_MINIMAL=false
        else
            echo "⚠️ Upstream hostnames not resolvable, using minimal configuration"
            USE_MINIMAL=true
        fi
    fi
fi

# Switch configuration if needed
if [ "$USE_MINIMAL" = "true" ] && [ -f config/nginx/nginx.minimal.conf ]; then
    cp config/nginx/nginx.minimal.conf config/nginx/nginx.conf
    echo "✅ Switched to minimal configuration"
elif [ "$USE_MINIMAL" = "false" ] && [ -f config/nginx/nginx.full.conf ]; then
    cp config/nginx/nginx.full.conf config/nginx/nginx.conf
    echo "✅ Switched to full configuration"
fi

echo "🛑 Stopping existing containers..."
sudo docker compose down 2>/dev/null || docker compose down 2>/dev/null || echo "No containers to stop"

echo "🚀 Starting services with SSL..."
sudo docker compose up -d || docker compose up -d

echo "⏳ Waiting for services to start..."
sleep 10

echo "📋 Service status:"
sudo docker compose ps || docker compose ps

echo "🔍 Testing NGINX..."
if curl -k -I https://localhost 2>/dev/null | grep -q "HTTP/"; then
    echo "✅ HTTPS is working"
elif curl -I http://localhost 2>/dev/null | grep -q "HTTP/"; then
    echo "✅ HTTP is working"
else
    echo "⚠️ NGINX test failed - check logs: docker logs nginx-proxy"
fi

echo "✅ Restart completed"
echo ""
echo "💡 Usage tips:"
echo "   ./restart-ssl.sh --minimal  # Use minimal config (no upstream servers)"
echo "   ./restart-ssl.sh --full     # Use full config (with upstream servers)"
echo "   ./restart-ssl.sh            # Auto-detect best configuration"
