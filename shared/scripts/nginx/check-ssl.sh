#!/bin/bash
echo "🔍 SSL Certificate Status Check"
echo "==============================="

echo "📂 SSL Directory Contents:"
ls -la ssl/ 2>/dev/null || echo "❌ ssl/ directory not found"

echo ""
echo "🐳 Container Status:"
sudo docker compose ps || docker compose ps

echo ""
echo "📋 NGINX Container Logs (last 5 lines):"
sudo docker logs nginx-proxy --tail=5 2>/dev/null || echo "❌ Could not get logs"

echo ""
echo "🌐 HTTPS Test:"
if curl -k -I https://localhost 2>/dev/null | head -1; then
    echo "✅ HTTPS is responding"
else
    echo "❌ HTTPS is not responding"
fi

echo ""
echo "📊 Certificate Details:"
if [ -f ssl/fullchain.pem ]; then
    openssl x509 -in ssl/fullchain.pem -text -noout | grep -E "(Subject:|DNS:|Not After)" 2>/dev/null || echo "Could not parse certificate"
else
    echo "❌ ssl/fullchain.pem not found"
fi
