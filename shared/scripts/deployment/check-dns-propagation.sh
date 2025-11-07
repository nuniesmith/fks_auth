#!/bin/bash

# Quick DNS propagation check script
DOMAIN_NAME="${1:-fkstrading.xyz}"

echo "🔍 Checking DNS propagation for $DOMAIN_NAME..."

# Method 1: Using dig (most reliable)
if command -v dig >/dev/null 2>&1; then
    echo "📡 Using dig to check DNS..."
    dig +short A "$DOMAIN_NAME" @8.8.8.8
    dig +short A "www.$DOMAIN_NAME" @8.8.8.8
elif command -v host >/dev/null 2>&1; then
    echo "📡 Using host to check DNS..."
    host "$DOMAIN_NAME" 8.8.8.8
    host "www.$DOMAIN_NAME" 8.8.8.8
elif command -v nslookup >/dev/null 2>&1; then
    echo "📡 Using nslookup to check DNS..."
    nslookup "$DOMAIN_NAME" 8.8.8.8
    nslookup "www.$DOMAIN_NAME" 8.8.8.8
else
    echo "📡 Using curl to check DNS resolution..."
    curl -4 -s --connect-timeout 5 "http://$DOMAIN_NAME" >/dev/null && echo "✅ $DOMAIN_NAME resolves" || echo "❌ $DOMAIN_NAME does not resolve"
    curl -4 -s --connect-timeout 5 "http://www.$DOMAIN_NAME" >/dev/null && echo "✅ www.$DOMAIN_NAME resolves" || echo "❌ www.$DOMAIN_NAME does not resolve"
fi

echo "🔍 DNS propagation check complete"
