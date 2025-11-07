#!/bin/bash
# =================================================================
# nginx-test-config.sh - Validates nginx configuration
# =================================================================

set -eo pipefail

echo "Testing Nginx configuration..."

# Check if nginx executable exists
if ! command -v nginx &> /dev/null; then
    echo "❌ Error: nginx command not found" >&2
    exit 1
fi

# Test the configuration
if nginx -t; then
    echo "✅ Nginx configuration is valid"
    exit 0
else
    echo "❌ Invalid Nginx configuration" >&2
    exit 1
fi
