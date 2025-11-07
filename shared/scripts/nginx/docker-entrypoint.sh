#!/bin/bash
# scripts/docker-entrypoint.sh - Docker entrypoint script

set -e

# Replace environment variables in nginx config
if [ -n "$NGINX_HOST" ]; then
    find /etc/nginx -name "*.conf" -exec sed -i "s/localhost/$NGINX_HOST/g" {} \;
fi

# Validate nginx configuration
echo "Testing nginx configuration..."
nginx -t

# Create PID directory
mkdir -p /var/run/nginx

# Execute CMD
exec "$@"