#!/bin/bash
# docker-entrypoint.sh for Node.js/React applications

set -e

# Function to substitute environment variables in nginx config
substitute_env_vars() {
    local file="$1"
    if [ -f "$file" ]; then
        envsubst '${SERVICE_PORT} ${API_URL} ${NODE_ENV}' < "$file" > "${file}.tmp"
        mv "${file}.tmp" "$file"
    fi
}

# Substitute environment variables in nginx config
substitute_env_vars "/etc/nginx/nginx.conf"
substitute_env_vars "/etc/nginx/conf.d/default.conf"

# If static files need environment variable substitution
if [ -n "$API_URL" ] || [ -n "$NODE_ENV" ]; then
    find /usr/share/nginx/html -name "*.js" -type f -exec \
        sed -i "s|__API_URL__|${API_URL:-http://localhost:8000}|g; s|__NODE_ENV__|${NODE_ENV:-production}|g" {} \;
fi

# Execute the original command
exec "$@"
