#!/bin/sh
echo "Running Nginx entrypoint as root to fix permission issues..."
exec nginx -g 'daemon off;'
