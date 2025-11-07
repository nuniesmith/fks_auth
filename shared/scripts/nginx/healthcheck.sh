#!/bin/bash  
# scripts/healthcheck.sh - Docker health check script

# Check if nginx is running
if ! pgrep -x "nginx" > /dev/null; then
    echo "Nginx is not running"
    exit 1
fi

# Check if nginx responds to health endpoint
if ! curl -sf http://localhost/health > /dev/null; then
    echo "Health endpoint not responding"
    exit 1
fi

echo "Healthy"
exit 0