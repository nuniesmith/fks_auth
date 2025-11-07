#!/bin/bash
# Fix deployment issues on FKS server

set -e

echo "🔧 Fixing FKS deployment issues..."

# Stop all FKS containers
echo "📦 Stopping all FKS containers..."
docker stop $(docker ps -q --filter "name=fks_") 2>/dev/null || true

# Remove all FKS containers
echo "🗑️ Removing all FKS containers..."
docker rm $(docker ps -aq --filter "name=fks_") 2>/dev/null || true

# Clean up any dangling volumes
echo "🧹 Cleaning up volumes..."
docker volume prune -f

# Navigate to FKS directory
cd /home/fks_user/fks

# Start services fresh
echo "🚀 Starting services fresh..."
docker compose down -v
docker compose pull
docker compose up -d

# Wait for services to stabilize
echo "⏳ Waiting for services to start..."
sleep 30

# Check status
echo "📊 Final status:"
docker compose ps

# Check health
echo ""
echo "🏥 Health checks:"
for port in 80 3000 8000; do
    if curl -s -f -o /dev/null "http://localhost:$port"; then
        echo "✅ Port $port is responding"
    else
        echo "❌ Port $port is not responding"
    fi
done

echo ""
echo "✅ Deployment fix complete!"
