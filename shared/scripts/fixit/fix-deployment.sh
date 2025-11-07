#!/bin/bash
# (Relocated) Fix deployment issues on FKS server
set -e
echo "🔧 Fixing FKS deployment issues..."
echo "📦 Stopping all FKS containers..."; docker stop $(docker ps -q --filter "name=fks_") 2>/dev/null || true
echo "🗑️ Removing all FKS containers..."; docker rm $(docker ps -aq --filter "name=fks_") 2>/dev/null || true
echo "🧹 Cleaning up volumes..."; docker volume prune -f
cd /home/fks_user/fks || { echo "Repo path missing"; exit 1; }
echo "🚀 Starting services fresh..."; docker compose down -v; docker compose pull; docker compose up -d
echo "⏳ Waiting for services to start..."; sleep 30
echo "📊 Final status:"; docker compose ps || true
echo "🏥 Health checks:"; for port in 80 3000 8000; do if curl -s -f -o /dev/null "http://localhost:$port"; then echo "✅ Port $port"; else echo "❌ Port $port"; fi; done
echo "✅ Deployment fix complete!"
