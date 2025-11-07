#!/bin/bash
# Quick update script for FKS Trading Systems

set -e

echo "🔄 Updating FKS Trading Systems..."

# Check for uncommitted changes
if [[ -n $(git status -s) ]]; then
    echo "⚠️  Uncommitted changes detected. Please commit or stash them first."
    exit 1
fi

# Pull latest changes
CURRENT_BRANCH=$(git branch --show-current)
echo "📥 Pulling latest changes from $CURRENT_BRANCH..."
git pull origin $CURRENT_BRANCH

# Update docker images
echo "🐳 Pulling latest Docker images..."
docker-compose pull

# Restart services
echo "🚀 Restarting services..."
docker-compose up -d --remove-orphans

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Show status
echo "📊 Service status:"
docker-compose ps

echo "✅ Update complete!"
