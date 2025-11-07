#!/bin/bash
# Deployment verification script

echo "🔍 Verifying deployment configuration..."

# Check if required files exist
required_files=("docker-compose.yml" ".env.example" "deployment/docker/nginx/Dockerfile")
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
    fi
done

# Test Docker Compose syntax
echo ""
echo "🐳 Testing Docker Compose configuration..."
if docker-compose config > /dev/null 2>&1; then
    echo "✅ Docker Compose configuration is valid"
else
    echo "❌ Docker Compose configuration has errors"
    docker-compose config
fi

# Check if .env file exists
if [ -f ".env" ]; then
    echo "✅ .env file exists"
else
    echo "⚠️  .env file not found - copy .env.example to .env and configure"
fi

echo ""
echo "🎯 Deployment verification complete!"
