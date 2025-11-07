#!/bin/bash
# Test Docker builds locally to ensure GitHub Actions compatibility

echo "🐳 Testing Docker builds locally..."

# Set environment variables for testing
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Test main application builds
echo ""
echo "🔍 Testing API service build..."
if docker build -f deployment/docker/Dockerfile --build-arg SERVICE_TYPE=api --build-arg APP_ENV=development -t fks:api-test .; then
    echo "✅ API service build successful"
else
    echo "❌ API service build failed"
    exit 1
fi

echo ""
echo "🔍 Testing Worker service build..."
if docker build -f deployment/docker/Dockerfile --build-arg SERVICE_TYPE=worker --build-arg APP_ENV=development -t fks:worker-test .; then
    echo "✅ Worker service build successful"
else
    echo "❌ Worker service build failed"
    exit 1
fi

echo ""
echo "🔍 Testing Web service build..."
if docker build -f deployment/docker/Dockerfile --build-arg SERVICE_TYPE=web --build-arg APP_ENV=development -t fks:web-test .; then
    echo "✅ Web service build successful"
else
    echo "❌ Web service build failed"
    exit 1
fi

echo ""
echo "🔍 Testing Nginx build..."
if docker build -f deployment/docker/nginx/Dockerfile -t fks_nginx:test .; then
    echo "✅ Nginx build successful"
else
    echo "❌ Nginx build failed"
    exit 1
fi

echo ""
echo "🧹 Cleaning up test images..."
docker rmi fks:api-test fks:worker-test fks:web-test fks_nginx:test 2>/dev/null || true

echo ""
echo "🎉 All Docker builds completed successfully!"
echo "✅ GitHub Actions workflow should work with your Docker setup"
