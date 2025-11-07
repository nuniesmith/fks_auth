#!/bin/bash
# (Relocated) Docker build test.
set -e
echo "🐳 Testing API build..."; docker build -f deployment/docker/Dockerfile --build-arg SERVICE_TYPE=api --build-arg APP_ENV=development -t fks:api-test .
echo "🐳 Testing Worker build..."; docker build -f deployment/docker/Dockerfile --build-arg SERVICE_TYPE=worker --build-arg APP_ENV=development -t fks:worker-test .
echo "✅ Builds completed"
