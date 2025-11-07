#!/bin/bash
set -euo pipefail

# Docker build script for API services
# Usage: ./build-api-docker.sh <service_name>

SERVICE_NAME="${1:-unknown}"

echo "🐳 Building API Docker images for $SERVICE_NAME..."

# Check for API service configuration
if [[ -f "docker-compose.api.yml" ]]; then
  echo "📋 Found docker-compose.api.yml - building API services"
  docker compose -f docker-compose.api.yml build
  
  if [[ -n "${DOCKER_USERNAME:-}" ]]; then
    echo "📤 Pushing API compose images..."
    docker compose -f docker-compose.api.yml push || echo "⚠️ Some API images may not have push configured"
  fi
elif [[ -f "docker-compose.yml" ]]; then
  # Build only API-related services from main compose file
  echo "📋 Building API services from main docker-compose.yml"
  
  # Extract API service names (common patterns: api, worker, data, backend)
  API_SERVICES=($(docker compose config --services 2>/dev/null | grep -E '^(api|worker|data|backend|server)$' || true))
  
  if [[ ${#API_SERVICES[@]} -gt 0 ]]; then
    echo "🔍 Found API services: ${API_SERVICES[*]}"
    
    for service in "${API_SERVICES[@]}"; do
      echo "🐳 Building service: $service"
      docker compose build "$service"
      
      if [[ -n "${DOCKER_USERNAME:-}" ]]; then
        echo "📤 Pushing service: $service"
        docker compose push "$service" || echo "⚠️ Failed to push $service"
      fi
    done
  else
    echo "ℹ️ No API services found in docker-compose.yml"
  fi
elif [[ -f "Dockerfile" ]]; then
  # Single Dockerfile - assume it's for API if service name suggests it
  if [[ "$SERVICE_NAME" =~ (api|backend|server) ]]; then
    echo "📋 Found Dockerfile - building as API service"
    
    IMAGE_TAG="${DOCKER_USERNAME:-local}/$SERVICE_NAME-api:latest"
    
    docker build -t "$IMAGE_TAG" .
    
    if [[ -n "${DOCKER_USERNAME:-}" ]]; then
      echo "📤 Pushing image: $IMAGE_TAG"
      docker push "$IMAGE_TAG"
    fi
  else
    echo "ℹ️ Service doesn't appear to be API-focused - skipping API build"
  fi
else
  echo "ℹ️ No Docker configuration found for API services"
fi

echo "✅ API Docker build complete"
