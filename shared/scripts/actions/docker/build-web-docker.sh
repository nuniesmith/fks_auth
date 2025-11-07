#!/bin/bash
set -euo pipefail

# Docker build script for Web services
# Usage: ./build-web-docker.sh <service_name>

SERVICE_NAME="${1:-unknown}"

echo "🌐 Building Web Docker images for $SERVICE_NAME..."

# Check for Web service configuration
if [[ -f "docker-compose.web.yml" ]]; then
  echo "📋 Found docker-compose.web.yml - building Web services"
  docker compose -f docker-compose.web.yml build
  
  if [[ -n "${DOCKER_USERNAME:-}" ]]; then
    echo "📤 Pushing Web compose images..."
    docker compose -f docker-compose.web.yml push || echo "⚠️ Some Web images may not have push configured"
  fi
elif [[ -f "docker-compose.yml" ]]; then
  # Build only Web-related services from main compose file
  echo "📋 Building Web services from main docker-compose.yml"
  
  # Extract Web service names (common patterns: web, frontend, ui, client)
  WEB_SERVICES=($(docker compose config --services 2>/dev/null | grep -E '^(web|frontend|ui|client|app)$' || true))
  
  if [[ ${#WEB_SERVICES[@]} -gt 0 ]]; then
    echo "🔍 Found Web services: ${WEB_SERVICES[*]}"
    
    for service in "${WEB_SERVICES[@]}"; do
      echo "🌐 Building service: $service"
      docker compose build "$service"
      
      if [[ -n "${DOCKER_USERNAME:-}" ]]; then
        echo "📤 Pushing service: $service"
        docker compose push "$service" || echo "⚠️ Failed to push $service"
      fi
    done
  else
    echo "ℹ️ No Web services found in docker-compose.yml"
  fi
elif [[ -f "Dockerfile" ]]; then
  # Single Dockerfile - assume it's for Web if service name suggests it
  if [[ "$SERVICE_NAME" =~ (web|frontend|ui|client) ]]; then
    echo "📋 Found Dockerfile - building as Web service"
    
    IMAGE_TAG="${DOCKER_USERNAME:-local}/$SERVICE_NAME-web:latest"
    
    docker build -t "$IMAGE_TAG" .
    
    if [[ -n "${DOCKER_USERNAME:-}" ]]; then
      echo "📤 Pushing image: $IMAGE_TAG"
      docker push "$IMAGE_TAG"
    fi
  else
    echo "ℹ️ Service doesn't appear to be Web-focused - skipping Web build"
  fi
else
  echo "ℹ️ No Docker configuration found for Web services"
fi

echo "✅ Web Docker build complete"
