#!/bin/bash
set -euo pipefail

# Docker build script for Auth services
# Usage: ./build-auth-docker.sh <service_name>

SERVICE_NAME="${1:-unknown}"

echo "🔐 Building Auth Docker images for $SERVICE_NAME..."

# Check for Auth service configuration
if [[ -f "docker-compose.auth.yml" ]]; then
  echo "📋 Found docker-compose.auth.yml - building Auth services"
  docker compose -f docker-compose.auth.yml build
  
  if [[ -n "${DOCKER_USERNAME:-}" ]]; then
    echo "📤 Pushing Auth compose images..."
    docker compose -f docker-compose.auth.yml push || echo "⚠️ Some Auth images may not have push configured"
  fi
elif [[ -f "docker-compose.yml" ]]; then
  # Build only Auth-related services from main compose file
  echo "📋 Building Auth services from main docker-compose.yml"
  
  # Extract Auth service names (common patterns: auth, oauth, keycloak, etc.)
  AUTH_SERVICES=($(docker compose config --services 2>/dev/null | grep -E '^(auth|oauth|keycloak|identity|session)$' || true))
  
  if [[ ${#AUTH_SERVICES[@]} -gt 0 ]]; then
    echo "🔍 Found Auth services: ${AUTH_SERVICES[*]}"
    
    for service in "${AUTH_SERVICES[@]}"; do
      echo "🔐 Building service: $service"
      docker compose build "$service"
      
      if [[ -n "${DOCKER_USERNAME:-}" ]]; then
        echo "📤 Pushing service: $service"
        docker compose push "$service" || echo "⚠️ Failed to push $service"
      fi
    done
  else
    echo "ℹ️ No Auth services found in docker-compose.yml - may use external auth services"
  fi
else
  echo "ℹ️ No custom Auth services to build - likely using external authentication"
fi

echo "✅ Auth Docker build complete (or skipped if no custom services)"
