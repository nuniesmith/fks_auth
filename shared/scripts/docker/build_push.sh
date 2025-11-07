#!/bin/bash
# =================================================================
# FKS Trading Systems - Docker Build and Push Script
# =================================================================
# This script builds Docker images and pushes them to DockerHub
# Usage: ./build-and-push.sh [service1] [service2] ...
# If no services are specified, all services will be built and pushed
# =================================================================

set -e  # Exit immediately if a command exits with a non-zero status

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    echo "Loading environment variables from .env file..."
    # More robust way to load environment variables - only process valid variable assignments
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        if [[ "$line" =~ ^\s*# ]] || [[ -z "$line" ]]; then
            continue
        fi
        
        # Only process lines that look like variable assignments (VAR=value)
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            # Extract variable name
            var_name="${line%%=*}"
            # Extract value (everything after the first =)
            var_value="${line#*=}"
            
            # Remove leading/trailing quotes if present
            var_value="${var_value#\"}"
            var_value="${var_value%\"}"
            var_value="${var_value#\'}"
            var_value="${var_value%\'}"
            
            # Remove any comments at the end of the line
            var_value=$(echo "$var_value" | sed 's/#.*$//')
            # Trim trailing whitespace
            var_value=$(echo "$var_value" | sed 's/[[:space:]]*$//')
            
            # Export the variable
            export "$var_name"="$var_value"
            
            # For debugging, uncomment the next line:
            # echo "Set $var_name=$var_value"
        fi
    done < .env
fi

# Set default values for required variables if not set
DOCKER_USERNAME=${DOCKER_USERNAME:-nuniesmith}
DOCKER_REPO=${DOCKER_REPO:-fks}
APP_VERSION=${APP_VERSION:-1.0.0}
APP_ENV=${APP_ENV:-development}

# Echo important variables to verify they are set
echo "DOCKER_USERNAME: $DOCKER_USERNAME"
echo "DOCKER_REPO: $DOCKER_REPO"
echo "APP_VERSION: $APP_VERSION"
echo "APP_ENV: $APP_ENV"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Available services
SERVICES=(
  "api"
  "worker"
  "app"
  "data"
  "web"
  "nginx"
)

# Display script banner
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}           FKS Trading Systems - Build and Push Script             ${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}Repository: ${DOCKER_USERNAME}/${DOCKER_REPO}${NC}"
echo -e "${BLUE}Version:    ${APP_VERSION}${NC}"
echo -e "${BLUE}Environment: ${APP_ENV}${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""

# Function to display usage information
usage() {
  echo -e "${YELLOW}Usage:${NC} $0 [service1] [service2] ..."
  echo "Available services:"
  for service in "${SERVICES[@]}"; do
    echo " - $service"
  done
  echo ""
  echo "If no services are specified, all services will be built and pushed"
  exit 1
}

# Function to check if Docker is running
check_docker() {
  if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running or not installed.${NC}"
    exit 1
  fi
}

# Function to login to DockerHub
docker_login() {
  echo -e "${BLUE}Logging in to DockerHub...${NC}"
  
  # Check if DOCKER_TOKEN is set
  if [ -z "$DOCKER_TOKEN" ]; then
    echo -e "${YELLOW}DOCKER_TOKEN not set. Please enter your DockerHub credentials manually:${NC}"
    docker login
  else
    echo "$DOCKER_TOKEN" | docker login --username "$DOCKER_USERNAME" --password-stdin
  fi
  
  if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to login to DockerHub. Aborting.${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}Successfully logged in to DockerHub.${NC}"
}

# Function to build a service
build_service() {
  local service=$1
  local actual_name
  local actual_tag
  
  echo -e "${BLUE}==================================================================${NC}"
  echo -e "${BLUE}Building service: ${service}${NC}"
  
  # Get the actual image name by looking at the docker-compose.yml file
  # This is more reliable than using environment variables
  if command -v yq >/dev/null 2>&1; then
    # If yq is available, use it to parse docker-compose.yml
    if [ -f "docker-compose.yml" ]; then
      actual_name=$(yq eval ".services.${service}.image" docker-compose.yml)
      echo -e "${BLUE}Image from docker-compose.yml: ${actual_name}${NC}"
    elif [ -f "docker-compose.yaml" ]; then
      actual_name=$(yq eval ".services.${service}.image" docker-compose.yaml)
      echo -e "${BLUE}Image from docker-compose.yaml: ${actual_name}${NC}"
    fi
  else
    # Fallback to grep/sed method if yq is not available
    if [ -f "docker-compose.yml" ]; then
      actual_name=$(grep -A 3 "^  ${service}:" docker-compose.yml | grep "image:" | sed 's/.*image: *//' | tr -d '[:space:]')
      echo -e "${BLUE}Image from docker-compose.yml: ${actual_name}${NC}"
    elif [ -f "docker-compose.yaml" ]; then
      actual_name=$(grep -A 3 "^  ${service}:" docker-compose.yaml | grep "image:" | sed 's/.*image: *//' | tr -d '[:space:]')
      echo -e "${BLUE}Image from docker-compose.yaml: ${actual_name}${NC}"
    fi
  fi
  
  # If we couldn't determine the name, use default
  if [ -z "$actual_name" ]; then
    local upper_service=$(echo "$service" | tr '[:lower:]' '[:upper:]')
    local image_tag_var="${upper_service}_IMAGE_TAG"
    
    # Try to get value from environment variable
    actual_name="${!image_tag_var}"
    echo -e "${YELLOW}Using image from environment variable ${image_tag_var}: ${actual_name}${NC}"
    
    # If still empty, use default naming convention
    if [ -z "$actual_name" ]; then
      actual_name="${DOCKER_USERNAME}/${DOCKER_REPO}:${service}"
      echo -e "${YELLOW}Using default image name: ${actual_name}${NC}"
    fi
  fi
  
  echo -e "${BLUE}Final Image: ${actual_name}${NC}"
  echo -e "${BLUE}==================================================================${NC}"
  
  # Build the service
  echo -e "${YELLOW}Building ${service}...${NC}"
  
  # Try to use docker-compose build
  if docker-compose build "${service}"; then
    echo -e "${GREEN}Successfully built ${service}.${NC}"
    return 0
  else
    # If that fails, try direct docker build
    echo -e "${YELLOW}docker-compose build failed, trying direct docker build...${NC}"
    
    # Use the Dockerfile path from compose file or use default
    local dockerfile_path="./Dockerfile"
    local context_path="."
    
    # Try to extract Dockerfile path from docker-compose.yml
    if command -v yq >/dev/null 2>&1; then
      if [ -f "docker-compose.yml" ]; then
        dockerfile_path=$(yq eval ".services.${service}.build.dockerfile" docker-compose.yml)
        context_path=$(yq eval ".services.${service}.build.context" docker-compose.yml)
      elif [ -f "docker-compose.yaml" ]; then
        dockerfile_path=$(yq eval ".services.${service}.build.dockerfile" docker-compose.yaml)
        context_path=$(yq eval ".services.${service}.build.context" docker-compose.yaml)
      fi
    fi
    
    if [ "$dockerfile_path" = "null" ]; then
      dockerfile_path="./Dockerfile"
    fi
    
    if [ "$context_path" = "null" ]; then
      context_path="."
    fi
    
    echo -e "${YELLOW}Using Dockerfile: ${dockerfile_path}${NC}"
    echo -e "${YELLOW}Using context: ${context_path}${NC}"
    
    # Extract build args from docker-compose.yml if possible
    local build_args=""
    if command -v yq >/dev/null 2>&1; then
      if [ -f "docker-compose.yml" ]; then
        # This is a simplistic approach and may not work with complex structures
        local args_count=$(yq eval ".services.${service}.build.args | keys | length" docker-compose.yml)
        if [ "$args_count" -gt 0 ]; then
          for i in $(seq 0 $((args_count-1))); do
            local key=$(yq eval ".services.${service}.build.args | keys | .[$i]" docker-compose.yml)
            local val=$(yq eval ".services.${service}.build.args.${key}" docker-compose.yml)
            
            # Handle variables in the value
            val=$(eval echo "$val")
            
            build_args="${build_args} --build-arg ${key}=${val}"
          done
        fi
      fi
    fi
    
    # Attempt the direct docker build
    if docker build ${build_args} -t "${actual_name}" -f "${dockerfile_path}" "${context_path}"; then
      echo -e "${GREEN}Successfully built ${service} using direct docker build.${NC}"
      return 0
    else
      echo -e "${RED}Failed to build ${service}. Aborting.${NC}"
      return 1
    fi
  fi
}

# Function to push a service
push_service() {
  local service=$1
  local actual_name
  
  # Get the actual image name by looking at the docker-compose.yml file
  if command -v yq >/dev/null 2>&1; then
    if [ -f "docker-compose.yml" ]; then
      actual_name=$(yq eval ".services.${service}.image" docker-compose.yml)
    elif [ -f "docker-compose.yaml" ]; then
      actual_name=$(yq eval ".services.${service}.image" docker-compose.yaml)
    fi
  else
    if [ -f "docker-compose.yml" ]; then
      actual_name=$(grep -A 3 "^  ${service}:" docker-compose.yml | grep "image:" | sed 's/.*image: *//' | tr -d '[:space:]')
    elif [ -f "docker-compose.yaml" ]; then
      actual_name=$(grep -A 3 "^  ${service}:" docker-compose.yaml | grep "image:" | sed 's/.*image: *//' | tr -d '[:space:]')
    fi
  fi
  
  # If we couldn't determine the name, use default
  if [ -z "$actual_name" ]; then
    local upper_service=$(echo "$service" | tr '[:lower:]' '[:upper:]')
    local image_tag_var="${upper_service}_IMAGE_TAG"
    
    # Try to get value from environment variable
    actual_name="${!image_tag_var}"
    
    # If still empty, use default naming convention
    if [ -z "$actual_name" ]; then
      actual_name="${DOCKER_USERNAME}/${DOCKER_REPO}:${service}"
    fi
  fi
  
  # Evaluate any variables in the image name
  actual_name=$(eval echo "$actual_name")
  
  echo -e "${YELLOW}Pushing image: ${actual_name}${NC}"
  
  # Add version tag
  local versioned_tag="${actual_name%:*}:${service}-${APP_VERSION}"
  echo -e "${YELLOW}Tagging ${actual_name} as ${versioned_tag}...${NC}"
  docker tag "${actual_name}" "${versioned_tag}"
  
  # Add environment tag
  local env_tag="${actual_name%:*}:${service}-${APP_ENV}"
  echo -e "${YELLOW}Tagging ${actual_name} as ${env_tag}...${NC}"
  docker tag "${actual_name}" "${env_tag}"
  
  # Add latest tag
  local latest_tag="${actual_name%:*}:${service}-latest"
  echo -e "${YELLOW}Tagging ${actual_name} as ${latest_tag}...${NC}"
  docker tag "${actual_name}" "${latest_tag}"
  
  # Push all tags
  echo -e "${YELLOW}Pushing ${actual_name}...${NC}"
  if ! docker push "${actual_name}"; then
    echo -e "${RED}Failed to push ${actual_name}${NC}"
    return 1
  fi
  
  echo -e "${YELLOW}Pushing ${versioned_tag}...${NC}"
  if ! docker push "${versioned_tag}"; then
    echo -e "${RED}Failed to push ${versioned_tag}${NC}"
    return 1
  fi
  
  echo -e "${YELLOW}Pushing ${env_tag}...${NC}"
  if ! docker push "${env_tag}"; then
    echo -e "${RED}Failed to push ${env_tag}${NC}"
    return 1
  fi
  
  echo -e "${YELLOW}Pushing ${latest_tag}...${NC}"
  if ! docker push "${latest_tag}"; then
    echo -e "${RED}Failed to push ${latest_tag}${NC}"
    return 1
  fi
  
  echo -e "${GREEN}Successfully pushed ${service} images.${NC}"
  return 0
}

# Main execution
check_docker

# Check if help is requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  usage
fi

# Login to DockerHub
docker_login

# Determine which services to build
build_services=()
if [ $# -eq 0 ]; then
  # No services specified, build all services
  build_services=("${SERVICES[@]}")
  echo -e "${YELLOW}No services specified. Building and pushing all services...${NC}"
else
  # Validate the specified services
  for arg in "$@"; do
    valid=false
    for service in "${SERVICES[@]}"; do
      if [ "$arg" = "$service" ]; then
        valid=true
        build_services+=("$arg")
        break
      fi
    done
    
    if [ "$valid" = false ]; then
      echo -e "${RED}Invalid service: $arg${NC}"
      usage
    fi
  done
fi

# Build and push each service
success=true
failed_services=()
built_services=()

for service in "${build_services[@]}"; do
  if build_service "$service"; then
    built_services+=("$service")
  else
    success=false
    failed_services+=("$service")
  fi
done

# Push built services
for service in "${built_services[@]}"; do
  if ! push_service "$service"; then
    success=false
    failed_services+=("$service (push)")
  fi
done

# Summary
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}                     Build and Push Summary                       ${NC}"
echo -e "${BLUE}==================================================================${NC}"

if [ "$success" = true ]; then
  echo -e "${GREEN}All services successfully built and pushed.${NC}"
else
  echo -e "${RED}Some services failed to build or push:${NC}"
  for service in "${failed_services[@]}"; do
    echo -e "${RED} - $service${NC}"
  done
fi

echo -e "${BLUE}==================================================================${NC}"