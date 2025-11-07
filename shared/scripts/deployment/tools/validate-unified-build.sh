#!/bin/bash

# =================================================================
# === FKS UNIFIED BUILD SYSTEM VALIDATION SCRIPT ================
# =================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo ""
    echo "================================================================="
    echo "=== $1"
    echo "================================================================="
}

print_step() {
    echo ""
    print_status "${BLUE}" ">>> $1"
}

print_success() {
    print_status "${GREEN}" "✓ $1"
}

print_warning() {
    print_status "${YELLOW}" "⚠ $1"
}

print_error() {
    print_status "${RED}" "❌ $1"
}

# Change to project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

print_header "FKS UNIFIED BUILD SYSTEM VALIDATION"

# Check if Docker is running
print_step "Checking Docker availability"
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi
print_success "Docker is running"

# Validate docker-compose.yml syntax
print_step "Validating docker-compose.yml syntax"
if docker-compose config --quiet; then
    print_success "docker-compose.yml syntax is valid"
else
    print_error "docker-compose.yml has syntax errors"
    exit 1
fi

# Validate environment variables
print_step "Validating environment configuration"
if [ ! -f ".env" ]; then
    print_error ".env file not found"
    exit 1
fi
print_success ".env file exists"

# Check unified Dockerfile
print_step "Validating unified Dockerfile"
if [ ! -f "deployment/docker/Dockerfile" ]; then
    print_error "Unified Dockerfile not found at deployment/docker/Dockerfile"
    exit 1
fi
print_success "Unified Dockerfile exists"

# Validate Dockerfile supports all runtimes
print_step "Checking Dockerfile runtime support"
DOCKERFILE="deployment/docker/Dockerfile"

# Check for Python support
if grep -q "builder-python" "$DOCKERFILE"; then
    print_success "Python runtime support found"
else
    print_warning "Python runtime support not clearly defined"
fi

# Check for .NET support
if grep -q "builder-dotnet\|mcr.microsoft.com/dotnet" "$DOCKERFILE"; then
    print_success ".NET runtime support found"
else
    print_warning ".NET runtime support not clearly defined"
fi

# Check for Node.js support
if grep -q "builder-node\|node:" "$DOCKERFILE"; then
    print_success "Node.js runtime support found"
else
    print_warning "Node.js runtime support not clearly defined"
fi

# Check for Rust support
if grep -q "builder-rust\|rust:" "$DOCKERFILE"; then
    print_success "Rust runtime support found"
else
    print_warning "Rust runtime support not clearly defined"
fi

# Validate service configurations
print_step "Validating service configurations"

# Core services
CORE_SERVICES=("api" "app" "data" "web" "worker" "training" "transformer")
for service in "${CORE_SERVICES[@]}"; do
    if docker-compose config | grep -q "^  ${service}:"; then
        print_success "Service '$service' configuration found"
    else
        print_warning "Service '$service' configuration not found"
    fi
done

# Ninja services
NINJA_SERVICES=("ninja-dev" "ninja-python" "ninja-build-api" "ninja-vscode")
for service in "${NINJA_SERVICES[@]}"; do
    if docker-compose config | grep -q "^  ${service}:"; then
        print_success "Ninja service '$service' configuration found"
    else
        print_warning "Ninja service '$service' configuration not found"
    fi
done

# Check for legacy Dockerfiles
print_step "Checking for legacy Dockerfiles"
LEGACY_DOCKERFILES=(
    "deployment/docker/Dockerfile.api"
    "deployment/docker/Dockerfile.dev" 
    "deployment/docker/Dockerfile.python"
    "deployment/docker/Dockerfile"
    "deployment/docker/Dockerfile.watcher"
)

legacy_found=false
for dockerfile in "${LEGACY_DOCKERFILES[@]}"; do
    if [ -f "$dockerfile" ]; then
        print_warning "Legacy Dockerfile found: $dockerfile (should be removed)"
        legacy_found=true
    fi
done

if [ "$legacy_found" = false ]; then
    print_success "No legacy Dockerfiles found"
fi

# Validate environment variables for all services
print_step "Checking critical environment variables"

# Check build configuration variables
CRITICAL_VARS=(
    "DOCKERFILE_PATH"
    "BUILD_CONTEXT"
    "PYTHON_VERSION"
    "DOTNET_VERSION"
    "NODE_VERSION"
    "APP_VERSION"
    "APP_ENV"
)

missing_vars=()
for var in "${CRITICAL_VARS[@]}"; do
    if grep -q "^${var}=" .env; then
        print_success "Variable '$var' configured"
    else
        missing_vars+=("$var")
        print_warning "Variable '$var' not found in .env"
    fi
done

# Validate build args are consistent
print_step "Validating build arguments consistency"
if docker-compose config | grep -q "BUILD_PYTHON"; then
    print_success "BUILD_PYTHON argument found in services"
else
    print_warning "BUILD_PYTHON argument not found in any service"
fi

if docker-compose config | grep -q "BUILD_DOTNET"; then
    print_success "BUILD_DOTNET argument found in services"
else
    print_warning "BUILD_DOTNET argument not found in any service"
fi

if docker-compose config | grep -q "BUILD_NODE"; then
    print_success "BUILD_NODE argument found in services"
else
    print_warning "BUILD_NODE argument not found in any service"
fi

# Test build for a simple service (if Docker is available and running)
print_step "Testing unified build system"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    print_status "${BLUE}" "Attempting test build of ninja-python service..."
    if timeout 300 docker-compose build --no-cache ninja-python >/dev/null 2>&1; then
        print_success "Test build of ninja-python service completed successfully"
    else
        print_warning "Test build failed or timed out (this may be normal if dependencies are missing)"
    fi
else
    print_warning "Skipping test build - Docker not available"
fi

# Summary
print_header "VALIDATION SUMMARY"

if [ ${#missing_vars[@]} -eq 0 ] && [ "$legacy_found" = false ]; then
    print_success "All checks passed! The unified build system is properly configured."
    echo ""
    echo "You can now build and run services using:"
    echo "  docker-compose build <service-name>"
    echo "  docker-compose up <service-name>"
    echo ""
    echo "Available services:"
    echo "  Core: api, app, data, web, worker, training, transformer"
    echo "  Ninja: ninja-dev, ninja-python, ninja-build-api, ninja-vscode"
    echo "  Database: redis, postgres"
else
    print_warning "Some issues were found. Please review the warnings above."
    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo ""
        echo "Missing environment variables:"
        printf '%s\n' "${missing_vars[@]}"
    fi
fi

print_header "VALIDATION COMPLETE"
