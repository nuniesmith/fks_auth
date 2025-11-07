#!/bin/bash
# Build multiple FKS services
# Usage: ./build_services.sh [service1,service2,...] [--push] [--parallel]

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SERVICES=""
PUSH_IMAGES=false
PARALLEL_BUILD=false
MAX_PARALLEL=4
VERSION=""
CONFIG_FILE="./config/services/environment.yaml"

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [SERVICES]

Build FKS Trading Systems services

OPTIONS:
    -s, --services     Comma-separated list of services to build (default: all)
    -p, --push        Push images to Docker registry
    -P, --parallel    Build services in parallel
    -j, --jobs        Number of parallel jobs (default: 4)
    -v, --version     Version tag for images (default: generated timestamp)
    -c, --config      Path to config file (default: ./config/services/environment.yaml)
    -h, --help        Display this help message

SERVICES:
    Python CPU: api, worker, app, data, web, nginx
    Python GPU: training, transformer
    Rust: node-registry, node, node-connector
    
EXAMPLES:
    $0 --services api,worker --push
    $0 --parallel --jobs 8
    $0 --services all --version v1.0.0
EOF
}

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--services)
            SERVICES="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_IMAGES=true
            shift
            ;;
        -P|--parallel)
            PARALLEL_BUILD=true
            shift
            ;;
        -j|--jobs)
            MAX_PARALLEL="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            SERVICES="$1"
            shift
            ;;
    esac
done

# Generate .env file if it doesn't exist
if [[ ! -f .env ]]; then
    print_status "$YELLOW" "Generating .env file from configuration..."
    if [[ -f generate_env.py ]]; then
        python generate_env.py --config "$CONFIG_FILE"
    else
        print_status "$RED" "Error: generate_env.py not found and .env doesn't exist!"
        exit 1
    fi
fi

# Source .env file
set -a
source .env
set +a

# Generate version if not provided
if [[ -z "$VERSION" ]]; then
    VERSION=$(date +%Y%m%d.%H%M%S)
    if [[ -n "${CI:-}" ]]; then
        VERSION="ci-${VERSION}"
    else
        VERSION="local-${VERSION}"
    fi
fi

print_status "$BLUE" "Building with version: $VERSION"

# Define all available services
declare -A ALL_SERVICES=(
    # Python CPU services
    ["api"]="python_cpu|${DOCKER_REPO}:api|./deployment/docker/Dockerfile|SERVICE_TYPE=api"
    ["worker"]="python_cpu|${DOCKER_REPO}:worker|./deployment/docker/Dockerfile|SERVICE_TYPE=worker"
    ["app"]="python_cpu|${DOCKER_REPO}:app|./deployment/docker/Dockerfile|SERVICE_TYPE=app"
    ["data"]="python_cpu|${DOCKER_REPO}:data|./deployment/docker/Dockerfile|SERVICE_TYPE=data"
    ["web"]="python_cpu|${DOCKER_REPO}:web|./deployment/docker/Dockerfile|SERVICE_TYPE=web"
    ["nginx"]="nginx|${DOCKER_REPO}:nginx|./deployment/docker/nginx/Dockerfile|"
    
    # Python GPU services
    ["training"]="python_gpu|${DOCKER_REPO}:training|./deployment/docker/Dockerfile|SERVICE_TYPE=training GPU_ENABLED=true"
    ["transformer"]="python_gpu|${DOCKER_REPO}:transformer|./deployment/docker/Dockerfile|SERVICE_TYPE=transformer GPU_ENABLED=true"
    
    # Rust services
    ["node-registry"]="rust|${DOCKER_REPO}:node-registry|./deployment/docker/rust/Dockerfile.registry|SERVICE_TYPE=registry"
    ["node"]="rust|${DOCKER_REPO}:node|./deployment/docker/rust/Dockerfile.node|SERVICE_TYPE=node"
    ["node-connector"]="rust|${DOCKER_REPO}:node-connector|./deployment/docker/rust/Dockerfile.connector|SERVICE_TYPE=connector"
)

# Determine which services to build
if [[ -z "$SERVICES" ]] || [[ "$SERVICES" == "all" ]]; then
    SERVICES_TO_BUILD=("${!ALL_SERVICES[@]}")
else
    IFS=',' read -ra SERVICES_TO_BUILD <<< "$SERVICES"
fi

# Validate services
for service in "${SERVICES_TO_BUILD[@]}"; do
    if [[ ! -v "ALL_SERVICES[$service]" ]]; then
        print_status "$RED" "Error: Unknown service '$service'"
        echo "Available services: ${!ALL_SERVICES[*]}"
        exit 1
    fi
done

print_status "$GREEN" "Services to build: ${SERVICES_TO_BUILD[*]}"

# Function to build a single service
build_service() {
    local service=$1
    local service_info="${ALL_SERVICES[$service]}"
    IFS='|' read -r type image dockerfile build_args <<< "$service_info"
    
    local full_image="${DOCKER_USERNAME}/${image}"
    
    print_status "$BLUE" "[$service] Starting build..."
    
    # Prepare build command
    local build_cmd="docker buildx build"
    build_cmd="$build_cmd --platform linux/amd64,linux/arm64"
    build_cmd="$build_cmd -f $dockerfile"
    build_cmd="$build_cmd -t ${full_image}:latest"
    build_cmd="$build_cmd -t ${full_image}:${VERSION}"
    
    # Add build args
    if [[ -n "$build_args" ]]; then
        for arg in $build_args; do
            build_cmd="$build_cmd --build-arg $arg"
        done
    fi
    
    # Add common build args
    build_cmd="$build_cmd --build-arg VERSION=${VERSION}"
    build_cmd="$build_cmd --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    build_cmd="$build_cmd --build-arg VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    
    # Add push flag if requested
    if [[ "$PUSH_IMAGES" == "true" ]]; then
        build_cmd="$build_cmd --push"
    fi
    
    build_cmd="$build_cmd ."
    
    # Execute build
    if eval "$build_cmd"; then
        print_status "$GREEN" "[$service] Build successful!"
        return 0
    else
        print_status "$RED" "[$service] Build failed!"
        return 1
    fi
}

# Function to build services in parallel
build_parallel() {
    local pids=()
    local failed_services=()
    
    for service in "${SERVICES_TO_BUILD[@]}"; do
        # Wait if we've reached max parallel jobs
        while [[ ${#pids[@]} -ge $MAX_PARALLEL ]]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}"
                    local exit_code=$?
                    if [[ $exit_code -ne 0 ]]; then
                        failed_services+=("${service_names[$i]}")
                    fi
                    unset pids[$i]
                    unset service_names[$i]
                fi
            done
            sleep 1
        done
        
        # Start build in background
        build_service "$service" &
        pids+=($!)
        service_names+=("$service")
    done
    
    # Wait for remaining builds
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}"
        local exit_code=$?
        if [[ $exit_code -ne 0 ]]; then
            failed_services+=("${service_names[$i]}")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        print_status "$RED" "Failed services: ${failed_services[*]}"
        return 1
    fi
    
    return 0
}

# Set up Docker buildx if not already configured
if ! docker buildx ls | grep -q "fks_builder"; then
    print_status "$YELLOW" "Setting up Docker buildx..."
    docker buildx create --name fks_builder --use
    docker buildx inspect --bootstrap
fi

# Main build process
print_status "$GREEN" "Starting build process..."

if [[ "$PARALLEL_BUILD" == "true" ]]; then
    print_status "$BLUE" "Building in parallel with max $MAX_PARALLEL jobs..."
    if build_parallel; then
        print_status "$GREEN" "All builds completed successfully!"
    else
        print_status "$RED" "Some builds failed!"
        exit 1
    fi
else
    # Sequential build
    failed_services=()
    for service in "${SERVICES_TO_BUILD[@]}"; do
        if ! build_service "$service"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        print_status "$RED" "Failed services: ${failed_services[*]}"
        exit 1
    else
        print_status "$GREEN" "All builds completed successfully!"
    fi
fi

# Summary
print_status "$BLUE" "Build Summary:"
echo "- Version: $VERSION"
echo "- Services built: ${#SERVICES_TO_BUILD[@]}"
echo "- Images pushed: $PUSH_IMAGES"

if [[ "$PUSH_IMAGES" == "true" ]]; then
    print_status "$YELLOW" "Images have been pushed to ${DOCKER_USERNAME}/${DOCKER_REPOSITORY}"
fi