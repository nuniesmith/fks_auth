#!/usr/bin/env bash
# build-images.sh - Build script for FKS Docker templates

set -euo pipefail

# Configuration
REGISTRY="${REGISTRY:-localhost:5000}"
PROJECT_NAME="${PROJECT_NAME:-fks}"
BUILD_VERSION="${BUILD_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo 'dev')}"
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
BUILD_TYPE="${BUILD_TYPE:-cpu}"
PUSH_IMAGES="${PUSH_IMAGES:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [TEMPLATES...]

Build Docker images from templates.

OPTIONS:
    -r, --registry REGISTRY    Docker registry (default: localhost:5000)
    -v, --version VERSION      Build version (default: git short hash)
    -t, --type TYPE           Build type: cpu or gpu (default: cpu)
    -p, --push                Push images to registry
    -h, --help                Show this help

TEMPLATES:
    python, rust, dotnet, node, nginx, base
    If no templates specified, builds all

EXAMPLES:
    $0 python rust                    # Build Python and Rust templates
    $0 --type gpu python              # Build Python with GPU support
    $0 --push --version 1.0.0 python # Build and push Python image

ENVIRONMENT VARIABLES:
    REGISTRY      - Docker registry
    BUILD_VERSION - Version tag
    BUILD_TYPE    - cpu or gpu
    PUSH_IMAGES   - true to push images
EOF
}

# Parse command line arguments
TEMPLATES=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -v|--version)
            BUILD_VERSION="$2"
            shift 2
            ;;
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_IMAGES="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            log_error "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            TEMPLATES+=("$1")
            shift
            ;;
    esac
done

# If no templates specified, build all
if [ ${#TEMPLATES[@]} -eq 0 ]; then
    TEMPLATES=("base" "python" "rust" "dotnet" "node" "nginx")
fi

# Validate build type
if [[ "$BUILD_TYPE" != "cpu" && "$BUILD_TYPE" != "gpu" ]]; then
    log_error "Build type must be 'cpu' or 'gpu'"
    exit 1
fi

# Function to build a single template
build_template() {
    local template="$1"
    local dockerfile="Dockerfile.${template}"
    
    if [[ ! -f "$dockerfile" ]]; then
        log_warn "Template $template not found, skipping"
        return 1
    fi
    
    local image_name="${REGISTRY}/${PROJECT_NAME}-${template}"
    local tags=(
        "${image_name}:${BUILD_VERSION}-${BUILD_TYPE}"
        "${image_name}:latest-${BUILD_TYPE}"
    )
    
    # Add latest tag for CPU builds
    if [[ "$BUILD_TYPE" == "cpu" ]]; then
        tags+=("${image_name}:latest")
    fi
    
    log_info "Building $template template..."
    log_info "  Image: $image_name"
    log_info "  Tags: ${tags[*]}"
    log_info "  Type: $BUILD_TYPE"
    
    # Build arguments
    local build_args=(
        --build-arg "BUILD_TYPE=${BUILD_TYPE}"
        --build-arg "BUILD_VERSION=${BUILD_VERSION}"
        --build-arg "BUILD_DATE=${BUILD_DATE}"
        --build-arg "BUILD_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
    )
    
    # Add template-specific build args
    case "$template" in
        "python")
            build_args+=(--build-arg "PYTHON_VERSION=3.13")
            ;;
        "rust")
            build_args+=(--build-arg "RUST_VERSION=1.81")
            ;;
        "dotnet")
            build_args+=(--build-arg "DOTNET_VERSION=9.0")
            ;;
        "node")
            build_args+=(--build-arg "NODE_VERSION=22")
            ;;
        "nginx")
            build_args+=(--build-arg "NGINX_VERSION=1.27.1")
            ;;
    esac
    
    # Build command
    local build_cmd=(
        docker build
        "${build_args[@]}"
        -f "$dockerfile"
    )
    
    # Add tags to build command
    for tag in "${tags[@]}"; do
        build_cmd+=(-t "$tag")
    done
    
    # Add build context
    build_cmd+=(.)
    
    if "${build_cmd[@]}"; then
        log_success "Built $template successfully"
        
        # Push if requested
        if [[ "$PUSH_IMAGES" == "true" ]]; then
            log_info "Pushing $template images..."
            for tag in "${tags[@]}"; do
                docker push "$tag" && log_success "Pushed $tag"
            done
        fi
        
        return 0
    else
        log_error "Failed to build $template"
        return 1
    fi
}

# Main build loop
log_info "Starting build process..."
log_info "Registry: $REGISTRY"
log_info "Version: $BUILD_VERSION"
log_info "Build type: $BUILD_TYPE"
log_info "Push images: $PUSH_IMAGES"
log_info "Templates: ${TEMPLATES[*]}"

failed_builds=()
successful_builds=()

for template in "${TEMPLATES[@]}"; do
    if build_template "$template"; then
        successful_builds+=("$template")
    else
        failed_builds+=("$template")
    fi
done

# Summary
echo
log_info "Build Summary:"
if [ ${#successful_builds[@]} -gt 0 ]; then
    log_success "Successful builds: ${successful_builds[*]}"
fi
if [ ${#failed_builds[@]} -gt 0 ]; then
    log_error "Failed builds: ${failed_builds[*]}"
    exit 1
else
    log_success "All builds completed successfully!"
fi
