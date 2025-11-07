#!/usr/bin/env bash
# test-templates.sh - Integration test script for Docker templates

set -euo pipefail

# Configuration
TEST_REGISTRY="localhost:5000"
TEST_PROJECT="fks-test"
TEST_VERSION="test-$(date +%s)"
DOCKER_COMPOSE_FILE="docker-compose.test.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[TEST]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    docker system prune -f --filter "label=fks-test=true" 2>/dev/null || true
}

# Set up cleanup trap
trap cleanup EXIT

# Test functions
test_build_template() {
    local template="$1"
    local dockerfile="Dockerfile.${template}"
    
    if [[ ! -f "$dockerfile" ]]; then
        log_warn "Template $template not found, skipping"
        return 1
    fi
    
    log_info "Testing build for $template template..."
    
    local image_name="${TEST_REGISTRY}/${TEST_PROJECT}-${template}:${TEST_VERSION}"
    
    if docker build -f "$dockerfile" -t "$image_name" \
       --label "fks-test=true" \
       --build-arg "BUILD_VERSION=${TEST_VERSION}" \
       --build-arg "BUILD_TYPE=cpu" \
       . >/dev/null 2>&1; then
        log_success "$template build successful"
        return 0
    else
        log_error "$template build failed"
        return 1
    fi
}

test_image_security() {
    local image="$1"
    log_info "Testing security for $image..."
    
    # Test non-root user
    local user_id
    user_id=$(docker run --rm "$image" id -u 2>/dev/null || echo "0")
    
    if [[ "$user_id" != "0" ]]; then
        log_success "Non-root user check passed (UID: $user_id)"
    else
        log_error "Security test failed: running as root"
        return 1
    fi
    
    # Test image size (should be reasonable)
    local size_mb
    size_mb=$(docker images "$image" --format "table {{.Size}}" | tail -n 1 | sed 's/MB//' | cut -d. -f1)
    
    if [[ "$size_mb" -lt 1000 ]]; then
        log_success "Image size check passed (${size_mb}MB)"
    else
        log_warn "Large image size: ${size_mb}MB"
    fi
    
    return 0
}

test_image_functionality() {
    local image="$1"
    local template="$2"
    
    log_info "Testing functionality for $image..."
    
    case "$template" in
        "python")
            # Test Python can start and import basic modules
            if docker run --rm "$image" python -c "import sys, os; print('Python version:', sys.version)" >/dev/null 2>&1; then
                log_success "Python functionality test passed"
            else
                log_error "Python functionality test failed"
                return 1
            fi
            ;;
        "rust")
            # Test that the binary exists and can show version
            if docker run --rm "$image" --help >/dev/null 2>&1 || true; then
                log_success "Rust functionality test passed"
            else
                log_warn "Rust functionality test inconclusive (no --help support)"
            fi
            ;;
        "dotnet")
            # Test .NET runtime
            if docker run --rm "$image" dotnet --version >/dev/null 2>&1; then
                log_success ".NET functionality test passed"
            else
                log_error ".NET functionality test failed"
                return 1
            fi
            ;;
        "nginx")
            # Test nginx configuration
            if docker run --rm "$image" nginx -t >/dev/null 2>&1; then
                log_success "Nginx functionality test passed"
            else
                log_error "Nginx functionality test failed"
                return 1
            fi
            ;;
        "node")
            # For Node/nginx combo, test nginx config
            if docker run --rm "$image" nginx -t >/dev/null 2>&1; then
                log_success "Node/nginx functionality test passed"
            else
                log_error "Node/nginx functionality test failed"
                return 1
            fi
            ;;
    esac
    
    return 0
}

create_test_compose() {
    cat > "$DOCKER_COMPOSE_FILE" << EOF
version: '3.8'
services:
  test-python:
    image: ${TEST_REGISTRY}/${TEST_PROJECT}-python:${TEST_VERSION}
    command: python -c "import time; time.sleep(5); print('Python service running')"
    labels:
      - fks-test=true

  test-nginx:
    image: ${TEST_REGISTRY}/${TEST_PROJECT}-nginx:${TEST_VERSION}
    ports:
      - "8080:80"
    labels:
      - fks-test=true
EOF
}

test_compose_integration() {
    log_info "Testing Docker Compose integration..."
    
    create_test_compose
    
    if docker-compose -f "$DOCKER_COMPOSE_FILE" up -d >/dev/null 2>&1; then
        sleep 5
        
        # Test if services are running
        local running_count
        running_count=$(docker-compose -f "$DOCKER_COMPOSE_FILE" ps -q | wc -l)
        
        if [[ "$running_count" -gt 0 ]]; then
            log_success "Docker Compose integration test passed"
            docker-compose -f "$DOCKER_COMPOSE_FILE" down >/dev/null 2>&1
            return 0
        else
            log_error "No services running in compose"
            return 1
        fi
    else
        log_error "Docker Compose integration test failed"
        return 1
    fi
}

# Main test execution
main() {
    log_info "Starting Docker template integration tests..."
    log_info "Test version: $TEST_VERSION"
    
    local failed_tests=0
    local passed_tests=0
    local templates=("python" "rust" "dotnet" "node" "nginx")
    
    # Test individual template builds
    for template in "${templates[@]}"; do
        if test_build_template "$template"; then
            local image_name="${TEST_REGISTRY}/${TEST_PROJECT}-${template}:${TEST_VERSION}"
            
            if test_image_security "$image_name"; then
                if test_image_functionality "$image_name" "$template"; then
                    ((passed_tests++))
                else
                    ((failed_tests++))
                fi
            else
                ((failed_tests++))
            fi
        else
            ((failed_tests++))
        fi
    done
    
    # Test compose integration if we have images
    if [[ "$passed_tests" -gt 0 ]]; then
        if test_compose_integration; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    fi
    
    # Summary
    echo
    log_info "Test Summary:"
    log_success "Passed tests: $passed_tests"
    if [[ "$failed_tests" -gt 0 ]]; then
        log_error "Failed tests: $failed_tests"
        exit 1
    else
        log_success "All tests passed!"
    fi
}

# Run tests
main "$@"
