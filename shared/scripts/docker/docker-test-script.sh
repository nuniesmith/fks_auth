#!/bin/bash
# =================================================================
# Docker Build Test Script
# =================================================================
# This script tests Docker builds for different service types
# Usage: ./test-docker-build.sh [options]
# Options:
#   --quick     Quick test (build only)
#   --full      Full test (build and run)
#   --service   Test specific service
#   --cleanup   Clean up test images after

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-./deployment/docker/Dockerfile}"
TEST_PREFIX="test"
TEST_MODE="quick"
CLEANUP=false
SPECIFIC_SERVICE=""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            TEST_MODE="quick"
            shift
            ;;
        --full)
            TEST_MODE="full"
            shift
            ;;
        --service)
            SPECIFIC_SERVICE="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--quick|--full] [--service SERVICE] [--cleanup]"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Test results tracking
declare -A TEST_RESULTS
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Record test result
record_result() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"
    
    TEST_RESULTS["$test_name"]="$result|$details"
    ((TOTAL_TESTS++))
    
    if [ "$result" = "PASS" ]; then
        ((PASSED_TESTS++))
        log_success "$test_name: PASSED"
    else
        ((FAILED_TESTS++))
        log_error "$test_name: FAILED - $details"
    fi
}

# Service configurations
declare -A SERVICE_CONFIGS
SERVICE_CONFIGS=(
    ["api"]="python|8000|requirements.txt"
    ["worker"]="python|8001|requirements.txt"
    ["web"]="python|3000|requirements_web.txt"
    ["training"]="python|8088|requirements_gpu.txt"
    ["node"]="rust|9000|"
    ["gateway"]="hybrid|9001|"
    ["connector"]="hybrid|9002|"
)

# Test Docker compose files
test_compose_files() {
    log_info "Testing Docker Compose files..."
    
    for compose_file in docker-compose*.yml; do
        if [ -f "$compose_file" ]; then
            log_info "Validating $compose_file..."
            
            if docker-compose -f "$compose_file" config >/dev/null 2>&1; then
                record_result "compose-$compose_file" "PASS"
            else
                error_msg=$(docker-compose -f "$compose_file" config 2>&1 || true)
                record_result "compose-$compose_file" "FAIL" "Validation failed: $error_msg"
            fi
        fi
    done
}

# Test Docker build for a service
test_docker_build() {
    local service=$1
    local config="${SERVICE_CONFIGS[$service]:-python|8000|requirements.txt}"
    IFS='|' read -r runtime port requirements <<< "$config"
    
    log_info "Building $service (runtime: $runtime, port: $port)..."
    
    local image_name="${TEST_PREFIX}-${service}"
    local build_args=(
        --build-arg "SERVICE_TYPE=$service"
        --build-arg "SERVICE_RUNTIME=$runtime"
        --build-arg "SERVICE_PORT=$port"
        --build-arg "BUILD_TYPE=cpu"
        --build-arg "APP_ENV=test"
        --build-arg "BUILD_DATE=$(date -u +'%Y-%m-%d')"
        --build-arg "BUILD_VERSION=test"
    )
    
    if [ -n "$requirements" ]; then
        build_args+=(--build-arg "REQUIREMENTS_FILE=$requirements")
    fi
    
    # Add runtime-specific build args
    case "$runtime" in
        rust)
            build_args+=(--build-arg "BUILD_RUST_NETWORK=true")
            ;;
        hybrid)
            build_args+=(--build-arg "BUILD_RUST_NETWORK=true")
            build_args+=(--build-arg "BUILD_CONNECTOR=true")
            ;;
    esac
    
    # Build the image
    if docker build \
        "${build_args[@]}" \
        --target final \
        -t "$image_name" \
        -f "$DOCKERFILE_PATH" \
        . 2>&1 | tee "/tmp/docker-build-${service}.log"; then
        
        record_result "build-$service" "PASS"
        
        # If full test mode, try to run the container
        if [ "$TEST_MODE" = "full" ]; then
            test_docker_run "$service" "$image_name" "$port"
        fi
    else
        record_result "build-$service" "FAIL" "Build failed - check /tmp/docker-build-${service}.log"
    fi
}

# Test running a Docker container
test_docker_run() {
    local service=$1
    local image_name=$2
    local port=$3
    
    log_info "Testing container run for $service..."
    
    local container_name="${TEST_PREFIX}-run-${service}"
    
    # Remove any existing container
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    
    # Run container in background
    if docker run -d \
        --name "$container_name" \
        -p "${port}:${port}" \
        -e "SERVICE_TYPE=$service" \
        -e "APP_ENV=test" \
        -e "APP_LOG_LEVEL=DEBUG" \
        "$image_name" >/dev/null 2>&1; then
        
        # Wait for container to start
        sleep 5
        
        # Check if container is still running
        if docker ps -q -f "name=$container_name" | grep -q .; then
            # Try health check
            if docker exec "$container_name" /healthcheck.sh --port "$port" --timeout 5 >/dev/null 2>&1; then
                record_result "run-$service" "PASS"
            else
                logs=$(docker logs "$container_name" 2>&1 | tail -20)
                record_result "run-$service" "FAIL" "Health check failed. Logs: $logs"
            fi
        else
            logs=$(docker logs "$container_name" 2>&1 | tail -20)
            record_result "run-$service" "FAIL" "Container exited. Logs: $logs"
        fi
        
        # Cleanup
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    else
        record_result "run-$service" "FAIL" "Failed to start container"
    fi
}

# Test Nginx build
test_nginx_build() {
    log_info "Testing Nginx build..."
    
    local nginx_dockerfile="./deployment/docker/nginx/Dockerfile"
    if [ -f "$nginx_dockerfile" ]; then
        if docker build \
            --build-arg "DOMAIN_NAME=test.local" \
            --build-arg "ENABLE_SSL=true" \
            --build-arg "BUILD_DATE=$(date -u +'%Y-%m-%d')" \
            --build-arg "BUILD_VERSION=test" \
            -t "${TEST_PREFIX}-nginx" \
            -f "$nginx_dockerfile" \
            . 2>&1 | tee "/tmp/docker-build-nginx.log"; then
            
            record_result "build-nginx" "PASS"
            
            if [ "$TEST_MODE" = "full" ]; then
                test_nginx_run
            fi
        else
            record_result "build-nginx" "FAIL" "Build failed - check /tmp/docker-build-nginx.log"
        fi
    else
        record_result "build-nginx" "SKIP" "Nginx Dockerfile not found"
    fi
}

# Test Nginx run
test_nginx_run() {
    log_info "Testing Nginx container..."
    
    local container_name="${TEST_PREFIX}-run-nginx"
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    
    if docker run -d \
        --name "$container_name" \
        -p "8080:80" \
        -e "DOMAIN_NAME=test.local" \
        -e "ENABLE_SSL=false" \
        "${TEST_PREFIX}-nginx" >/dev/null 2>&1; then
        
        sleep 3
        
        if curl -sf "http://localhost:8080/health/" >/dev/null 2>&1; then
            record_result "run-nginx" "PASS"
        else
            logs=$(docker logs "$container_name" 2>&1 | tail -20)
            record_result "run-nginx" "FAIL" "Health check failed. Logs: $logs"
        fi
        
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    else
        record_result "run-nginx" "FAIL" "Failed to start container"
    fi
}

# Clean up test images
cleanup_test_images() {
    log_info "Cleaning up test images..."
    
    docker images --format "{{.Repository}}:{{.Tag}}" | grep "^${TEST_PREFIX}-" | while read -r image; do
        log_info "Removing $image..."
        docker rmi "$image" >/dev/null 2>&1 || true
    done
    
    # Also clean up any test containers
    docker ps -a --format "{{.Names}}" | grep "^${TEST_PREFIX}-" | while read -r container; do
        log_info "Removing container $container..."
        docker rm -f "$container" >/dev/null 2>&1 || true
    done
}

# Print test summary
print_summary() {
    echo
    echo "====================================="
    echo "        TEST SUMMARY"
    echo "====================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    echo
    
    if [ ${#TEST_RESULTS[@]} -gt 0 ]; then
        echo "Detailed Results:"
        echo "-----------------"
        for test_name in "${!TEST_RESULTS[@]}"; do
            IFS='|' read -r result details <<< "${TEST_RESULTS[$test_name]}"
            if [ "$result" = "PASS" ]; then
                echo -e "  ✅ ${test_name}: ${GREEN}PASSED${NC}"
            elif [ "$result" = "SKIP" ]; then
                echo -e "  ⏭️  ${test_name}: ${YELLOW}SKIPPED${NC} - $details"
            else
                echo -e "  ❌ ${test_name}: ${RED}FAILED${NC} - $details"
            fi
        done
    fi
    
    echo "====================================="
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    fi
}

# Main test execution
main() {
    log_info "Starting Docker build tests..."
    log_info "Test mode: $TEST_MODE"
    
    cd "$PROJECT_ROOT" || exit 1
    
    # Test compose files first
    test_compose_files
    
    # Test services
    if [ -n "$SPECIFIC_SERVICE" ]; then
        # Test specific service
        if [[ ${SERVICE_CONFIGS[$SPECIFIC_SERVICE]+isset} ]]; then
            test_docker_build "$SPECIFIC_SERVICE"
        else
            log_error "Unknown service: $SPECIFIC_SERVICE"
            exit 1
        fi
    else
        # Test all services
        for service in "${!SERVICE_CONFIGS[@]}"; do
            test_docker_build "$service"
        done
    fi
    
    # Test Nginx
    test_nginx_build
    
    # Cleanup if requested
    if [ "$CLEANUP" = "true" ]; then
        cleanup_test_images
    fi
    
    # Print summary
    print_summary
}

# Run main
main