#!/bin/bash
# FKS Service Management Template Script
# Standardized script for managing FKS microservices

set -euo pipefail

# FKS Script Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/logs/${SCRIPT_NAME%.*}.log"

# FKS Standard Environment Variables (with defaults)
export FKS_SERVICE_NAME="${FKS_SERVICE_NAME:-fks-service}"
export FKS_SERVICE_TYPE="${FKS_SERVICE_TYPE:-api}"
export FKS_SERVICE_PORT="${FKS_SERVICE_PORT:-8000}"
export FKS_ENVIRONMENT="${FKS_ENVIRONMENT:-development}"
export FKS_LOG_LEVEL="${FKS_LOG_LEVEL:-INFO}"
export FKS_HEALTH_CHECK_PATH="${FKS_HEALTH_CHECK_PATH:-/health}"
export FKS_METRICS_PATH="${FKS_METRICS_PATH:-/metrics}"
export FKS_CONFIG_PATH="${FKS_CONFIG_PATH:-./config}"
export FKS_DATA_PATH="${FKS_DATA_PATH:-./data}"

# Docker and Compose Configuration
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1
export FKS_REGISTRY="${FKS_REGISTRY:-ghcr.io/nuniesmith}"
export FKS_IMAGE_TAG="${FKS_IMAGE_TAG:-latest}"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Emoji constants
readonly CHECK_MARK="✅"
readonly CROSS_MARK="❌"
readonly WARNING="⚠️"
readonly INFO="ℹ️"
readonly ROCKET="🚀"
readonly WRENCH="🔧"
readonly MICROSCOPE="🔬"
readonly SHIELD="🛡️"

# Initialize logging
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
}

# Logging functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&3
}

log_info() {
    log "${INFO} ${BLUE}INFO${NC}: $*"
}

log_success() {
    log "${CHECK_MARK} ${GREEN}SUCCESS${NC}: $*"
}

log_warning() {
    log "${WARNING} ${YELLOW}WARNING${NC}: $*"
}

log_error() {
    log "${CROSS_MARK} ${RED}ERROR${NC}: $*"
}

log_debug() {
    if [[ "${FKS_LOG_LEVEL:-INFO}" == "DEBUG" ]]; then
        log "${MICROSCOPE} ${PURPLE}DEBUG${NC}: $*"
    fi
}

# Error handling
error_handler() {
    local line_number=$1
    log_error "Script failed at line $line_number"
    exit 1
}

trap 'error_handler $LINENO' ERR

# FKS Service Detection
detect_service_type() {
    local service_name="$FKS_SERVICE_NAME"
    
    case "$service_name" in
        fks-api) echo "python" ;;
        fks-auth) echo "python" ;;
        fks-data) echo "python" ;;
        fks-engine) echo "python" ;;
        fks-training) echo "python" ;;
        fks-transformer) echo "python" ;;
        fks-worker) echo "python" ;;
        fks-execution|fks-nodes|fks-config) echo "rust" ;;
        fks-ninja) echo "dotnet" ;;
        fks-web) echo "react" ;;
        fks-nginx) echo "nginx" ;;
        *) echo "generic" ;;
    esac
}

get_service_port() {
    local service_name="$FKS_SERVICE_NAME"
    
    case "$service_name" in
        fks-api) echo "8001" ;;
        fks-auth) echo "8002" ;;
        fks-data) echo "8003" ;;
        fks-engine) echo "8004" ;;
        fks-training) echo "8005" ;;
        fks-transformer) echo "8006" ;;
        fks-worker) echo "8007" ;;
        fks-execution|fks-nodes|fks-config|fks-ninja) echo "8080" ;;
        fks-web) echo "3000" ;;
        fks-nginx) echo "80" ;;
        *) echo "8000" ;;
    esac
}

# Health check functions
check_service_health() {
    local port="${1:-$(get_service_port)}"
    local host="${2:-localhost}"
    local endpoint="${3:-$FKS_HEALTH_CHECK_PATH}"
    
    log_info "Checking health of $FKS_SERVICE_NAME at $host:$port$endpoint"
    
    if curl -f -s --max-time 10 "http://$host:$port$endpoint" > /dev/null; then
        log_success "Service is healthy"
        return 0
    else
        log_error "Service health check failed"
        return 1
    fi
}

wait_for_service() {
    local port="${1:-$(get_service_port)}"
    local host="${2:-localhost}"
    local timeout="${3:-60}"
    
    log_info "Waiting for $FKS_SERVICE_NAME to be ready (timeout: ${timeout}s)"
    
    local counter=0
    while [[ $counter -lt $timeout ]]; do
        if check_service_health "$port" "$host"; then
            log_success "Service is ready after ${counter} seconds"
            return 0
        fi
        
        sleep 1
        ((counter++))
    done
    
    log_error "Service failed to start within $timeout seconds"
    return 1
}

# Docker operations
build_service() {
    local service_type
    service_type=$(detect_service_type)
    
    log_info "${WRENCH} Building $FKS_SERVICE_NAME ($service_type service)"
    
    local dockerfile="Dockerfile"
    if [[ ! -f "$dockerfile" ]]; then
        log_warning "No Dockerfile found, looking for template"
        dockerfile="../shared/templates/docker/Dockerfile.$service_type"
        
        if [[ ! -f "$dockerfile" ]]; then
            log_error "No Dockerfile template found for $service_type"
            return 1
        fi
    fi
    
    docker build \
        --build-arg "SERVICE_NAME=$FKS_SERVICE_NAME" \
        --build-arg "SERVICE_TYPE=$FKS_SERVICE_TYPE" \
        --build-arg "SERVICE_PORT=$(get_service_port)" \
        --tag "$FKS_REGISTRY/$FKS_SERVICE_NAME:$FKS_IMAGE_TAG" \
        --file "$dockerfile" \
        .
    
    log_success "Build completed for $FKS_SERVICE_NAME"
}

start_service() {
    log_info "${ROCKET} Starting $FKS_SERVICE_NAME"
    
    # Create required directories
    mkdir -p "$FKS_CONFIG_PATH" "$FKS_DATA_PATH"
    
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose up -d
    else
        docker run -d \
            --name "$FKS_SERVICE_NAME" \
            --port "$(get_service_port):$(get_service_port)" \
            --env "FKS_SERVICE_NAME=$FKS_SERVICE_NAME" \
            --env "FKS_SERVICE_TYPE=$FKS_SERVICE_TYPE" \
            --env "FKS_ENVIRONMENT=$FKS_ENVIRONMENT" \
            --env "FKS_LOG_LEVEL=$FKS_LOG_LEVEL" \
            --volume "$PWD/$FKS_CONFIG_PATH:/app/config" \
            --volume "$PWD/$FKS_DATA_PATH:/app/data" \
            "$FKS_REGISTRY/$FKS_SERVICE_NAME:$FKS_IMAGE_TAG"
    fi
    
    # Wait for service to be ready
    if wait_for_service; then
        log_success "Service started successfully"
    else
        log_error "Failed to start service"
        return 1
    fi
}

stop_service() {
    log_info "Stopping $FKS_SERVICE_NAME"
    
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose down
    else
        docker stop "$FKS_SERVICE_NAME" || true
        docker rm "$FKS_SERVICE_NAME" || true
    fi
    
    log_success "Service stopped"
}

restart_service() {
    log_info "Restarting $FKS_SERVICE_NAME"
    stop_service
    start_service
}

# Testing functions
run_tests() {
    local service_type
    service_type=$(detect_service_type)
    
    log_info "${MICROSCOPE} Running tests for $service_type service"
    
    case "$service_type" in
        "python")
            if [[ -f "pytest.ini" ]] || [[ -d "tests" ]]; then
                python -m pytest tests/ -v
            else
                log_warning "No pytest configuration found"
            fi
            ;;
        "rust")
            cargo test --all-features
            ;;
        "dotnet")
            dotnet test --configuration Release
            ;;
        "react")
            npm test -- --coverage --watchAll=false
            ;;
        *)
            log_warning "No test command defined for $service_type"
            ;;
    esac
    
    log_success "Tests completed"
}

# Monitoring functions
show_logs() {
    local lines="${1:-100}"
    
    log_info "Showing last $lines lines of logs"
    
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose logs --tail="$lines" -f
    else
        docker logs "$FKS_SERVICE_NAME" --tail="$lines" -f
    fi
}

show_metrics() {
    local port
    port=$(get_service_port)
    
    log_info "Fetching metrics from $FKS_SERVICE_NAME"
    
    if curl -s "http://localhost:$port$FKS_METRICS_PATH" | jq . 2>/dev/null; then
        log_success "Metrics retrieved successfully"
    else
        log_error "Failed to retrieve metrics"
        return 1
    fi
}

# Security functions
security_scan() {
    log_info "${SHIELD} Running security scan"
    
    local image="$FKS_REGISTRY/$FKS_SERVICE_NAME:$FKS_IMAGE_TAG"
    
    # Run Trivy scan
    if command -v trivy &> /dev/null; then
        trivy image "$image"
    else
        log_warning "Trivy not installed, skipping vulnerability scan"
    fi
    
    # Run Docker security scan (if available)
    if docker scout --help &> /dev/null; then
        docker scout cves "$image"
    else
        log_warning "Docker Scout not available, skipping security scan"
    fi
}

# Deployment functions
deploy_service() {
    local environment="${1:-$FKS_ENVIRONMENT}"
    
    log_info "${ROCKET} Deploying $FKS_SERVICE_NAME to $environment"
    
    # Build service
    build_service
    
    # Run tests
    run_tests
    
    # Security scan
    security_scan
    
    # Push to registry
    docker push "$FKS_REGISTRY/$FKS_SERVICE_NAME:$FKS_IMAGE_TAG"
    
    # Deploy based on environment
    case "$environment" in
        "production"|"staging")
            log_info "Deploying to $environment environment"
            # Add your deployment logic here
            ;;
        *)
            log_info "Starting service locally for $environment environment"
            restart_service
            ;;
    esac
    
    log_success "Deployment completed"
}

# Utility functions
show_status() {
    log_info "Status of $FKS_SERVICE_NAME:"
    echo
    echo "Service: $FKS_SERVICE_NAME"
    echo "Type: $(detect_service_type)"
    echo "Port: $(get_service_port)"
    echo "Environment: $FKS_ENVIRONMENT"
    echo "Registry: $FKS_REGISTRY"
    echo "Image Tag: $FKS_IMAGE_TAG"
    echo
    
    # Check if service is running
    if check_service_health; then
        echo "${CHECK_MARK} Service is running and healthy"
    else
        echo "${CROSS_MARK} Service is not running or unhealthy"
    fi
}

cleanup() {
    log_info "Cleaning up resources"
    
    # Remove containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    log_success "Cleanup completed"
}

# Help function
show_help() {
    cat << EOF
FKS Service Management Script

Usage: $SCRIPT_NAME <command> [options]

Commands:
  build                 Build the service Docker image
  start                 Start the service
  stop                  Stop the service
  restart               Restart the service
  test                  Run tests
  logs [lines]          Show service logs (default: 100 lines)
  health                Check service health
  metrics               Show service metrics
  status                Show service status
  deploy [env]          Deploy service to environment
  security-scan         Run security vulnerability scan
  cleanup               Clean up Docker resources
  help                  Show this help message

Environment Variables:
  FKS_SERVICE_NAME      Service name (default: fks-service)
  FKS_SERVICE_TYPE      Service type (default: api)
  FKS_SERVICE_PORT      Service port (auto-detected)
  FKS_ENVIRONMENT       Environment (default: development)
  FKS_LOG_LEVEL         Log level (default: INFO)
  FKS_REGISTRY          Docker registry (default: ghcr.io/nuniesmith)
  FKS_IMAGE_TAG         Docker image tag (default: latest)

Examples:
  $SCRIPT_NAME build
  $SCRIPT_NAME start
  $SCRIPT_NAME logs 50
  $SCRIPT_NAME deploy production
  FKS_LOG_LEVEL=DEBUG $SCRIPT_NAME start

EOF
}

# Main function
main() {
    init_logging
    
    local command="${1:-help}"
    shift || true
    
    log_info "Starting FKS service management for $FKS_SERVICE_NAME"
    log_debug "Command: $command, Args: $*"
    
    case "$command" in
        "build") build_service ;;
        "start") start_service ;;
        "stop") stop_service ;;
        "restart") restart_service ;;
        "test") run_tests ;;
        "logs") show_logs "$@" ;;
        "health") check_service_health ;;
        "metrics") show_metrics ;;
        "status") show_status ;;
        "deploy") deploy_service "$@" ;;
        "security-scan") security_scan ;;
        "cleanup") cleanup ;;
        "help"|"--help"|"-h") show_help ;;
        *)
            log_error "Unknown command: $command"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
