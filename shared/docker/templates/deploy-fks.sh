#!/usr/bin/env bash
# deploy-fks.sh - Complete deployment script for FKS Trading Systems

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
REGISTRY="${REGISTRY:-your-registry.com}"
VERSION="${VERSION:-latest}"
DRY_RUN="${DRY_RUN:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[DEPLOY]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

Deploy FKS Trading Systems using Docker templates.

COMMANDS:
    build      Build all Docker images
    deploy     Deploy services to environment
    monitor    Deploy monitoring stack
    test       Run integration tests
    status     Check deployment status
    logs       Show service logs
    stop       Stop all services
    cleanup    Clean up resources

OPTIONS:
    -e, --env ENV         Deployment environment (dev/staging/prod)
    -r, --registry REG    Docker registry
    -v, --version VER     Version to deploy
    -d, --dry-run         Show what would be done
    -h, --help           Show this help

EXAMPLES:
    $0 build                              # Build all images
    $0 deploy --env staging               # Deploy to staging
    $0 monitor                            # Deploy monitoring
    $0 test                              # Run tests
    $0 logs fks-api                      # Show API logs
    $0 --dry-run deploy                  # Preview deployment

ENVIRONMENT VARIABLES:
    DEPLOYMENT_ENV    - Target environment
    REGISTRY          - Docker registry
    VERSION           - Image version
    DRY_RUN          - Preview mode
EOF
}

# Validation functions
validate_environment() {
    case "$DEPLOYMENT_ENV" in
        dev|development|staging|prod|production)
            log_info "Deploying to environment: $DEPLOYMENT_ENV"
            ;;
        *)
            log_error "Invalid environment: $DEPLOYMENT_ENV"
            log_error "Valid environments: dev, staging, prod"
            exit 1
            ;;
    esac
}

check_prerequisites() {
    local missing=()
    
    command -v docker >/dev/null 2>&1 || missing+=("docker")
    command -v docker-compose >/dev/null 2>&1 || missing+=("docker-compose")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Please install missing tools and try again"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running or accessible"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

load_environment() {
    local env_file=".env.${DEPLOYMENT_ENV}"
    
    if [[ -f "$env_file" ]]; then
        log_info "Loading environment from $env_file"
        set -a
        source "$env_file"
        set +a
    elif [[ -f ".env" ]]; then
        log_info "Loading default environment from .env"
        set -a
        source ".env"
        set +a
    else
        log_warn "No environment file found, using defaults"
    fi
}

# Command functions
cmd_build() {
    log_info "Building Docker images..."
    
    local build_args=(
        --version "$VERSION"
        --registry "$REGISTRY"
    )
    
    if [[ "$DEPLOYMENT_ENV" == "dev" ]]; then
        build_args+=(--type cpu)
    elif [[ "$DEPLOYMENT_ENV" == "prod" ]]; then
        build_args+=(--push)
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ./build-images.sh ${build_args[*]}"
        return 0
    fi
    
    ./build-images.sh "${build_args[@]}"
    log_success "Build completed successfully"
}

cmd_deploy() {
    log_info "Deploying FKS Trading Systems..."
    
    local compose_files=(
        "-f docker-compose.example.yml"
    )
    
    # Add environment-specific overrides
    if [[ -f "docker-compose.${DEPLOYMENT_ENV}.yml" ]]; then
        compose_files+=("-f docker-compose.${DEPLOYMENT_ENV}.yml")
    fi
    
    local deploy_cmd=(
        docker-compose
        "${compose_files[@]}"
        up -d
        --remove-orphans
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ${deploy_cmd[*]}"
        return 0
    fi
    
    "${deploy_cmd[@]}"
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 10
    
    cmd_status
    log_success "Deployment completed successfully"
}

cmd_monitor() {
    log_info "Deploying monitoring stack..."
    
    local monitor_cmd=(
        docker-compose
        -f docker-compose.monitoring.yml
        up -d
        --remove-orphans
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ${monitor_cmd[*]}"
        return 0
    fi
    
    "${monitor_cmd[@]}"
    
    log_success "Monitoring stack deployed"
    log_info "Access points:"
    log_info "  - Grafana: http://localhost:3001"
    log_info "  - Prometheus: http://localhost:9090"
    log_info "  - AlertManager: http://localhost:9093"
}

cmd_test() {
    log_info "Running integration tests..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ./test-templates.sh"
        return 0
    fi
    
    ./test-templates.sh
    log_success "Tests completed successfully"
}

cmd_status() {
    log_info "Checking deployment status..."
    
    local compose_files=("-f docker-compose.example.yml")
    
    if [[ -f "docker-compose.${DEPLOYMENT_ENV}.yml" ]]; then
        compose_files+=("-f docker-compose.${DEPLOYMENT_ENV}.yml")
    fi
    
    echo
    log_info "Service Status:"
    docker-compose "${compose_files[@]}" ps
    
    echo
    log_info "Service Health:"
    docker-compose "${compose_files[@]}" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    
    # Check for unhealthy services
    local unhealthy
    unhealthy=$(docker-compose "${compose_files[@]}" ps --format "table {{.Name}}\t{{.Status}}" | grep -v "Up (healthy)" | grep "Up" || true)
    
    if [[ -n "$unhealthy" ]]; then
        log_warn "Some services are not healthy:"
        echo "$unhealthy"
    else
        log_success "All services are healthy"
    fi
}

cmd_logs() {
    local service="${1:-}"
    
    if [[ -z "$service" ]]; then
        log_info "Showing logs for all services..."
        docker-compose -f docker-compose.example.yml logs -f --tail=100
    else
        log_info "Showing logs for service: $service"
        docker-compose -f docker-compose.example.yml logs -f --tail=100 "$service"
    fi
}

cmd_stop() {
    log_info "Stopping FKS Trading Systems..."
    
    local stop_cmd=(
        docker-compose
        -f docker-compose.example.yml
        -f docker-compose.monitoring.yml
        down
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ${stop_cmd[*]}"
        return 0
    fi
    
    "${stop_cmd[@]}"
    log_success "Services stopped"
}

cmd_cleanup() {
    log_info "Cleaning up resources..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would clean up Docker resources"
        return 0
    fi
    
    # Stop services
    cmd_stop
    
    # Remove volumes (with confirmation)
    echo
    read -p "Remove persistent volumes? This will delete all data! (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose -f docker-compose.example.yml down -v
        docker-compose -f docker-compose.monitoring.yml down -v
        log_warn "Volumes removed"
    fi
    
    # Clean up unused images and containers
    docker system prune -f
    log_success "Cleanup completed"
}

# Parse command line arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env)
            DEPLOYMENT_ENV="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        build|deploy|monitor|test|status|logs|stop|cleanup)
            COMMAND="$1"
            shift
            break
            ;;
        -*)
            log_error "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            log_error "Unknown command $1"
            usage
            exit 1
            ;;
    esac
done

# Validate command
if [[ -z "$COMMAND" ]]; then
    log_error "No command specified"
    usage
    exit 1
fi

# Main execution
main() {
    cd "$SCRIPT_DIR"
    
    log_info "FKS Trading Systems Deployment"
    log_info "Command: $COMMAND"
    log_info "Environment: $DEPLOYMENT_ENV"
    log_info "Registry: $REGISTRY"
    log_info "Version: $VERSION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "DRY RUN MODE - No changes will be made"
    fi
    
    validate_environment
    check_prerequisites
    load_environment
    
    case "$COMMAND" in
        build)   cmd_build ;;
        deploy)  cmd_deploy ;;
        monitor) cmd_monitor ;;
        test)    cmd_test ;;
        status)  cmd_status ;;
        logs)    cmd_logs "$@" ;;
        stop)    cmd_stop ;;
        cleanup) cmd_cleanup ;;
        *)
            log_error "Invalid command: $COMMAND"
            exit 1
            ;;
    esac
}

main "$@"
