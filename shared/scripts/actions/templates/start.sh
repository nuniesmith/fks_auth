#!/bin/bash

# Universal Service Startup Script Template
# This script can be customized for any service by setting SERVICE_NAME

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - can be overridden by environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ENV_FILE="$PROJECT_ROOT/.env"

# Service configuration - should be set by each service
SERVICE_NAME="${SERVICE_NAME:-unknown}"
SERVICE_DISPLAY_NAME="${SERVICE_DISPLAY_NAME:-$SERVICE_NAME}"
DEFAULT_HTTP_PORT="${DEFAULT_HTTP_PORT:-80}"
DEFAULT_HTTPS_PORT="${DEFAULT_HTTPS_PORT:-443}"

# Docker Hub configuration
DOCKER_NAMESPACE="${DOCKER_NAMESPACE:-nuniesmith}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"

# Environment detection
detect_environment() {
    # Check if we're in a cloud environment
    if [ -f /etc/cloud-id ] || [ -f /var/lib/cloud/data/instance-id ] || [ -n "$AWS_INSTANCE_ID" ] || [ -n "$GCP_PROJECT" ] || [ -n "$AZURE_SUBSCRIPTION_ID" ]; then
        echo "cloud"
        return
    fi
    
    # Check if we're in a container (dev server might be containerized)
    if [ -f /.dockerenv ] || [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        echo "container"
        return
    fi
    
    # Check system resources to detect if we're on a resource-constrained environment
    if command -v free &> /dev/null; then
        local total_mem=$(free -m | awk '/^Mem:/{print $2}')
        if [ "$total_mem" -lt 4096 ]; then  # Less than 4GB RAM
            echo "resource_constrained"
            return
        fi
    fi
    
    # Check hostname patterns that might indicate a dev server
    local hostname=$(hostname)
    if [[ "$hostname" =~ (dev|staging|cloud|vps|server) ]]; then
        echo "dev_server"
        return
    fi
    
    # Check if we have a .laptop or .local file marker
    if [ -f "$HOME/.laptop" ] || [ -f "$PROJECT_ROOT/.local" ]; then
        echo "laptop"
        return
    fi
    
    # Default to cloud for service deployment
    echo "cloud"
}

# Determine build strategy based on environment
DETECTED_ENV=$(detect_environment)
if [ -z "$BUILD_LOCAL" ]; then
    case "$DETECTED_ENV" in
        "cloud"|"container"|"resource_constrained"|"dev_server")
            BUILD_LOCAL="false"
            ;;
        "laptop")
            BUILD_LOCAL="true"
            ;;
        *)
            BUILD_LOCAL="false"
            ;;
    esac
fi

# Simple logging
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log "ERROR" "Docker is not installed!"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log "ERROR" "Docker is not running!"
        exit 1
    fi
    
    # Check Docker Compose
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
        log "INFO" "Using modern Docker Compose (docker compose)"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        log "INFO" "Using legacy Docker Compose (docker-compose)"
    else
        log "ERROR" "Docker Compose is not available!"
        exit 1
    fi
    
    log "INFO" "Prerequisites check passed"
}

# Create environment file
create_env_file() {
    log "INFO" "Creating environment file..."
    
    # Find available port for monitoring (starting from 19999)
    MONITORING_PORT=19999
    while netstat -tlnp 2>/dev/null | grep -q ":${MONITORING_PORT} "; do
        MONITORING_PORT=$((MONITORING_PORT + 1))
        if [ $MONITORING_PORT -gt 20010 ]; then
            log "WARN" "Could not find available port for monitoring, using 19999 anyway"
            MONITORING_PORT=19999
            break
        fi
    done
    
    if [ $MONITORING_PORT -ne 19999 ]; then
        log "INFO" "Port 19999 is in use, using port $MONITORING_PORT for monitoring"
    fi
    
    # Create service-specific environment file
    cat > "$ENV_FILE" << EOF
# ${SERVICE_DISPLAY_NAME} Service Environment
COMPOSE_PROJECT_NAME=${SERVICE_NAME}
ENVIRONMENT=production
APP_ENV=production
NODE_ENV=production

# Service Configuration
SERVICE_NAME=${SERVICE_NAME}
HTTP_PORT=${DEFAULT_HTTP_PORT}
HTTPS_PORT=${DEFAULT_HTTPS_PORT}

# Monitoring Configuration
NETDATA_PORT=$MONITORING_PORT
MONITORING_PORT=$MONITORING_PORT

# SSL Configuration
SSL_EMAIL=admin@7gram.xyz
DOMAIN_NAME=${SERVICE_NAME}.7gram.xyz
LETSENCRYPT_EMAIL=admin@7gram.xyz

# Docker Hub
DOCKER_NAMESPACE=$DOCKER_NAMESPACE
DOCKER_REGISTRY=$DOCKER_REGISTRY

# Timezone
TZ=America/Toronto
EOF
    
    # Allow services to add custom environment variables
    if declare -f "create_custom_env" > /dev/null; then
        create_custom_env >> "$ENV_FILE"
    fi
    
    log "INFO" "Environment file created"
}

# Docker networking check
check_docker_networking() {
    log "INFO" "🔧 Checking Docker networking..."
    
    # For non-root users in docker group, we can't check iptables directly
    # Instead, we'll test Docker networking functionality
    if ! docker network ls >/dev/null 2>&1; then
        log "ERROR" "❌ Docker is not accessible. Please ensure Docker is running and you're in the docker group."
        exit 1
    fi
    
    # In GitHub Actions deployment or service user context, skip network creation test
    # since networks are handled by the deployment workflow
    local current_user="${USER:-$(whoami)}"
    if [ -n "$GITHUB_ACTIONS" ] || [[ "$current_user" =~ .*_user$ ]] || [ "$current_user" = "root" ]; then
        log "INFO" "✅ Docker networking check skipped (deployment environment)"
        return 0
    fi
    
    # Test if we can create a test network (only for local environments)
    local test_network="test-network-$$"
    if ! docker network create --driver bridge "$test_network" >/dev/null 2>&1; then
        log "WARN" "⚠️ Docker networking appears to be broken."
        log "INFO" "🔧 Attempting to fix Docker networking without sudo..."
        
        # Stop all containers
        log "INFO" "Stopping all containers..."
        docker stop $(docker ps -aq) 2>/dev/null || true
        
        # Remove all containers
        docker rm $(docker ps -aq) 2>/dev/null || true
        
        # Clean up Docker networks
        log "INFO" "Cleaning up Docker networks..."
        docker network prune -f >/dev/null 2>&1 || true
        
        log "ERROR" "❌ Docker networking issues detected. This requires administrative privileges to fix."
        log "ERROR" "Please contact your system administrator to run:"
        log "ERROR" "  sudo systemctl restart docker"
        exit 1
    else
        # Remove the test network
        docker network rm "$test_network" >/dev/null 2>&1 || true
        log "INFO" "✅ Docker networking is properly configured"
    fi
}

# Clean up existing service network
cleanup_service_network() {
    local network_name="${SERVICE_NAME}-network"
    
    if docker network inspect "$network_name" >/dev/null 2>&1; then
        if [ -z "$(docker network inspect "$network_name" -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null)" ]; then
            log "INFO" "Removing existing $network_name to let docker-compose recreate it..."
            docker network rm "$network_name" 2>/dev/null || true
        fi
    fi
}

# Docker authentication
docker_login() {
    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_TOKEN" ]; then
        log "INFO" "🔐 Logging into Docker Hub..."
        echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
    fi
}

# Build or pull images
handle_images() {
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "🏗️ Building images locally..."
        $COMPOSE_CMD build --parallel
    else
        log "INFO" "🐳 Pulling images from Docker Hub..."
        
        # Force pull latest images
        log "INFO" "🔄 Pulling latest images from Docker Hub..."
        if $COMPOSE_CMD pull --ignore-pull-failures 2>&1 | tee /tmp/docker-pull.log; then
            log "INFO" "✅ Images pulled successfully"
        else
            log "WARN" "⚠️ Failed to pull images, will build locally as fallback"
            log "INFO" "🏗️ Building images locally..."
            $COMPOSE_CMD build --parallel
        fi
    fi
}

# Test service connectivity
test_connectivity() {
    log "INFO" "🔌 Testing connectivity..."
    
    # Test HTTP port
    if curl -s -f "http://localhost:${DEFAULT_HTTP_PORT}" >/dev/null 2>&1; then
        log "INFO" "✅ ${SERVICE_DISPLAY_NAME} HTTP is accessible at http://localhost:${DEFAULT_HTTP_PORT}"
    else
        log "WARN" "⚠️ ${SERVICE_DISPLAY_NAME} HTTP not yet accessible (may still be starting)"
    fi
    
    # Test HTTPS port
    if curl -s -k -f "https://localhost:${DEFAULT_HTTPS_PORT}" >/dev/null 2>&1; then
        log "INFO" "✅ ${SERVICE_DISPLAY_NAME} HTTPS is accessible at https://localhost:${DEFAULT_HTTPS_PORT}"
    else
        log "WARN" "⚠️ ${SERVICE_DISPLAY_NAME} HTTPS not yet accessible (SSL may still be configuring)"
    fi
}

# Main function
main() {
    # Parse command line arguments first
    parse_args "$@"
    
    log "INFO" "🌐 Starting ${SERVICE_DISPLAY_NAME}..."
    
    # Show detected environment
    log "INFO" "🔍 Detected environment: $DETECTED_ENV"
    
    # Show build strategy
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "📦 Build strategy: LOCAL (building images on this machine)"
    else
        log "INFO" "📦 Build strategy: REMOTE (pulling from Docker Hub)"
    fi
    
    # Change to project directory
    cd "$PROJECT_ROOT"
    
    # Check prerequisites
    check_prerequisites
    
    # Create .env file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        create_env_file
    else
        log "INFO" "Using existing .env file"
    fi
    
    # Stop existing services
    log "INFO" "Stopping existing services..."
    $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
    
    # Check Docker networking
    check_docker_networking
    
    # Clean up service network
    cleanup_service_network
    
    # Docker login
    docker_login
    
    # Handle images (build or pull)
    handle_images
    
    # Start services
    log "INFO" "🚀 Starting ${SERVICE_DISPLAY_NAME} Services..."
    
    # Start services in detached mode
    $COMPOSE_CMD up -d
    
    # Wait for services to start
    log "INFO" "⏳ Waiting for services to initialize..."
    sleep 10
    
    # Show status
    log "INFO" "📊 Service status:"
    $COMPOSE_CMD ps
    
    # Test connectivity
    test_connectivity
    
    log "INFO" "🎉 ${SERVICE_DISPLAY_NAME} startup complete!"
    log "INFO" "🌐 HTTP: http://localhost:${DEFAULT_HTTP_PORT}"
    log "INFO" "🔒 HTTPS: https://localhost:${DEFAULT_HTTPS_PORT}"
    log "INFO" "📝 View logs: docker compose logs -f"
    log "INFO" "🛑 Stop services: docker compose down"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --set-laptop)
                touch "$PROJECT_ROOT/.local"
                log "INFO" "Created .local marker file. This environment will now be detected as 'laptop'."
                exit 0
                ;;
            --show-env)
                show_environment_info
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done
}

show_help() {
    echo "${SERVICE_DISPLAY_NAME} Startup Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --set-laptop        Mark this environment as a laptop (creates .local file)"
    echo "  --show-env          Show detected environment and exit"
    echo ""
    echo "Environment Variables:"
    echo "  BUILD_LOCAL=true/false    Override automatic build strategy detection"
    echo "  DOCKER_NAMESPACE=name     Docker Hub namespace (default: nuniesmith)"
    echo "  DOCKER_REGISTRY=registry  Docker registry (default: docker.io)"
    echo "  DOCKER_USERNAME=user      Docker Hub username for login"
    echo "  DOCKER_TOKEN=token        Docker Hub token for login"
    echo ""
}

show_environment_info() {
    echo "Service: $SERVICE_DISPLAY_NAME"
    echo "Detected environment: $DETECTED_ENV"
    echo "Build strategy: $([ "$BUILD_LOCAL" = "true" ] && echo "LOCAL" || echo "REMOTE")"
    echo ""
    echo "System information:"
    if command -v free &> /dev/null; then
        echo "  Memory: $(free -m | awk '/^Mem:/{print $2}') MB"
    fi
    echo "  Hostname: $(hostname)"
    echo "  User: $USER"
    if [ -f "$PROJECT_ROOT/.local" ]; then
        echo "  .local marker: Present"
    else
        echo "  .local marker: Not found"
    fi
}

# Allow services to define custom functions before calling main
# Services can override these functions by defining them before sourcing this script

# Custom environment variables function (override in service script)
create_custom_env() {
    # Override this function in service-specific script to add custom env vars
    true
}

# Only run main if this script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Default service name if not set
    if [ "$SERVICE_NAME" = "unknown" ]; then
        log "ERROR" "SERVICE_NAME must be set before running this script"
        exit 1
    fi
    
    # Run main function
    main "$@"
fi
