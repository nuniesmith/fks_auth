#!/bin/bash

# Universal Service Startup Script Template
# This template can be used by any service and configured via environment variables

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service Configuration - Must be set by service or environment
SERVICE_NAME="${SERVICE_NAME:-}"
SERVICE_DISPLAY_NAME="${SERVICE_DISPLAY_NAME:-$SERVICE_NAME}"
DEFAULT_HTTP_PORT="${DEFAULT_HTTP_PORT:-80}"
DEFAULT_HTTPS_PORT="${DEFAULT_HTTPS_PORT:-443}"

# Service-specific features (can be overridden by service)
SUPPORTS_GPU="${SUPPORTS_GPU:-false}"
SUPPORTS_MINIMAL="${SUPPORTS_MINIMAL:-false}"
SUPPORTS_DEV="${SUPPORTS_DEV:-false}"
HAS_MULTIPLE_COMPOSE_FILES="${HAS_MULTIPLE_COMPOSE_FILES:-false}"
HAS_NETDATA="${HAS_NETDATA:-false}"
HAS_SSL="${HAS_SSL:-false}"

# Validate required configuration
if [ -z "$SERVICE_NAME" ]; then
    echo "❌ ERROR: SERVICE_NAME environment variable is required"
    echo "   Set SERVICE_NAME before running this script"
    exit 1
fi

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ENV_FILE="$PROJECT_ROOT/.env"

# Feature flags for service options
USE_GPU=false
USE_MINIMAL=false
USE_DEV=false

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
    
    # Default based on service type
    if [[ "$SERVICE_NAME" == "nginx" ]]; then
        echo "cloud"  # Nginx defaults to cloud deployment
    else
        echo "laptop"  # Other services default to laptop
    fi
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

# Create custom environment file (override this function in service-specific configs)
create_custom_env() {
    log "INFO" "Creating $SERVICE_DISPLAY_NAME environment file..."
    
    # Common environment variables for all services
    cat > "$ENV_FILE" << EOF
# $SERVICE_DISPLAY_NAME Environment
COMPOSE_PROJECT_NAME=$SERVICE_NAME
ENVIRONMENT=production
APP_ENV=production

# Service Ports
HTTP_PORT=$DEFAULT_HTTP_PORT
HTTPS_PORT=$DEFAULT_HTTPS_PORT

# Docker Hub
DOCKER_NAMESPACE=$DOCKER_NAMESPACE
DOCKER_REGISTRY=$DOCKER_REGISTRY

# Timezone
TZ=America/Toronto
EOF

    # Add Netdata configuration if supported
    if [ "$HAS_NETDATA" = "true" ]; then
        # Find available port for Netdata (starting from 19999)
        NETDATA_PORT=19999
        while netstat -tlnp 2>/dev/null | grep -q ":${NETDATA_PORT} "; do
            NETDATA_PORT=$((NETDATA_PORT + 1))
            if [ $NETDATA_PORT -gt 20010 ]; then
                log "WARN" "Could not find available port for Netdata, using 19999 anyway"
                NETDATA_PORT=19999
                break
            fi
        done
        
        echo "" >> "$ENV_FILE"
        echo "# Monitoring Configuration" >> "$ENV_FILE"
        echo "NETDATA_PORT=$NETDATA_PORT" >> "$ENV_FILE"
        
        if [ $NETDATA_PORT -ne 19999 ]; then
            log "INFO" "Port 19999 is in use, using port $NETDATA_PORT for Netdata"
        fi
    fi

    # Add SSL configuration if supported
    if [ "$HAS_SSL" = "true" ]; then
        echo "" >> "$ENV_FILE"
        echo "# SSL Configuration" >> "$ENV_FILE"
        echo "SSL_EMAIL=admin@7gram.xyz" >> "$ENV_FILE"
        echo "DOMAIN_NAME=${SERVICE_NAME}.7gram.xyz" >> "$ENV_FILE"
        echo "LETSENCRYPT_EMAIL=admin@7gram.xyz" >> "$ENV_FILE"
    fi
    
    log "INFO" "Environment file created"
}

# Check if GPU is available and properly configured (for services that support GPU)
check_gpu() {
    if [ "$SUPPORTS_GPU" != "true" ]; then
        return 1
    fi
    
    log "INFO" "Checking GPU requirements..."
    
    # Check if nvidia-smi is available
    if ! command -v nvidia-smi &> /dev/null; then
        log "ERROR" "nvidia-smi not found. Please ensure NVIDIA drivers are installed."
        return 1
    fi

    # Check if GPU is detected
    if ! nvidia-smi &> /dev/null; then
        log "ERROR" "No NVIDIA GPU detected or driver issues found."
        return 1
    fi

    # Get GPU info
    local gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)
    local gpu_memory=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
    log "INFO" "GPU detected: $gpu_name (${gpu_memory}MB memory)"

    # Check if nvidia-docker is available
    if ! docker info 2> /dev/null | grep -i nvidia > /dev/null; then
        log "ERROR" "NVIDIA Docker runtime not found. Please install nvidia-docker2."
        return 1
    fi

    # Test GPU access in Docker
    log "INFO" "Testing GPU access in Docker..."
    if ! docker run --rm --gpus all nvidia/cuda:12.1.0-base-ubuntu22.04 nvidia-smi &> /dev/null; then
        log "ERROR" "GPU access test failed. Docker cannot access GPU."
        return 1
    fi

    log "INFO" "✅ GPU configuration validated successfully"
    return 0
}

# Test service connectivity (override this function for service-specific tests)
test_connectivity() {
    log "INFO" "🔌 Testing connectivity..."
    
    # Test HTTP port
    if curl -s -f http://localhost:$DEFAULT_HTTP_PORT >/dev/null 2>&1; then
        log "INFO" "✅ $SERVICE_DISPLAY_NAME HTTP is accessible at http://localhost:$DEFAULT_HTTP_PORT"
    else
        log "WARN" "⚠️ $SERVICE_DISPLAY_NAME HTTP not yet accessible (may still be starting)"
    fi
    
    # Test HTTPS port if SSL is supported
    if [ "$HAS_SSL" = "true" ]; then
        if curl -s -k -f https://localhost:$DEFAULT_HTTPS_PORT >/dev/null 2>&1; then
            log "INFO" "✅ $SERVICE_DISPLAY_NAME HTTPS is accessible at https://localhost:$DEFAULT_HTTPS_PORT"
        else
            log "WARN" "⚠️ $SERVICE_DISPLAY_NAME HTTPS not yet accessible (SSL may still be configuring)"
        fi
    fi
}

# Main function
main() {
    # Parse command line arguments first
    parse_args "$@"
    
    log "INFO" "🚀 Starting $SERVICE_DISPLAY_NAME..."
    
    # Show detected environment
    log "INFO" "🔍 Detected environment: $DETECTED_ENV"
    
    # Show build strategy
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "📦 Build strategy: LOCAL (building images on this machine)"
    else
        log "INFO" "📦 Build strategy: REMOTE (pulling from Docker Hub)"
    fi
    
    # Show configuration
    if [ "$USE_GPU" = "true" ] && [ "$SUPPORTS_GPU" = "true" ]; then
        log "INFO" "🎮 GPU support: ENABLED"
    fi
    if [ "$USE_DEV" = "true" ] && [ "$SUPPORTS_DEV" = "true" ]; then
        log "INFO" "🔧 Development mode: ENABLED"
    fi
    if [ "$USE_MINIMAL" = "true" ] && [ "$SUPPORTS_MINIMAL" = "true" ]; then
        log "INFO" "📦 Minimal mode: ENABLED"
    fi
    
    # Change to project directory
    cd "$PROJECT_ROOT"
    
    # Check prerequisites
    check_prerequisites
    
    # Create .env file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        create_custom_env
    else
        log "INFO" "Using existing .env file"
    fi
    
    # Stop existing services
    log "INFO" "Stopping existing services..."
    $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
    
    # Fix Docker networking if needed
    log "INFO" "🔧 Checking Docker networking..."
    
    # For non-root users in docker group, we can't check iptables directly
    # Instead, we'll test Docker networking functionality
    if ! docker network ls >/dev/null 2>&1; then
        log "ERROR" "❌ Docker is not accessible. Please ensure Docker is running and you're in the docker group."
        exit 1
    fi
    
    # In GitHub Actions deployment, skip network creation test since networks are handled by the deployment workflow
    if [ -n "$GITHUB_ACTIONS" ] || [ "$USER" = "${SERVICE_NAME}_user" ] || [ "$USER" = "root" ]; then
        log "INFO" "✅ Docker networking check skipped (deployment environment)"
    else
        # Test if we can create a test network (only for local environments)
        if ! docker network create --driver bridge test-network-$$$ >/dev/null 2>&1; then
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
            docker network rm test-network-$$$ >/dev/null 2>&1 || true
            log "INFO" "✅ Docker networking is properly configured"
        fi
    fi
    
    # Clean up any existing service network (skip in deployment environments to avoid iptables conflicts)
    if [ -n "$GITHUB_ACTIONS" ] || [ "$USER" = "${SERVICE_NAME}_user" ] || [ "$USER" = "root" ]; then
        log "INFO" "✅ Network cleanup skipped (deployment environment - avoiding iptables conflicts)"
    else
        if docker network inspect ${SERVICE_NAME}-network >/dev/null 2>&1; then
            if [ -z "$(docker network inspect ${SERVICE_NAME}-network -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null)" ]; then
                log "INFO" "Removing existing ${SERVICE_NAME}-network to let docker-compose recreate it..."
                docker network rm ${SERVICE_NAME}-network 2>/dev/null || true
            fi
        fi
    fi
    
    # Docker login if credentials are available
    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_TOKEN" ]; then
        log "INFO" "🔐 Logging into Docker Hub..."
        echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
    fi
    
    # Determine compose file strategy
    COMPOSE_FILES="-f docker-compose.yml"
    
    # Configure GPU services if requested and supported
    if [ "$USE_GPU" = "true" ] && [ "$SUPPORTS_GPU" = "true" ]; then
        log "INFO" "🎮 Checking GPU configuration..."
        if check_gpu; then
            log "INFO" "✅ GPU support enabled"
            if [ -f "$PROJECT_ROOT/docker-compose.gpu.yml" ]; then
                COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.gpu.yml"
                log "INFO" "📄 Added GPU-enabled compose file"
            else
                log "WARN" "⚠️ GPU compose file not found, falling back to default configuration"
            fi
        else
            log "WARN" "⚠️ GPU support requested but hardware/drivers not properly configured"
            log "WARN" "⚠️ Falling back to CPU-only mode"
            USE_GPU=false
        fi
    fi
    
    # Add development overrides if requested and supported
    if [ "$USE_DEV" = "true" ] && [ "$SUPPORTS_DEV" = "true" ]; then
        if [ -f "$PROJECT_ROOT/docker-compose.dev.yml" ]; then
            COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.dev.yml"
            log "INFO" "📄 Added development compose file"
        else
            log "WARN" "⚠️ Development compose file not found"
        fi
    fi
    
    # Use minimal configuration if requested and supported
    if [ "$USE_MINIMAL" = "true" ] && [ "$SUPPORTS_MINIMAL" = "true" ]; then
        if [ -f "$PROJECT_ROOT/docker-compose.minimal.yml" ]; then
            COMPOSE_FILES="-f docker-compose.minimal.yml"
            log "INFO" "📄 Using minimal compose configuration"
        else
            log "WARN" "⚠️ Minimal compose file not found, using default"
        fi
    fi
    
    # Override with pull-only for production environments
    if [ "$BUILD_LOCAL" != "true" ] && [ -f "$PROJECT_ROOT/docker-compose.pull-only.yml" ]; then
        # Use pull-only compose file for cloud/production environments
        COMPOSE_FILES="-f docker-compose.pull-only.yml"
        log "INFO" "📄 Using pull-only compose file for production deployment"
    fi
    
    # Determine build strategy
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "🏗️ Building images locally..."
        $COMPOSE_CMD $COMPOSE_FILES build --parallel
    else
        log "INFO" "🐳 Pulling images from Docker Hub..."
        
        # Force pull latest images
        log "INFO" "🔄 Pulling latest images from Docker Hub..."
        if $COMPOSE_CMD $COMPOSE_FILES pull --ignore-pull-failures 2>&1 | tee /tmp/docker-pull.log; then
            log "INFO" "✅ Images pulled successfully"
        else
            if [ "$BUILD_LOCAL" != "true" ] && [[ "$COMPOSE_FILES" == *"pull-only"* ]]; then
                log "ERROR" "❌ Failed to pull images from Docker Hub"
                log "ERROR" "Please ensure Docker Hub credentials are configured"
                exit 1
            else
                log "WARN" "⚠️ Failed to pull images, will build locally as fallback"
                log "INFO" "🏗️ Building images locally..."
                $COMPOSE_CMD $COMPOSE_FILES build --parallel
            fi
        fi
    fi
    
    # Start services
    log "INFO" "🚀 Starting $SERVICE_DISPLAY_NAME Services..."
    if [ "$USE_GPU" = "true" ] && [ "$SUPPORTS_GPU" = "true" ]; then
        # Start GPU services with specific profiles
        $COMPOSE_CMD $COMPOSE_FILES --profile gpu up -d
    else
        $COMPOSE_CMD $COMPOSE_FILES up -d
    fi
    
    # Wait for services to start
    log "INFO" "⏳ Waiting for services to initialize..."
    sleep 15
    
    # Show status
    log "INFO" "📊 Service status:"
    $COMPOSE_CMD $COMPOSE_FILES ps
    
    # Test connectivity
    test_connectivity
    
    log "INFO" "🎉 $SERVICE_DISPLAY_NAME startup complete!"
    if [ "$DEFAULT_HTTP_PORT" != "80" ]; then
        log "INFO" "🌐 HTTP: http://localhost:$DEFAULT_HTTP_PORT"
    else
        log "INFO" "🌐 HTTP: http://localhost"
    fi
    if [ "$HAS_SSL" = "true" ]; then
        if [ "$DEFAULT_HTTPS_PORT" != "443" ]; then
            log "INFO" "🔒 HTTPS: https://localhost:$DEFAULT_HTTPS_PORT"
        else
            log "INFO" "🔒 HTTPS: https://localhost"
        fi
    fi
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
            --gpu)
                if [ "$SUPPORTS_GPU" = "true" ]; then
                    USE_GPU=true
                else
                    log "WARN" "GPU support not available for $SERVICE_DISPLAY_NAME"
                fi
                shift
                ;;
            --minimal)
                if [ "$SUPPORTS_MINIMAL" = "true" ]; then
                    USE_MINIMAL=true
                else
                    log "WARN" "Minimal mode not available for $SERVICE_DISPLAY_NAME"
                fi
                shift
                ;;
            --dev)
                if [ "$SUPPORTS_DEV" = "true" ]; then
                    USE_DEV=true
                else
                    log "WARN" "Development mode not available for $SERVICE_DISPLAY_NAME"
                fi
                shift
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
    echo "$SERVICE_DISPLAY_NAME Startup Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --set-laptop        Mark this environment as a laptop (creates .local file)"
    echo "  --show-env          Show detected environment and exit"
    if [ "$SUPPORTS_GPU" = "true" ]; then
        echo "  --gpu               Enable GPU support for AI/ML services"
    fi
    if [ "$SUPPORTS_MINIMAL" = "true" ]; then
        echo "  --minimal           Start only core services (no AI/ML components)"
    fi
    if [ "$SUPPORTS_DEV" = "true" ]; then
        echo "  --dev               Start in development mode with hot reloading"
    fi
    echo ""
    echo "Environment Variables:"
    echo "  BUILD_LOCAL=true/false    Override automatic build strategy detection"
    echo "  DOCKER_NAMESPACE=name     Docker Hub namespace (default: nuniesmith)"
    echo "  DOCKER_REGISTRY=registry  Docker registry (default: docker.io)"
    echo "  DOCKER_USERNAME=user      Docker Hub username for login"
    echo "  DOCKER_TOKEN=token        Docker Hub token for login"
    echo ""
    echo "Required Configuration:"
    echo "  SERVICE_NAME              Service identifier (required)"
    echo "  SERVICE_DISPLAY_NAME      Human-readable service name"
    echo "  DEFAULT_HTTP_PORT         Default HTTP port (default: 80)"
    echo "  DEFAULT_HTTPS_PORT        Default HTTPS port (default: 443)"
    echo ""
    echo "Feature Flags:"
    echo "  SUPPORTS_GPU=true/false   Enable --gpu option"
    echo "  SUPPORTS_MINIMAL=true/false   Enable --minimal option"
    echo "  SUPPORTS_DEV=true/false   Enable --dev option"
    echo "  HAS_NETDATA=true/false    Include Netdata configuration"
    echo "  HAS_SSL=true/false        Include SSL configuration"
    echo ""
}

show_environment_info() {
    echo "Service: $SERVICE_DISPLAY_NAME ($SERVICE_NAME)"
    echo "Detected environment: $DETECTED_ENV"
    echo "Build strategy: $([ "$BUILD_LOCAL" = "true" ] && echo "LOCAL" || echo "REMOTE")"
    echo ""
    echo "Feature Support:"
    echo "  GPU: $SUPPORTS_GPU"
    echo "  Minimal: $SUPPORTS_MINIMAL"
    echo "  Development: $SUPPORTS_DEV"
    echo "  Netdata: $HAS_NETDATA"
    echo "  SSL: $HAS_SSL"
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
    
    if [ "$SUPPORTS_GPU" = "true" ]; then
        echo ""
        echo "GPU Status:"
        if command -v nvidia-smi &> /dev/null; then
            echo "  NVIDIA drivers: Available"
            if nvidia-smi &> /dev/null; then
                echo "  GPU detection: $(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)"
            else
                echo "  GPU detection: Failed"
            fi
        else
            echo "  NVIDIA drivers: Not available"
        fi
        
        if docker info 2> /dev/null | grep -i nvidia > /dev/null; then
            echo "  NVIDIA Docker runtime: Available"
        else
            echo "  NVIDIA Docker runtime: Not available"
        fi
    fi
}

# Run main function
main "$@"
