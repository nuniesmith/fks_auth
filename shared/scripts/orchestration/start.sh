#!/bin/bash

# FKS Trading Systems - Simple Startup Script
# Defaults to pulling images from Docker Hub

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ENV_FILE="$PROJECT_ROOT/.env"
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
    
    # Default to laptop if we can't determine
    echo "laptop"
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
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        log "ERROR" "Docker Compose is not available!"
        exit 1
    fi
    
    log "INFO" "Prerequisites check passed"
}

# Create environment file
create_env_file() {
    log "INFO" "Creating environment file..."
    
    # Generate secure passwords
    POSTGRES_PASSWORD="fks_postgres_$(openssl rand -hex 8)"
    REDIS_PASSWORD="fks_redis_$(openssl rand -hex 8)"
    JWT_SECRET_KEY="$(openssl rand -hex 32)"
    
    cat > "$ENV_FILE" << EOF
# FKS Trading Systems Environment
COMPOSE_PROJECT_NAME=fks
ENVIRONMENT=production
APP_ENV=production

# Domain Configuration
AUTH_DOMAIN_NAME=auth.7gram.xyz
API_DOMAIN_NAME=api.7gram.xyz
WEB_DOMAIN_NAME=fks.7gram.xyz

# Service Ports
WEB_PORT=3000
API_PORT=8000
NGINX_PORT=80

# Database
POSTGRES_DB=fks_trading
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_PORT=5432

# Redis
REDIS_PORT=6379
REDIS_PASSWORD=$REDIS_PASSWORD

# API
JWT_SECRET_KEY=$JWT_SECRET_KEY
API_WORKERS=4

# Docker Hub
DOCKER_NAMESPACE=$DOCKER_NAMESPACE
DOCKER_REGISTRY=$DOCKER_REGISTRY

# Timezone
TZ=America/Toronto

# SSL Configuration
SSL_EMAIL=admin@7gram.xyz
LETSENCRYPT_EMAIL=admin@7gram.xyz
EOF
    
    log "INFO" "Environment file created"
}

# Check if GPU is available and properly configured
check_gpu() {
    log "INFO" "Checking GPU requirements..."
    
    # Check if nvidia-smi is available
    if ! command -v nvidia-smi &> /dev/null; then
        log "ERROR" "nvidia-smi not found. Please ensure NVIDIA drivers are installed."
        log "ERROR" "Install NVIDIA drivers with: sudo apt install nvidia-driver-535"
        return 1
    fi

    # Check if GPU is detected
    if ! nvidia-smi &> /dev/null; then
        log "ERROR" "No NVIDIA GPU detected or driver issues found."
        log "ERROR" "Run 'nvidia-smi' to diagnose GPU issues."
        return 1
    fi

    # Get GPU info
    local gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)
    local gpu_memory=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
    log "INFO" "GPU detected: $gpu_name (${gpu_memory}MB memory)"

    # Check if nvidia-docker is available
    if ! docker info 2> /dev/null | grep -i nvidia > /dev/null; then
        log "ERROR" "NVIDIA Docker runtime not found. Please install nvidia-docker2."
        log "ERROR" "Installation commands:"
        log "ERROR" "  curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -"
        log "ERROR" "  distribution=\$(. /etc/os-release;echo \$ID\$VERSION_ID)"
        log "ERROR" "  curl -s -L https://nvidia.github.io/nvidia-docker/\$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list"
        log "ERROR" "  sudo apt-get update && sudo apt-get install -y nvidia-docker2"
        log "ERROR" "  sudo systemctl restart docker"
        return 1
    fi

    # Test GPU access in Docker
    log "INFO" "Testing GPU access in Docker..."
    if ! docker run --rm --gpus all nvidia/cuda:12.1.0-base-ubuntu22.04 nvidia-smi &> /dev/null; then
        log "ERROR" "GPU access test failed. Docker cannot access GPU."
        log "ERROR" "Try restarting Docker: sudo systemctl restart docker"
        return 1
    fi

    log "INFO" "✅ GPU configuration validated successfully"
    return 0
}

# Main function
main() {
    # Parse command line arguments first
    parse_args "$@"
    
    log "INFO" "🚀 Starting FKS Trading Systems..."
    
    # Show detected environment
    log "INFO" "🔍 Detected environment: $DETECTED_ENV"
    
    # Show build strategy
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "📦 Build strategy: LOCAL (building images on this machine)"
    else
        log "INFO" "📦 Build strategy: REMOTE (pulling from Docker Hub)"
    fi
    
    # Show configuration
    if [ "$USE_GPU" = "true" ]; then
        log "INFO" "🎮 GPU support: ENABLED"
    fi
    if [ "$USE_DEV" = "true" ]; then
        log "INFO" "🔧 Development mode: ENABLED"
    fi
    if [ "$USE_MINIMAL" = "true" ]; then
        log "INFO" "📦 Minimal mode: ENABLED"
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
    
    # Fix Docker networking if needed
    log "INFO" "🔧 Checking Docker networking..."
    
    # For non-root users in docker group, we can't check iptables directly
    # Instead, we'll test Docker networking functionality
    if ! docker network ls >/dev/null 2>&1; then
        log "ERROR" "❌ Docker is not accessible. Please ensure Docker is running and you're in the docker group."
        exit 1
    fi
    
    # Test if we can create a test network (this will fail if Docker networking is broken)
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
        
        # Remove any custom networks
        for network in $(docker network ls --format '{{.Name}}' | grep -v -E '^(bridge|host|none)$'); do
            docker network rm "$network" 2>/dev/null || true
        done
        
        log "ERROR" "❌ Docker networking issues detected. This requires administrative privileges to fix."
        log "ERROR" "Please contact your system administrator to run:"
        log "ERROR" "  sudo systemctl restart docker"
        log "ERROR" "Or if you have sudo access, run:"
        log "ERROR" "  sudo $(dirname "$0")/scripts/fix-docker-network.sh"
        exit 1
    else
        # Remove the test network
        docker network rm test-network-$$$ >/dev/null 2>&1 || true
        log "INFO" "✅ Docker networking is properly configured"
    fi
    
    # Clean up any existing fks_network that wasn't created by compose
    # This avoids label conflicts between manually created networks and compose-managed networks
    if docker network inspect fks_network >/dev/null 2>&1; then
        # Check if network has containers attached
        if [ -z "$(docker network inspect fks_network -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null)" ]; then
            log "INFO" "Removing existing fks_network to let docker-compose recreate it..."
            docker network rm fks_network 2>/dev/null || true
        fi
    fi
    
    # Determine compose file based on environment and options
    COMPOSE_FILES="-f docker-compose.yml"
    
    # Configure GPU services if requested
    if [ "$USE_GPU" = "true" ]; then
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
    
    # Add development overrides if requested
    if [ "$USE_DEV" = "true" ]; then
        if [ -f "$PROJECT_ROOT/docker-compose.dev.yml" ]; then
            COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.dev.yml"
            log "INFO" "📄 Added development compose file"
        else
            log "WARN" "⚠️ Development compose file not found"
        fi
    fi
    
    # Use minimal configuration if requested
    if [ "$USE_MINIMAL" = "true" ]; then
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

    # For local laptop environments, include docker-compose.override.yml to force HTTP and local domains
    if [ "$DETECTED_ENV" = "laptop" ] && [ -f "$PROJECT_ROOT/docker-compose.override.yml" ] && [[ "$COMPOSE_FILES" != *"pull-only"* ]]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.override.yml"
        log "INFO" "📄 Added local override compose file (docker-compose.override.yml)"
    fi
    
    # Determine build strategy
    COMPOSE_PROFILES=""
    if [ "$USE_GPU" = "true" ]; then
        COMPOSE_PROFILES="--profile gpu"
    fi
    if [ "$BUILD_LOCAL" = "true" ]; then
        log "INFO" "🏗️ Building images locally..."
        $COMPOSE_CMD $COMPOSE_FILES $COMPOSE_PROFILES build --parallel
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
                $COMPOSE_CMD $COMPOSE_FILES $COMPOSE_PROFILES build --parallel
            fi
        fi
    fi
    
    # Start services
    log "INFO" "🚀 Starting FKS Services..."
    if [ "$USE_GPU" = "true" ]; then
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
    log "INFO" "🔌 Testing connectivity..."
    
    # Test web service
    if curl -s -f http://localhost:3000 >/dev/null 2>&1; then
        log "INFO" "✅ Web service is accessible at http://localhost:3000"
    else
        log "WARN" "⚠️ Web service not yet accessible (may still be starting)"
    fi
    
    # Test API service
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        log "INFO" "✅ API service is accessible at http://localhost:8000"
    else
        log "WARN" "⚠️ API service not yet accessible (may still be starting)"
    fi
    
    # Test nginx
    if curl -s -f http://localhost >/dev/null 2>&1; then
        log "INFO" "✅ Nginx is accessible at http://localhost"
    else
        log "WARN" "⚠️ Nginx not yet accessible (may still be starting)"
    fi
    
    log "INFO" "🎉 FKS Trading Systems startup complete!"
    log "INFO" "📱 Web Interface: http://localhost"
    log "INFO" "🔧 API Endpoint: http://localhost:8000"
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
                USE_GPU=true
                shift
                ;;
            --minimal)
                USE_MINIMAL=true
                shift
                ;;
            --dev)
                USE_DEV=true
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
    echo "FKS Trading Systems Startup Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --set-laptop        Mark this environment as a laptop (creates .local file)"
    echo "  --show-env          Show detected environment and exit"
    echo "  --gpu               Enable GPU support for AI/ML services"
    echo "  --minimal           Start only core services (no AI/ML components)"
    echo "  --dev               Start in development mode with hot reloading"
    echo ""
    echo "Environment Variables:"
    echo "  BUILD_LOCAL=true/false    Override automatic build strategy detection"
    echo "  DOCKER_NAMESPACE=name     Docker Hub namespace (default: nuniesmith)"
    echo "  DOCKER_REGISTRY=registry  Docker registry (default: docker.io)"
    echo ""
    echo "Environment Detection:"
    echo "  The script automatically detects your environment and chooses the appropriate"
    echo "  build strategy:"
    echo "  - laptop:               Builds locally (has sufficient resources)"
    echo "  - cloud/dev_server:     Pulls from Docker Hub (built by GitHub Actions)"
    echo "  - resource_constrained: Pulls from Docker Hub (insufficient RAM < 4GB)"
    echo ""
    echo "Examples:"
    echo "  $0                        # Auto-detect environment"
    echo "  $0 --show-env             # Show detected environment"
    echo "  $0 --set-laptop           # Mark as laptop and build locally"
    echo "  $0 --gpu                  # Start with GPU-accelerated AI services"
    echo "  $0 --minimal              # Start only core services"
    echo "  $0 --dev --gpu            # Development mode with GPU support"
    echo "  BUILD_LOCAL=false $0      # Force pull from Docker Hub"
    echo "  BUILD_LOCAL=true $0       # Force local build"
    echo ""
}

show_environment_info() {
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
}

# Run main function
main "$@"
