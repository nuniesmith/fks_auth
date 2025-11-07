#!/usr/bin/env bash
# Shim: start-multi moved to orchestration/multi/start.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/orchestration/multi/start.sh"
if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
# =================================================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} [$timestamp] $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} [$timestamp] $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} [$timestamp] $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} [$timestamp] $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} [$timestamp] $message"
            ;;
        "MULTI")
            echo -e "${PURPLE}[MULTI]${NC} [$timestamp] $message"
            ;;
    esac
}

# =================================================================
# ENVIRONMENT DETECTION
# =================================================================
detect_environment() {
    # Check for server type markers
    if [ -f "/etc/fks_server-type" ]; then
        cat /etc/fks_server-type
        return
    fi
    
    # Check environment variables
    if [ -n "$FKS_SERVER_TYPE" ]; then
        echo "$FKS_SERVER_TYPE"
        return
    fi
    
    # Check hostname patterns
    local hostname=$(hostname)
    case "$hostname" in
        *auth*|auth-*)
            echo "auth"
            return
            ;;
        *api*|api-*)
            echo "api"
            return
            ;;
        *web*|web-*)
            echo "web"
            return
            ;;
    esac
    
    # Check if we're in a cloud environment
    if [ -f /etc/cloud-id ] || [ -f /var/lib/cloud/data/instance-id ] || [ -n "$AWS_INSTANCE_ID" ] || [ -n "$GCP_PROJECT" ] || [ -n "$AZURE_SUBSCRIPTION_ID" ]; then
        echo "cloud"
        return
    fi
    
    # Check if we're in a container
    if [ -f /.dockerenv ] || [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        echo "container"
        return
    fi
    
    # Check system resources
    if command -v free &> /dev/null; then
        local total_mem=$(free -m | awk '/^Mem:/{print $2}')
        if [ "$total_mem" -lt 4096 ]; then
            echo "resource_constrained"
            return
        fi
    fi
    
    # Default to laptop
    echo "laptop"
}

# =================================================================
# DEPLOYMENT MODE DETECTION
# =================================================================
detect_deployment_mode() {
    # Check for multi-server environment variables
    if [ -n "$AUTH_SERVER_IP" ] && [ -n "$API_SERVER_IP" ] && [ -n "$WEB_SERVER_IP" ]; then
        echo "multi"
        return
    fi
    
    # Check for server type specific deployment
    local detected_env=$(detect_environment)
    case "$detected_env" in
        "auth"|"api"|"web")
            echo "$detected_env"
            return
            ;;
    esac
    
    # Check for multi-server compose files
    if [ -f "$PROJECT_ROOT/docker-compose.auth.yml" ] && [ -f "$PROJECT_ROOT/docker-compose.api.yml" ] && [ -f "$PROJECT_ROOT/docker-compose.web.yml" ]; then
        if [ "$DEPLOYMENT_MODE" = "auto" ] || [ "$DEPLOYMENT_MODE" = "single" ]; then
            echo "single"  # Default to single unless explicitly multi
        else
            echo "multi"
        fi
        return
    fi
    
    echo "single"
}

# =================================================================
# PREREQUISITES CHECK
# =================================================================
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log "ERROR" "Docker is not installed!"
        log "INFO" "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log "ERROR" "Docker is not running!"
        log "INFO" "Please start Docker daemon"
        exit 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        log "ERROR" "Docker Compose is not available!"
        log "INFO" "Please install Docker Compose"
        exit 1
    fi
    
    log "SUCCESS" "Prerequisites check passed"
}

# =================================================================
# ENVIRONMENT FILE CREATION
# =================================================================
create_env_file() {
    if [ -f "$ENV_FILE" ]; then
        log "INFO" "Environment file already exists"
        return
    fi
    
    log "INFO" "Creating environment file..."
    
    # Generate secure passwords
    POSTGRES_PASSWORD="fks_postgres_$(openssl rand -hex 8)"
    REDIS_PASSWORD="fks_redis_$(openssl rand -hex 8)"
    JWT_SECRET_KEY="$(openssl rand -hex 32)"
    AUTHELIA_SECRET_KEY="$(openssl rand -hex 32)"
    
    cat > "$ENV_FILE" << EOF
# =================================================================
# FKS Trading Systems Environment Configuration
# =================================================================

# Deployment Configuration
DEPLOYMENT_MODE=${DEPLOYMENT_MODE}
SERVER_TYPE=${SERVER_TYPE}
ENVIRONMENT=production

# Domain Configuration
DOMAIN_NAME=fkstrading.xyz
AUTH_DOMAIN_NAME=auth.fkstrading.xyz
API_DOMAIN_NAME=api.fkstrading.xyz
WEB_DOMAIN_NAME=fkstrading.xyz

# Multi-Server IPs (Tailscale)
AUTH_SERVER_IP=${AUTH_SERVER_IP}
API_SERVER_IP=${API_SERVER_IP}
WEB_SERVER_IP=${WEB_SERVER_IP}

# Database Configuration
POSTGRES_USER=fks_user
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=fks_trading

# Redis Configuration
REDIS_PASSWORD=${REDIS_PASSWORD}

# Authentication
JWT_SECRET_KEY=${JWT_SECRET_KEY}
AUTHELIA_SECRET_KEY=${AUTHELIA_SECRET_KEY}

# Docker Configuration
DOCKER_REGISTRY=${DOCKER_REGISTRY}
DOCKER_NAMESPACE=${DOCKER_NAMESPACE}

# SSL Configuration
ENABLE_SSL=true
ADMIN_EMAIL=admin@fkstrading.xyz

# API Configuration
API_PORT=8000
API_WORKERS=2

# Feature Flags
TRADING_ENABLED=false
PAPER_TRADING=true
ENABLE_GPU=${USE_GPU}

# Timezone
TZ=America/Toronto
EOF
    
    log "SUCCESS" "Environment file created"
}

# =================================================================
# COMPOSE FILE SELECTION
# =================================================================
get_compose_files() {
    local mode="$1"
    local files=""
    
    case "$mode" in
        "single")
            files="docker-compose.yml"
            if [ "$USE_GPU" = "true" ]; then
                files="$files -f docker-compose.gpu.yml"
            fi
            if [ "$USE_MINIMAL" = "true" ]; then
                files="$files -f docker-compose.minimal.yml"
            fi
            if [ "$USE_DEV" = "true" ]; then
                files="$files -f docker-compose.dev.yml"
            fi
            ;;
        "auth")
            files="docker-compose.auth.yml"
            ;;
        "api")
            files="docker-compose.api.yml"
            if [ "$USE_GPU" = "true" ]; then
                files="$files -f docker-compose.gpu.yml"
            fi
            ;;
        "web")
            files="docker-compose.web.yml"
            ;;
        "multi")
            files="docker-compose.auth.yml -f docker-compose.api.yml -f docker-compose.web.yml"
            if [ "$USE_GPU" = "true" ]; then
                files="$files -f docker-compose.gpu.yml"
            fi
            ;;
    esac
    
    echo "$files"
}

# =================================================================
# SERVICE MANAGEMENT
# =================================================================
start_services() {
    local mode="$1"
    local compose_files=$(get_compose_files "$mode")
    
    log "MULTI" "Starting services in $mode mode..."
    log "INFO" "Compose files: $compose_files"
    
    # Check if compose files exist
    for file in $(echo "$compose_files" | tr ' ' '\n' | grep -v '^-f$'); do
        if [ ! -f "$PROJECT_ROOT/$file" ]; then
            log "ERROR" "Compose file not found: $file"
            exit 1
        fi
    done
    
    # Pull images if not building locally
    if [ "$BUILD_LOCAL" != "true" ]; then
        log "INFO" "Pulling Docker images..."
        $COMPOSE_CMD -f $compose_files pull --ignore-pull-failures || log "WARN" "Some images failed to pull"
    fi
    
    # Start services
    log "INFO" "Starting Docker containers..."
    $COMPOSE_CMD -f $compose_files up -d
    
    # Wait for services to be healthy
    log "INFO" "Waiting for services to be healthy..."
    sleep 10
    
    # Check service health
    check_service_health "$mode" "$compose_files"
}

check_service_health() {
    local mode="$1"
    local compose_files="$2"
    local max_attempts=30
    local attempt=1
    
    log "INFO" "Checking service health..."
    
    while [ $attempt -le $max_attempts ]; do
        local all_healthy=true
        
        # Get running containers
        local containers=$($COMPOSE_CMD -f $compose_files ps --services --filter "status=running" 2>/dev/null || echo "")
        
        if [ -z "$containers" ]; then
            log "WARN" "No running containers found (attempt $attempt/$max_attempts)"
            all_healthy=false
        else
            # Check each container
            for container in $containers; do
                local health=$($COMPOSE_CMD -f $compose_files ps --format "{{.Health}}" "$container" 2>/dev/null || echo "unknown")
                case "$health" in
                    "healthy")
                        ;;
                    "starting")
                        all_healthy=false
                        ;;
                    "unhealthy")
                        log "WARN" "Container $container is unhealthy"
                        all_healthy=false
                        ;;
                    *)
                        # Container might not have healthcheck
                        local status=$($COMPOSE_CMD -f $compose_files ps --format "{{.Status}}" "$container" 2>/dev/null || echo "unknown")
                        if [[ ! "$status" =~ "Up" ]]; then
                            all_healthy=false
                        fi
                        ;;
                esac
            done
        fi
        
        if [ "$all_healthy" = "true" ]; then
            log "SUCCESS" "All services are healthy!"
            return 0
        fi
        
        log "INFO" "Waiting for services... (attempt $attempt/$max_attempts)"
        sleep 5
        ((attempt++))
    done
    
    log "WARN" "Some services may not be fully healthy yet"
    log "INFO" "Check service status with: $COMPOSE_CMD -f $compose_files ps"
    return 1
}

# =================================================================
# INFORMATION DISPLAY
# =================================================================
show_service_info() {
    local mode="$1"
    local compose_files=$(get_compose_files "$mode")
    
    echo ""
    echo "=========================================="
    echo "🚀 FKS Trading Systems - $mode Mode"
    echo "=========================================="
    echo ""
    
    case "$mode" in
        "single")
            echo "📊 Single Server Deployment"
            echo "   • All services on one server"
            echo "   • Web:  http://localhost:3000"
            echo "   • API:  http://localhost:8000"
            echo "   • Auth: http://localhost:9000"
            ;;
        "auth")
            echo "🔐 Auth Server"
            echo "   • Authentik SSO"
            echo "   • URL: https://auth.fkstrading.xyz"
            ;;
        "api")
            echo "⚡ API Server" 
            echo "   • Trading API & Workers"
            echo "   • URL: https://api.fkstrading.xyz"
            ;;
        "web")
            echo "🌐 Web Server"
            echo "   • React Frontend"
            echo "   • URL: https://fkstrading.xyz"
            ;;
        "multi")
            echo "🔄 Multi-Server Deployment"
            echo "   • Auth: https://auth.fkstrading.xyz"
            echo "   • API:  https://api.fkstrading.xyz"
            echo "   • Web:  https://fkstrading.xyz"
            ;;
    esac
    
    echo ""
    echo "📋 Service Status:"
    $COMPOSE_CMD -f $compose_files ps
    
    echo ""
    echo "🔧 Management Commands:"
    echo "   • View logs:    $COMPOSE_CMD -f $compose_files logs -f"
    echo "   • Stop:         ./stop.sh $mode"
    echo "   • Restart:      ./start.sh $mode"
    echo ""
}

# =================================================================
# MAIN FUNCTION
# =================================================================
main() {
    local detected_env=$(detect_environment)
    local detected_mode=$(detect_deployment_mode)
    
    # Override with command line arguments
    if [ "$DEPLOYMENT_MODE" != "single" ] && [ "$DEPLOYMENT_MODE" != "auto" ]; then
        detected_mode="$DEPLOYMENT_MODE"
    fi
    
    log "INFO" "🚀 Starting FKS Trading Systems..."
    log "INFO" "Environment: $detected_env"
    log "INFO" "Deployment Mode: $detected_mode"
    
    # Set build strategy
    if [ "$BUILD_LOCAL" = "auto" ]; then
        case "$detected_env" in
            "laptop")
                BUILD_LOCAL="true"
                ;;
            *)
                BUILD_LOCAL="false"
                ;;
        esac
    fi
    
    log "INFO" "Build Strategy: $([ "$BUILD_LOCAL" = "true" ] && echo "LOCAL" || echo "REMOTE")"
    
    # Check prerequisites
    check_prerequisites
    
    # Create environment file
    create_env_file
    
    # Start services
    start_services "$detected_mode"
    
    # Show information
    show_service_info "$detected_mode"
    
    log "SUCCESS" "🎉 FKS Trading Systems started successfully!"
}

# =================================================================
# COMMAND LINE PARSING
# =================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --single)
            DEPLOYMENT_MODE="single"
            shift
            ;;
        --multi)
            DEPLOYMENT_MODE="multi"
            shift
            ;;
        --auth)
            DEPLOYMENT_MODE="auth"
            shift
            ;;
        --api)
            DEPLOYMENT_MODE="api"
            shift
            ;;
        --web)
            DEPLOYMENT_MODE="web"
            shift
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
        --build-local)
            BUILD_LOCAL="true"
            shift
            ;;
        --pull-images)
            BUILD_LOCAL="false"
            shift
            ;;
        --show-env)
            show_environment_info
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# =================================================================
# HELP FUNCTION
# =================================================================
show_help() {
    cat << EOF
FKS Trading Systems - Multi-Server Startup Script

USAGE:
    $0 [OPTIONS] [MODE]

DEPLOYMENT MODES:
    --single        Single server deployment (default)
    --multi         Multi-server deployment
    --auth          Auth server only
    --api           API server only  
    --web           Web server only

OPTIONS:
    --gpu           Enable GPU-accelerated services
    --minimal       Start only core services
    --dev           Development mode
    --build-local   Force local Docker builds
    --pull-images   Force pull from Docker Hub
    --show-env      Show environment information
    --help, -h      Show this help message

EXAMPLES:
    $0                  # Auto-detect and start
    $0 --single         # Single server mode
    $0 --multi          # Multi-server mode
    $0 --auth           # Auth server only
    $0 --api --gpu      # API server with GPU
    $0 --web            # Web server only
    $0 --dev --gpu      # Development with GPU

ENVIRONMENT VARIABLES:
    BUILD_LOCAL=true/false          Force build strategy
    DEPLOYMENT_MODE=single/multi    Set deployment mode
    AUTH_SERVER_IP=x.x.x.x         Auth server Tailscale IP
    API_SERVER_IP=x.x.x.x          API server Tailscale IP  
    WEB_SERVER_IP=x.x.x.x          Web server Tailscale IP

EOF
}

show_environment_info() {
    local detected_env=$(detect_environment)
    local detected_mode=$(detect_deployment_mode)
    
    echo "🔍 Environment Information"
    echo "=========================="
    echo "Detected environment: $detected_env"
    echo "Deployment mode: $detected_mode"
    echo "Build strategy: $([ "$BUILD_LOCAL" = "true" ] && echo "LOCAL" || echo "REMOTE")"
    echo ""
    echo "System Information:"
    if command -v free &> /dev/null; then
        echo "  Memory: $(free -m | awk '/^Mem:/{print $2}') MB"
    fi
    echo "  Hostname: $(hostname)"
    echo "  User: $USER"
    echo ""
    echo "Multi-Server Configuration:"
    echo "  Auth Server IP: ${AUTH_SERVER_IP:-not set}"
    echo "  API Server IP: ${API_SERVER_IP:-not set}"
    echo "  Web Server IP: ${WEB_SERVER_IP:-not set}"
    echo ""
}

# =================================================================
# SCRIPT EXECUTION
# =================================================================
main "$@"
