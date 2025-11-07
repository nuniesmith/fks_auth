#!/bin/bash
# filepath: /home/${USER}/fks/run.sh
# FKS Trading Systems - Enhanced Orchestrator
# Hardcoded paths version with full script integration

set -e

# =============================================================================
# HARDCODED CONFIGURATION - NO DYNAMIC RESOLUTION
# =============================================================================

# Base paths (dynamically determined from script location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
BUILD_SCRIPTS_DIR="$PROJECT_ROOT/scripts/build"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
LOGS_DIR="$PROJECT_ROOT/logs"
TEMP_DIR="/tmp"
DEPLOYMENT_DIR="$PROJECT_ROOT/deployment"
CONDA_HOME_DIR="$PROJECT_ROOT/.conda"
CONDA_ENV_PREFIX="$CONDA_HOME_DIR/fks_dev"

# Docker Hub Configuration
DOCKER_HUB_USERNAME="${DOCKER_HUB_USERNAME:-nuniesmith}"
DOCKER_HUB_REPO="${DOCKER_HUB_REPO:-fks}"
DOCKER_BUILD_CONTEXT="${DOCKER_BUILD_CONTEXT:-$PROJECT_ROOT}"

# Key files (dynamically determined)
MAIN_SCRIPT="$PROJECT_ROOT/scripts/main.sh"
DOCKER_SCRIPT="$PROJECT_ROOT/scripts/build/docker.sh"
REQUIREMENTS_SCRIPT="$PROJECT_ROOT/scripts/build/requirements.sh"
MAIN_CONFIG="$PROJECT_ROOT/config/main.yaml"
SERVICES_CONFIG="$PROJECT_ROOT/config/services.yaml"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"

# Script settings
SCRIPT_VERSION="1.0.0"
FKS_MODE="${FKS_MODE:-development}"

# =============================================================================
# SIMPLE LOGGING
# =============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} ✅ $1"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# =============================================================================
# SIMPLE ERROR HANDLING
# =============================================================================

handle_error() {
    local exit_code=$?
    log_error "Script failed with exit code $exit_code"
    log_error "Check logs in: $LOGS_DIR"
    log_error "Use '$0 help' for usage information"
    exit $exit_code
}

trap 'handle_error' ERR

# =============================================================================
# SYMLINK MANAGEMENT
# =============================================================================

# Create symlink for FKS directory
create_fks_symlink() {
    local current_dir="$PROJECT_ROOT"
    local target_dir="/home/$USER/fks"
    
    # Skip if already at target location
    if [[ "$current_dir" == "$target_dir" ]]; then
        log_info "FKS directory already at standard location: $target_dir"
        return 0
    fi
    
    # Check if target already exists
    if [[ -e "$target_dir" ]]; then
        if [[ -L "$target_dir" ]]; then
            local existing_target=$(readlink -f "$target_dir")
            if [[ "$existing_target" == "$current_dir" ]]; then
                log_success "Symlink already exists and points to correct location"
                return 0
            else
                log_warn "Symlink exists but points to different location: $existing_target"
                echo -n "Remove existing symlink and create new one? (y/N): "
                read -r confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    rm "$target_dir"
                else
                    log_info "Keeping existing symlink"
                    return 0
                fi
            fi
        else
            log_error "Target path exists but is not a symlink: $target_dir"
            echo "Please manually resolve this conflict before creating symlink"
            return 1
        fi
    fi
    
    # Create symlink
    log_info "Creating symlink: $target_dir -> $current_dir"
    if ln -s "$current_dir" "$target_dir"; then
        log_success "Symlink created successfully"
        log_info "You can now access your FKS project at: $target_dir"
    else
        log_error "Failed to create symlink"
        return 1
    fi
}

# Remove FKS symlink
remove_fks_symlink() {
    local target_dir="/home/$USER/fks"
    
    if [[ -L "$target_dir" ]]; then
        log_info "Removing symlink: $target_dir"
        if rm "$target_dir"; then
            log_success "Symlink removed successfully"
        else
            log_error "Failed to remove symlink"
            return 1
        fi
    elif [[ -e "$target_dir" ]]; then
        log_error "Path exists but is not a symlink: $target_dir"
        return 1
    else
        log_info "No symlink exists at: $target_dir"
    fi
}

# =============================================================================
# BASIC DIRECTORY SETUP
# =============================================================================

ensure_directories() {
    local dirs=(
        "$CONFIG_DIR"
        "$DATA_DIR" 
        "$LOGS_DIR"
        "$TEMP_DIR"
        "$SCRIPTS_DIR"
        "$BUILD_SCRIPTS_DIR"
        "$DEPLOYMENT_DIR"
        "$DEPLOYMENT_DIR/requirements"
        "$DEPLOYMENT_DIR/docker"
        "$CONFIG_DIR/services"
        "$CONFIG_DIR/python"
    "$CONDA_HOME_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_debug "Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done
}

# =============================================================================
# PYTHON / CONDA ENVIRONMENT
# =============================================================================

get_conda_cmd() {
    # Detect conda/mamba/micromamba; return cmd in CONDA_CMD and KIND
    if command -v conda >/dev/null 2>&1; then
        CONDA_CMD="conda"; CONDA_KIND="conda"; return 0
    elif command -v mamba >/dev/null 2>&1; then
        CONDA_CMD="mamba"; CONDA_KIND="mamba"; return 0
    elif command -v micromamba >/dev/null 2>&1; then
        CONDA_CMD="micromamba"; CONDA_KIND="micromamba"; return 0
    else
        return 1
    fi
}

conda_setup_env() {
    local py_ver="${FKS_PY_VERSION:-3.11}"
    local req_main="$PROJECT_ROOT/src/python/requirements.txt"
    local req_dev="$PROJECT_ROOT/src/python/requirements_dev.txt"

    ensure_directories

    if ! get_conda_cmd; then
        log_error "No conda/mamba/micromamba found in PATH. Install one and retry."
        echo "Suggested: micromamba (fast, single binary)."
        echo "Linux install example:"
        echo "  curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba"
        echo "  sudo mv bin/micromamba /usr/local/bin/"
        return 1
    fi

    log_info "Using $CONDA_CMD ($CONDA_KIND)"
    log_info "Creating env at: $CONDA_ENV_PREFIX (python=$py_ver)"

    # Create env with python and pip
    if [[ "$CONDA_KIND" == "conda" || "$CONDA_KIND" == "mamba" ]]; then
        "$CONDA_CMD" create -y -p "$CONDA_ENV_PREFIX" python="$py_ver" pip
    else
        # micromamba
        "$CONDA_CMD" create -y -p "$CONDA_ENV_PREFIX" python="$py_ver" pip
    fi

    log_success "Conda env created"

    # Install requirements via conda/mamba/micromamba run (no activation needed)
    if [[ -f "$req_main" ]]; then
        log_info "Installing core requirements from $req_main"
        "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -m pip install --upgrade pip
        "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -m pip install -r "$req_main"
    else
        log_warn "Missing $req_main"
    fi

    if [[ -f "$req_dev" ]]; then
        log_info "Installing dev requirements from $req_dev"
        "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -m pip install -r "$req_dev"
    else
        log_warn "Missing $req_dev"
    fi

    log_success "Environment ready"
    echo "To activate in your shell:"
    case "$CONDA_KIND" in
        conda|mamba)
            echo "  conda activate $CONDA_ENV_PREFIX"
            ;;
        micromamba)
            echo "  micromamba activate -p $CONDA_ENV_PREFIX"
            ;;
    esac
}

conda_install_requirements() {
    local req_file="${1:-$PROJECT_ROOT/src/python/requirements_dev.txt}"
    if ! get_conda_cmd; then
        log_error "No conda/mamba/micromamba found in PATH."
        return 1
    fi
    if [[ ! -d "$CONDA_ENV_PREFIX" ]]; then
        log_error "Conda env not found at $CONDA_ENV_PREFIX. Run: $0 conda-setup"
        return 1
    fi
    if [[ ! -f "$req_file" ]]; then
        log_error "Requirements file not found: $req_file"
        return 1
    fi
    log_info "Installing requirements from $req_file into env at $CONDA_ENV_PREFIX"
    "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -m pip install -r "$req_file"
    log_success "Requirements installed"
}

conda_info() {
    echo "Conda kind: ${CONDA_KIND:-unknown}"
    echo "Conda cmd: ${CONDA_CMD:-not detected}"
    echo "Env prefix: $CONDA_ENV_PREFIX"
    if [[ -d "$CONDA_ENV_PREFIX" ]]; then
        if get_conda_cmd; then
            "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -c 'import sys; print("Python:", sys.version); import pip; print("pip:", pip.__version__)'
            "$CONDA_CMD" run -p "$CONDA_ENV_PREFIX" python -c 'import site,sys; print("site-packages:", site.getsitepackages()); print("executable:", sys.executable)'
        fi
    else
        echo "Env not created yet. Run: $0 conda-setup"
    fi
}

# =============================================================================
# SCRIPT VALIDATION
# =============================================================================

check_scripts() {
    local all_good=true
    
    # Check main script
    if [[ ! -f "$MAIN_SCRIPT" ]]; then
        log_error "Main script not found: $MAIN_SCRIPT"
        all_good=false
    elif [[ ! -x "$MAIN_SCRIPT" ]]; then
        log_warn "Main script not executable, fixing..."
        chmod +x "$MAIN_SCRIPT"
    fi
    
    # Check docker script
    if [[ ! -f "$DOCKER_SCRIPT" ]]; then
        log_warn "Docker script not found: $DOCKER_SCRIPT"
    elif [[ ! -x "$DOCKER_SCRIPT" ]]; then
        log_debug "Making Docker script executable..."
        chmod +x "$DOCKER_SCRIPT"
    fi
    
    # Check requirements script
    if [[ ! -f "$REQUIREMENTS_SCRIPT" ]]; then
        log_warn "Requirements script not found: $REQUIREMENTS_SCRIPT"
    elif [[ ! -x "$REQUIREMENTS_SCRIPT" ]]; then
        log_debug "Making Requirements script executable..."
        chmod +x "$REQUIREMENTS_SCRIPT"
    fi
    
    $all_good
}

# =============================================================================
# DOCKER COMPOSE DETECTION AND MULTI-FILE SUPPORT
# =============================================================================

get_docker_compose_cmd() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        log_error "Neither 'docker compose' nor 'docker-compose' found"
        return 1
    fi
}

# Get compose files based on deployment type
get_compose_files() {
    local deployment_type="${1:-standard}"
    local compose_files=""
    
    case "$deployment_type" in
        "standard"|"default")
            compose_files="-f docker-compose.yml"
            ;;
        "api")
            compose_files="-f docker-compose.yml -f docker-compose.api.yml"
            ;;
        "auth")
            compose_files="-f docker-compose.yml -f docker-compose.auth.yml"
            ;;
        "web")
            compose_files="-f docker-compose.yml -f docker-compose.web.yml"
            ;;
        "minimal")
            compose_files="-f docker-compose.minimal.yml"
            ;;
        "development"|"dev")
            compose_files="-f docker-compose.yml -f docker-compose.dev.yml"
            ;;
        "production"|"prod")
            compose_files="-f docker-compose.yml -f docker-compose.prod.yml"
            ;;
        "gpu")
            compose_files="-f docker-compose.yml -f docker-compose.gpu.yml"
            ;;
        "pull-only")
            compose_files="-f docker-compose.pull-only.yml"
            ;;
        "node-network")
            compose_files="-f docker-compose.yml -f docker-compose.node-network.yml"
            ;;
        "full-stack")
            # All main services
            compose_files="-f docker-compose.yml -f docker-compose.api.yml -f docker-compose.web.yml -f docker-compose.auth.yml"
            ;;
        "multi-node")
            # Complete multi-node setup
            compose_files="-f docker-compose.yml -f docker-compose.api.yml -f docker-compose.web.yml -f docker-compose.auth.yml -f docker-compose.node-network.yml"
            ;;
        *)
            log_warn "Unknown deployment type: $deployment_type, using standard"
            compose_files="-f docker-compose.yml"
            ;;
    esac
    
    echo "$compose_files"
}

# Execute docker compose with appropriate files
docker_compose_exec() {
    local deployment_type="${FKS_DEPLOYMENT_TYPE:-standard}"
    local compose_files
    
    # Check if first argument is a deployment type
    case "$1" in
        "api"|"auth"|"web"|"minimal"|"dev"|"development"|"prod"|"production"|"gpu"|"pull-only"|"node-network"|"full-stack"|"multi-node")
            deployment_type="$1"
            shift
            ;;
    esac
    
    compose_files=$(get_compose_files "$deployment_type")
    
    cd "$PROJECT_ROOT"
    docker_compose=$(get_docker_compose_cmd)
    
    log_debug "Using deployment type: $deployment_type"
    log_debug "Compose files: $compose_files"
    log_debug "Command: $docker_compose $compose_files $*"
    
    $docker_compose $compose_files "$@"
}

# =============================================================================
# NEW COMMANDS FOR CI/CD
# =============================================================================

# List available services
list_services() {
    local deployment_type="${1:-standard}"
    
    log_info "Listing available services for deployment type: $deployment_type"
    
    local compose_files=$(get_compose_files "$deployment_type")
    
    if command -v docker >/dev/null 2>&1; then
        cd "$PROJECT_ROOT"
        if docker_compose=$(get_docker_compose_cmd 2>/dev/null); then
            log_info "Services from compose files: $compose_files"
            if services=$($docker_compose $compose_files config --services 2>/dev/null); then
                echo "$services" | while read -r service; do
                    [[ -n "$service" ]] && echo "  - $service"
                done
                return 0
            fi
        fi
        
        # Fallback to parsing compose files manually
        log_debug "Parsing compose files manually..."
        for file in docker-compose.yml docker-compose.*.yml; do
            if [[ -f "$file" ]]; then
                log_debug "Checking file: $file"
                grep -E "^  [a-zA-Z_-]+:" "$file" | sed 's/://g' | tr -d ' ' | while read -r service; do
                    [[ -n "$service" ]] && echo "  - $service (from $file)"
                done
            fi
        done
    else
        log_warn "Docker not available - showing common services"
        # Return default services for different deployment types
        case "$deployment_type" in
            "api")
                echo "  - postgres"
                echo "  - redis"
                echo "  - redis-cache"
                echo "  - api"
                echo "  - worker"
                echo "  - scheduler"
                echo "  - market-data"
                echo "  - risk-manager"
                ;;
            "auth")
                echo "  - authelia-db"
                echo "  - authelia-redis"
                echo "  - authelia-server"
                echo "  - authelia-worker"
                echo "  - nginx-auth"
                echo "  - certbot"
                ;;
            "web")
                echo "  - frontend-builder"
                echo "  - nginx"
                echo "  - certbot"
                echo "  - asset-optimizer"
                echo "  - health-check"
                echo "  - netdata"
                ;;
            "minimal")
                echo "  - postgres"
                echo "  - redis"
                echo "  - web"
                echo "  - nginx"
                echo "  - adminer"
                ;;
            *)
                echo "  - api"
                echo "  - data"
                echo "  - worker"
                echo "  - web"
                echo "  - nginx"
                echo "  - postgres"
                echo "  - redis"
                ;;
        esac
    fi
}

# Deploy services to environment
deploy_services() {
    local environment="${1:-development}"
    local deployment_type="${2:-standard}"
    shift 2 || true
    
    local services="$*"
    
    log_info "Deploying to $environment environment with $deployment_type deployment type..."
    [[ -n "$services" ]] && log_info "Services: $services"
    
    local compose_files=$(get_compose_files "$deployment_type")
    cd "$PROJECT_ROOT"
    docker_compose=$(get_docker_compose_cmd)
    
    case "$environment" in
        "production")
            log_warn "Production deployment - using careful rollout"
            # Add production overrides if not already specified
            if [[ "$deployment_type" != "prod" && "$deployment_type" != "production" ]]; then
                if [[ -f "docker-compose.prod.yml" ]]; then
                    compose_files="$compose_files -f docker-compose.prod.yml"
                fi
            fi
            
            # Stop services first
            $docker_compose $compose_files down || true
            # Pull latest images
            $docker_compose $compose_files pull
            # Start with health checks
            if [[ -n "$services" ]]; then
                $docker_compose $compose_files up -d --remove-orphans $services
            else
                $docker_compose $compose_files up -d --remove-orphans
            fi
            ;;
        "staging")
            log_info "Staging deployment"
            $docker_compose $compose_files pull
            if [[ -n "$services" ]]; then
                $docker_compose $compose_files up -d --force-recreate $services
            else
                $docker_compose $compose_files up -d --force-recreate
            fi
            ;;
        *)
            log_info "Development deployment"
            # Add development overrides if not already specified
            if [[ "$deployment_type" != "dev" && "$deployment_type" != "development" ]]; then
                if [[ -f "docker-compose.dev.yml" ]]; then
                    compose_files="$compose_files -f docker-compose.dev.yml"
                fi
            fi
            
            if [[ -n "$services" ]]; then
                $docker_compose $compose_files up -d --build $services
            else
                $docker_compose $compose_files up -d --build
            fi
            ;;
    esac
    
    log_success "Deployment completed"
}

# Update .env file with new image tags
update_env_file() {
    local services=""
    local tag=""
    local repo=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --services) services="$2"; shift 2 ;;
            --tag) tag="$2"; shift 2 ;;
            --repo) repo="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    
    if [[ -z "$services" ]] || [[ -z "$tag" ]] || [[ -z "$repo" ]]; then
        log_error "Missing required arguments for update-env"
        return 1
    fi
    
    log_info "Updating .env file with new image tags..."
    
    cd "$PROJECT_ROOT"
    
    # Backup existing .env
    [[ -f .env ]] && cp .env .env.backup
    
    # Update image tags
    IFS=',' read -ra SERVICE_ARRAY <<< "$services"
    for service in "${SERVICE_ARRAY[@]}"; do
        service=$(echo "$service" | xargs)
        service_upper=$(echo "$service" | tr '[:lower:]' '[:upper:]')
        image_tag="$repo:$service-$tag"
        
        # Update or add the image tag
        if grep -q "^${service_upper}_IMAGE=" .env 2>/dev/null; then
            sed -i "s|^${service_upper}_IMAGE=.*|${service_upper}_IMAGE=$image_tag|" .env
        else
            echo "${service_upper}_IMAGE=$image_tag" >> .env
        fi
    done
    
    log_success "Updated .env file with new image tags"
}

# Basic health check
health_check() {
    local deployment_type="${FKS_DEPLOYMENT_TYPE:-standard}"
    
    log_info "Running health check for deployment type: $deployment_type"
    
    cd "$PROJECT_ROOT"
    docker_compose=$(get_docker_compose_cmd)
    local compose_files=$(get_compose_files "$deployment_type")
    
    # Check Docker
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not accessible"
        return 1
    fi
    
    # Check running services
    running_services=$($docker_compose $compose_files ps --services --filter "status=running" 2>/dev/null || echo "")
    
    if [[ -z "$running_services" ]]; then
        log_warn "No services are running for deployment type: $deployment_type"
        return 1
    fi
    
    log_success "Services running: $(echo $running_services | tr '\n' ' ')"
    
    # Check service health
    while read -r service; do
        [[ -z "$service" ]] && continue
        
        # Check if service container exists and is healthy
        if docker ps --format "table {{.Names}}\t{{.Status}}" | grep -q "$service.*healthy"; then
            log_success "$service is healthy"
        elif docker ps --format "table {{.Names}}" | grep -q "$service"; then
            log_warn "$service is running but health unknown"
        else
            log_error "$service is not running"
        fi
    done <<< "$running_services"
    
    log_success "Health check completed for $deployment_type deployment"
}

# Clean system
clean_system() {
    local level="${1:-basic}"
    
    case "$level" in
        "basic")
            log_info "Basic cleanup..."
            rm -rf "$TEMP_DIR"/* 2>/dev/null || true
            rm -rf "$LOGS_DIR"/*.log 2>/dev/null || true
            ;;
        "docker")
            log_info "Docker cleanup..."
            docker system prune -f || true
            docker builder prune -f || true
            ;;
        "requirements")
            log_info "Requirements cleanup..."
            find "$DEPLOYMENT_DIR/requirements" -type f -delete 2>/dev/null || true
            ;;
        "all")
            log_warn "Full cleanup..."
            clean_system "basic"
            clean_system "docker"
            clean_system "requirements"
            # Remove all containers and volumes
            cd "$PROJECT_ROOT"
            docker_compose=$(get_docker_compose_cmd)
            $docker_compose down -v || true
            ;;
        *)
            log_error "Unknown cleanup level: $level"
            return 1
            ;;
    esac
    
    log_success "Cleanup completed"
}

# =============================================================================
# DOCKER HUB BUILD AND PUSH FUNCTIONS
# =============================================================================

# Validate Docker Hub configuration
validate_docker_hub_config() {
    if [[ -z "$DOCKER_HUB_USERNAME" ]]; then
        log_error "Docker Hub username not set. Set DOCKER_HUB_USERNAME environment variable."
        return 1
    fi
    
    # Check if logged into Docker Hub
    if ! docker info | grep -q "Username: $DOCKER_HUB_USERNAME"; then
        log_warn "Not logged into Docker Hub as $DOCKER_HUB_USERNAME"
        log_info "Please run: docker login"
        return 1
    fi
    
    return 0
}

# Get list of buildable services
get_buildable_services() {
    local deployment_type="${1:-standard}"
    
    # Define all 7 main custom services with their availability
    declare -A service_availability=(
        ["nginx"]="always"
        ["web"]="always" 
        ["api"]="always"
        ["worker"]="always"
        ["data"]="always"
        ["training"]="gpu"
        ["transformer"]="gpu"
    )
    
    local available_services=()
    local compose_files=$(get_compose_files "$deployment_type")
    
    # Try to get services from compose files first
    if [[ -f "docker-compose.yml" ]] && command -v docker >/dev/null 2>&1; then
        if docker_compose=$(get_docker_compose_cmd 2>/dev/null); then
            cd "$PROJECT_ROOT"
            # For GPU services, we need to include profiles
            local config_cmd="$docker_compose $compose_files"
            if [[ "$deployment_type" == "gpu" || "$deployment_type" == "ml" ]]; then
                config_cmd="$config_cmd --profile gpu --profile ml"
            fi
            
            if services_list=$($config_cmd config --services 2>/dev/null); then
                # Check each service for buildability
                for service in "${!service_availability[@]}"; do
                    if echo "$services_list" | grep -q "^${service}$"; then
                        if has_build_config "$service" "$deployment_type"; then
                            available_services+=("$service")
                        fi
                    fi
                done
            fi
        fi
    fi
    
    # Enhanced fallback based on deployment type
    if [[ ${#available_services[@]} -eq 0 ]]; then
        case "$deployment_type" in
            "api")
                available_services=("api" "worker" "nginx")
                ;;
            "web")
                available_services=("web" "nginx")
                ;;
            "auth")
                available_services=("nginx")
                ;;
            "minimal")
                available_services=("web" "api" "nginx")
                ;;
            "gpu"|"ml")
                # Include all services for GPU deployment
                available_services=("nginx" "web" "api" "worker" "data" "training" "transformer")
                ;;
            "development"|"dev")
                available_services=("nginx" "web" "api" "worker" "data")
                ;;
            "production"|"prod")
                available_services=("nginx" "web" "api" "worker" "data")
                ;;
            "full-stack"|"multi-node")
                # All main services except GPU-specific ones
                available_services=("nginx" "web" "api" "worker" "data")
                ;;
            *)
                # Standard deployment includes main services
                available_services=("nginx" "web" "api" "worker" "data")
                ;;
        esac
        log_debug "Using fallback service list for $deployment_type: ${available_services[*]}" >&2
    fi
    
    # Sort services for consistent output
    printf '%s\n' "${available_services[@]}" | sort
}

# Helper function to check if a service has build configuration
has_build_config() {
    local service="$1"
    local deployment_type="${2:-standard}"
    
    # Check for service-specific Dockerfile (like nginx)
    local service_dockerfile="$DEPLOYMENT_DIR/docker/$service/Dockerfile"
    if [[ -f "$service_dockerfile" ]]; then
        return 0
    fi
    
    # Check for shared Dockerfile that can build this service
    local shared_dockerfile="$DEPLOYMENT_DIR/docker/Dockerfile"
    if [[ -f "$shared_dockerfile" ]]; then
        # Services that use the shared Dockerfile
        case "$service" in
            web|api|worker|data|training|transformer)
                return 0
                ;;
        esac
    fi
    
    return 1
}

# Get all buildable services (for Docker Hub management)
get_all_buildable_services() {
    # Return all 7 main custom services that can be built
    echo "nginx"
    echo "web" 
    echo "api"
    echo "worker"
    echo "data"
    echo "training"
    echo "transformer"
}

# Build Docker image for a service
build_docker_image() {
    local service="$1"
    local tag="${2:-latest}"
    local dockerfile_path="$3"
    
    if [[ -z "$service" ]]; then
        log_error "Service name required for build"
        return 1
    fi
    
    local image_name="$DOCKER_HUB_USERNAME/$DOCKER_HUB_REPO:$service-$tag"
    
    log_info "Building Docker image: $image_name"
    
    # Determine Dockerfile path with improved logic
    if [[ -z "$dockerfile_path" ]]; then
        # Check for service-specific Dockerfile first (for nginx and other custom services)
        local possible_dockerfiles=(
            "$DEPLOYMENT_DIR/docker/$service/Dockerfile"
            "$DEPLOYMENT_DIR/docker/Dockerfile.$service"
            "$PROJECT_ROOT/docker/$service/Dockerfile"
            "$PROJECT_ROOT/Dockerfile.$service"
            "$PROJECT_ROOT/src/$service/Dockerfile"
        )
        
        local service_specific_found=false
        for df in "${possible_dockerfiles[@]}"; do
            if [[ -f "$df" ]]; then
                dockerfile_path="$df"
                service_specific_found=true
                log_info "Using service-specific Dockerfile: $dockerfile_path"
                break
            fi
        done
        
        # If no service-specific Dockerfile found, use shared Dockerfile for supported services
        if [[ "$service_specific_found" == false ]]; then
            local shared_dockerfile="$DEPLOYMENT_DIR/docker/Dockerfile"
            if [[ -f "$shared_dockerfile" ]]; then
                case "$service" in
                    web|api|worker|data|training|transformer)
                        dockerfile_path="$shared_dockerfile"
                        log_info "Using shared Dockerfile for service: $service"
                        ;;
                    *)
                        log_error "No supported Dockerfile configuration for service: $service"
                        log_info "Tried service-specific locations:"
                        printf '  %s\n' "${possible_dockerfiles[@]}"
                        log_info "  $shared_dockerfile (shared - not supported for $service)"
                        return 1
                        ;;
                esac
            else
                log_error "No Dockerfile found for service: $service"
                log_info "Tried locations:"
                printf '  %s\n' "${possible_dockerfiles[@]}"
                log_info "  $shared_dockerfile (shared Dockerfile - missing)"
                return 1
            fi
        fi
    fi
    
    if [[ ! -f "$dockerfile_path" ]]; then
        log_error "Dockerfile not found: $dockerfile_path"
        return 1
    fi
    
    log_info "Using Dockerfile: $dockerfile_path"
    log_info "Build context: $DOCKER_BUILD_CONTEXT"
    
    # Determine service type based on service name
    local service_type="$service"
    case "$service" in
        web|app) service_type="web" ;;
        api|data|worker|training|transformer) service_type="$service" ;;
        nginx) service_type="nginx" ;;
        *) service_type="$service" ;;
    esac
    
    # Build the image with appropriate build arguments
    local build_cmd="docker build -f \"$dockerfile_path\" -t \"$image_name\""
    
    # Add standard build arguments
    build_cmd="$build_cmd --build-arg SERVICE_NAME=\"$service\""
    build_cmd="$build_cmd --build-arg SERVICE_TYPE=\"$service_type\""
    build_cmd="$build_cmd --build-arg BUILD_DATE=\"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\""
    build_cmd="$build_cmd --build-arg VCS_REF=\"$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')\""
    build_cmd="$build_cmd --build-arg BUILD_VERSION=\"$tag\""
    build_cmd="$build_cmd --build-arg BUILD_COMMIT=\"$(git rev-parse HEAD 2>/dev/null || echo 'unknown')\""
    
    # Add service-specific build arguments based on Dockerfile type
    if [[ "$dockerfile_path" == *"deployment/docker/Dockerfile" ]]; then
        # Using shared Dockerfile - add service-specific arguments
        case "$service_type" in
            web)
                # Web service uses Node.js runtime
                build_cmd="$build_cmd --build-arg SERVICE_RUNTIME=node"
                build_cmd="$build_cmd --build-arg BUILD_NODE=true"
                build_cmd="$build_cmd --build-arg BUILD_PYTHON=false"
                build_cmd="$build_cmd --build-arg NODE_SRC_DIR=./src/web/react"
                build_cmd="$build_cmd --build-arg SERVICE_PORT=3000"
                ;;
            api|data|worker)
                # These services use Python runtime
                build_cmd="$build_cmd --build-arg BUILD_PYTHON=true"
                build_cmd="$build_cmd --build-arg SERVICE_RUNTIME=python"
                
                # Set appropriate requirements file and port based on service
                case "$service_type" in
                    api) 
                        build_cmd="$build_cmd --build-arg SERVICE_PORT=8000"
                        if [[ -f "$PROJECT_ROOT/src/python/requirements_prod.txt" ]]; then
                            build_cmd="$build_cmd --build-arg REQUIREMENTS_FILE=requirements_prod.txt"
                        fi
                        ;;
                    data)
                        build_cmd="$build_cmd --build-arg SERVICE_PORT=9001"
                        if [[ -f "$PROJECT_ROOT/src/python/requirements_prod.txt" ]]; then
                            build_cmd="$build_cmd --build-arg REQUIREMENTS_FILE=requirements_prod.txt"
                        fi
                        ;;
                    worker)
                        build_cmd="$build_cmd --build-arg SERVICE_PORT=8001"
                        if [[ -f "$PROJECT_ROOT/src/python/requirements_prod.txt" ]]; then
                            build_cmd="$build_cmd --build-arg REQUIREMENTS_FILE=requirements_prod.txt"
                        fi
                        ;;
                esac
                ;;
            training|transformer)
                # GPU services use Python runtime with GPU support
                build_cmd="$build_cmd --build-arg BUILD_PYTHON=true"
                build_cmd="$build_cmd --build-arg SERVICE_RUNTIME=python"
                build_cmd="$build_cmd --build-arg BUILD_TYPE=gpu"
                
                case "$service_type" in
                    training)
                        build_cmd="$build_cmd --build-arg SERVICE_PORT=8088"
                        ;;
                    transformer)
                        build_cmd="$build_cmd --build-arg SERVICE_PORT=8089"
                        ;;
                esac
                
                # Use GPU requirements if available
                if [[ -f "$PROJECT_ROOT/src/python/requirements_gpu.txt" ]]; then
                    build_cmd="$build_cmd --build-arg REQUIREMENTS_FILE=requirements_gpu.txt"
                fi
                ;;
            *)
                # Default to Python for other services
                build_cmd="$build_cmd --build-arg BUILD_PYTHON=true"
                build_cmd="$build_cmd --build-arg SERVICE_RUNTIME=python"
                ;;
        esac
    elif [[ "$dockerfile_path" == *"nginx/Dockerfile" ]]; then
        # Using nginx-specific Dockerfile
        build_cmd="$build_cmd --build-arg DOMAIN_NAME=\${DOMAIN_NAME:-localhost}"
        build_cmd="$build_cmd --build-arg ENABLE_SSL=\${ENABLE_SSL:-false}"
    fi
    
    build_cmd="$build_cmd \"$DOCKER_BUILD_CONTEXT\""
    
    log_debug "Build command: $build_cmd"
    
    # Execute build
    if eval "$build_cmd"; then
        log_success "Built image: $image_name"
        return 0
    else
        log_error "Failed to build image: $image_name"
        return 1
    fi
}

# Push Docker image to Docker Hub
push_docker_image() {
    local service="$1"
    local tag="${2:-latest}"
    
    if [[ -z "$service" ]]; then
        log_error "Service name required for push"
        return 1
    fi
    
    local image_name="$DOCKER_HUB_USERNAME/$DOCKER_HUB_REPO:$service-$tag"
    
    log_info "Pushing Docker image: $image_name"
    
    if docker push "$image_name"; then
        log_success "Pushed image: $image_name"
        return 0
    else
        log_error "Failed to push image: $image_name"
        return 1
    fi
}

# Build and push all services
build_and_push_all() {
    local tag="${1:-latest}"
    local services_to_build=()
    
    # Get services to build
    readarray -t services_to_build < <(get_all_buildable_services)
    
    if [[ ${#services_to_build[@]} -eq 0 ]]; then
        log_error "No services found to build"
        return 1
    fi
    
    log_info "Building and pushing ${#services_to_build[@]} FKS custom services with tag: $tag"
    log_info "Services: ${services_to_build[*]}"
    
    local failed_services=()
    local successful_services=()
    
    for service in "${services_to_build[@]}"; do
        [[ -z "$service" ]] && continue
        
        log_info "Processing service: $service"
        
        if build_docker_image "$service" "$tag"; then
            if push_docker_image "$service" "$tag"; then
                successful_services+=("$service")
            else
                failed_services+=("$service")
            fi
        else
            failed_services+=("$service")
        fi
    done
    
    # Report results
    echo ""
    log_info "Build and push summary:"
    
    if [[ ${#successful_services[@]} -gt 0 ]]; then
        log_success "Successful services (${#successful_services[@]}):"
        printf '  ✅ %s\n' "${successful_services[@]}"
    fi
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "Failed services (${#failed_services[@]}):"
        printf '  ❌ %s\n' "${failed_services[@]}"
        return 1
    fi
    
    log_success "All services built and pushed successfully!"
    return 0
}

# Build and push specific services
build_and_push_services() {
    local tag="latest"
    local services=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tag)
                tag="$2"
                shift 2
                ;;
            *)
                services+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_error "No services specified"
        return 1
    fi
    
    log_info "Building and pushing services: ${services[*]} with tag: $tag"
    
    local failed_services=()
    local successful_services=()
    
    for service in "${services[@]}"; do
        log_info "Processing service: $service"
        
        if build_docker_image "$service" "$tag"; then
            if push_docker_image "$service" "$tag"; then
                successful_services+=("$service")
            else
                failed_services+=("$service")
            fi
        else
            failed_services+=("$service")
        fi
    done
    
    # Report results
    echo ""
    log_info "Build and push summary:"
    
    if [[ ${#successful_services[@]} -gt 0 ]]; then
        log_success "Successful services (${#successful_services[@]}):"
        printf '  ✅ %s\n' "${successful_services[@]}"
    fi
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "Failed services (${#failed_services[@]}):"
        printf '  ❌ %s\n' "${failed_services[@]}"
        return 1
    fi
    
    log_success "All specified services built and pushed successfully!"
    return 0
}

# Pull prebuilt images from Docker Hub
pull_prebuilt_images() {
    local tag="${1:-latest}"
    local services=()
    
    shift || true
    services=("$@")
    
    # If no services specified, get all available
    if [[ ${#services[@]} -eq 0 ]]; then
        readarray -t services < <(get_all_buildable_services)
    fi
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_error "No services found to pull"
        return 1
    fi
    
    log_info "Pulling prebuilt FKS custom service images with tag: $tag"
    log_info "Services: ${services[*]}"
    
    local failed_services=()
    local successful_services=()
    
    for service in "${services[@]}"; do
        [[ -z "$service" ]] && continue
        
        local image_name="$DOCKER_HUB_USERNAME/$DOCKER_HUB_REPO:$service-$tag"
        log_info "Pulling: $image_name"
        
        if docker pull "$image_name"; then
            successful_services+=("$service")
        else
            failed_services+=("$service")
        fi
    done
    
    # Report results
    echo ""
    log_info "Pull summary:"
    
    if [[ ${#successful_services[@]} -gt 0 ]]; then
        log_success "Successfully pulled (${#successful_services[@]}):"
        printf '  ✅ %s\n' "${successful_services[@]}"
    fi
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "Failed to pull (${#failed_services[@]}):"
        printf '  ❌ %s\n' "${failed_services[@]}"
        return 1
    fi
    
    log_success "All images pulled successfully!"
    return 0
}

# Show Docker Hub status
show_docker_hub_status() {
    log_info "Docker Hub Configuration:"
    echo "  Username: ${DOCKER_HUB_USERNAME:-'Not set'}"
    echo "  Repository: $DOCKER_HUB_REPO"
    echo "  Build Context: $DOCKER_BUILD_CONTEXT"
    echo ""
    
    # Check login status
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            local logged_in_user=$(docker info 2>/dev/null | grep "Username:" | awk '{print $2}' || echo "")
            if [[ -n "$logged_in_user" ]]; then
                if [[ "$logged_in_user" == "$DOCKER_HUB_USERNAME" ]]; then
                    log_success "Logged into Docker Hub as: $logged_in_user"
                else
                    log_warn "Logged into Docker Hub as: $logged_in_user (expected: $DOCKER_HUB_USERNAME)"
                fi
            else
                log_warn "Not logged into Docker Hub"
            fi
        else
            log_error "Docker is not running"
        fi
    else
        log_error "Docker is not installed"
    fi
    
    echo ""
    log_info "FKS Custom Services (buildable):"
    get_all_buildable_services | while read -r service; do
        [[ -n "$service" ]] && echo "  - $service"
    done
    echo ""
    log_info "External Services (not buildable):"
    echo "  - postgres, redis, authelia-*, adminer, redis-commander, netdata, vscode"
}
# =============================================================================
# ENHANCED INTERACTIVE MODE
# =============================================================================

show_menu() {
    clear
    echo -e "${WHITE}===============================================================================${NC}"
    echo -e "${CYAN}         FKS Trading Systems v$SCRIPT_VERSION - $FKS_MODE Mode${NC}"
    if [[ -n "${FKS_DEPLOYMENT_TYPE:-}" ]]; then
        echo -e "${CYAN}         Deployment Type: ${FKS_DEPLOYMENT_TYPE}${NC}"
    fi
    echo -e "${WHITE}===============================================================================${NC}"
    echo ""
    echo -e "${YELLOW}System Management:${NC}"
    echo -e "  ${GREEN}1${NC}) System Status           ${GREEN}2${NC}) Health Check"
    echo -e "  ${GREEN}3${NC}) Setup System            ${GREEN}4${NC}) Update System"
    echo -e "  ${GREEN}5${NC}) Create FKS Symlink      ${GREEN}6${NC}) Remove FKS Symlink"
    echo ""
    echo -e "${YELLOW}Deployment Management:${NC}"
    echo -e "  ${GREEN}7${NC}) Set Deployment Type     ${GREEN}8${NC}) Show Deployment Info"
    echo ""
    echo -e "${YELLOW}Service Management:${NC}"
    echo -e "  ${GREEN}9${NC}) Start Services          ${GREEN}10${NC}) Stop Services"
    echo -e "  ${GREEN}11${NC}) Restart Services        ${GREEN}12${NC}) Show Logs"
    echo ""
    echo -e "${YELLOW}Build & Deploy:${NC}"
    echo -e "  ${GREEN}13${NC}) Build Services         ${GREEN}14${NC}) Build Images"
    echo -e "  ${GREEN}15${NC}) Generate Dockerfiles   ${GREEN}16${NC}) Generate Requirements"
    echo ""
    echo -e "${YELLOW}Requirements Management:${NC}"
    echo -e "  ${GREEN}17${NC}) Requirements Status    ${GREEN}18${NC}) List Services"
    echo -e "  ${GREEN}19${NC}) Validate Requirements  ${GREEN}20${NC}) Clean Requirements"
    echo ""
    echo -e "${YELLOW}Docker Management:${NC}"
    echo -e "  ${GREEN}21${NC}) Docker Status          ${GREEN}22${NC}) Docker Cleanup"
    echo -e "  ${GREEN}23${NC}) Docker Logs           ${GREEN}24${NC}) Container Shell"
    echo ""
    echo -e "${YELLOW}Cleanup Options:${NC}"
    echo -e "  ${GREEN}25${NC}) Clean Basic            ${GREEN}26${NC}) Clean Docker"
    echo -e "  ${GREEN}27${NC}) Clean All             ${GREEN}28${NC}) Emergency Reset"
    echo ""
    echo -e "${YELLOW}Docker Hub Management:${NC}"
    echo -e "  ${GREEN}29${NC}) Docker Hub Status      ${GREEN}30${NC}) Build & Push All"
    echo -e "  ${GREEN}31${NC}) Build & Push Services  ${GREEN}32${NC}) Pull Prebuilt Images"
    echo ""
    echo -e "${YELLOW}Information:${NC}"
    echo -e "  ${GREEN}h${NC}) Show Help              ${GREEN}d${NC}) Toggle Debug"
    echo -e "  ${GREEN}v${NC}) Show Version           ${GREEN}q${NC}) Exit"
    echo ""
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG MODE ENABLED]${NC}"
        echo ""
    fi
}

show_service_submenu() {
    clear
    echo -e "${CYAN}Service Selection${NC}"
    echo ""
    
    # Try to get services from compose file or discovered services
    local services=()
    if [[ -f "$COMPOSE_FILE" ]] && command -v docker >/dev/null 2>&1; then
        if services_list=$(cd "$PROJECT_ROOT" && get_docker_compose_cmd config --services 2>/dev/null); then
            readarray -t services <<< "$services_list"
        fi
    fi
    
    # Fallback to common services if none found (excludes postgres/redis)
    if [[ ${#services[@]} -eq 0 ]]; then
        services=("api" "app" "worker" "data" "web" "training" "transformer" "nginx")
    fi
    
    echo -e "${YELLOW}Available Services:${NC}"
    for i in "${!services[@]}"; do
        echo -e "  ${GREEN}$((i+1))${NC}) ${services[i]}"
    done
    echo ""
    echo -e "${GREEN}a${NC}) All services"
    echo -e "${GREEN}b${NC}) Back to main menu"
    echo ""
    echo -n "Select service(s) (comma-separated numbers, 'a' for all, 'b' for back): "
    
    read -r selection
    
    case "$selection" in
        "b"|"") return 1 ;;
        "a") echo "${services[*]}" ;;
        *)
            local selected_services=()
            IFS=',' read -ra selections <<< "$selection"
            for sel in "${selections[@]}"; do
                sel=$(echo "$sel" | tr -d ' ')  # Remove spaces
                if [[ "$sel" =~ ^[0-9]+$ ]] && [[ $sel -ge 1 ]] && [[ $sel -le ${#services[@]} ]]; then
                    selected_services+=("${services[$((sel-1))]}")
                fi
            done
            echo "${selected_services[*]}"
            ;;
    esac
}

# Deployment type management functions
show_deployment_submenu() {
    clear
    echo -e "${CYAN}Deployment Type Selection${NC}"
    echo ""
    echo -e "${YELLOW}Available Deployment Types:${NC}"
    echo -e "  ${GREEN}1${NC}) standard      - Default docker-compose.yml only"
    echo -e "  ${GREEN}2${NC}) api          - API server focused (includes database)"
    echo -e "  ${GREEN}3${NC}) auth         - Authentication server focused"
    echo -e "  ${GREEN}4${NC}) web          - Web server focused (frontend)"
    echo -e "  ${GREEN}5${NC}) minimal      - Minimal services only"
    echo -e "  ${GREEN}6${NC}) development  - Development with hot reloading"
    echo -e "  ${GREEN}7${NC}) production   - Production optimized"
    echo -e "  ${GREEN}8${NC}) gpu          - GPU-accelerated services"
    echo -e "  ${GREEN}9${NC}) pull-only    - Pull prebuilt images only"
    echo -e "  ${GREEN}10${NC}) node-network - Multi-node network setup"
    echo -e "  ${GREEN}11${NC}) full-stack   - All main services"
    echo -e "  ${GREEN}12${NC}) multi-node   - Complete multi-node cluster"
    echo ""
    echo -e "Current deployment type: ${FKS_DEPLOYMENT_TYPE:-standard}"
    echo ""
    echo -e "${GREEN}c${NC}) Clear deployment type (use standard)"
    echo -e "${GREEN}b${NC}) Back to main menu"
    echo ""
    echo -n "Select deployment type: "
    
    read -r selection
    
    case "$selection" in
        "1") echo "standard" ;;
        "2") echo "api" ;;
        "3") echo "auth" ;;
        "4") echo "web" ;;
        "5") echo "minimal" ;;
        "6") echo "development" ;;
        "7") echo "production" ;;
        "8") echo "gpu" ;;
        "9") echo "pull-only" ;;
        "10") echo "node-network" ;;
        "11") echo "full-stack" ;;
        "12") echo "multi-node" ;;
        "c") echo "clear" ;;
        "b"|"") return 1 ;;
        *) return 1 ;;
    esac
}

set_deployment_type() {
    if deployment_type=$(show_deployment_submenu); then
        if [[ "$deployment_type" == "clear" ]]; then
            unset FKS_DEPLOYMENT_TYPE
            log_info "Deployment type cleared (using standard)"
        else
            export FKS_DEPLOYMENT_TYPE="$deployment_type"
            log_success "Deployment type set to: $deployment_type"
        fi
    fi
}

show_deployment_info() {
    echo -e "${CYAN}Deployment Information${NC}"
    echo ""
    echo "Current deployment type: ${FKS_DEPLOYMENT_TYPE:-standard}"
    echo ""
    
    local deployment_type="${FKS_DEPLOYMENT_TYPE:-standard}"
    local compose_files=$(get_compose_files "$deployment_type")
    
    echo "Compose files that will be used:"
    echo "$compose_files" | tr ' ' '\n' | grep -E "^-f" | sed 's/-f /  - /'
    echo ""
    
    echo "Available services for this deployment:"
    list_services "$deployment_type"
    echo ""
    
    echo "Buildable services for this deployment:"
    get_buildable_services "$deployment_type" | while read -r service; do
        [[ -n "$service" ]] && echo "  - $service"
    done
}

# Docker Hub submenu helper
show_docker_hub_submenu() {
    clear
    echo -e "${CYAN}Docker Hub Options${NC}"
    echo ""
    
    # Show current config
    echo -e "${YELLOW}Current Configuration:${NC}"
    echo "  Username: ${DOCKER_HUB_USERNAME:-'Not set'}"
    echo "  Repository: $DOCKER_HUB_REPO"
    echo ""
    
    # Get available services (suppress warnings for cleaner display)
    local services=()
    readarray -t services < <(get_all_buildable_services)
    
    # This should always have all 7 services, but fallback just in case
    if [[ ${#services[@]} -eq 0 ]]; then
        services=("nginx" "web" "api" "worker" "data" "training" "transformer")
    fi
    
    echo -e "${YELLOW}Available Services:${NC}"
    for i in "${!services[@]}"; do
        echo -e "  ${GREEN}$((i+1))${NC}) ${services[i]}"
    done
    echo ""
    echo -e "${GREEN}a${NC}) All services"
    echo -e "${GREEN}b${NC}) Back to main menu"
    echo ""
    
    echo -n "Enter tag (default: latest): "
    read -r tag
    tag="${tag:-latest}"
    
    echo -n "Select service(s) (comma-separated numbers, 'a' for all, 'b' for back): "
    read -r selection
    
    case "$selection" in
        "b"|"") return 1 ;;
        "a") echo "all:$tag" ;;
        *)
            local selected_services=()
            IFS=',' read -ra selections <<< "$selection"
            for sel in "${selections[@]}"; do
                sel=$(echo "$sel" | tr -d ' ')
                if [[ "$sel" =~ ^[0-9]+$ ]] && [[ $sel -ge 1 ]] && [[ $sel -le ${#services[@]} ]]; then
                    selected_services+=("${services[$((sel-1))]}")
                fi
            done
            if [[ ${#selected_services[@]} -gt 0 ]]; then
                echo "${selected_services[*]}:$tag"
            else
                return 1
            fi
            ;;
    esac
}

run_interactive() {
    while true; do
        show_menu
        echo -n "Select option: "
        read -r choice
        echo ""
        
        case "$choice" in
            # System Management
            1) execute_command "status" ;;
            2) execute_command "health" ;;
            3) execute_command "setup" ;;
            4) execute_command "update" ;;
            5) create_fks_symlink ;;
            6) remove_fks_symlink ;;
            
            # Deployment Management
            7) set_deployment_type ;;
            8) show_deployment_info ;;
            
            # Service Management
            9) 
                if selected_services=$(show_service_submenu); then
                    [[ -n "$selected_services" ]] && execute_command "start" $selected_services
                fi
                ;;
            10) 
                if selected_services=$(show_service_submenu); then
                    [[ -n "$selected_services" ]] && execute_command "stop" $selected_services
                fi
                ;;
            11) 
                if selected_services=$(show_service_submenu); then
                    [[ -n "$selected_services" ]] && execute_command "restart" $selected_services
                fi
                ;;
            12) 
                if selected_services=$(show_service_submenu); then
                    [[ -n "$selected_services" ]] && execute_command "logs" $selected_services
                fi
                ;;
            
            # Build & Deploy
            13) execute_command "build" ;;
            14) execute_command "build-images" ;;
            15) execute_command "generate-dockerfiles" ;;
            16) execute_command "generate-requirements" ;;
            
            # Requirements Management
            17) execute_command "requirements-status" ;;
            18) execute_command "list-services" ;;
            19) execute_command "validate-requirements" ;;
            20) execute_command "clean-requirements" ;;
            
            # Docker Management
            21) execute_command "docker-status" ;;
            22) 
                echo "Cleanup level:"
                echo "1) Basic  2) System  3) All"
                echo -n "Select: "
                read -r level_choice
                case "$level_choice" in
                    1) execute_command "docker-cleanup" "basic" ;;
                    2) execute_command "docker-cleanup" "system" ;;
                    3) execute_command "docker-cleanup" "all" ;;
                    *) log_warn "Invalid choice" ;;
                esac
                ;;
            23) 
                if selected_services=$(show_service_submenu); then
                    [[ -n "$selected_services" ]] && execute_command "docker-logs" $selected_services
                fi
                ;;
            24) run_container_shell ;;
            
            # Cleanup Options
            25) execute_command "clean" "basic" ;;
            26) execute_command "clean" "docker" ;;
            27) execute_command "clean" "all" ;;
            28) run_emergency_reset ;;
            
            # Docker Hub Management
            29) run_docker_hub_status ;;
            30) run_docker_hub_build_push_all ;;
            31) run_docker_hub_build_push_services ;;
            32) run_docker_hub_pull_images ;;
            
            # Information
            h) execute_command "help" ;;
            d) toggle_debug ;;
            v) execute_command "version" ;;
            q) break ;;
            "") continue ;;
            *) log_warn "Invalid option: $choice" ;;
        esac
        
        if [[ "$choice" != "q" ]]; then
            echo ""
            echo "Press Enter to continue..."
            read -r
        fi
    done
}

run_container_shell() {
    if selected_services=$(show_service_submenu); then
        if [[ -n "$selected_services" ]]; then
            local service=$(echo "$selected_services" | cut -d' ' -f1)  # Take first service
            echo "Opening shell in $service container..."
            if cd "$PROJECT_ROOT" && docker_compose=$(get_docker_compose_cmd); then
                $docker_compose exec "$service" /bin/bash || \
                $docker_compose exec "$service" /bin/sh || \
                log_error "Could not open shell in $service"
            fi
        fi
    fi
}

run_emergency_reset() {
    echo -e "${RED}⚠️  EMERGENCY RESET - This will clean everything!${NC}"
    echo "This will:"
    echo "  • Stop all services"
    echo "  • Remove all Docker containers, images, and volumes"
    echo "  • Clean all logs and temp files"
    echo "  • Reset requirements files"
    echo ""
    echo -n "Are you sure? Type 'EMERGENCY RESET' to continue: "
    read -r confirmation
    
    if [[ "$confirmation" == "EMERGENCY RESET" ]]; then
        log_warn "Performing emergency reset..."
        execute_command "stop" 2>/dev/null || true
        execute_command "clean" "all"
        log_success "Emergency reset completed"
    else
        log_info "Emergency reset cancelled"
    fi
}

toggle_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        export DEBUG=false
        log_info "Debug mode disabled"
    else
        export DEBUG=true
        log_info "Debug mode enabled"
    fi
}

# Docker Hub interactive functions
run_docker_hub_status() {
    if ! validate_docker_hub_config; then
        echo ""
        echo "To configure Docker Hub:"
        echo "1. Set DOCKER_HUB_USERNAME environment variable"
        echo "2. Run: docker login"
        echo ""
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    show_docker_hub_status
}

run_docker_hub_build_push_all() {
    if ! validate_docker_hub_config; then
        echo ""
        echo "Please configure Docker Hub first (option 25)"
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    echo -n "Enter tag for all images (default: latest): "
    read -r tag
    tag="${tag:-latest}"
    
    echo ""
    log_info "Building and pushing ALL services with tag: $tag"
    echo "This may take a while..."
    echo ""
    echo -n "Continue? (y/N): "
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        build_and_push_all "$tag"
    else
        log_info "Operation cancelled"
    fi
}

run_docker_hub_build_push_services() {
    if ! validate_docker_hub_config; then
        echo ""
        echo "Please configure Docker Hub first (option 25)"
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    if selection=$(show_docker_hub_submenu); then
        if [[ -n "$selection" ]]; then
            local services_and_tag="$selection"
            local tag="${services_and_tag#*:}"
            local services="${services_and_tag%:*}"
            
            if [[ "$services" == "all" ]]; then
                build_and_push_all "$tag"
            else
                build_and_push_services --tag "$tag" $services
            fi
        fi
    fi
}

run_docker_hub_pull_images() {
    if [[ -z "$DOCKER_HUB_USERNAME" ]]; then
        echo ""
        echo "Docker Hub username not set. Set DOCKER_HUB_USERNAME environment variable."
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    if selection=$(show_docker_hub_submenu); then
        if [[ -n "$selection" ]]; then
            local services_and_tag="$selection"
            local tag="${services_and_tag#*:}"
            local services="${services_and_tag%:*}"
            
            if [[ "$services" == "all" ]]; then
                pull_prebuilt_images "$tag"
            else
                pull_prebuilt_images "$tag" $services
            fi
        fi
    fi
}
# =============================================================================
# COMMAND EXECUTION
# =============================================================================

execute_command() {
    local cmd="$1"
    shift || true
    
    # Built-in commands
    case "$cmd" in
        "help"|"-h"|"--help")
            show_help
            return 0
            ;;
        "version"|"-v"|"--version")
            show_version
            return 0
            ;;
        "init"|"initialize")
            initialize_system
            return 0
            ;;
        "create-symlink"|"symlink")
            create_fks_symlink
            return 0
            ;;
        "remove-symlink"|"unsymlink")
            remove_fks_symlink
            return 0
            ;;
        "set-deployment-type")
            export FKS_DEPLOYMENT_TYPE="$1"
            log_success "Deployment type set to: $1"
            return 0
            ;;
        "show-deployment-info")
            show_deployment_info
            return 0
            ;;
        "list-services")
            list_services "${1:-${FKS_DEPLOYMENT_TYPE:-standard}}"
            return 0
            ;;
        "deploy")
            deploy_services "$@"
            return 0
            ;;
        "update-env")
            update_env_file "$@"
            return 0
            ;;
        "health")
            health_check
            return 0
            ;;
        "clean")
            clean_system "$@"
            return 0
            ;;
        # Conda environment management
        "conda-setup")
            conda_setup_env
            return 0
            ;;
        "conda-install")
            conda_install_requirements "$@"
            return 0
            ;;
        "conda-info")
            get_conda_cmd >/dev/null 2>&1 || true
            conda_info
            return 0
            ;;
        # Docker Hub commands
        "docker-hub-status")
            show_docker_hub_status
            return 0
            ;;
        "build-push-all")
            if ! validate_docker_hub_config; then
                return 1
            fi
            build_and_push_all "$@"
            return 0
            ;;
        "build-push")
            if ! validate_docker_hub_config; then
                return 1
            fi
            build_and_push_services "$@"
            return 0
            ;;
        "pull-images")
            pull_prebuilt_images "$@"
            return 0
            ;;
        # Direct build commands
        "build-images")
            if [[ $# -eq 0 ]]; then
                log_info "Building all Docker images..."
                if ! validate_docker_hub_config; then
                    return 1
                fi
                build_and_push_all "latest"
            else
                log_info "Building specific Docker images: $*"
                if ! validate_docker_hub_config; then
                    return 1
                fi
                local services=("$@")
                local tag="latest"
                
                # Check if last argument is a tag (not a service name)
                local last_arg="${!#}"
                if [[ "$last_arg" =~ ^[a-z0-9.-]+$ ]] && [[ "${#services[@]}" -gt 1 ]]; then
                    # Last argument might be a tag, extract it
                    tag="$last_arg"
                    unset 'services[-1]'  # Remove last element
                fi
                
                for service in "${services[@]}"; do
                    if ! build_docker_image "$service" "$tag"; then
                        log_error "Failed to build $service"
                        return 1
                    fi
                done
            fi
            return 0
            ;;
    esac
    
    # Check scripts
    if ! check_scripts; then
        log_error "Cannot execute commands - script issues detected"
        return 1
    fi
    
    # Execute via main script
    log_info "Executing: $cmd $*"
    cd "$PROJECT_ROOT"
    
    # Set debug mode if enabled
    local debug_flag=""
    if [[ "${DEBUG:-false}" == "true" ]]; then
        debug_flag="--debug"
    fi
    
    "$MAIN_SCRIPT" $debug_flag "$cmd" "$@"
}

# =============================================================================
# SYSTEM INITIALIZATION
# =============================================================================

initialize_system() {
    log_info "🔧 Initializing FKS Trading Systems..."
    
    # Ensure directories
    log_info "Creating directory structure..."
    ensure_directories
    
    # Make scripts executable
    log_info "Setting script permissions..."
    [[ -f "$MAIN_SCRIPT" ]] && chmod +x "$MAIN_SCRIPT"
    [[ -f "$DOCKER_SCRIPT" ]] && chmod +x "$DOCKER_SCRIPT"
    [[ -f "$REQUIREMENTS_SCRIPT" ]] && chmod +x "$REQUIREMENTS_SCRIPT"
    
    # Find and make all .sh files executable
    find "$SCRIPTS_DIR" -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true
    
    # Initialize via main script if available
    if check_scripts; then
        log_info "Running system setup..."
        execute_command "setup"
    else
        log_warn "Some scripts missing - basic initialization only"
    fi
    
    log_success "System initialization completed"
}

show_version() {
    echo -e "${WHITE}FKS Trading Systems v$SCRIPT_VERSION${NC}"
    echo -e "${CYAN}Mode: $FKS_MODE${NC}"
    echo -e "${CYAN}Deployment Type: ${FKS_DEPLOYMENT_TYPE:-standard}${NC}"
    echo ""
    echo "Component Status:"
    
    # Check main script
    if [[ -f "$MAIN_SCRIPT" ]]; then
        echo "  ✅ Main Script: Available"
    else
        echo "  ❌ Main Script: Missing"
    fi
    
    # Check docker script
    if [[ -f "$DOCKER_SCRIPT" ]]; then
        echo "  ✅ Docker Script: Available"
    else
        echo "  ❌ Docker Script: Missing"
    fi
    
    # Check requirements script
    if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
        echo "  ✅ Requirements Script: Available"
    else
        echo "  ❌ Requirements Script: Missing"
    fi
    
    # Check Docker
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            echo "  ✅ Docker: Running"
        else
            echo "  ⚠️  Docker: Installed but not running"
        fi
    else
        echo "  ❌ Docker: Not installed"
    fi
    
    echo ""
    echo "Available Compose Files:"
    for file in docker-compose*.yml; do
        if [[ -f "$file" ]]; then
            echo "  ✅ $file"
        fi
    done
    
    echo ""
    echo "Current Deployment Configuration:"
    local compose_files=$(get_compose_files "${FKS_DEPLOYMENT_TYPE:-standard}")
    echo "  Compose files: $compose_files"
    
    echo ""
    echo "Paths:"
    echo "  Project Root: $PROJECT_ROOT"
    echo "  Scripts: $SCRIPTS_DIR"
    echo "  Config: $CONFIG_DIR"
}

# =============================================================================
# HELP SYSTEM
# =============================================================================

show_help() {
    cat << EOF
${WHITE}FKS Trading Systems v$SCRIPT_VERSION${NC} - ${CYAN}Mode: $FKS_MODE${NC}

${YELLOW}USAGE:${NC}
  $0 [command] [arguments]      # Direct command execution
  $0                            # Interactive mode
  $0 --interactive              # Force interactive mode

${YELLOW}SYSTEM COMMANDS:${NC}
  status                        Show comprehensive system status
  health                        Run health check
  setup                         Setup system directories and scripts
  update                        Update requirements and rebuild
    conda-setup                   Create local conda env in ./.conda/fks_dev and install dev deps
    conda-install [req.txt]       Install requirements into the local conda env
    conda-info                    Show info about the local conda env
  init                          Initialize system (first-time setup)
  create-symlink | symlink      Create symlink from current location to /home/$USER/fks
  remove-symlink | unsymlink    Remove symlink at /home/$USER/fks
  clean [basic|docker|requirements|all]  Clean system

${YELLOW}DEPLOYMENT COMMANDS:${NC}
  set-deployment-type <type>    Set deployment type (standard, api, auth, web, minimal, dev, prod, gpu, etc.)
  show-deployment-info          Show current deployment configuration
  deploy <env> [type] [services]  Deploy to environment with optional type
  list-services [type]          List services for deployment type

${YELLOW}SERVICE COMMANDS:${NC}
  start [services...]           Start services
  stop [services...]            Stop services
  restart [services...]         Restart services
  logs [services...]            Show service logs
  list-services                 List available services

${YELLOW}BUILD COMMANDS:${NC}
  build [services...]           Build services (compose)
  build-images [services...]    Build Docker images (docker.sh)
  generate-dockerfiles          Generate Dockerfiles

${YELLOW}REQUIREMENTS COMMANDS:${NC}
  generate-requirements         Generate service requirements
  requirements-status           Show requirements status
  validate-requirements         Validate requirements system
  clean-requirements            Clean requirements files

${YELLOW}DOCKER HUB COMMANDS:${NC}
  docker-hub-status             Show Docker Hub configuration and status
  build-push-all [tag]          Build and push all services to Docker Hub
  build-push [--tag <tag>] <services...>  Build and push specific services
  pull-images [tag] [services...]  Pull prebuilt images from Docker Hub

${YELLOW}DEPLOYMENT COMMANDS:${NC}
  deploy [environment] [services...]  Deploy to environment
  update-env --services <list> --tag <tag> --repo <repo>  Update .env

${YELLOW}DOCKER COMMANDS:${NC}
  docker-status                 Show Docker system status
  docker-cleanup [level]        Clean Docker system
  docker-logs [service]         Show Docker logs

${YELLOW}OPTIONS:${NC}
  -h, --help                    Show this help
  -v, --version                 Show version and component status
  -i, --interactive             Force interactive mode
  --debug                       Enable debug output
  --deployment-type <type>      Set deployment type for this run
  --set-deployment-type <type>  Set deployment type and exit

${YELLOW}ENVIRONMENT VARIABLES:${NC}
  FKS_DEPLOYMENT_TYPE           Set default deployment type
  DEBUG                         Enable debug output (true/false)
  FKS_MODE                      Set operation mode (development/production)
  DOCKER_HUB_USERNAME           Docker Hub username for builds
  DOCKER_HUB_REPO               Docker Hub repository name

${YELLOW}EXAMPLES:${NC}
  $0                            # Interactive mode
  $0 init                       # First-time setup
  $0 status                     # Show system status
  $0 create-symlink             # Create symlink to /home/$USER/fks
  $0 set-deployment-type api    # Set deployment type to API-focused
  $0 list-services gpu          # List services for GPU deployment
  $0 deploy production api      # Deploy API services to production
  $0 start api worker           # Start specific services
  $0 generate-requirements      # Generate service requirements
  $0 build-images               # Build all Docker images
  $0 docker-cleanup system      # Clean Docker system
  $0 clean all                  # Full system cleanup
  
  # Docker Hub examples
  $0 docker-hub-status          # Show Docker Hub config
  $0 build-push-all v1.0        # Build and push all with tag v1.0
  $0 build-push --tag latest api worker  # Build and push specific services
  $0 pull-images v1.0           # Pull all prebuilt images with tag v1.0
  $0 pull-images latest api     # Pull specific image

${YELLOW}DOCKER HUB SETUP:${NC}
  1. Set environment variable: export DOCKER_HUB_USERNAME=yourusername
  2. Login to Docker Hub: docker login
  3. Optionally set repository: export DOCKER_HUB_REPO=your-repo-name

${WHITE}Integration:${NC}
  Main Script: $MAIN_SCRIPT
  Docker Script: $DOCKER_SCRIPT
  Requirements Script: $REQUIREMENTS_SCRIPT

${WHITE}Key Paths:${NC}
  Project Root: $PROJECT_ROOT
  Config Dir: $CONFIG_DIR
  Scripts Dir: $SCRIPTS_DIR
  Compose File: $COMPOSE_FILE

${YELLOW}Interactive Mode Features:${NC}
  • Visual menu interface
  • Service selection menus
  • Built-in help and debug toggle
  • Safe emergency reset option
  • Real-time status display
EOF
}

# =============================================================================
# MAIN FUNCTION
# =============================================================================

main() {
    # Ensure directories exist
    ensure_directories
    
    # Handle debug flag early
    if [[ "${1:-}" == "--debug" ]]; then
        export DEBUG=true
        shift
    fi
    
    # Handle special flags
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            show_version
            exit 0
            ;;
        -i|--interactive)
            run_interactive
            exit 0
            ;;
        --init|init|initialize)
            initialize_system
            exit 0
            ;;
        --deployment-type)
            export FKS_DEPLOYMENT_TYPE="$2"
            log_info "Deployment type set to: $2"
            shift 2
            ;;
        --set-deployment-type)
            export FKS_DEPLOYMENT_TYPE="$2"
            log_success "Deployment type set to: $2"
            exit 0
            ;;
    esac
    
    # No arguments = interactive mode
    if [[ $# -eq 0 ]]; then
        run_interactive
        exit 0
    fi
    
    # Execute command
    execute_command "$@"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

# Export environment variables
export PROJECT_ROOT SCRIPTS_DIR BUILD_SCRIPTS_DIR CONFIG_DIR DATA_DIR LOGS_DIR DEPLOYMENT_DIR
export FKS_MODE SCRIPT_VERSION

# Run main function
main "$@"