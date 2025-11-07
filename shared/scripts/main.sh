#!/usr/bin/env bash
# Universal Service Orchestrator (neutralized)
# Backward-compatible with prior hardcoded FKS main.sh (v0.2.x).
# New: dynamic root detection, PROJECT_NS + SERVICE_FAMILY namespace, unified logging.

set -euo pipefail

# =============================================================================
# HARDCODED CONFIGURATION
# =============================================================================

PROJECT_NS="${PROJECT_NS:-fks}"           # namespace (was implicitly fks)
SERVICE_FAMILY="${SERVICE_FAMILY:-trading}" # logical grouping; customizable

# Root autodetect: if this script is inside shared_scripts, assume repo root two levels up unless OVERRIDE_ROOT set.
if [[ -n "${OVERRIDE_ROOT:-}" ]]; then
    PROJECT_ROOT="$OVERRIDE_ROOT"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # Allow execution from anywhere; look upward for marker dirs
    _probe="$SCRIPT_DIR"
    while [[ "$ _probe" != "/" ]]; do
        if [[ -d "$_probe/config" && -d "$_probe/scripts" ]] || [[ -f "$_probe/.project-root" ]]; then
            PROJECT_ROOT="$_probe"
            break
        fi
        _probe="$(dirname "$_probe")"
    done
    PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}" # fallback
fi

SCRIPTS_DIR="$PROJECT_ROOT/scripts"
BUILD_SCRIPTS_DIR="$SCRIPTS_DIR/build"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
LOGS_DIR="$PROJECT_ROOT/logs"
DEPLOYMENT_DIR="$PROJECT_ROOT/deployment"
TEMP_DIR="$PROJECT_ROOT/temp"

MAIN_CONFIG="$CONFIG_DIR/main.yaml"
SERVICES_CONFIG="$CONFIG_DIR/services.yaml"
DOCKER_CONFIG="$CONFIG_DIR/docker.yaml"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
LOG_FILE="$LOGS_DIR/main.log"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"

# Build scripts
DOCKER_SCRIPT="$BUILD_SCRIPTS_DIR/docker.sh"
REQUIREMENTS_SCRIPT="$BUILD_SCRIPTS_DIR/requirements.sh"

# Script settings
MAIN_SCRIPT_VERSION="0.3.0"
FKS_MODE="${FKS_MODE:-development}"

# Import centralized logging if available
if [[ -f "$PROJECT_ROOT/shared_repos/shared_scripts/lib/log.sh" ]]; then
    # if running inside mono-repo with shared_repos layout
    source "$PROJECT_ROOT/shared_repos/shared_scripts/lib/log.sh"
elif [[ -f "$PROJECT_ROOT/scripts/lib/log.sh" ]]; then
    source "$PROJECT_ROOT/scripts/lib/log.sh"
fi

: "${LOG_FORMAT:=plain}" # allow override

# If no logging functions (standalone usage), define minimal fallbacks
if ! declare -F log_info >/dev/null 2>&1; then
    _plain_log() { printf '[%s] %s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >&2; }
    log_info() { _plain_log INFO "$*"; }
    log_warn() { _plain_log WARN "$*"; }
    log_error() { _plain_log ERROR "$*"; }
    log_success() { _plain_log INFO "$*"; }
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && _plain_log DEBUG "$*" || true; }
fi

# =============================================================================
# SCRIPT INTEGRATION
# =============================================================================

run_docker_script() {
    local action="$1"
    shift || true
    
    if [[ ! -f "$DOCKER_SCRIPT" ]]; then
        log_error "Docker script not found: $DOCKER_SCRIPT"
        return 1
    fi
    
    log_info "🐳 Running Docker script: $action"
    bash "$DOCKER_SCRIPT" "$action" "$@"
}

run_requirements_script() {
    local action="$1"
    shift || true
    
    if [[ ! -f "$REQUIREMENTS_SCRIPT" ]]; then
        log_error "Requirements script not found: $REQUIREMENTS_SCRIPT"
        return 1
    fi
    
    log_info "📦 Running Requirements script: $action"
    bash "$REQUIREMENTS_SCRIPT" "$action" "$@"
}

# =============================================================================
# DOCKER COMPOSE WRAPPER WITH MULTI-FILE SUPPORT
# =============================================================================

# Get compose files based on deployment type  
get_compose_files() {
    local deployment_type="${FKS_DEPLOYMENT_TYPE:-standard}"
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
            compose_files="-f docker-compose.yml -f docker-compose.api.yml -f docker-compose.web.yml -f docker-compose.auth.yml"
            ;;
        "multi-node")
            compose_files="-f docker-compose.yml -f docker-compose.api.yml -f docker-compose.web.yml -f docker-compose.auth.yml -f docker-compose.node-network.yml"
            ;;
        *)
            log_warn "Unknown deployment type: $deployment_type, using standard"
            compose_files="-f docker-compose.yml"
            ;;
    esac
    
    echo "$compose_files"
}

docker_compose() {
    local compose_cmd
    local compose_files
    
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    else
        log_error "Neither 'docker compose' nor 'docker-compose' found"
        return 1
    fi
    
    compose_files=$(get_compose_files)
    
    cd "$PROJECT_ROOT"
    log_debug "Using compose files: $compose_files"
    log_debug "Command: $compose_cmd $compose_files $*"
    
    $compose_cmd $compose_files "$@"
}

# =============================================================================
# SYSTEM STATUS & HEALTH
# =============================================================================

show_system_status() {
    log_info "📊 ${PROJECT_NS^^} System Status"
    echo ""
    
    # Environment info
    echo "Environment:"
    echo "  Mode: $FKS_MODE"
    echo "  Version: $MAIN_SCRIPT_VERSION"
    echo "  Project Root: $PROJECT_ROOT"
    echo ""
    
    # Directory status
    echo "Directories:"
    local dirs=("$CONFIG_DIR:config" "$DATA_DIR:data" "$LOGS_DIR:logs" "$SCRIPTS_DIR:scripts" "$DEPLOYMENT_DIR:deployment")
    for entry in "${dirs[@]}"; do
        local dir="${entry%:*}"
        local name="${entry#*:}"
        if [[ -d "$dir" ]]; then
            local count=$(find "$dir" -type f 2>/dev/null | wc -l)
            echo "  ✅ $name: $count files"
        else
            echo "  ❌ $name: Missing"
        fi
    done
    echo ""
    
    # Key files
    echo "Key Files:"
    local files=(
        "$COMPOSE_FILE:docker-compose.yml"
        "$MAIN_CONFIG:main.yaml"
        "$SERVICES_CONFIG:services.yaml"
        "$REQUIREMENTS_FILE:requirements.txt"
        "$DOCKER_SCRIPT:docker.sh"
        "$REQUIREMENTS_SCRIPT:requirements.sh"
    )
    for entry in "${files[@]}"; do
        local file="${entry%:*}"
        local name="${entry#*:}"
        if [[ -f "$file" ]]; then
            echo "  ✅ $name: Found"
        else
            echo "  ❌ $name: Missing"
        fi
    done
    echo ""
    
    # Build scripts status
    check_build_scripts_status
    
    # Docker status
    check_docker_status
    
    # Services status
    check_services_status
    
    # Requirements status
    check_requirements_status
}

check_build_scripts_status() {
    echo "Build Scripts:"
    
    if [[ -f "$DOCKER_SCRIPT" ]]; then
        echo "  ✅ Docker script: Available"
        if [[ -x "$DOCKER_SCRIPT" ]]; then
            echo "    ✅ Executable"
        else
            echo "    ⚠️  Not executable"
        fi
    else
        echo "  ❌ Docker script: Missing"
    fi
    
    if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
        echo "  ✅ Requirements script: Available"
        if [[ -x "$REQUIREMENTS_SCRIPT" ]]; then
            echo "    ✅ Executable"
        else
            echo "    ⚠️  Not executable"
        fi
    else
        echo "  ❌ Requirements script: Missing"
    fi
    echo ""
}

check_docker_status() {
    echo "Docker Status:"
    
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            echo "  ✅ Docker: Running"
            
            if docker compose version >/dev/null 2>&1; then
                echo "  ✅ Docker Compose: Available (new)"
            elif command -v docker-compose >/dev/null 2>&1; then
                echo "  ✅ Docker Compose: Available (legacy)"
            else
                echo "  ❌ Docker Compose: Not found"
            fi
            
            # Show Docker system info
            local images_count=$(docker images -q | wc -l)
            local containers_count=$(docker ps -aq | wc -l)
            echo "  📊 Images: $images_count, Containers: $containers_count"
        else
            echo "  ❌ Docker: Not running"
        fi
    else
        echo "  ❌ Docker: Not installed"
    fi
    echo ""
}

check_services_status() {
    echo "Services Status:"
    
    local deployment_type="${FKS_DEPLOYMENT_TYPE:-standard}"
    log_debug "Checking services for deployment type: $deployment_type"
    
    local compose_files=$(get_compose_files)
    
    # Check if we can get services
    local services
    if command -v docker >/dev/null 2>&1; then
        if services=$(docker_compose config --services 2>/dev/null); then
            local service_count=$(echo "$services" | grep -v '^$' | wc -l)
            echo "  📋 Configured services: $service_count (deployment: $deployment_type)"
            
            # Check running services
            local running_count=0
            while IFS= read -r service; do
                [[ -z "$service" ]] && continue
                if docker_compose ps "$service" 2>/dev/null | grep -q "Up"; then
                    echo "  ✅ $service: Running"
                    ((running_count++)) || true
                else
                    echo "  ❌ $service: Stopped"
                fi
            done <<< "$services"
            
            echo "  🏃 Running: $running_count/$service_count"
        else
            echo "  ❌ Cannot get service status for deployment type: $deployment_type"
        fi
    else
        echo "  ❌ Docker not available"
    fi
    echo ""
}

check_requirements_status() {
    echo "Requirements Status:"
    
    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        local package_count=$(grep -c '^[a-zA-Z0-9_-]' "$REQUIREMENTS_FILE" 2>/dev/null || echo "0")
        echo "  ✅ Master requirements.txt: $package_count packages"
    else
        echo "  ❌ Master requirements.txt: Missing"
    fi
    
    local req_output_dir="/home/${USER}/fks/deployment/requirements"
    if [[ -d "$req_output_dir" ]]; then
        local service_req_count=$(find "$req_output_dir" -name "*_requirements.txt" 2>/dev/null | wc -l)
        if [[ $service_req_count -gt 0 ]]; then
            echo "  ✅ Service requirements: $service_req_count files"
        else
            echo "  ⚠️  Service requirements: No files generated"
        fi
    else
        echo "  ❌ Service requirements: Directory missing"
    fi
    echo ""
}

run_health_check() {
    log_info "🏥 Running comprehensive health check..."
    echo ""
    
    local issues=0
    local warnings=0
    
    # Check directories
    log_info "Checking directories..."
    local required_dirs=("$CONFIG_DIR" "$LOGS_DIR" "$SCRIPTS_DIR" "$BUILD_SCRIPTS_DIR" "$DEPLOYMENT_DIR")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_error "Required directory missing: $dir"
            ((issues++))
        fi
    done
    
    # Check build scripts
    log_info "Checking build scripts..."
    if [[ ! -f "$DOCKER_SCRIPT" ]]; then
        log_error "Docker script missing: $DOCKER_SCRIPT"
        ((issues++))
    elif [[ ! -x "$DOCKER_SCRIPT" ]]; then
        log_warn "Docker script not executable: $DOCKER_SCRIPT"
        ((warnings++))
    fi
    
    if [[ ! -f "$REQUIREMENTS_SCRIPT" ]]; then
        log_error "Requirements script missing: $REQUIREMENTS_SCRIPT"
        ((issues++))
    elif [[ ! -x "$REQUIREMENTS_SCRIPT" ]]; then
        log_warn "Requirements script not executable: $REQUIREMENTS_SCRIPT"
        ((warnings++))
    fi
    
    # Check Docker
    log_info "Checking Docker..."
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker not installed"
        ((issues++))
    elif ! docker info >/dev/null 2>&1; then
        log_error "Docker not running"
        ((issues++))
    fi
    
    # Check compose file
    log_info "Checking Docker Compose..."
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Docker compose file not found: $COMPOSE_FILE"
        ((issues++))
    fi
    
    # Check requirements
    log_info "Checking requirements..."
    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
        log_warn "Master requirements.txt not found: $REQUIREMENTS_FILE"
        ((warnings++))
    fi
    
    echo ""
    if [[ $issues -eq 0 && $warnings -eq 0 ]]; then
        log_success "Health check passed!"
        return 0
    elif [[ $issues -eq 0 ]]; then
        log_warn "Health check completed with $warnings warning(s)"
        return 0
    else
        log_error "Health check failed with $issues error(s) and $warnings warning(s)"
        return 1
    fi
}

# =============================================================================
# SERVICE MANAGEMENT
# =============================================================================

start_services() {
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "🚀 Starting all services..."
        docker_compose up -d
    else
        log_info "🚀 Starting services: ${services[*]}"
        docker_compose up -d "${services[@]}"
    fi
    
    log_success "Services started"
    
    # Wait a moment then show status
    sleep 3
    check_services_status
}

stop_services() {
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "🛑 Stopping all services..."
        docker_compose down
    else
        log_info "🛑 Stopping services: ${services[*]}"
        docker_compose stop "${services[@]}"
    fi
    
    log_success "Services stopped"
}

restart_services() {
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "🔄 Restarting all services..."
        docker_compose restart
    else
        log_info "🔄 Restarting services: ${services[*]}"
        docker_compose restart "${services[@]}"
    fi
    
    log_success "Services restarted"
    
    # Wait a moment then show status
    sleep 3
    check_services_status
}

show_logs() {
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "📋 Showing logs for all services..."
        docker_compose logs -f --tail=100
    else
        log_info "📋 Showing logs for: ${services[*]}"
        docker_compose logs -f --tail=100 "${services[@]}"
    fi
}

# =============================================================================
# BUILD MANAGEMENT
# =============================================================================

build_services() {
    local services=("$@")
    
    log_info "🏗️ Building services..."
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Building all services..."
        docker_compose build
    else
        log_info "Building services: ${services[*]}"
        docker_compose build "${services[@]}"
    fi
    
    log_success "Build completed"
}

build_images() {
    local services=("$@")
    
    log_info "🏗️ Building Docker images using docker.sh..."
    
    if [[ ${#services[@]} -eq 0 ]]; then
        run_docker_script "build-all"
    else
        for service in "${services[@]}"; do
            run_docker_script "build" "$service"
        done
    fi
}

generate_dockerfiles() {
    log_info "📝 Generating Dockerfiles..."
    run_docker_script "generate-dockerfiles"
}

# =============================================================================
# REQUIREMENTS MANAGEMENT
# =============================================================================

generate_requirements() {
    log_info "📦 Generating service requirements..."
    run_requirements_script "generate"
}

requirements_status() {
    log_info "📊 Checking requirements status..."
    run_requirements_script "status"
}

list_services() {
    log_info "📋 Listing discovered services..."
    run_requirements_script "list-services"
}

validate_requirements() {
    log_info "🔍 Validating requirements system..."
    run_requirements_script "validate"
}

clean_requirements() {
    log_info "🧹 Cleaning requirements files..."
    run_requirements_script "clean"
}

# =============================================================================
# DOCKER MANAGEMENT
# =============================================================================

docker_status() {
    log_info "🐳 Checking Docker status..."
    run_docker_script "status"
}

docker_cleanup() {
    local level="${1:-basic}"
    log_info "🧹 Cleaning Docker ($level)..."
    run_docker_script "cleanup" "$level"
}

docker_logs() {
    local service="${1:-}"
    if [[ -n "$service" ]]; then
        log_info "📋 Showing Docker logs for $service..."
        run_docker_script "logs" "$service"
    else
        log_info "📋 Showing Docker logs for all services..."
        show_logs
    fi
}

# =============================================================================
# SYSTEM MANAGEMENT
# =============================================================================

setup_system() {
    log_info "🔧 Setting up ${PROJECT_NS} system..."
    
    # Create directories
    log_info "Creating directories..."
    local dirs=(
        "$CONFIG_DIR"
        "$DATA_DIR"
        "$LOGS_DIR"
        "$TEMP_DIR"
        "$DEPLOYMENT_DIR"
        "$DEPLOYMENT_DIR/requirements"
        "$DEPLOYMENT_DIR/docker"
        "$BUILD_SCRIPTS_DIR"
        "$CONFIG_DIR/services"
        "$CONFIG_DIR/python"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created: $dir"
        fi
    done
    
    # Make scripts executable
    log_info "Setting script permissions..."
    if [[ -f "$DOCKER_SCRIPT" ]]; then
        chmod +x "$DOCKER_SCRIPT"
        log_info "Made executable: $DOCKER_SCRIPT"
    fi
    
    if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
        chmod +x "$REQUIREMENTS_SCRIPT"
        log_info "Made executable: $REQUIREMENTS_SCRIPT"
    fi
    
    # Initialize requirements if script exists
    if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
        log_info "Initializing requirements system..."
        run_requirements_script "init"
    fi
    
    log_success "System setup completed"
}

clean_system() {
    local level="${1:-basic}"
    
    log_info "🧹 Cleaning system ($level)..."
    
    case "$level" in
        "basic")
            # Clean logs and temp files
            if [[ -d "$LOGS_DIR" ]]; then
                find "$LOGS_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
                log_info "Cleaned old log files"
            fi
            
            if [[ -d "$TEMP_DIR" ]]; then
                rm -rf "$TEMP_DIR"/*
                log_info "Cleaned temp files"
            fi
            ;;
            
        "docker")
            log_info "Stopping all services..."
            docker_compose down 2>/dev/null || true
            
            # Use docker script for cleanup
            if [[ -f "$DOCKER_SCRIPT" ]]; then
                run_docker_script "cleanup" "system"
            else
                log_info "Cleaning Docker system..."
                if command -v docker >/dev/null 2>&1; then
                    docker system prune -f
                    log_info "Docker system cleaned"
                fi
            fi
            ;;
            
        "requirements")
            if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
                run_requirements_script "clean"
            else
                log_warn "Requirements script not found"
            fi
            ;;
            
        "all")
            # Stop services
            docker_compose down 2>/dev/null || true
            
            # Clean everything
            if [[ -d "$LOGS_DIR" ]]; then
                rm -rf "$LOGS_DIR"/*
            fi
            if [[ -d "$TEMP_DIR" ]]; then
                rm -rf "$TEMP_DIR"/*
            fi
            
            # Clean requirements
            if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
                run_requirements_script "clean"
            fi
            
            # Docker cleanup
            if [[ -f "$DOCKER_SCRIPT" ]]; then
                run_docker_script "cleanup" "all"
            else
                if command -v docker >/dev/null 2>&1; then
                    docker system prune -af --volumes
                fi
            fi
            ;;
    esac
    
    log_success "Cleanup completed"
}

update_system() {
    log_info "🔄 Updating ${PROJECT_NS} system..."
    
    # Generate requirements
    if [[ -f "$REQUIREMENTS_SCRIPT" ]]; then
        log_info "Updating requirements..."
        run_requirements_script "generate"
    fi
    
    # Generate dockerfiles
    if [[ -f "$DOCKER_SCRIPT" ]]; then
        log_info "Updating Dockerfiles..."
        run_docker_script "generate-dockerfiles"
    fi
    
    # Rebuild services
    log_info "Rebuilding services..."
    docker_compose build
    
    log_success "System update completed"
}

# =============================================================================
# HELP SYSTEM
# =============================================================================

show_help() {
    cat << EOF
${PROJECT_NS^^} Universal Orchestrator v$MAIN_SCRIPT_VERSION
Mode: $FKS_MODE

SYSTEM COMMANDS:
  status                      Show comprehensive system status
  health                      Run health check
  setup                       Setup system directories and scripts
  update                      Update requirements and rebuild
  clean [basic|docker|requirements|all]  Clean system

SERVICE COMMANDS:
  start [services...]         Start services
  stop [services...]          Stop services  
  restart [services...]       Restart services
  logs [services...]          Show service logs

BUILD COMMANDS:
  build [services...]         Build services (compose)
  build-images [services...]  Build Docker images (docker.sh)
  generate-dockerfiles        Generate Dockerfiles

REQUIREMENTS COMMANDS:
  generate-requirements       Generate service requirements
  requirements-status         Show requirements status
  list-services              List discovered services
  validate-requirements      Validate requirements system
  clean-requirements         Clean requirements files

DOCKER COMMANDS:
  docker-status              Show Docker system status
  docker-cleanup [level]     Clean Docker system
  docker-logs [service]      Show Docker logs

EXAMPLES:
  $0 status                   # Show system status
  $0 setup                    # Initial system setup
  $0 generate-requirements    # Generate service requirements
  $0 build-images api worker  # Build specific images
  $0 start api worker         # Start specific services
  $0 logs app                 # Show app logs
  $0 docker-cleanup system   # Clean Docker system
  $0 clean all                # Full system cleanup
  $0 update                   # Update everything

Integration:
  Docker Script: $DOCKER_SCRIPT
  Requirements Script: $REQUIREMENTS_SCRIPT
  Compose File: $COMPOSE_FILE

Paths:
  Project: $PROJECT_ROOT
  Config: $CONFIG_DIR
  Logs: $LOGS_DIR
  Build Scripts: $BUILD_SCRIPTS_DIR
EOF
}

# =============================================================================
# COMMAND ROUTER
# =============================================================================

route_command() {
    local cmd="$1"
    shift || true
    
    case "$cmd" in
        # System commands
        "status")
            show_system_status
            ;;
        "health")
            run_health_check
            ;;
        "setup")
            setup_system
            ;;
        "update")
            update_system
            ;;
        "clean")
            clean_system "${1:-basic}"
            ;;
            
        # Service commands
        "start")
            start_services "$@"
            ;;
        "stop")
            stop_services "$@"
            ;;
        "restart")
            restart_services "$@"
            ;;
        "logs")
            show_logs "$@"
            ;;
            
        # Build commands
        "build")
            build_services "$@"
            ;;
        "build-images")
            build_images "$@"
            ;;
        "generate-dockerfiles")
            generate_dockerfiles
            ;;
            
        # Requirements commands
        "generate-requirements")
            generate_requirements
            ;;
        "requirements-status")
            requirements_status
            ;;
        "list-services")
            list_services
            ;;
        "validate-requirements")
            validate_requirements
            ;;
        "clean-requirements")
            clean_requirements
            ;;
            
        # Docker commands
        "docker-status")
            docker_status
            ;;
        "docker-cleanup")
            docker_cleanup "${1:-basic}"
            ;;
        "docker-logs")
            docker_logs "${1:-}"
            ;;
            
        # Help
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $cmd"
            echo ""
            show_help
            return 1
            ;;
    esac
}

# =============================================================================
# MAIN FUNCTION
# =============================================================================

main() {
    # Ensure log directory exists
    mkdir -p "$LOGS_DIR"
    
    # Handle debug flag
    if [[ "${1:-}" == "--debug" ]]; then
        export DEBUG=true
        shift
    fi
    
    # Handle no arguments
    if [[ $# -eq 0 ]]; then
        show_system_status
        return 0
    fi
    
    # Route command
    route_command "$@"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

# Export key variables
export PROJECT_ROOT CONFIG_DIR DATA_DIR LOGS_DIR FKS_MODE SCRIPTS_DIR BUILD_SCRIPTS_DIR

# Run main function
main "$@"