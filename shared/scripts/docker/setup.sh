#!/bin/bash
# filepath: scripts/docker/setup.sh
# FKS Trading Systems - Docker Environment Setup and Management

# Prevent multiple sourcing
[[ -n "${FKS_DOCKER_SETUP_LOADED:-}" ]] && return 0
readonly FKS_DOCKER_SETUP_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"
source "$SCRIPT_DIR/../yaml/processor.sh"
source "$SCRIPT_DIR/../utils/menu.sh"

# Module metadata
readonly DOCKER_SETUP_VERSION="3.0.0"
readonly DOCKER_SETUP_LOADED="$(date +%s)"

# Docker configuration
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
readonly COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fks}"
readonly DOCKER_NETWORK_NAME="${FKS_DOCKER_NETWORK_NAME:-fks_network}"

# Global variables
COMPOSE_CMD=""
SELECTED_SERVICES=""

# =============================================================================
# CORE FUNCTIONS
# =============================================================================

# Initialize Docker environment
init_docker_environment() {
    log_info "🐳 Initializing Docker environment..."
    
    if ! check_docker_availability; then
        log_error "❌ Docker environment not available"
        return 1
    fi
    
    setup_docker_network
    validate_docker_environment
    load_environment_variables
    
    log_success "✅ Docker environment initialized"
}

# Check Docker availability and set COMPOSE_CMD
check_docker_availability() {
    log_debug "Checking Docker availability..."
    
    # Check Docker daemon
    if ! command -v docker &>/dev/null; then
        log_error "❌ Docker not found"
        show_installation_help "docker"
        return 1
    fi
    
    if ! docker info &>/dev/null; then
        log_error "❌ Docker daemon not running"
        log_info "Try: sudo systemctl start docker"
        return 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
        log_debug "✅ Using docker-compose"
    elif docker compose version &>/dev/null; then
        COMPOSE_CMD="docker compose"
        log_debug "✅ Using docker compose (v2)"
    else
        log_error "❌ Docker Compose not found"
        show_installation_help "docker-compose"
        return 1
    fi
    
    log_success "✅ Docker environment available"
    return 0
}

# Setup Docker network
setup_docker_network() {
    if ! docker network ls | grep -q "$DOCKER_NETWORK_NAME"; then
        if docker network create "$DOCKER_NETWORK_NAME" &>/dev/null; then
            log_debug "✅ Created Docker network: $DOCKER_NETWORK_NAME"
        else
            log_warn "⚠️  Could not create Docker network: $DOCKER_NETWORK_NAME"
        fi
    else
        log_debug "Docker network exists: $DOCKER_NETWORK_NAME"
    fi
}

# Validate Docker environment
validate_docker_environment() {
    log_debug "Validating Docker environment..."
    
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "❌ $COMPOSE_FILE not found"
        return 1
    fi
    
    if ! $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" config -q 2>/dev/null; then
        log_error "❌ Docker Compose configuration invalid"
        log_info "Run '$COMPOSE_CMD config' for details"
        return 1
    fi
    
    log_success "✅ Docker environment validated"
}

# Load environment variables
load_environment_variables() {
    local env_files=(".env" ".env.local" ".env.development")
    local loaded=0
    
    for env_file in "${env_files[@]}"; do
        if [[ -f "$env_file" ]]; then
            log_debug "Loading environment from $env_file"
            set -o allexport
            source "$env_file"
            set +o allexport
            ((loaded++))
        fi
    done
    
    [[ $loaded -eq 0 ]] && log_warn "⚠️  No environment files found"
}

# =============================================================================
# SERVICE MANAGEMENT
# =============================================================================

# Main Docker stack execution
run_docker_stack() {
    log_info "🐳 Running FKS Trading Systems..."
    
    init_docker_environment || return 1
    show_system_info
    
    if ! select_services_menu; then
        return 0
    fi
    
    handle_existing_containers
    perform_preflight_checks
    build_and_start_services
    monitor_services
}

# Service selection menu
select_services_menu() {
    local options=(
        "🔧 Core Services"
        "🧠 ML Services"
        "🌐 Web Services"
        "📊 All Services"
        "🎯 Custom Selection"
        "🔍 Service Status"
    )
    
    local choice
    choice=$(select_from_menu "Select services to run:" "${options[@]}")
    
    case "$choice" in
        "🔧 Core Services")
            SELECTED_SERVICES=$(get_services_in_group "core" 2>/dev/null | tr '\n' ' ')
            ;;
        "🧠 ML Services")
            SELECTED_SERVICES=$(get_services_in_group "ml" 2>/dev/null | tr '\n' ' ')
            ;;
        "🌐 Web Services")
            SELECTED_SERVICES=$(get_services_in_group "web" 2>/dev/null | tr '\n' ' ')
            ;;
        "📊 All Services")
            SELECTED_SERVICES=""
            ;;
        "🎯 Custom Selection")
            select_custom_services
            ;;
        "🔍 Service Status")
            show_service_status
            return 1
            ;;
        *)
            log_info "Selection cancelled"
            return 1
            ;;
    esac
    
    log_info "Selected: ${choice}"
    return 0
}

# Custom service selection
select_custom_services() {
    show_available_services
    echo -n "Enter services (space-separated): "
    read -r SELECTED_SERVICES
}

# Show available services
show_available_services() {
    log_info "Available services:"
    
    if command -v yq >/dev/null 2>&1 && [[ -f "$DOCKER_CONFIG_PATH" ]]; then
        local groups=("core" "ml" "web" "database")
        for group in "${groups[@]}"; do
            local services
            services=$(get_services_in_group "$group" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
            [[ -n "$services" ]] && echo "$group: $services"
        done
    else
        echo "Core: api, worker, app, data"
        echo "ML: training, transformer"
        echo "Web: web, nginx"
        echo "Database: redis, postgres"
    fi
}

# Handle existing containers
handle_existing_containers() {
    local running_count
    running_count=$($COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q 2>/dev/null | wc -l || echo 0)
    
    if [[ $running_count -gt 0 ]]; then
        log_warn "⚠️  Found $running_count running container(s)"
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps
        
        if ask_yes_no "Stop existing containers?" "y"; then
            log_info "🧹 Stopping existing containers..."
            $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" down --remove-orphans
        fi
    fi
}

# Build and start services
build_and_start_services() {
    log_info "🚀 Building and starting services..."
    
    # Build images
    log_info "🔨 Building images..."
    local build_cmd="$COMPOSE_CMD -p $COMPOSE_PROJECT_NAME build"
    [[ -n "$SELECTED_SERVICES" ]] && build_cmd="$build_cmd $SELECTED_SERVICES"
    
    if ! eval "$build_cmd"; then
        log_error "❌ Build failed"
        return 1
    fi
    
    # Start services
    log_info "▶️  Starting services..."
    local start_cmd="$COMPOSE_CMD -p $COMPOSE_PROJECT_NAME up -d"
    [[ -n "$SELECTED_SERVICES" ]] && start_cmd="$start_cmd $SELECTED_SERVICES"
    
    if eval "$start_cmd"; then
        log_success "✅ Services started successfully"
    else
        log_error "❌ Failed to start services"
        return 1
    fi
}

# =============================================================================
# MONITORING AND STATUS
# =============================================================================

# Monitor services after startup
monitor_services() {
    log_info "⏳ Waiting for services to initialize..."
    sleep 10
    
    perform_health_checks
    show_service_access_info
    
    if ask_yes_no "Follow service logs?" "n"; then
        follow_service_logs
    fi
}

# Perform health checks
perform_health_checks() {
    log_info "🏥 Checking service health..."
    
    # Show service status
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps
    
    # Test endpoints
    test_service_endpoints
    
    # Check for unhealthy services
    check_unhealthy_services
}

# Test service endpoints
test_service_endpoints() {
    local endpoints=(
        "api:8000:/health"
        "app:9000:/health"
        "web:9999:/health"
        "training:8088:/health"
    )
    
    log_info "Testing endpoints..."
    for endpoint in "${endpoints[@]}"; do
        IFS=':' read -r service port path <<< "$endpoint"
        
        if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps "$service" >/dev/null 2>&1; then
            if curl -sf "http://localhost:${port}${path}" >/dev/null 2>&1; then
                echo "✅ $service responding"
            else
                echo "❌ $service not responding"
            fi
        fi
    done
}

# Check for unhealthy services
check_unhealthy_services() {
    local unhealthy
    unhealthy=$(docker ps --filter "health=unhealthy" --format "{{.Names}}" | grep "^$COMPOSE_PROJECT_NAME" || true)
    
    if [[ -n "$unhealthy" ]]; then
        log_warn "⚠️  Unhealthy services: $unhealthy"
        for service in $unhealthy; do
            log_info "Logs for $service:"
            docker logs --tail=10 "$service" || true
        done
    fi
}

# Show service access information
show_service_access_info() {
    log_success "🎉 FKS Trading Systems is running!"
    
    cat << EOF

📊 Service Access URLs:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 Web Dashboard:    http://localhost:9999
🔗 API Endpoint:     http://localhost:8000/docs
📱 Main App:         http://localhost:9000
📈 Data Service:     http://localhost:9001
🧠 Training:         http://localhost:8088
🤖 Transformer:      http://localhost:8089
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛠️  Management Commands:
View logs:    $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs -f [service]
Stop all:     $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME down
Restart:      $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME restart [service]
Scale:        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME up -d --scale worker=3

EOF
}

# Show current service status
show_service_status() {
    log_info "🔍 Service Status"
    
    if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q >/dev/null 2>&1; then
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps
        echo ""
        log_info "Recent logs:"
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" logs --tail=10
    else
        log_info "No services are currently running"
    fi
}

# Follow service logs
follow_service_logs() {
    echo "Press Ctrl+C to stop following logs"
    sleep 2
    
    local logs_cmd="$COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs -f"
    [[ -n "$SELECTED_SERVICES" ]] && logs_cmd="$logs_cmd $SELECTED_SERVICES"
    
    eval "$logs_cmd"
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Show system information
show_system_info() {
    log_info "🐳 Docker System Information"
    
    echo "Docker: $(docker --version)"
    echo "Compose: $COMPOSE_CMD"
    
    # Check GPU support
    if docker run --rm --gpus all nvidia/cuda:12.8-base-ubuntu24.04 nvidia-smi &>/dev/null 2>&1; then
        log_info "🎮 NVIDIA GPU support detected"
    else
        log_info "💻 Running without GPU support"
    fi
    
    # Show disk usage
    docker system df 2>/dev/null || true
}

# Perform pre-flight checks
perform_preflight_checks() {
    log_info "🔍 Pre-flight checks..."
    
    check_port_availability
    check_disk_space
    check_docker_resources
}

# Check port availability (non-blocking)
check_port_availability() {
    local ports=(8000 8001 9000 9001 9999 80 443 6379 5432)
    local blocked=()
    
    for port in "${ports[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":$port " || netstat -tuln 2>/dev/null | grep -q ":$port "; then
            blocked+=("$port")
        fi
    done
    
    [[ ${#blocked[@]} -gt 0 ]] && log_warn "⚠️  Ports in use: ${blocked[*]}"
}

# Check disk space
check_disk_space() {
    local available_gb
    available_gb=$(df . | awk 'NR==2 {print int($4/1024/1024)}')
    
    if [[ $available_gb -lt 5 ]]; then
        log_warn "⚠️  Low disk space: ${available_gb}GB free"
        ask_yes_no "Continue anyway?" "n" || exit 1
    fi
}

# Check Docker resources
check_docker_resources() {
    local docker_info
    docker_info=$(docker system info 2>/dev/null || echo "")
    
    if [[ -n "$docker_info" ]]; then
        local memory
        memory=$(echo "$docker_info" | grep "Total Memory" | awk '{print $3}' | cut -d'G' -f1 || echo "unknown")
        
        if [[ "$memory" != "unknown" && "${memory%.*}" -lt 4 ]]; then
            log_warn "⚠️  Low Docker memory: ${memory}GB"
        fi
    fi
}

# Show installation help
show_installation_help() {
    local component="$1"
    
    case "$component" in
        "docker")
            cat << EOF
${YELLOW}Docker Installation:${NC}
Ubuntu/Debian: sudo apt install docker.io
CentOS/RHEL:   sudo yum install docker
macOS/Windows: Download Docker Desktop
EOF
            ;;
        "docker-compose")
            cat << EOF
${YELLOW}Docker Compose Installation:${NC}
pip install docker-compose
Or use Docker Desktop (includes Compose v2)
EOF
            ;;
    esac
}

# =============================================================================
# SERVICE CONTROL FUNCTIONS
# =============================================================================

# Stop Docker services
stop_docker_services() {
    log_info "🛑 Stopping Docker services..."
    
    if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" down --remove-orphans; then
        log_success "✅ Services stopped"
    else
        log_error "❌ Failed to stop services"
        return 1
    fi
}

# Restart Docker services
restart_docker_services() {
    log_info "🔄 Restarting Docker services..."
    
    stop_docker_services
    sleep 3
    build_and_start_services
    monitor_services
}

# Scale services
scale_docker_services() {
    local scale_options=(
        "Scale workers"
        "Scale API instances"
        "Custom scaling"
        "Reset to default"
    )
    
    local choice
    choice=$(select_from_menu "Scaling options:" "${scale_options[@]}")
    
    case "$choice" in
        "Scale workers")
            scale_service "worker"
            ;;
        "Scale API instances")
            scale_service "api"
            ;;
        "Custom scaling")
            echo -n "Enter scaling config (e.g., worker=3 api=2): "
            read -r scale_config
            $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" up -d --scale $scale_config
            ;;
        "Reset to default")
            $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" up -d --scale worker=1 --scale api=1
            ;;
    esac
}

# Scale individual service
scale_service() {
    local service="$1"
    echo -n "Enter number of $service instances: "
    read -r count
    
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" up -d --scale "$service=$count"
        log_success "✅ Scaled $service to $count instances"
    else
        log_error "Invalid number"
    fi
}

# View service logs
view_docker_logs() {
    if ! $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q >/dev/null 2>&1; then
        log_warn "No services running"
        return 1
    fi
    
    echo "Available services:"
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps --format "table {{.Name}}\t{{.Status}}"
    
    echo -n "Enter service name (or 'all'): "
    read -r service_name
    
    if [[ "$service_name" == "all" ]]; then
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" logs --tail=50 -f
    else
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" logs --tail=50 -f "$service_name"
    fi
}

# Execute command in container
exec_in_container() {
    if ! $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q >/dev/null 2>&1; then
        log_warn "No services running"
        return 1
    fi
    
    echo "Available services:"
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps --format "table {{.Name}}\t{{.Status}}"
    
    echo -n "Enter service name: "
    read -r service_name
    
    echo -n "Enter command (default: bash): "
    read -r command
    command="${command:-bash}"
    
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" exec "$service_name" $command
}

# Get service metrics
get_docker_metrics() {
    log_info "📊 Docker Service Metrics"
    
    if ! $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q >/dev/null 2>&1; then
        log_warn "No services running"
        return 1
    fi
    
    echo "Container Resource Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
        $($COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q) 2>/dev/null || echo "Stats unavailable"
    
    echo ""
    echo "Service Status:"
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps
}

# Update Docker images
update_docker_images() {
    local update_options=(
        "Update base images"
        "Rebuild FKS images"
        "Update and rebuild all"
    )
    
    local choice
    choice=$(select_from_menu "Update options:" "${update_options[@]}")
    
    case "$choice" in
        "Update base images")
            log_info "Pulling base images..."
            docker pull python:3.11 redis:latest postgres:latest nginx:latest
            ;;
        "Rebuild FKS images")
            log_info "Rebuilding FKS images..."
            $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" build --no-cache --pull
            ;;
        "Update and rebuild all")
            log_info "Updating all images..."
            docker pull python:3.11 redis:latest postgres:latest nginx:latest
            $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" build --no-cache --pull
            ;;
    esac
    
    log_success "✅ Update completed"
}

# =============================================================================
# EXPORTS
# =============================================================================

# Export main functions
export -f init_docker_environment check_docker_availability
export -f run_docker_stack stop_docker_services restart_docker_services
export -f scale_docker_services view_docker_logs exec_in_container
export -f get_docker_metrics update_docker_images show_service_status

echo "📦 Docker setup module loaded (v$DOCKER_SETUP_VERSION)"