#!/bin/bash
# filepath: scripts/docker/services.sh
# FKS Trading Systems - Docker Service Management

# Prevent multiple sourcing
[[ -n "${FKS_DOCKER_SERVICES_LOADED:-}" ]] && return 0
readonly FKS_DOCKER_SERVICES_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"
source "$SCRIPT_DIR/../yaml/processor.sh"

# Configuration
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
readonly COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fks}"

# Service groups
declare -A SERVICE_GROUPS=(
    [core]="api worker app data redis postgres"
    [ml]="training transformer redis postgres"
    [web]="web nginx api redis postgres"
    [databases]="redis postgres"
    [monitoring]="prometheus grafana"
)

# Get Docker Compose command
get_compose_cmd() {
    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    else
        log_error "Neither docker-compose nor 'docker compose' found"
        return 1
    fi
}

# Start specific services
start_services() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Starting all services..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" up -d
    else
        log_info "Starting services: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" up -d "${services[@]}"
    fi
}

# Stop specific services
stop_services() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Stopping all services..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" down
    else
        log_info "Stopping services: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" stop "${services[@]}"
    fi
}

# Restart specific services
restart_services() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Restarting all services..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" restart
    else
        log_info "Restarting services: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" restart "${services[@]}"
    fi
}

# Scale a service
scale_service() {
    local service="$1"
    local replicas="$2"
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ -z "$service" ]] || [[ -z "$replicas" ]]; then
        log_error "Usage: scale_service <service> <replicas>"
        return 1
    fi
    
    log_info "Scaling $service to $replicas replicas..."
    $compose_cmd -p "$COMPOSE_PROJECT_NAME" up -d --scale "$service=$replicas"
}

# Get service status
get_service_status() {
    local service="$1"
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ -z "$service" ]]; then
        # Show all services
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" ps
    else
        # Show specific service
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" ps "$service"
    fi
}

# Execute command in service container
exec_in_service() {
    local service="$1"
    shift
    local command=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ -z "$service" ]] || [[ ${#command[@]} -eq 0 ]]; then
        log_error "Usage: exec_in_service <service> <command>"
        return 1
    fi
    
    log_info "Executing in $service: ${command[*]}"
    $compose_cmd -p "$COMPOSE_PROJECT_NAME" exec "$service" "${command[@]}"
}

# View service logs
view_service_logs() {
    local service="$1"
    local follow="${2:-false}"
    local tail="${3:-50}"
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    local log_args=("--tail=$tail")
    [[ "$follow" == "true" ]] && log_args+=("-f")
    
    if [[ -z "$service" ]]; then
        log_info "Viewing logs for all services..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" logs "${log_args[@]}"
    else
        log_info "Viewing logs for $service..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" logs "${log_args[@]}" "$service"
    fi
}

# Pull latest images for services
pull_service_images() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Pulling all service images..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" pull
    else
        log_info "Pulling images for: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" pull "${services[@]}"
    fi
}

# Build service images
build_service_images() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Building all service images..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" build
    else
        log_info "Building images for: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" build "${services[@]}"
    fi
}

# Remove service containers
remove_service_containers() {
    local services=("$@")
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_info "Removing all service containers..."
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" rm -f
    else
        log_info "Removing containers for: ${services[*]}"
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" rm -f "${services[@]}"
    fi
}

# Start service group
start_service_group() {
    local group="$1"
    
    if [[ -z "${SERVICE_GROUPS[$group]:-}" ]]; then
        log_error "Unknown service group: $group"
        log_info "Available groups: ${!SERVICE_GROUPS[*]}"
        return 1
    fi
    
    local services=(${SERVICE_GROUPS[$group]})
    log_info "Starting $group service group: ${services[*]}"
    start_services "${services[@]}"
}

# Stop service group
stop_service_group() {
    local group="$1"
    
    if [[ -z "${SERVICE_GROUPS[$group]:-}" ]]; then
        log_error "Unknown service group: $group"
        return 1
    fi
    
    local services=(${SERVICE_GROUPS[$group]})
    log_info "Stopping $group service group: ${services[*]}"
    stop_services "${services[@]}"
}

# Get service health status
get_service_health() {
    local service="$1"
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    # Get container ID
    local container_id
    container_id=$($compose_cmd -p "$COMPOSE_PROJECT_NAME" ps -q "$service" 2>/dev/null)
    
    if [[ -z "$container_id" ]]; then
        echo "not_running"
        return 1
    fi
    
    # Check health status
    local health_status
    health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_id" 2>/dev/null || echo "none")
    
    echo "$health_status"
}

# Wait for service to be healthy
wait_for_service_health() {
    local service="$1"
    local timeout="${2:-300}"  # Default 5 minutes
    local interval="${3:-5}"
    
    log_info "Waiting for $service to be healthy (timeout: ${timeout}s)..."
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        local health
        health=$(get_service_health "$service")
        
        case "$health" in
            "healthy")
                log_success "✅ $service is healthy"
                return 0
                ;;
            "unhealthy")
                log_error "❌ $service is unhealthy"
                return 1
                ;;
            "starting")
                log_debug "$service is still starting..."
                ;;
            "none")
                log_debug "$service has no health check"
                # Check if container is at least running
                if get_service_status "$service" | grep -q "Up"; then
                    log_success "✅ $service is running (no health check)"
                    return 0
                fi
                ;;
            "not_running")
                log_error "❌ $service is not running"
                return 1
                ;;
        esac
        
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    log_error "❌ Timeout waiting for $service to be healthy"
    return 1
}

# Wait for multiple services to be healthy
wait_for_services_health() {
    local services=("$@")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if ! wait_for_service_health "$service"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "❌ Failed services: ${failed_services[*]}"
        return 1
    fi
    
    log_success "✅ All services are healthy"
    return 0
}

# Get service resource usage
get_service_resources() {
    local service="$1"
    local compose_cmd
    compose_cmd=$(get_compose_cmd) || return 1
    
    # Get container ID
    local container_id
    container_id=$($compose_cmd -p "$COMPOSE_PROJECT_NAME" ps -q "$service" 2>/dev/null)
    
    if [[ -z "$container_id" ]]; then
        log_error "Service $service is not running"
        return 1
    fi
    
    # Get resource stats
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" "$container_id"
}

# Interactive service management menu
service_management_menu() {
    while true; do
        echo ""
        log_info "🐳 Docker Service Management"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1) Start services"
        echo "2) Stop services"
        echo "3) Restart services"
        echo "4) Scale service"
        echo "5) View service status"
        echo "6) View service logs"
        echo "7) Execute command in service"
        echo "8) Service health check"
        echo "9) Service resource usage"
        echo "10) Rebuild service images"
        echo "11) Back to main menu"
        echo ""
        
        echo "Select option (1-11): "
        read -r REPLY
        
        case $REPLY in
            1) interactive_start_services ;;
            2) interactive_stop_services ;;
            3) interactive_restart_services ;;
            4) interactive_scale_service ;;
            5) get_service_status ;;
            6) interactive_view_logs ;;
            7) interactive_exec_command ;;
            8) interactive_health_check ;;
            9) interactive_resource_usage ;;
            10) interactive_rebuild_images ;;
            11|*) break ;;
        esac
        
        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}

# Interactive service selection
select_services() {
    echo "Select services:"
    echo "1) All services"
    echo "2) Core services (${SERVICE_GROUPS[core]})"
    echo "3) ML services (${SERVICE_GROUPS[ml]})"
    echo "4) Web services (${SERVICE_GROUPS[web]})"
    echo "5) Database services (${SERVICE_GROUPS[databases]})"
    echo "6) Custom selection"
    echo ""
    
    echo "Select option (1-6): "
    read -r REPLY
    
    case $REPLY in
        1) echo "" ;;  # Empty means all services
        2) echo "${SERVICE_GROUPS[core]}" ;;
        3) echo "${SERVICE_GROUPS[ml]}" ;;
        4) echo "${SERVICE_GROUPS[web]}" ;;
        5) echo "${SERVICE_GROUPS[databases]}" ;;
        6) 
            echo "Enter service names (space-separated): "
            read -r services
            echo "$services"
            ;;
        *) echo "" ;;
    esac
}

# Interactive functions
interactive_start_services() {
    local services
    services=$(select_services)
    start_services $services
}

interactive_stop_services() {
    local services
    services=$(select_services)
    stop_services $services
}

interactive_restart_services() {
    local services
    services=$(select_services)
    restart_services $services
}

interactive_scale_service() {
    echo "Enter service name: "
    read -r service
    echo "Enter number of replicas: "
    read -r replicas
    
    if [[ "$replicas" =~ ^[0-9]+$ ]]; then
        scale_service "$service" "$replicas"
    else
        log_error "Invalid number of replicas"
    fi
}

interactive_view_logs() {
    echo "Enter service name (or press Enter for all): "
    read -r service
    echo "Follow logs? (y/N): "
    read -r follow
    
    local follow_flag="false"
    [[ "$follow" =~ ^[Yy]$ ]] && follow_flag="true"
    
    view_service_logs "$service" "$follow_flag"
}

interactive_exec_command() {
    echo "Enter service name: "
    read -r service
    echo "Enter command to execute: "
    read -r command
    
    exec_in_service "$service" $command
}

interactive_health_check() {
    local services
    services=$(select_services)
    
    if [[ -z "$services" ]]; then
        # Check all services
        local all_services
        all_services=$(get_compose_cmd && $compose_cmd -p "$COMPOSE_PROJECT_NAME" ps --services)
        for service in $all_services; do
            local health
            health=$(get_service_health "$service")
            echo "$service: $health"
        done
    else
        # Check selected services
        for service in $services; do
            local health
            health=$(get_service_health "$service")
            echo "$service: $health"
        done
    fi
}

interactive_resource_usage() {
    echo "Enter service name (or press Enter for all): "
    read -r service
    
    if [[ -z "$service" ]]; then
        docker stats --no-stream
    else
        get_service_resources "$service"
    fi
}

interactive_rebuild_images() {
    local services
    services=$(select_services)
    build_service_images $services
}

# Service monitoring functions
monitor_services() {
    local interval="${1:-5}"
    
    log_info "Monitoring services (press Ctrl+C to stop)..."
    
    while true; do
        clear
        echo "FKS Trading Systems - Service Monitor"
        echo "Time: $(date)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # Show service status
        get_service_status
        
        echo ""
        echo "Resource Usage:"
        docker stats --no-stream
        
        sleep "$interval"
    done
}

# Export functions
export -f start_services stop_services restart_services
export -f scale_service get_service_status exec_in_service
export -f view_service_logs pull_service_images build_service_images
export -f remove_service_containers start_service_group stop_service_group
export -f get_service_health wait_for_service_health wait_for_services_health
export -f get_service_resources service_management_menu monitor_services