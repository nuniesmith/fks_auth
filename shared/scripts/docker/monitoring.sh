#!/bin/bash
# filepath: scripts/docker/monitoring.sh
# Docker monitoring, health checks, and log management

# Ensure this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly"
    exit 1
fi

# View service logs
view_service_logs() {
    log_info "📋 Service Logs Viewer"
    
    if ! $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q >/dev/null 2>&1; then
        log_warn "No services are currently running"
        return 1
    fi
    
    echo ""
    echo "Available services:"
    $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps --format "table {{.Name}}\t{{.Status}}"
    echo ""
    
    echo "Enter service name (or 'all' for all services): "
    read -r service_name
    
    if [ "$service_name" = "all" ]; then
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs --tail=50 -f
    else
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs --tail=50 -f "$service_name"
    fi
}

# Comprehensive health check of all services
health_check_services() {
    log_info "🔍 Comprehensive Health Check"
    
    if ! $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q >/dev/null 2>&1; then
        log_warn "No services are currently running"
        return 1
    fi
    
    echo ""
    echo "Service Status:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check each service
    local services
    if command -v $COMPOSE_CMD >/dev/null 2>&1; then
        services=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps --services 2>/dev/null))
        
        for service in "${services[@]}"; do
            local status=$($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" --format "{{.Status}}" 2>/dev/null)
            
            if [[ $status == *"healthy"* ]]; then
                echo "✅ $service: $status"
            elif [[ $status == *"Up"* ]]; then
                echo "🟡 $service: $status (no health check)"
            else
                echo "❌ $service: $status"
            fi
        done
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Test service endpoints
    test_service_endpoints
}

# Test service endpoints
test_service_endpoints() {
    echo ""
    log_info "Testing service endpoints..."
    
    local endpoints=(
        "api:8000:/health"
        "app:9000:/health"
        "data:9001:/health"
        "web:9999:/health"
        "training:8088:/health"
        "transformer:8089:/health"
    )
    
    for endpoint in "${endpoints[@]}"; do
        IFS=':' read -r service port path <<< "$endpoint"
        
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" >/dev/null 2>&1; then
            if curl -sf "http://localhost:${port}${path}" >/dev/null 2>&1; then
                echo "✅ $service endpoint is responding"
            else
                echo "❌ $service endpoint is not responding"
            fi
        else
            echo "⏭️  $service is not running"
        fi
    done
}

# Monitor service resource usage
monitor_service_resources() {
    log_info "💾 Service Resource Usage"
    
    if ! $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q >/dev/null 2>&1; then
        log_warn "No services are currently running"
        return 1
    fi
    
    echo ""
    echo "Resource Usage by Service:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Get container IDs
    local containers=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q 2>/dev/null))
    
    if command -v docker >/dev/null 2>&1; then
        printf "%-15s %-10s %-10s %-15s %-10s\n" "SERVICE" "CPU%" "MEM%" "MEM USAGE" "NET I/O"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        for container in "${containers[@]}"; do
            if [ -n "$container" ]; then
                docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}\t{{.MemUsage}}\t{{.NetIO}}" "$container" | tail -n +2 | \
                while IFS=$'\t' read -r name cpu mem mem_usage net_io; do
                    # Clean up service name
                    service_name=$(echo "$name" | sed "s/^${COMPOSE_PROJECT_NAME}[-_]//")
                    printf "%-15s %-10s %-10s %-15s %-10s\n" "$service_name" "$cpu" "$mem" "$mem_usage" "$net_io"
                done
            fi
        done
    else
        log_warn "Docker command not available for resource monitoring"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Show Docker system information
show_docker_system_info() {
    log_info "🐳 Docker System Information:"
    echo "Docker version: $(docker --version)"
    echo "Compose command: $COMPOSE_CMD"
    
    if command -v docker &> /dev/null; then
        local docker_info=$(docker system df 2>/dev/null || echo "N/A")
        echo "Docker disk usage:"
        echo "$docker_info"
        
        # Check for GPU support
        if docker run --rm --gpus all nvidia/cuda:12.8-base-ubuntu24.04 nvidia-smi &>/dev/null 2>&1; then
            log_success "🎮 NVIDIA GPU support detected"
        else
            log_info "💻 Running without GPU support"
        fi
    fi
}

# Service dependency health check
check_service_dependencies() {
    log_info "🔗 Checking Service Dependencies"
    
    echo ""
    echo "Database Connectivity:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check Redis
    if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps redis >/dev/null 2>&1; then
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T redis redis-cli ping >/dev/null 2>&1; then
            echo "✅ Redis: Connected"
        else
            echo "❌ Redis: Connection failed"
        fi
    else
        echo "⏭️  Redis: Not running"
    fi
    
    # Check PostgreSQL
    if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps postgres >/dev/null 2>&1; then
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
            echo "✅ PostgreSQL: Connected"
        else
            echo "❌ PostgreSQL: Connection failed"
        fi
    else
        echo "⏭️  PostgreSQL: Not running"
    fi
    
    echo ""
    echo "Service-to-Service Communication:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Test internal network connectivity
    local services=("api" "app" "data" "training" "transformer")
    
    for service in "${services[@]}"; do
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" >/dev/null 2>&1; then
            # Test if service can reach Redis
            if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" sh -c "nc -z redis 6379" >/dev/null 2>&1; then
                echo "✅ $service → Redis: Connected"
            else
                echo "❌ $service → Redis: Failed"
            fi
            
            # Test if service can reach PostgreSQL
            if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" sh -c "nc -z postgres 5432" >/dev/null 2>&1; then
                echo "✅ $service → PostgreSQL: Connected"
            else
                echo "❌ $service → PostgreSQL: Failed"
            fi
        fi
    done
}

# GPU monitoring for ML services
monitor_gpu_usage() {
    log_info "🎮 GPU Usage Monitoring"
    
    # Check if nvidia-smi is available
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        log_warn "nvidia-smi not available. GPU monitoring disabled."
        return 1
    fi
    
    echo ""
    echo "Host GPU Status:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,noheader,nounits | \
    awk -F', ' 'BEGIN{printf "%-3s %-20s %-10s %-10s %-8s %-6s\n", "ID", "Name", "Mem Used", "Mem Total", "GPU%", "Temp"} 
                {printf "%-3s %-20s %-10s %-10s %-8s %-6s\n", $1, substr($2,1,20), $3"MB", $4"MB", $5"%", $6"°C"}'
    
    echo ""
    echo "Container GPU Usage:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check GPU services
    local gpu_services=("training" "transformer")
    
    for service in "${gpu_services[@]}"; do
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" >/dev/null 2>&1; then
            echo "Service: $service"
            # Try to get GPU info from within container
            if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" sh -c "nvidia-smi -L" >/dev/null 2>&1; then
                $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits | \
                awk -F', ' '{printf "  GPU Util: %s%%, Memory: %s/%s MB\n", $1, $2, $3}'
            else
                echo "  ❌ GPU not accessible in container"
            fi
        else
            echo "Service: $service (not running)"
        fi
    done
}

# Log rotation and management
manage_service_logs() {
    log_info "📝 Log Management"
    
    echo ""
    echo "Log Management Options:"
    echo "1) View recent logs (last 100 lines)"
    echo "2) Follow logs in real-time"
    echo "3) Export logs to file"
    echo "4) Rotate/cleanup old logs"
    echo "5) Show log sizes"
    echo "6) Back to monitoring menu"
    echo ""
    
    echo "Select option (1-6): "
    read -r REPLY
    
    case $REPLY in
        1)
            view_recent_logs
            ;;
        2)
            follow_logs_realtime
            ;;
        3)
            export_logs_to_file
            ;;
        4)
            rotate_cleanup_logs
            ;;
        5)
            show_log_sizes
            ;;
        *)
            return 0
            ;;
    esac
}

# View recent logs
view_recent_logs() {
    echo ""
    echo "Select service for recent logs:"
    $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps --format "table {{.Name}}\t{{.Status}}"
    echo ""
    echo "Enter service name (or 'all'): "
    read -r service_name
    
    if [ "$service_name" = "all" ]; then
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs --tail=100
    else
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs --tail=100 "$service_name"
    fi
}

# Follow logs in real-time
follow_logs_realtime() {
    echo ""
    echo "Following logs in real-time (Ctrl+C to stop)..."
    echo "Services available:"
    $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps --format "table {{.Name}}\t{{.Status}}"
    echo ""
    echo "Enter service name (or 'all'): "
    read -r service_name
    
    if [ "$service_name" = "all" ]; then
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs -f
    else
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs -f "$service_name"
    fi
}

# Export logs to file
export_logs_to_file() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local log_dir="./exported_logs_$timestamp"
    
    echo ""
    echo "Exporting logs to: $log_dir"
    mkdir -p "$log_dir"
    
    # Export logs for each service
    local services=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps --services 2>/dev/null))
    
    for service in "${services[@]}"; do
        if [ -n "$service" ]; then
            log_info "Exporting logs for $service..."
            $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME logs "$service" > "$log_dir/${service}.log" 2>&1
        fi
    done
    
    # Create a summary file
    cat > "$log_dir/export_summary.txt" << EOF
FKS Trading Systems - Log Export Summary
======================================
Export Date: $(date)
Project: $COMPOSE_PROJECT_NAME

Services Exported:
$(printf '%s\n' "${services[@]}" | sed 's/^/- /')

Total Log Files: $(ls -1 "$log_dir"/*.log | wc -l)
Total Size: $(du -sh "$log_dir" | cut -f1)
EOF
    
    log_success "✅ Logs exported to: $log_dir"
    echo "Summary: $(cat "$log_dir/export_summary.txt")"
}

# Show log sizes
show_log_sizes() {
    echo ""
    echo "Docker Container Log Sizes:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local containers=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q 2>/dev/null))
    
    for container in "${containers[@]}"; do
        if [ -n "$container" ]; then
            local container_name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/^\///')
            local log_path=$(docker inspect --format='{{.LogPath}}' "$container")
            
            if [ -f "$log_path" ]; then
                local log_size=$(du -h "$log_path" | cut -f1)
                echo "$container_name: $log_size"
            else
                echo "$container_name: No log file found"
            fi
        fi
    done
    
    # Show total Docker logs size
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Total Docker logs size: $(docker system df | grep "Local Volumes" | awk '{print $3}')"
}

# Rotate and cleanup old logs
rotate_cleanup_logs() {
    echo ""
    log_warn "⚠️  This will remove old Docker logs. This action cannot be undone."
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Rotating Docker logs..."
        
        # Restart services to rotate logs
        log_info "Restarting services to rotate logs..."
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME restart
        
        # Clean up Docker log files
        if command -v docker >/dev/null 2>&1; then
            docker system prune --volumes -f
        fi
        
        log_success "✅ Log rotation completed"
    else
        log_info "Log rotation cancelled"
    fi
}

# Service performance metrics
show_service_metrics() {
    log_info "📊 Service Performance Metrics"
    
    echo ""
    echo "Service Response Times:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local endpoints=(
        "api:8000:/health"
        "app:9000:/health"
        "data:9001:/health"
        "web:9999:/health"
        "training:8088:/health"
        "transformer:8089:/health"
    )
    
    for endpoint in "${endpoints[@]}"; do
        IFS=':' read -r service port path <<< "$endpoint"
        
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" >/dev/null 2>&1; then
            local response_time=$(curl -o /dev/null -s -w "%{time_total}" "http://localhost:${port}${path}" 2>/dev/null || echo "N/A")
            if [ "$response_time" != "N/A" ]; then
                printf "%-12s: %.3fs\n" "$service" "$response_time"
            else
                printf "%-12s: %s\n" "$service" "Not responding"
            fi
        else
            printf "%-12s: %s\n" "$service" "Not running"
        fi
    done
    
    echo ""
    echo "Service Uptime:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local containers=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q 2>/dev/null))
    
    for container in "${containers[@]}"; do
        if [ -n "$container" ]; then
            local container_name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/^\///')
            local uptime=$(docker inspect --format='{{.State.StartedAt}}' "$container")
            echo "$container_name: Started at $uptime"
        fi
    done
}

# Network connectivity check
check_network_connectivity() {
    log_info "🌐 Network Connectivity Check"
    
    echo ""
    echo "Docker Networks:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # List Docker networks for this project
    docker network ls --filter "name=${COMPOSE_PROJECT_NAME}" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    
    echo ""
    echo "Network Connectivity Tests:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Test external connectivity
    local services=("api" "app" "training" "transformer")
    
    for service in "${services[@]}"; do
        if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps "$service" >/dev/null 2>&1; then
            echo "Testing $service external connectivity:"
            
            # Test DNS resolution
            if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" sh -c "nslookup google.com" >/dev/null 2>&1; then
                echo "  ✅ DNS resolution: Working"
            else
                echo "  ❌ DNS resolution: Failed"
            fi
            
            # Test internet connectivity
            if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME exec -T "$service" sh -c "ping -c 1 8.8.8.8" >/dev/null 2>&1; then
                echo "  ✅ Internet connectivity: Working"
            else
                echo "  ❌ Internet connectivity: Failed"
            fi
            
            echo ""
        fi
    done
}

# Main monitoring menu
monitoring_menu() {
    while true; do
        echo ""
        log_info "🔍 Docker Monitoring & Health Checks"
        echo "============================================"
        echo "1) 🏥 Service Health Check"
        echo "2) 📋 View Service Logs"
        echo "3) 💾 Monitor Resource Usage"
        echo "4) 🔗 Check Service Dependencies"
        echo "5) 🎮 Monitor GPU Usage"
        echo "6) 📝 Log Management"
        echo "7) 📊 Performance Metrics"
        echo "8) 🌐 Network Connectivity"
        echo "9) 🐳 Docker System Info"
        echo "10) ⬅️ Back to main menu"
        echo ""
        
        echo "Select monitoring option (1-10): "
        read -r REPLY
        
        case $REPLY in
            1)
                health_check_services
                ;;
            2)
                view_service_logs
                ;;
            3)
                monitor_service_resources
                ;;
            4)
                check_service_dependencies
                ;;
            5)
                monitor_gpu_usage
                ;;
            6)
                manage_service_logs
                ;;
            7)
                show_service_metrics
                ;;
            8)
                check_network_connectivity
                ;;
            9)
                show_docker_system_info
                ;;
            *)
                return 0
                ;;
        esac
        
        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}