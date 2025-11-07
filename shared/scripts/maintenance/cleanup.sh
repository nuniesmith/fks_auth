#!/bin/bash
# filepath: scripts/maintenance/cleanup.sh
# FKS Trading Systems - System Cleanup Operations

# Prevent multiple sourcing
[[ -n "${FKS_MAINTENANCE_CLEANUP_LOADED:-}" ]] && return 0
readonly FKS_MAINTENANCE_CLEANUP_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"

# Docker configuration
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
readonly COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fks}"
COMPOSE_CMD=""

# Detect Docker Compose command
detect_compose_command() {
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        log_error "Neither docker-compose nor 'docker compose' found"
        return 1
    fi
}

# Main Docker cleanup function
clean_docker_resources() {
    log_info "🧹 Cleaning Docker resources..."
    
    if ! detect_compose_command; then
        return 1
    fi
    
    echo "This will remove:"
    echo "- Stopped containers"
    echo "- Unused networks"
    echo "- Unused images"
    echo "- Build cache"
    echo "- Dangling volumes"
    echo ""
    
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Stop FKS containers first
        stop_fks_containers
        
        # Clean Docker resources
        clean_containers
        clean_networks
        clean_images
        clean_volumes
        clean_build_cache
        
        # Show space freed
        show_cleanup_results
    else
        log_info "Cleanup cancelled"
    fi
}

# Stop FKS containers
stop_fks_containers() {
    if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" ps -q >/dev/null 2>&1; then
        log_info "Stopping FKS services..."
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" down --remove-orphans
        log_success "✅ FKS services stopped"
    else
        log_debug "No FKS services running"
    fi
}

# Clean containers
clean_containers() {
    log_info "🗑️  Cleaning containers..."
    
    # Remove stopped containers
    local stopped_containers
    stopped_containers=$(docker ps -aq --filter "status=exited" 2>/dev/null)
    
    if [[ -n "$stopped_containers" ]]; then
        echo "Removing $(echo "$stopped_containers" | wc -l) stopped containers..."
        docker rm $stopped_containers
        log_success "✅ Stopped containers removed"
    else
        log_info "No stopped containers to remove"
    fi
    
    # Clean up container logs that are too large
    clean_container_logs
}

# Clean container logs
clean_container_logs() {
    log_info "📋 Cleaning large container logs..."
    
    # Find containers with logs larger than 100MB
    docker ps -a --format "table {{.Names}}" | tail -n +2 | while read -r container; do
        if [[ -n "$container" ]]; then
            local log_file="/var/lib/docker/containers/$(docker inspect --format='{{.Id}}' "$container" 2>/dev/null)/$(docker inspect --format='{{.Id}}' "$container" 2>/dev/null)-json.log"
            
            if [[ -f "$log_file" ]]; then
                local size
                size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
                local size_mb=$((size / 1024 / 1024))
                
                if [[ $size_mb -gt 100 ]]; then
                    log_warn "Container $container has large log file (${size_mb}MB)"
                    echo "Truncate log for $container? (y/N): "
                    read -r REPLY
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        docker logs "$container" --tail 1000 > "/tmp/${container}_last_1000.log" 2>&1
                        truncate -s 0 "$log_file" 2>/dev/null || echo "" > "$log_file"
                        log_success "✅ Truncated log for $container (backup saved to /tmp/${container}_last_1000.log)"
                    fi
                fi
            fi
        fi
    done
}

# Clean networks
clean_networks() {
    log_info "🌐 Cleaning networks..."
    
    # Remove unused networks (excluding default ones)
    local unused_networks
    unused_networks=$(docker network ls --filter "dangling=true" -q 2>/dev/null)
    
    if [[ -n "$unused_networks" ]]; then
        echo "Removing $(echo "$unused_networks" | wc -l) unused networks..."
        docker network rm $unused_networks 2>/dev/null || true
        log_success "✅ Unused networks removed"
    else
        log_info "No unused networks to remove"
    fi
}

# Clean images
clean_images() {
    log_info "🐳 Cleaning images..."
    
    # Remove dangling images
    local dangling_images
    dangling_images=$(docker images --filter "dangling=true" -q 2>/dev/null)
    
    if [[ -n "$dangling_images" ]]; then
        echo "Removing $(echo "$dangling_images" | wc -l) dangling images..."
        docker rmi $dangling_images 2>/dev/null || true
        log_success "✅ Dangling images removed"
    else
        log_info "No dangling images to remove"
    fi
    
    # Optionally remove unused images
    echo ""
    echo "Remove unused images? This will remove images not used by any container. (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker image prune -a -f
        log_success "✅ Unused images removed"
    fi
}

# Clean volumes
clean_volumes() {
    log_info "💾 Cleaning volumes..."
    
    # Remove dangling volumes
    local dangling_volumes
    dangling_volumes=$(docker volume ls --filter "dangling=true" -q 2>/dev/null)
    
    if [[ -n "$dangling_volumes" ]]; then
        echo "Found $(echo "$dangling_volumes" | wc -l) dangling volumes:"
        echo "$dangling_volumes"
        echo ""
        echo "Remove dangling volumes? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker volume rm $dangling_volumes 2>/dev/null || true
            log_success "✅ Dangling volumes removed"
        fi
    else
        log_info "No dangling volumes to remove"
    fi
}

# Clean build cache
clean_build_cache() {
    log_info "🔨 Cleaning build cache..."
    
    # Clean Docker buildkit cache
    if docker builder prune -f >/dev/null 2>&1; then
        log_success "✅ Build cache cleaned"
    else
        log_warn "⚠️  Could not clean build cache"
    fi
}

# Show cleanup results
show_cleanup_results() {
    log_success "🎉 Docker cleanup completed!"
    echo ""
    echo "Current Docker disk usage:"
    docker system df 2>/dev/null || echo "Could not retrieve disk usage"
    echo ""
    
    # Show running containers
    local running_containers
    running_containers=$(docker ps -q | wc -l)
    echo "Running containers: $running_containers"
    
    # Show total images
    local total_images
    total_images=$(docker images -q | wc -l)
    echo "Total images: $total_images"
    
    # Show total volumes
    local total_volumes
    total_volumes=$(docker volume ls -q | wc -l)
    echo "Total volumes: $total_volumes"
}

# Clean project directories
clean_project_directories() {
    log_info "🗂️  Cleaning Project Directories"
    
    echo "This will clean:"
    echo "- Log files older than 7 days (./logs/)"
    echo "- Python cache files (__pycache__, *.pyc)"
    echo "- Build artifacts"
    echo "- Old model checkpoints (keeping latest 5)"
    echo "- Temporary files"
    echo ""
    
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        clean_log_files
        clean_python_cache
        clean_build_artifacts
        clean_model_checkpoints
        clean_temporary_files
        
        log_success "✅ Project directories cleaned"
    else
        log_info "Cleanup cancelled"
    fi
}

# Clean log files
clean_log_files() {
    if [[ -d "logs" ]]; then
        log_info "🧹 Cleaning log files..."
        
        # Remove log files older than 7 days
        find logs -name "*.log" -mtime +7 -delete 2>/dev/null || true
        
        # Compress large current log files
        find logs -name "*.log" -size +50M | while read -r logfile; do
            if [[ -f "$logfile" ]]; then
                log_info "Compressing large log file: $logfile"
                gzip "$logfile" 2>/dev/null || true
            fi
        done
        
        log_success "✅ Log files cleaned"
    else
        log_debug "No logs directory found"
    fi
}

# Clean Python cache
clean_python_cache() {
    log_info "🐍 Cleaning Python cache..."
    
    # Remove __pycache__ directories
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    
    # Remove .pyc and .pyo files
    find . -name "*.pyc" -delete 2>/dev/null || true
    find . -name "*.pyo" -delete 2>/dev/null || true
    
    # Remove .pytest_cache
    rm -rf .pytest_cache/ 2>/dev/null || true
    
    # Remove other Python artifacts
    rm -rf .coverage .mypy_cache/ .tox/ 2>/dev/null || true
    
    log_success "✅ Python cache cleaned"
}

# Clean build artifacts
clean_build_artifacts() {
    log_info "🔨 Cleaning build artifacts..."
    
    # Remove common build directories
    local build_dirs=("build" "dist" "*.egg-info" ".eggs")
    
    for pattern in "${build_dirs[@]}"; do
        find . -name "$pattern" -type d -exec rm -rf {} + 2>/dev/null || true
    done
    
    # Remove compiled extensions
    find . -name "*.so" -delete 2>/dev/null || true
    find . -name "*.dylib" -delete 2>/dev/null || true
    find . -name "*.dll" -delete 2>/dev/null || true
    
    log_success "✅ Build artifacts cleaned"
}

# Clean model checkpoints (keep latest 5)
clean_model_checkpoints() {
    if [[ -d "models" ]]; then
        log_info "🧠 Cleaning old model checkpoints..."
        
        # Find checkpoint files and keep only the latest 5
        find models -name "checkpoint_*.pt" -print0 2>/dev/null | \
        sort -z | head -z -n -5 | xargs -0 rm -f 2>/dev/null || true
        
        # Clean up temporary model files
        find models -name "*.tmp" -delete 2>/dev/null || true
        find models -name "*.lock" -delete 2>/dev/null || true
        
        log_success "✅ Model checkpoints cleaned"
    else
        log_debug "No models directory found"
    fi
}

# Clean temporary files
clean_temporary_files() {
    log_info "🗑️  Cleaning temporary files..."
    
    # Remove common temporary files
    find . -name "*.tmp" -delete 2>/dev/null || true
    find . -name "*.temp" -delete 2>/dev/null || true
    find . -name "*~" -delete 2>/dev/null || true
    find . -name "*.bak" -delete 2>/dev/null || true
    find . -name "*.swp" -delete 2>/dev/null || true
    find . -name ".DS_Store" -delete 2>/dev/null || true
    
    # Remove empty directories
    find . -type d -empty -delete 2>/dev/null || true
    
    log_success "✅ Temporary files cleaned"
}