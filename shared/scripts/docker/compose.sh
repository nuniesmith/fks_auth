#!/bin/bash
# filepath: scripts/docker/compose.sh
# FKS Trading Systems - Docker Compose Operations

# Prevent multiple sourcing
[[ -n "${FKS_DOCKER_COMPOSE_LOADED:-}" ]] && return 0
readonly FKS_DOCKER_COMPOSE_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"
source "$SCRIPT_DIR/../yaml/processor.sh"

# Configuration
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
readonly COMPOSE_OVERRIDE="${COMPOSE_OVERRIDE:-docker-compose.override.yml}"
readonly COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fks}"
readonly COMPOSE_PROFILES="${COMPOSE_PROFILES:-}"

# Compose file management
validate_compose_file() {
    local compose_file="${1:-$COMPOSE_FILE}"
    
    log_info "🔍 Validating Docker Compose file: $compose_file"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Compose file not found: $compose_file"
        return 1
    fi
    
    # Get compose command
    local compose_cmd
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    # Validate syntax
    if $compose_cmd -f "$compose_file" config -q >/dev/null 2>&1; then
        log_success "✅ Compose file is valid"
        return 0
    else
        log_error "❌ Compose file has syntax errors"
        $compose_cmd -f "$compose_file" config 2>&1 | head -20
        return 1
    fi
}

# Generate compose config
generate_compose_config() {
    local output_file="${1:-}"
    
    log_info "📋 Generating Docker Compose configuration..."
    
    local compose_cmd
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    if [[ -n "$output_file" ]]; then
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" config > "$output_file"
        log_success "✅ Configuration saved to: $output_file"
    else
        $compose_cmd -p "$COMPOSE_PROJECT_NAME" config
    fi
}

# Merge compose files
merge_compose_files() {
    local base_file="$1"
    local override_file="$2"
    local output_file="${3:-merged-compose.yml}"
    
    log_info "🔄 Merging compose files..."
    
    if [[ ! -f "$base_file" ]]; then
        log_error "Base compose file not found: $base_file"
        return 1
    fi
    
    if [[ ! -f "$override_file" ]]; then
        log_error "Override compose file not found: $override_file"
        return 1
    fi
    
    # Use docker-compose to merge files
    local compose_cmd
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    $compose_cmd -f "$base_file" -f "$override_file" config > "$output_file"
    
    if [[ $? -eq 0 ]]; then
        log_success "✅ Merged compose file created: $output_file"
        return 0
    else
        log_error "❌ Failed to merge compose files"
        return 1
    fi
}

# Create compose override file
create_compose_override() {
    local override_file="${1:-$COMPOSE_OVERRIDE}"
    
    log_info "📝 Creating Docker Compose override file..."
    
    if [[ -f "$override_file" ]]; then
        log_warn "Override file already exists: $override_file"
        echo "Overwrite? (y/N): "
        read -r REPLY
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 1
    fi
    
    cat > "$override_file" << 'EOF'
# Docker Compose Override File
# Use this file for local development overrides



services:
  # Example: Override API service for development
  # api:
  #   environment:
  #     - DEBUG=true
  #   volumes:
  #     - ./src:/app/src:ro
  #   command: ["python", "-m", "main", "service", "api", "--reload"]

  # Example: Expose additional ports
  # postgres:
  #   ports:
  #     - "5432:5432"

  # Example: Add development tools
  # redis:
  #   ports:
  #     - "6379:6379"
EOF
    
    log_success "✅ Override file created: $override_file"
    log_info "Edit this file to add your local development overrides"
}

# Compose environment management
export_compose_env() {
    local env_file="${1:-.env.compose}"
    
    log_info "📤 Exporting Docker Compose environment..."
    
    # Export current environment variables used by compose
    {
        echo "# Docker Compose Environment Variables"
        echo "# Generated: $(date)"
        echo ""
        echo "COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME"
        echo "COMPOSE_FILE=$COMPOSE_FILE"
        
        if [[ -f "$COMPOSE_OVERRIDE" ]]; then
            echo "COMPOSE_FILE=$COMPOSE_FILE:$COMPOSE_OVERRIDE"
        fi
        
        echo "COMPOSE_PROFILES=$COMPOSE_PROFILES"
        echo "DOCKER_BUILDKIT=1"
        echo "COMPOSE_DOCKER_CLI_BUILD=1"
        echo ""
        
        # Add other relevant environment variables
        env | grep -E "^(DOCKER_|COMPOSE_|FKS_)" | sort
    } > "$env_file"
    
    log_success "✅ Environment exported to: $env_file"
}

# Compose project operations
list_compose_projects() {
    log_info "📋 Listing Docker Compose projects..."
    
    # List all compose projects
    docker ps --filter "label=com.docker.compose.project" \
        --format "table {{.Label \"com.docker.compose.project\"}}\t{{.Names}}\t{{.Status}}" \
        | sort -u
}

# Remove compose project
remove_compose_project() {
    local project="${1:-$COMPOSE_PROJECT_NAME}"
    
    log_info "🗑️  Removing Docker Compose project: $project"
    
    echo "This will remove all containers, networks, and volumes for project: $project"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local compose_cmd
        if command -v docker-compose >/dev/null 2>&1; then
            compose_cmd="docker-compose"
        elif docker compose version >/dev/null 2>&1; then
            compose_cmd="docker compose"
        else
            log_error "Docker Compose not available"
            return 1
        fi
        
        $compose_cmd -p "$project" down -v --remove-orphans
        log_success "✅ Project removed: $project"
    else
        log_info "Operation cancelled"
    fi
}

# Compose service discovery
discover_services() {
    local compose_file="${1:-$COMPOSE_FILE}"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Compose file not found: $compose_file"
        return 1
    fi
    
    # Use yq if available, otherwise use docker-compose
    if command -v yq >/dev/null 2>&1; then
        yq eval '.services | keys | .[]' "$compose_file" 2>/dev/null
    else
        local compose_cmd
        if command -v docker-compose >/dev/null 2>&1; then
            compose_cmd="docker-compose"
        elif docker compose version >/dev/null 2>&1; then
            compose_cmd="docker compose"
        else
            log_error "Neither yq nor docker-compose available"
            return 1
        fi
        
        $compose_cmd -f "$compose_file" config --services
    fi
}

# Get service dependencies
get_service_dependencies() {
    local service="$1"
    local compose_file="${2:-$COMPOSE_FILE}"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Compose file not found: $compose_file"
        return 1
    fi
    
    # Use yq to get depends_on
    if command -v yq >/dev/null 2>&1; then
        yq eval ".services.$service.depends_on | .[]" "$compose_file" 2>/dev/null
    else
        log_warn "yq not available, cannot extract dependencies"
        return 1
    fi
}

# Compose profiles management
list_compose_profiles() {
    local compose_file="${1:-$COMPOSE_FILE}"
    
    log_info "📋 Available Docker Compose profiles:"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Compose file not found: $compose_file"
        return 1
    fi
    
    # Extract profiles from services
    if command -v yq >/dev/null 2>&1; then
        local profiles
        profiles=$(yq eval '.services[].profiles[]' "$compose_file" 2>/dev/null | sort -u)
        
        if [[ -n "$profiles" ]]; then
            echo "$profiles"
        else
            echo "No profiles defined"
        fi
    else
        log_warn "yq not available, cannot list profiles"
    fi
}

# Activate compose profile
activate_compose_profile() {
    local profile="$1"
    
    if [[ -z "$profile" ]]; then
        log_error "Profile name required"
        return 1
    fi
    
    log_info "🔄 Activating profile: $profile"
    
    export COMPOSE_PROFILES="$profile"
    
    # Update .env if it exists
    if [[ -f ".env" ]]; then
        if grep -q "^COMPOSE_PROFILES=" .env; then
            sed -i.bak "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=$profile/" .env
        else
            echo "COMPOSE_PROFILES=$profile" >> .env
        fi
        log_success "✅ Profile activated in .env"
    fi
    
    log_success "✅ Profile activated: $profile"
}

# Compose volume management
list_compose_volumes() {
    local project="${1:-$COMPOSE_PROJECT_NAME}"
    
    log_info "📦 Listing volumes for project: $project"
    
    docker volume ls --filter "label=com.docker.compose.project=$project" \
        --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
}

# Backup compose volumes
backup_compose_volumes() {
    local project="${1:-$COMPOSE_PROJECT_NAME}"
    local backup_dir="${2:-./backups/volumes_$(date +%Y%m%d_%H%M%S)}"
    
    log_info "💾 Backing up volumes for project: $project"
    
    mkdir -p "$backup_dir"
    
    # Get all volumes for project
    local volumes
    volumes=$(docker volume ls --filter "label=com.docker.compose.project=$project" -q)
    
    if [[ -z "$volumes" ]]; then
        log_warn "No volumes found for project: $project"
        return 1
    fi
    
    # Backup each volume
    for volume in $volumes; do
        log_info "Backing up volume: $volume"
        
        # Create tar backup using a temporary container
        docker run --rm \
            -v "$volume:/data:ro" \
            -v "$backup_dir:/backup" \
            alpine tar -czf "/backup/${volume}.tar.gz" -C /data .
    done
    
    log_success "✅ Volumes backed up to: $backup_dir"
}

# Restore compose volumes
restore_compose_volumes() {
    local backup_dir="$1"
    
    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup directory not found: $backup_dir"
        return 1
    fi
    
    log_info "📥 Restoring volumes from: $backup_dir"
    
    # Find all volume backups
    for backup_file in "$backup_dir"/*.tar.gz; do
        if [[ -f "$backup_file" ]]; then
            local volume_name
            volume_name=$(basename "$backup_file" .tar.gz)
            
            log_info "Restoring volume: $volume_name"
            
            # Create volume if it doesn't exist
            docker volume create "$volume_name" >/dev/null 2>&1
            
            # Restore data
            docker run --rm \
                -v "$volume_name:/data" \
                -v "$backup_dir:/backup:ro" \
                alpine tar -xzf "/backup/$(basename "$backup_file")" -C /data
        fi
    done
    
    log_success "✅ Volumes restored"
}

# Compose networking
list_compose_networks() {
    local project="${1:-$COMPOSE_PROJECT_NAME}"
    
    log_info "🌐 Listing networks for project: $project"
    
    docker network ls --filter "label=com.docker.compose.project=$project" \
        --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
}

# Inspect compose service
inspect_compose_service() {
    local service="$1"
    
    if [[ -z "$service" ]]; then
        log_error "Service name required"
        return 1
    fi
    
    local compose_cmd
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    log_info "🔍 Inspecting service: $service"
    
    # Get container ID
    local container_id
    container_id=$($compose_cmd -p "$COMPOSE_PROJECT_NAME" ps -q "$service" 2>/dev/null)
    
    if [[ -z "$container_id" ]]; then
        log_error "Service not running: $service"
        return 1
    fi
    
    # Inspect container
    docker inspect "$container_id"
}

# Compose debugging utilities
debug_compose_config() {
    log_info "🐛 Debugging Docker Compose configuration..."
    
    local compose_cmd
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    echo "Compose version:"
    $compose_cmd version
    
    echo ""
    echo "Environment variables:"
    env | grep -E "^(COMPOSE_|DOCKER_)" | sort
    
    echo ""
    echo "Compose files:"
    if [[ -n "${COMPOSE_FILE:-}" ]]; then
        echo "COMPOSE_FILE=$COMPOSE_FILE"
        IFS=':' read -ra FILES <<< "$COMPOSE_FILE"
        for file in "${FILES[@]}"; do
            if [[ -f "$file" ]]; then
                echo "  ✅ $file exists"
            else
                echo "  ❌ $file missing"
            fi
        done
    fi
    
    echo ""
    echo "Project name: $COMPOSE_PROJECT_NAME"
    echo "Active profiles: ${COMPOSE_PROFILES:-none}"
    
    echo ""
    echo "Services defined:"
    discover_services
}

# Interactive compose management
compose_management_menu() {
    while true; do
        echo ""
        log_info "🐳 Docker Compose Management"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1) Validate compose file"
        echo "2) Generate compose config"
        echo "3) Merge compose files"
        echo "4) Create override file"
        echo "5) List services"
        echo "6) List profiles"
        echo "7) Activate profile"
        echo "8) List volumes"
        echo "9) Backup volumes"
        echo "10) List networks"
        echo "11) Debug configuration"
        echo "12) Back to main menu"
        echo ""
        
        echo "Select option (1-12): "
        read -r REPLY
        
        case $REPLY in
            1) validate_compose_file ;;
            2) 
                echo "Save to file? (y/N): "
                read -r save
                if [[ $save =~ ^[Yy]$ ]]; then
                    echo "Enter filename: "
                    read -r filename
                    generate_compose_config "$filename"
                else
                    generate_compose_config
                fi
                ;;
            3) interactive_merge_files ;;
            4) create_compose_override ;;
            5) discover_services ;;
            6) list_compose_profiles ;;
            7) 
                echo "Enter profile name: "
                read -r profile
                activate_compose_profile "$profile"
                ;;
            8) list_compose_volumes ;;
            9) backup_compose_volumes ;;
            10) list_compose_networks ;;
            11) debug_compose_config ;;
            12|*) break ;;
        esac
        
        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}

# Interactive merge files
interactive_merge_files() {
    echo "Enter base compose file: "
    read -r base_file
    echo "Enter override compose file: "
    read -r override_file
    echo "Enter output file name: "
    read -r output_file
    
    merge_compose_files "$base_file" "$override_file" "$output_file"
}

# Export functions
export -f validate_compose_file generate_compose_config merge_compose_files
export -f create_compose_override export_compose_env list_compose_projects
export -f remove_compose_project discover_services get_service_dependencies
export -f list_compose_profiles activate_compose_profile list_compose_volumes
export -f backup_compose_volumes restore_compose_volumes list_compose_networks
export -f inspect_compose_service debug_compose_config compose_management_menu