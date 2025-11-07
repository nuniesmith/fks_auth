#!/bin/bash
# filepath: scripts/yaml/generator.sh
# FKS Trading Systems - Generate .env and docker-compose.yml from YAML configs
# Version: 1.0.0 - Aligned with configuration standards

# Prevent multiple sourcing
[[ -n "${FKS_YAML_GENERATOR_LOADED:-}" ]] && return 0
readonly FKS_YAML_GENERATOR_LOADED=1

# =============================================================================
# CONFIGURATION AND DEPENDENCIES
# =============================================================================

# Script directory and dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source dependencies with fallback
source "$SCRIPT_DIR/../core/logging.sh" 2>/dev/null || {
    # Fallback logging if core logging not available
    log_info() { echo "[INFO] $1"; }
    log_warn() { echo "[WARN] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_success() { echo "[SUCCESS] $1"; }
}

source "$SCRIPT_DIR/processor.sh" 2>/dev/null || {
    log_warn "processor.sh not found - some functions may not be available"
}

# Configuration paths (hardcoded for reliability)
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly DOCKER_CONFIG_PATH="${CONFIG_DIR}/docker.yaml"
readonly SERVICES_CONFIG_PATH="${CONFIG_DIR}/services.yaml"
readonly MAIN_CONFIG_PATH="${CONFIG_DIR}/main.yaml"
readonly SERVICE_CONFIGS_DIR="${CONFIG_DIR}/services"

# Output files
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
readonly ENV_FILE="${ENV_FILE:-.env}"

# Version and metadata
readonly GENERATOR_VERSION="1.0.0"
readonly GENERATION_TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Ensure yq is available
ensure_yq_available() {
    if command -v yq >/dev/null 2>&1; then
        return 0
    fi
    
    log_error "yq is required but not installed"
    log_info "Install with: sudo snap install yq --channel=v4/stable"
    log_info "Or: brew install yq"
    return 1
}

# Check if YAML path exists
yaml_path_exists() {
    local file="$1"
    local path="$2"
    
    [[ -f "$file" ]] && yq eval "has(\"$path\")" "$file" 2>/dev/null | grep -q "true"
}

# Get YAML value with fallback
get_yaml_value() {
    local file="$1"
    local path="$2"
    local fallback="$3"
    
    if [[ -f "$file" ]] && yaml_path_exists "$file" "$path"; then
        yq eval ".$path" "$file" 2>/dev/null || echo "$fallback"
    else
        echo "$fallback"
    fi
}

# Get YAML keys
get_yaml_keys() {
    local file="$1"
    local path="$2"
    
    if [[ -f "$file" ]] && yaml_path_exists "$file" "$path"; then
        yq eval ".$path | keys | .[]" "$file" 2>/dev/null
    fi
}

# Convert YAML path to environment variable name
yaml_to_env_var() {
    local yaml_path="$1"
    local prefix="$2"
    
    # Convert dots to underscores and make uppercase
    local env_var="${prefix}$(echo "$yaml_path" | sed 's/\./_/g' | tr '[:lower:]' '[:upper:]')"
    echo "$env_var"
}

# Extract YAML section to environment variables
extract_yaml_section() {
    local file="$1"
    local section="$2"
    local prefix="$3"
    local output_file="$4"
    
    if [[ ! -f "$file" ]]; then
        log_warn "YAML file not found: $file"
        return 1
    fi
    
    if ! yaml_path_exists "$file" "$section"; then
        log_warn "Section '$section' not found in $file"
        return 1
    fi
    
    log_info "Extracting section '$section' from $(basename "$file")"
    
    # Get all paths in the section
    local paths
    mapfile -t paths < <(yq eval ".$section | paths(scalars) as \$p | \$p | join(\".\")" "$file" 2>/dev/null)
    
    # Process each path
    for path in "${paths[@]}"; do
        if [[ -n "$path" ]]; then
            local value
            value=$(yq eval ".$section.$path" "$file" 2>/dev/null)
            local env_var
            env_var=$(yaml_to_env_var "${section}.${path}" "$prefix")
            
            # Write to output file
            echo "${env_var}=${value}" >> "$output_file"
        fi
    done
}

# =============================================================================
# ENV FILE GENERATION
# =============================================================================

# Main function to generate .env file from YAML configs
generate_env_from_yaml_configs() {
    log_info "🔄 Generating .env file from YAML configurations..."
    
    # Ensure yq is available
    ensure_yq_available || {
        log_error "Failed to ensure yq availability"
        return 1
    }
    
    # Backup existing .env file
    backup_existing_env_file
    
    # Create new .env file with header
    create_env_file_header
    
    # Extract configurations in order
    extract_system_config
    extract_docker_config
    extract_services_config
    extract_application_config
    add_compose_variables
    add_computed_variables
    
    # Set permissions and show summary
    chmod 600 "$ENV_FILE"
    show_env_generation_summary
    
    log_success "🎉 .env file generated successfully!"
}

# Backup existing .env file
backup_existing_env_file() {
    if [[ -f "$ENV_FILE" ]]; then
        local backup_name="${ENV_FILE}.backup.$(date +%s)"
        cp "$ENV_FILE" "$backup_name"
        log_info "📁 Backed up existing .env to $backup_name"
    fi
}

# Create .env file header
create_env_file_header() {
    cat > "$ENV_FILE" << EOF
# =================================================================
# === AUTO-GENERATED .env FILE FROM YAML CONFIGURATIONS =========
# =================================================================
# 
# This file is automatically generated from YAML configuration files:
# - ${MAIN_CONFIG_PATH} (Main application settings)
# - ${DOCKER_CONFIG_PATH} (Docker and infrastructure settings)
# - ${SERVICES_CONFIG_PATH} (Consolidated service settings)
# 
# DO NOT EDIT MANUALLY - Changes will be overwritten!
# Modify the YAML files instead and regenerate with:
#   ./scripts/yaml/generator.sh
# 
# Generator Version: ${GENERATOR_VERSION}
# Generated at: ${GENERATION_TIMESTAMP}
# =================================================================

EOF
}

# Extract system configuration
extract_system_config() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === SYSTEM CONFIGURATION ========================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    if [[ -f "$MAIN_CONFIG_PATH" ]]; then
        extract_yaml_section "$MAIN_CONFIG_PATH" "system" "SYSTEM_" "$ENV_FILE"
        extract_yaml_section "$MAIN_CONFIG_PATH" "environment" "ENV_" "$ENV_FILE"
        log_success "✅ System config variables extracted"
    else
        log_warn "⚠️  Main config file not found: $MAIN_CONFIG_PATH"
        add_default_system_variables
    fi
}

# Add default system variables if config not found
add_default_system_variables() {
    cat >> "$ENV_FILE" << EOF
# Default system variables (config file not found)
SYSTEM_NAME=FKS Trading Systems
SYSTEM_VERSION=1.0.0
ENV_MODE=development
ENV_DEBUG=false
EOF
}

# Extract Docker configuration
extract_docker_config() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === DOCKER CONFIGURATION ========================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    if [[ -f "$DOCKER_CONFIG_PATH" ]]; then
        # Extract main docker sections
        extract_yaml_section "$DOCKER_CONFIG_PATH" "system" "DOCKER_SYSTEM_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "build" "DOCKER_BUILD_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "services" "DOCKER_SERVICES_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "databases" "DOCKER_DATABASES_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "networks" "DOCKER_NETWORKS_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "volumes" "DOCKER_VOLUMES_" "$ENV_FILE"
        extract_yaml_section "$DOCKER_CONFIG_PATH" "resources" "DOCKER_RESOURCES_" "$ENV_FILE"
        
        log_success "✅ Docker config variables extracted"
    else
        log_warn "⚠️  Docker config file not found: $DOCKER_CONFIG_PATH"
        add_default_docker_variables
    fi
}

# Add default docker variables if config not found
add_default_docker_variables() {
    cat >> "$ENV_FILE" << EOF
# Default Docker variables (config file not found)
DOCKER_SYSTEM_APP_VERSION=1.0.0
DOCKER_SYSTEM_APP_ENVIRONMENT=development
DOCKER_SYSTEM_USER_NAME=appuser
DOCKER_SYSTEM_USER_ID=1088
DOCKER_SYSTEM_GROUP_ID=1088
DOCKER_BUILD_PARALLEL=true
DOCKER_BUILD_CACHE=true
EOF
}

# Extract services configuration
extract_services_config() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === SERVICES CONFIGURATION ======================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    if [[ -f "$SERVICES_CONFIG_PATH" ]]; then
        # Extract each service section
        local services
        mapfile -t services < <(get_yaml_keys "$SERVICES_CONFIG_PATH" ".")
        
        for service in "${services[@]}"; do
            if [[ "$service" != "global" && "$service" != "service_groups" && "$service" != "dependencies" ]]; then
                local service_upper
                service_upper=$(echo "$service" | tr '[:lower:]' '[:upper:]')
                extract_yaml_section "$SERVICES_CONFIG_PATH" "$service" "${service_upper}_" "$ENV_FILE"
            fi
        done
        
        # Extract global service configuration
        extract_yaml_section "$SERVICES_CONFIG_PATH" "global" "SERVICES_GLOBAL_" "$ENV_FILE"
        
        log_success "✅ Services config variables extracted"
    else
        log_warn "⚠️  Services config file not found: $SERVICES_CONFIG_PATH"
        add_default_service_variables
    fi
}

# Add default service variables if config not found
add_default_service_variables() {
    cat >> "$ENV_FILE" << EOF
# Default service variables (config file not found)
API_SERVICE_PORT=8000
APP_SERVICE_PORT=9000
DATA_SERVICE_PORT=9001
WEB_SERVICE_PORT=9999
WORKER_SERVICE_PORT=8001
EOF
}

# Extract application configuration
extract_application_config() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === APPLICATION CONFIGURATION ====================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    if [[ -f "$MAIN_CONFIG_PATH" ]]; then
        # Extract application-specific sections
        extract_yaml_section "$MAIN_CONFIG_PATH" "trading" "TRADING_" "$ENV_FILE"
        extract_yaml_section "$MAIN_CONFIG_PATH" "models" "MODELS_" "$ENV_FILE"
        extract_yaml_section "$MAIN_CONFIG_PATH" "market" "MARKET_" "$ENV_FILE"
        extract_yaml_section "$MAIN_CONFIG_PATH" "logging" "LOGGING_" "$ENV_FILE"
        extract_yaml_section "$MAIN_CONFIG_PATH" "security" "SECURITY_" "$ENV_FILE"
        
        log_success "✅ Application config variables extracted"
    else
        log_warn "⚠️  Application config file not found"
        add_default_application_variables
    fi
}

# Add default application variables
add_default_application_variables() {
    cat >> "$ENV_FILE" << EOF
# Default application variables (config file not found)
TRADING_MODE=paper
TRADING_INITIAL_BALANCE=10000
MODELS_DEFAULT_MODEL=transformer
LOGGING_LEVEL=INFO
EOF
}

# Add Docker Compose specific variables
add_compose_variables() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === DOCKER COMPOSE VARIABLES ====================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    # Get project name from config or use default
    local project_name
    project_name=$(get_yaml_value "$MAIN_CONFIG_PATH" "system.name" "fks")
    project_name=$(echo "$project_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    
    cat >> "$ENV_FILE" << EOF
COMPOSE_PROJECT_NAME=${project_name}
COMPOSE_FILE=${COMPOSE_FILE}
COMPOSE_PATH_SEPARATOR=:
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_PARALLEL_LIMIT=4
EOF
}

# Add computed variables derived from configuration
add_computed_variables() {
    echo "" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "# === COMPUTED VARIABLES ===========================================" >> "$ENV_FILE"
    echo "# ==================================================================" >> "$ENV_FILE"
    echo "" >> "$ENV_FILE"
    
    # Compute derived values
    local app_version
    app_version=$(get_yaml_value "$MAIN_CONFIG_PATH" "system.version" "1.0.0")
    
    local docker_username
    docker_username=$(get_yaml_value "$DOCKER_CONFIG_PATH" "system.registry.username" "nuniesmith")
    
    local docker_repo
    docker_repo=$(get_yaml_value "$DOCKER_CONFIG_PATH" "system.registry.repository" "fks")
    
    cat >> "$ENV_FILE" << EOF
# Computed image tags
API_IMAGE_TAG=${docker_username}/${docker_repo}:api-${app_version}
APP_IMAGE_TAG=${docker_username}/${docker_repo}:app-${app_version}
DATA_IMAGE_TAG=${docker_username}/${docker_repo}:data-${app_version}
WEB_IMAGE_TAG=${docker_username}/${docker_repo}:web-${app_version}
WORKER_IMAGE_TAG=${docker_username}/${docker_repo}:worker-${app_version}
TRAINING_IMAGE_TAG=${docker_username}/${docker_repo}:training-${app_version}
TRANSFORMER_IMAGE_TAG=${docker_username}/${docker_repo}:transformer-${app_version}

# Generation metadata
GENERATOR_VERSION=${GENERATOR_VERSION}
GENERATION_TIMESTAMP=${GENERATION_TIMESTAMP}
EOF
}

# Show .env generation summary
show_env_generation_summary() {
    local var_count
    var_count=$(grep -c '^[^#].*=' "$ENV_FILE" 2>/dev/null || echo 0)
    log_info "📊 Generated $var_count environment variables"
    
    # Show breakdown by category
    local system_vars=$(grep -c '^SYSTEM_\|^ENV_' "$ENV_FILE" 2>/dev/null || echo 0)
    local docker_vars=$(grep -c '^DOCKER_' "$ENV_FILE" 2>/dev/null || echo 0)
    local service_vars=$(grep -c '^API_\|^APP_\|^DATA_\|^WEB_\|^WORKER_\|^TRAINING_\|^TRANSFORMER_' "$ENV_FILE" 2>/dev/null || echo 0)
    local compose_vars=$(grep -c '^COMPOSE_' "$ENV_FILE" 2>/dev/null || echo 0)
    
    log_info "  - System variables: $system_vars"
    log_info "  - Docker variables: $docker_vars"  
    log_info "  - Service variables: $service_vars"
    log_info "  - Compose variables: $compose_vars"
}

# =============================================================================
# DOCKER COMPOSE GENERATION
# =============================================================================

# Main function to generate docker-compose.yml from YAML configs
generate_docker_compose_from_yaml() {
    log_info "🐳 Generating docker-compose.yml from YAML configurations..."
    
    # Ensure yq is available
    ensure_yq_available || {
        log_error "Failed to ensure yq availability"
        return 1
    }
    
    # Backup existing compose file
    backup_existing_compose_file
    
    # Generate compose file
    create_compose_file_header
    generate_compose_services
    generate_compose_networks
    generate_compose_volumes
    
    show_compose_generation_summary
    log_success "🎉 docker-compose.yml generated successfully!"
}

# Backup existing compose file
backup_existing_compose_file() {
    if [[ -f "$COMPOSE_FILE" ]]; then
        local backup_name="${COMPOSE_FILE}.backup.$(date +%s)"
        cp "$COMPOSE_FILE" "$backup_name"
        log_info "📁 Backed up existing compose file to $backup_name"
    fi
}

# Create compose file header
create_compose_file_header() {
    cat > "$COMPOSE_FILE" << EOF
# =================================================================
# === AUTO-GENERATED DOCKER COMPOSE FILE =========================
# =================================================================
# 
# This file is automatically generated from YAML configuration files:
# - ${DOCKER_CONFIG_PATH} (Docker and infrastructure settings)
# - ${SERVICES_CONFIG_PATH} (Service-specific settings)
# 
# DO NOT EDIT MANUALLY - Changes will be overwritten!
# Modify the YAML files instead and regenerate with:
#   ./scripts/yaml/generator.sh
# 
# Generator Version: ${GENERATOR_VERSION}
# Generated at: ${GENERATION_TIMESTAMP}
# =================================================================




EOF
}

# Generate services section
generate_compose_services() {
    echo "services:" >> "$COMPOSE_FILE"
    echo "" >> "$COMPOSE_FILE"
    
    # Generate in dependency order
    generate_database_services
    generate_core_services
    generate_gpu_services
    generate_optional_services
}

# Generate database services
generate_database_services() {
    cat >> "$COMPOSE_FILE" << 'EOF'
  # =================================================================
  # === Database Services ===========================================
  # =================================================================

  redis:
    container_name: ${DOCKER_DATABASES_REDIS_CONTAINER_NAME:-fks_redis}
    image: ${DOCKER_DATABASES_REDIS_IMAGE:-redis:7-alpine}
    restart: ${DOCKER_DATABASES_REDIS_RESTART_POLICY:-unless-stopped}
    ports:
      - "${DOCKER_DATABASES_REDIS_PORT:-6379}:${DOCKER_DATABASES_REDIS_PORT:-6379}"
    command: [
      "redis-server",
      "--requirepass", "${DOCKER_DATABASES_REDIS_PASSWORD}",
      "--appendonly", "yes",
      "--maxmemory", "${DOCKER_DATABASES_REDIS_MAXMEMORY:-512mb}",
      "--maxmemory-policy", "${DOCKER_DATABASES_REDIS_MAXMEMORY_POLICY:-allkeys-lru}"
    ]
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
    volumes:
      - redis_data:/data
    networks:
      - fks_database
      - fks_backend
    healthcheck:
      test: ["CMD-SHELL", "${DOCKER_DATABASES_REDIS_HEALTHCHECK_CMD}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-10s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_REDIS_CPU_LIMIT:-1}'
          memory: ${DOCKER_RESOURCES_REDIS_MEMORY_LIMIT:-512M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"

  postgres:
    container_name: ${DOCKER_DATABASES_POSTGRES_CONTAINER_NAME:-fks_postgres}
    image: ${DOCKER_DATABASES_POSTGRES_IMAGE:-postgres:16-alpine}
    restart: ${DOCKER_DATABASES_POSTGRES_RESTART_POLICY:-unless-stopped}
    ports:
      - "${DOCKER_DATABASES_POSTGRES_PORT:-5432}:${DOCKER_DATABASES_POSTGRES_PORT:-5432}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
      - POSTGRES_MAX_CONNECTIONS=${DOCKER_DATABASES_POSTGRES_MAX_CONNECTIONS:-100}
      - POSTGRES_SHARED_BUFFERS=${DOCKER_DATABASES_POSTGRES_SHARED_BUFFERS:-256MB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - fks_database
      - fks_backend
    healthcheck:
      test: ["CMD-SHELL", "${DOCKER_DATABASES_POSTGRES_HEALTHCHECK_CMD}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-10s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_POSTGRES_CPU_LIMIT:-2}'
          memory: ${DOCKER_RESOURCES_POSTGRES_MEMORY_LIMIT:-1024M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"

EOF
}

# Generate core services
generate_core_services() {
    cat >> "$COMPOSE_FILE" << 'EOF'
  # =================================================================
  # === Core Application Services ===================================
  # =================================================================

  api:
    container_name: ${API_CONTAINER_NAME:-fks_api}
    image: ${API_IMAGE_TAG}
    restart: ${API_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=cpu
        - SERVICE_TYPE=api
        - SERVICE_NAME=api
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "api"]
    ports:
      - "${API_SERVICE_PORT:-8000}:${API_SERVICE_PORT:-8000}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=api
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${API_CONFIG_FILE:-/app/config/services/api.yaml}
      - API_PORT=${API_SERVICE_PORT:-8000}
      - API_HOST=${API_SERVICE_HOST:-0.0.0.0}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
    networks:
      - fks_frontend
      - fks_backend
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${API_HEALTHCHECK_CMD:-curl --fail http://localhost:8000/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_API_CPU_LIMIT:-2}'
          memory: ${DOCKER_RESOURCES_API_MEMORY_LIMIT:-2048M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - core
      - all

  data:
    container_name: ${DATA_CONTAINER_NAME:-fks_data}
    image: ${DATA_IMAGE_TAG}
    restart: ${DATA_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=cpu
        - SERVICE_TYPE=data
        - SERVICE_NAME=data
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "data"]
    ports:
      - "${DATA_SERVICE_PORT:-9001}:${DATA_SERVICE_PORT:-9001}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=data
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${DATA_CONFIG_FILE:-/app/config/services/data.yaml}
      - DATA_PORT=${DATA_SERVICE_PORT:-9001}
      - DATA_HOST=${DATA_SERVICE_HOST:-0.0.0.0}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
    networks:
      - fks_backend
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${DATA_HEALTHCHECK_CMD:-curl --fail http://localhost:9001/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_DATA_CPU_LIMIT:-2}'
          memory: ${DOCKER_RESOURCES_DATA_MEMORY_LIMIT:-2048M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - core
      - all

  worker:
    container_name: ${WORKER_CONTAINER_NAME:-fks_worker}
    image: ${WORKER_IMAGE_TAG}
    restart: ${WORKER_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=cpu
        - SERVICE_TYPE=worker
        - SERVICE_NAME=worker
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "worker"]
    expose:
      - "${WORKER_SERVICE_PORT:-8001}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=worker
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${WORKER_CONFIG_FILE:-/app/config/services/worker.yaml}
      - WORKER_PORT=${WORKER_SERVICE_PORT:-8001}
      - WORKER_HOST=${WORKER_SERVICE_HOST:-0.0.0.0}
      - WORKER_COUNT=${WORKER_COUNT:-2}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
    networks:
      - fks_backend
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${WORKER_HEALTHCHECK_CMD:-curl --fail http://localhost:8001/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_WORKER_CPU_LIMIT:-2}'
          memory: ${DOCKER_RESOURCES_WORKER_MEMORY_LIMIT:-2048M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - core
      - all

  app:
    container_name: ${APP_CONTAINER_NAME:-fks_app}
    image: ${APP_IMAGE_TAG}
    restart: ${APP_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=cpu
        - SERVICE_TYPE=app
        - SERVICE_NAME=app
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "app"]
    ports:
      - "${APP_SERVICE_PORT:-9000}:${APP_SERVICE_PORT:-9000}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=app
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${APP_CONFIG_FILE:-/app/config/services/app.yaml}
      - APP_PORT=${APP_SERVICE_PORT:-9000}
      - APP_HOST=${APP_SERVICE_HOST:-0.0.0.0}
      - TRADING_MODE=${APP_TRADING_MODE:-paper}
      # Service connections
      - API_HOST=api
      - API_PORT=${API_SERVICE_PORT:-8000}
      - DATA_HOST=data
      - DATA_PORT=${DATA_SERVICE_PORT:-9001}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
      - app_models:/app/models
    networks:
      - fks_frontend
      - fks_backend
    depends_on:
      api:
        condition: service_healthy
      data:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${APP_HEALTHCHECK_CMD:-curl --fail http://localhost:9000/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_APP_CPU_LIMIT:-2}'
          memory: ${DOCKER_RESOURCES_APP_MEMORY_LIMIT:-2048M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - core
      - all

  web:
    container_name: ${WEB_CONTAINER_NAME:-fks_web}
    image: ${WEB_IMAGE_TAG}
    restart: ${WEB_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=cpu
        - SERVICE_TYPE=web
        - SERVICE_NAME=web
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "web"]
    ports:
      - "${WEB_SERVICE_PORT:-9999}:${WEB_SERVICE_PORT:-9999}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=web
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${WEB_CONFIG_FILE:-/app/config/services/web.yaml}
      - WEB_PORT=${WEB_SERVICE_PORT:-9999}
      - WEB_HOST=${WEB_SERVICE_HOST:-0.0.0.0}
      # Service connections
      - API_HOST=api
      - API_PORT=${API_SERVICE_PORT:-8000}
      - APP_HOST=app
      - APP_PORT=${APP_SERVICE_PORT:-9000}
      - DATA_HOST=data
      - DATA_PORT=${DATA_SERVICE_PORT:-9001}
    volumes:
      - app_logs:/app/logs
    networks:
      - fks_frontend
      - fks_backend
    depends_on:
      api:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${WEB_HEALTHCHECK_CMD:-curl --fail http://localhost:9999/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_WEB_CPU_LIMIT:-1}'
          memory: ${DOCKER_RESOURCES_WEB_MEMORY_LIMIT:-1024M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - web
      - all

EOF
}

# Generate GPU services
generate_gpu_services() {
    cat >> "$COMPOSE_FILE" << 'EOF'
  # =================================================================
  # === GPU Services (Optional) =====================================
  # =================================================================

  training:
    container_name: ${TRAINING_CONTAINER_NAME:-fks_training}
    image: ${TRAINING_IMAGE_TAG}
    restart: ${TRAINING_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_GPU_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=gpu
        - SERVICE_TYPE=training
        - SERVICE_NAME=training
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - CUDA_VERSION=${DOCKER_BUILD_VERSIONS_CUDA:-12.8.0}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "training"]
    ports:
      - "${TRAINING_SERVICE_PORT:-8088}:${TRAINING_SERVICE_PORT:-8088}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=training
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${TRAINING_CONFIG_FILE:-/app/config/services/training.yaml}
      - TRAINING_PORT=${TRAINING_SERVICE_PORT:-8088}
      - TRAINING_HOST=${TRAINING_SERVICE_HOST:-0.0.0.0}
      - TRAINING_EPOCHS=${TRAINING_EPOCHS:-50}
      - TRAINING_BATCH_SIZE=${TRAINING_BATCH_SIZE:-32}
      - CUDA_VISIBLE_DEVICES=${TRAINING_CUDA_VISIBLE_DEVICES:-0}
      - MPLCONFIGDIR=/tmp/mpl_config
      # Service connections
      - DATA_HOST=data
      - DATA_PORT=${DATA_SERVICE_PORT:-9001}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
      - app_models:/app/models
    networks:
      - fks_backend
    depends_on:
      data:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${TRAINING_HEALTHCHECK_CMD:-curl --fail http://localhost:8088/health || nvidia-smi > /dev/null}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-60s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-60s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_TRAINING_CPU_LIMIT:-4}'
          memory: ${DOCKER_RESOURCES_TRAINING_MEMORY_LIMIT:-4096M}
        reservations:
          devices:
            - driver: nvidia
              count: ${TRAINING_GPU_COUNT:-1}
              capabilities: [gpu]
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - gpu
      - ml
      - all

  transformer:
    container_name: ${TRANSFORMER_CONTAINER_NAME:-fks_transformer}
    image: ${TRANSFORMER_IMAGE_TAG}
    restart: ${TRANSFORMER_RESTART_POLICY:-unless-stopped}
    build:
      context: ${DOCKER_BUILD_CONTEXT:-.}
      dockerfile: ${DOCKER_BUILD_DOCKERFILE_GPU_PATH:-./deployment/docker/Dockerfile}
      args:
        - SERVICE_RUNTIME=python
        - BUILD_TYPE=gpu
        - SERVICE_TYPE=transformer
        - SERVICE_NAME=transformer
        - PYTHON_VERSION=${DOCKER_BUILD_VERSIONS_PYTHON:-3.11}
        - CUDA_VERSION=${DOCKER_BUILD_VERSIONS_CUDA:-12.8.0}
        - USER_NAME=${DOCKER_SYSTEM_USER_NAME:-appuser}
        - USER_ID=${DOCKER_SYSTEM_USER_ID:-1088}
        - GROUP_ID=${DOCKER_SYSTEM_GROUP_ID:-1088}
    entrypoint: ["python", "-m", "main", "service", "transformer"]
    ports:
      - "${TRANSFORMER_SERVICE_PORT:-8089}:${TRANSFORMER_SERVICE_PORT:-8089}"
    environment:
      - TZ=${DOCKER_SYSTEM_APP_TIMEZONE:-America/New_York}
      - SERVICE_TYPE=transformer
      - PYTHONPATH=/app/src
      - PYTHONUNBUFFERED=1
      - CONFIG_DIR=/app/config
      - CONFIG_FILE=${TRANSFORMER_CONFIG_FILE:-/app/config/services/transformer.yaml}
      - TRANSFORMER_PORT=${TRANSFORMER_SERVICE_PORT:-8089}
      - TRANSFORMER_HOST=${TRANSFORMER_SERVICE_HOST:-0.0.0.0}
      - TRANSFORMER_MODEL_TYPE=${TRANSFORMER_MODEL_TYPE:-transformer}
      - TRANSFORMER_MAX_SEQUENCE_LENGTH=${TRANSFORMER_MAX_SEQUENCE_LENGTH:-512}
      - TRANSFORMER_BATCH_SIZE=${TRANSFORMER_BATCH_SIZE:-32}
      - CUDA_VISIBLE_DEVICES=${TRANSFORMER_CUDA_VISIBLE_DEVICES:-0}
      - MPLCONFIGDIR=/tmp/mpl_config
      # Service connections
      - DATA_HOST=data
      - DATA_PORT=${DATA_SERVICE_PORT:-9001}
      # Database connections
      - REDIS_HOST=redis
      - REDIS_PORT=${DOCKER_DATABASES_REDIS_PORT:-6379}
      - REDIS_PASSWORD=${DOCKER_DATABASES_REDIS_PASSWORD}
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=${DOCKER_DATABASES_POSTGRES_PORT:-5432}
      - POSTGRES_DB=${DOCKER_DATABASES_POSTGRES_DATABASE:-financial_data}
      - POSTGRES_USER=${DOCKER_DATABASES_POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${DOCKER_DATABASES_POSTGRES_PASSWORD}
    volumes:
      - app_data:/app/data
      - app_logs:/app/logs
      - app_models:/app/models
    networks:
      - fks_backend
    depends_on:
      data:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "${TRANSFORMER_HEALTHCHECK_CMD:-curl --fail http://localhost:8089/health || nvidia-smi > /dev/null}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-60s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-60s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_TRANSFORMER_CPU_LIMIT:-4}'
          memory: ${DOCKER_RESOURCES_TRANSFORMER_MEMORY_LIMIT:-4096M}
        reservations:
          devices:
            - driver: nvidia
              count: ${TRANSFORMER_GPU_COUNT:-1}
              capabilities: [gpu]
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - gpu
      - ml
      - all

EOF
}

# Generate optional services (monitoring, etc.)
generate_optional_services() {
    # Check if monitoring is enabled in config
    if yaml_path_exists "$DOCKER_CONFIG_PATH" "monitoring.prometheus.enabled" && 
       [[ "$(get_yaml_value "$DOCKER_CONFIG_PATH" "monitoring.prometheus.enabled" "false")" == "true" ]]; then
        generate_monitoring_services
    fi
}

# Generate monitoring services
generate_monitoring_services() {
    cat >> "$COMPOSE_FILE" << 'EOF'
  # =================================================================
  # === Monitoring Services (Optional) ==============================
  # =================================================================

  prometheus:
    container_name: ${DOCKER_MONITORING_PROMETHEUS_CONTAINER_NAME:-fks_prometheus}
    image: ${DOCKER_MONITORING_PROMETHEUS_IMAGE:-prom/prometheus:latest}
    restart: ${DOCKER_MONITORING_PROMETHEUS_RESTART_POLICY:-unless-stopped}
    ports:
      - "${DOCKER_MONITORING_PROMETHEUS_PORT:-9090}:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    volumes:
      - prometheus_data:/prometheus
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - fks_backend
    healthcheck:
      test: ["CMD-SHELL", "${DOCKER_MONITORING_PROMETHEUS_HEALTHCHECK_CMD:-curl -f http://localhost:9090/-/healthy}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_PROMETHEUS_CPU_LIMIT:-1}'
          memory: ${DOCKER_RESOURCES_PROMETHEUS_MEMORY_LIMIT:-1024M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - monitoring
      - all

  grafana:
    container_name: ${DOCKER_MONITORING_GRAFANA_CONTAINER_NAME:-fks_grafana}
    image: ${DOCKER_MONITORING_GRAFANA_IMAGE:-grafana/grafana:latest}
    restart: ${DOCKER_MONITORING_GRAFANA_RESTART_POLICY:-unless-stopped}
    ports:
      - "${DOCKER_MONITORING_GRAFANA_PORT:-3000}:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=${DOCKER_MONITORING_GRAFANA_ADMIN_USER:-admin}
      - GF_SECURITY_ADMIN_PASSWORD=${DOCKER_MONITORING_GRAFANA_ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=${DOCKER_MONITORING_GRAFANA_ALLOW_SIGN_UP:-false}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    networks:
      - fks_frontend
      - fks_backend
    depends_on:
      - prometheus
    healthcheck:
      test: ["CMD-SHELL", "${DOCKER_MONITORING_GRAFANA_HEALTHCHECK_CMD:-curl -f http://localhost:3000/api/health}"]
      interval: ${DOCKER_BUILD_HEALTHCHECK_INTERVAL:-30s}
      timeout: ${DOCKER_BUILD_HEALTHCHECK_TIMEOUT:-10s}
      retries: ${DOCKER_BUILD_HEALTHCHECK_RETRIES:-3}
      start_period: ${DOCKER_BUILD_HEALTHCHECK_START_PERIOD:-30s}
    deploy:
      resources:
        limits:
          cpus: '${DOCKER_RESOURCES_GRAFANA_CPU_LIMIT:-1}'
          memory: ${DOCKER_RESOURCES_GRAFANA_MEMORY_LIMIT:-512M}
    logging:
      driver: ${DOCKER_LOGGING_DRIVER:-json-file}
      options:
        max-size: ${DOCKER_LOGGING_MAX_SIZE:-100m}
        max-file: "${DOCKER_LOGGING_MAX_FILES:-3}"
    profiles:
      - monitoring
      - all

EOF
}

# Generate networks section
generate_compose_networks() {
    cat >> "$COMPOSE_FILE" << 'EOF'

# =================================================================
# === Networks ====================================================
# =================================================================
networks:
  fks_frontend:
    name: ${DOCKER_NETWORKS_FRONTEND_NAME:-fks_frontend}
    driver: ${DOCKER_NETWORKS_FRONTEND_DRIVER:-bridge}
    
  fks_backend:
    name: ${DOCKER_NETWORKS_BACKEND_NAME:-fks_backend}
    driver: ${DOCKER_NETWORKS_BACKEND_DRIVER:-bridge}
    
  fks_database:
    name: ${DOCKER_NETWORKS_DATABASE_NAME:-fks_database}
    driver: ${DOCKER_NETWORKS_DATABASE_DRIVER:-bridge}
    internal: ${DOCKER_NETWORKS_DATABASE_INTERNAL:-true}

EOF
}

# Generate volumes section
generate_compose_volumes() {
    cat >> "$COMPOSE_FILE" << 'EOF'
# =================================================================
# === Volumes =====================================================
# =================================================================
volumes:
  # Application volumes
  app_data:
    name: ${DOCKER_VOLUMES_APP_DATA_NAME:-fks_app_data}
    driver: ${DOCKER_VOLUMES_APP_DATA_DRIVER:-local}
    
  app_logs:
    name: ${DOCKER_VOLUMES_APP_LOGS_NAME:-fks_app_logs}
    driver: ${DOCKER_VOLUMES_APP_LOGS_DRIVER:-local}
    
  app_models:
    name: ${DOCKER_VOLUMES_APP_MODELS_NAME:-fks_app_models}
    driver: ${DOCKER_VOLUMES_APP_MODELS_DRIVER:-local}
  
  # Database volumes
  postgres_data:
    name: ${DOCKER_VOLUMES_POSTGRES_DATA_NAME:-fks_postgres_data}
    driver: ${DOCKER_VOLUMES_POSTGRES_DATA_DRIVER:-local}
    
  redis_data:
    name: ${DOCKER_VOLUMES_REDIS_DATA_NAME:-fks_redis_data}
    driver: ${DOCKER_VOLUMES_REDIS_DATA_DRIVER:-local}
  
  # Monitoring volumes (if enabled)
  prometheus_data:
    name: ${DOCKER_VOLUMES_PROMETHEUS_DATA_NAME:-fks_prometheus_data}
    driver: ${DOCKER_VOLUMES_PROMETHEUS_DATA_DRIVER:-local}
    
  grafana_data:
    name: ${DOCKER_VOLUMES_GRAFANA_DATA_NAME:-fks_grafana_data}
    driver: ${DOCKER_VOLUMES_GRAFANA_DATA_DRIVER:-local}
EOF
}

# Show compose generation summary
show_compose_generation_summary() {
    local service_count
    service_count=$(grep -c '^  [a-zA-Z][a-zA-Z0-9_]*:$' "$COMPOSE_FILE" 2>/dev/null || echo 0)
    log_info "📊 Generated $service_count services in docker-compose.yml"
    
    # Show breakdown by profile
    local core_services=$(grep -A 5 'profiles:' "$COMPOSE_FILE" | grep -c 'core' || echo 0)
    local gpu_services=$(grep -A 5 'profiles:' "$COMPOSE_FILE" | grep -c 'gpu' || echo 0)
    local web_services=$(grep -A 5 'profiles:' "$COMPOSE_FILE" | grep -c 'web' || echo 0)
    local monitoring_services=$(grep -A 5 'profiles:' "$COMPOSE_FILE" | grep -c 'monitoring' || echo 0)
    
    log_info "  - Core services: $core_services"
    log_info "  - GPU services: $gpu_services"
    log_info "  - Web services: $web_services"
    log_info "  - Monitoring services: $monitoring_services"
}

# =============================================================================
# COMMAND LINE FUNCTIONS
# =============================================================================

# Regenerate .env file (for command line usage)
regenerate_env_file() {
    log_info "🔄 Regenerating .env file from YAML configurations..."
    if generate_env_from_yaml_configs; then
        log_success "✅ .env file regenerated successfully"
        return 0
    else
        log_error "❌ Failed to regenerate .env file"
        return 1
    fi
}

# Regenerate docker-compose.yml (for command line usage)
regenerate_compose_file() {
    log_info "🐳 Regenerating docker-compose.yml from YAML configurations..."
    if generate_docker_compose_from_yaml; then
        log_success "✅ docker-compose.yml regenerated successfully"
        return 0
    else
        log_error "❌ Failed to regenerate docker-compose.yml"
        return 1
    fi
}

# Generate both files
regenerate_all_files() {
    log_info "🔄 Regenerating all generated files..."
    
    local success=true
    
    if ! generate_env_from_yaml_configs; then
        log_error "Failed to generate .env file"
        success=false
    fi
    
    if ! generate_docker_compose_from_yaml; then
        log_error "Failed to generate docker-compose.yml"
        success=false
    fi
    
    if [[ "$success" == "true" ]]; then
        log_success "✅ All files regenerated successfully"
        return 0
    else
        log_error "❌ Failed to regenerate some files"
        return 1
    fi
}

# Validate generated files
validate_generated_files() {
    log_info "🔍 Validating generated files..."
    
    local valid=true
    
    # Check .env file
    if [[ -f "$ENV_FILE" ]]; then
        local env_vars
        env_vars=$(grep -c '^[^#].*=' "$ENV_FILE" 2>/dev/null || echo 0)
        if [[ $env_vars -gt 0 ]]; then
            log_success "✅ .env file is valid ($env_vars variables)"
        else
            log_error "❌ .env file appears to be empty or invalid"
            valid=false
        fi
        
        # Check for required variables
        local required_vars=("DOCKER_DATABASES_REDIS_PASSWORD" "DOCKER_DATABASES_POSTGRES_PASSWORD")
        for var in "${required_vars[@]}"; do
            if ! grep -q "^${var}=" "$ENV_FILE"; then
                log_error "❌ Required variable missing: $var"
                valid=false
            fi
        done
    else
        log_error "❌ .env file not found"
        valid=false
    fi
    
    # Check docker-compose.yml file
    if [[ -f "$COMPOSE_FILE" ]]; then
        # Try docker compose first, then docker-compose
        if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
            if docker compose -f "$COMPOSE_FILE" config -q 2>/dev/null; then
                log_success "✅ docker-compose.yml is valid"
            else
                log_error "❌ docker-compose.yml has syntax errors"
                docker compose -f "$COMPOSE_FILE" config 2>&1 | head -5
                valid=false
            fi
        elif command -v docker-compose >/dev/null 2>&1; then
            if docker-compose -f "$COMPOSE_FILE" config -q 2>/dev/null; then
                log_success "✅ docker-compose.yml is valid"
            else
                log_error "❌ docker-compose.yml has syntax errors"
                docker-compose -f "$COMPOSE_FILE" config 2>&1 | head -5
                valid=false
            fi
        else
            log_warn "⚠️  Cannot validate docker-compose.yml (docker-compose not available)"
        fi
    else
        log_error "❌ docker-compose.yml file not found"
        valid=false
    fi
    
    if [[ "$valid" == "true" ]]; then
        log_success "✅ All generated files are valid"
        return 0
    else
        log_error "❌ Some generated files are invalid"
        return 1
    fi
}

# Show generator status
show_generator_status() {
    log_info "📊 YAML Generator Status"
    echo ""
    
    # Show configuration files status
    log_info "Configuration Files:"
    local config_files=("$MAIN_CONFIG_PATH" "$DOCKER_CONFIG_PATH" "$SERVICES_CONFIG_PATH")
    for file in "${config_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_info "  ✅ $(basename "$file"): Found"
        else
            log_info "  ❌ $(basename "$file"): Missing"
        fi
    done
    
    echo ""
    
    # Show generated files status
    log_info "Generated Files:"
    if [[ -f "$ENV_FILE" ]]; then
        local env_vars=$(grep -c '^[^#].*=' "$ENV_FILE" 2>/dev/null || echo 0)
        local env_age=$(stat -c %Y "$ENV_FILE" 2>/dev/null || echo 0)
        local env_age_str=""
        if [[ $env_age -gt 0 ]]; then
            env_age_str=" ($(date -d "@$env_age" '+%Y-%m-%d %H:%M:%S'))"
        fi
        log_info "  ✅ $ENV_FILE: $env_vars variables$env_age_str"
    else
        log_info "  ❌ $ENV_FILE: Not found"
    fi
    
    if [[ -f "$COMPOSE_FILE" ]]; then
        local compose_services=$(grep -c '^  [a-zA-Z][a-zA-Z0-9_]*:$' "$COMPOSE_FILE" 2>/dev/null || echo 0)
        local compose_age=$(stat -c %Y "$COMPOSE_FILE" 2>/dev/null || echo 0)
        local compose_age_str=""
        if [[ $compose_age -gt 0 ]]; then
            compose_age_str=" ($(date -d "@$compose_age" '+%Y-%m-%d %H:%M:%S'))"
        fi
        log_info "  ✅ $COMPOSE_FILE: $compose_services services$compose_age_str"
    else
        log_info "  ❌ $COMPOSE_FILE: Not found"
    fi
    
    echo ""
    
    # Show dependencies
    log_info "Dependencies:"
    if command -v yq >/dev/null 2>&1; then
        local yq_version=$(yq --version 2>/dev/null | head -1)
        log_info "  ✅ yq: $yq_version"
    else
        log_info "  ❌ yq: Not installed"
    fi
    
    if command -v docker >/dev/null 2>&1; then
        if docker compose version >/dev/null 2>&1; then
            log_info "  ✅ docker compose: Available"
        elif command -v docker-compose >/dev/null 2>&1; then
            log_info "  ✅ docker-compose: Available (legacy)"
        else
            log_info "  ❌ docker compose: Not available"
        fi
    else
        log_info "  ❌ docker: Not installed"
    fi
}

# Create sample configuration structure
create_sample_configs() {
    log_info "📁 Creating sample configuration structure..."
    
    # Create directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$SERVICE_CONFIGS_DIR"
    
    # Create sample main config
    if [[ ! -f "$MAIN_CONFIG_PATH" ]]; then
        log_info "Creating sample main.yaml..."
        cat > "$MAIN_CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Main Configuration
system:
  name: "FKS Trading Systems"
  version: "1.0.0"
  timezone: "America/New_York"

environment:
  mode: "development"
  debug: false

trading:
  mode: "paper"
  initial_balance: 10000

models:
  default_model: "transformer"

logging:
  level: "INFO"
  file: "/app/logs/main.log"
EOF
    fi
    
    # Create sample docker config
    if [[ ! -f "$DOCKER_CONFIG_PATH" ]]; then
        log_info "Creating sample docker.yaml..."
        cat > "$DOCKER_CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Docker Configuration
system:
  registry:
    username: "nuniesmith"
    repository: "fks"
  user:
    name: "appuser"
    id: 1088
    group_id: 1088

build:
  parallel: true
  cache: true
  healthcheck:
    interval: "30s"
    timeout: "10s"
    retries: 3

databases:
  redis:
    image: "redis:7-alpine"
    port: 6379
    password: "fks_redis_2024_secure!"
  postgres:
    image: "postgres:16-alpine"
    port: 5432
    database: "financial_data"
    user: "postgres"
    password: "fks_postgres_2024_secure!"

networks:
  frontend:
    name: "fks_frontend"
    driver: "bridge"
  backend:
    name: "fks_backend"
    driver: "bridge"
  database:
    name: "fks_database"
    driver: "bridge"

volumes:
  app_data:
    driver: "local"
  postgres_data:
    driver: "local"
  redis_data:
    driver: "local"
EOF
    fi
    
    # Create sample services config
    if [[ ! -f "$SERVICES_CONFIG_PATH" ]]; then
        log_info "Creating sample services.yaml..."
        cat > "$SERVICES_CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Services Configuration
global:
  timeout: 300
  log_level: "INFO"

api:
  service:
    port: 8000
    host: "0.0.0.0"
  config_file: "/app/config/services/api.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8000/health"

app:
  service:
    port: 9000
    host: "0.0.0.0"
  trading_mode: "paper"
  config_file: "/app/config/services/app.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9000/health"

data:
  service:
    port: 9001
    host: "0.0.0.0"
  config_file: "/app/config/services/data.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9001/health"

web:
  service:
    port: 9999
    host: "0.0.0.0"
  config_file: "/app/config/services/web.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9999/health"

worker:
  service:
    port: 8001
    host: "0.0.0.0"
  count: 2
  config_file: "/app/config/services/worker.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8001/health"
EOF
    fi
    
    log_success "✅ Sample configuration structure created"
    log_info "You can now customize the YAML files and run: $0 regenerate-all"
}

# =============================================================================
# MAIN COMMAND HANDLING
# =============================================================================

# Main function for command line usage
main() {
    case "${1:-}" in
        "env"|"generate-env")
            regenerate_env_file
            ;;
        "compose"|"generate-compose")
            regenerate_compose_file
            ;;
        "all"|"regenerate-all"|"generate-all")
            regenerate_all_files
            ;;
        "validate")
            validate_generated_files
            ;;
        "status")
            show_generator_status
            ;;
        "sample"|"create-samples")
            create_sample_configs
            ;;
        "help"|"-h"|"--help")
            cat << EOF
YAML Generator v${GENERATOR_VERSION} - Generate files from YAML configs

USAGE:
  $0 [command]

COMMANDS:
  env, generate-env         Generate .env file from YAML configs
  compose, generate-compose Generate docker-compose.yml from YAML configs
  all, regenerate-all       Generate both .env and docker-compose.yml
  validate                  Validate generated files
  status                    Show generator and file status
  sample, create-samples    Create sample configuration structure
  help, -h, --help         Show this help

EXAMPLES:
  $0 all                    # Generate both files
  $0 env                    # Generate .env only
  $0 validate               # Check generated files
  $0 status                 # Show current status

CONFIGURATION FILES:
  ${MAIN_CONFIG_PATH}
  ${DOCKER_CONFIG_PATH}
  ${SERVICES_CONFIG_PATH}

OUTPUT FILES:
  ${ENV_FILE}
  ${COMPOSE_FILE}
EOF
            ;;
        "")
            log_info "YAML Generator v${GENERATOR_VERSION}"
            log_info "Use '$0 help' for usage information"
            show_generator_status
            ;;
        *)
            log_error "Unknown command: $1"
            log_info "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Export functions for external use
export -f generate_env_from_yaml_configs generate_docker_compose_from_yaml
export -f regenerate_env_file regenerate_compose_file regenerate_all_files
export -f validate_generated_files show_generator_status create_sample_configs

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi