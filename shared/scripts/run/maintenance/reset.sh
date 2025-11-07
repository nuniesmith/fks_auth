#!/bin/bash
# filepath: scripts/maintenance/reset.sh
# Reset operations for environments and configurations

# Ensure this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly"
    exit 1
fi

# Reset Python environment
reset_python_environment() {
    log_info "🔄 Resetting Python environment..."
    
    case $PYTHON_ENV_TYPE in
        "conda")
            reset_conda_environment
            ;;
        "venv")
            reset_venv_environment
            ;;
        *)
            log_warn "System Python environment cannot be reset"
            ;;
    esac
}

# Reset conda environment
reset_conda_environment() {
    echo "This will remove and recreate the conda environment: $CONDA_ENV"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "🐍 Resetting Conda environment..."
        
        # Deactivate if currently active
        if [ "${CONDA_DEFAULT_ENV:-}" = "$CONDA_ENV" ]; then
            conda deactivate || true
        fi
        
        # Remove existing environment
        if conda env list | grep -q "^$CONDA_ENV "; then
            log_info "Removing existing environment..."
            conda env remove -n $CONDA_ENV -y
        fi
        
        # Create fresh environment
        log_info "Creating fresh environment..."
        create_conda_environment
        log_success "✅ Conda environment reset completed"
    else
        log_info "Conda environment reset cancelled"
    fi
}

# Reset virtual environment
reset_venv_environment() {
    echo "This will remove and recreate the virtual environment: $VENV_DIR"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "🐍 Resetting Virtual environment..."
        
        # Deactivate if currently active
        if [ -n "${VIRTUAL_ENV:-}" ]; then
            deactivate || true
        fi
        
        # Remove existing virtual environment
        if [ -d "$VENV_DIR" ]; then
            log_info "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        fi
        
        # Create fresh virtual environment
        log_info "Creating fresh virtual environment..."
        python3 -m venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        pip install --upgrade pip
        install_requirements
        log_success "✅ Virtual environment reset completed"
    else
        log_info "Virtual environment reset cancelled"
    fi
}

# Reset Docker environment
reset_docker_environment() {
    log_info "🐳 Docker Environment Reset"
    
    echo ""
    echo "This will:"
    echo "- Stop all FKS containers"
    echo "- Remove all FKS containers and volumes"
    echo "- Remove all FKS images"
    echo "- Clean Docker build cache"
    echo "- Reset Docker networks"
    echo ""
    echo "⚠️  This is a destructive operation!"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        perform_docker_reset
    else
        log_info "Docker reset cancelled"
    fi
}

# Perform complete Docker reset
perform_docker_reset() {
    log_info "🧹 Performing complete Docker reset..."
    
    # Stop all FKS services
    if $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME ps -q >/dev/null 2>&1; then
        log_info "Stopping FKS services..."
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME down --remove-orphans
    fi
    
    # Remove FKS volumes
    log_info "Removing FKS volumes..."
    $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME down --volumes
    
    # Remove FKS images
    log_info "Removing FKS images..."
    local fks_images=$(docker images --filter="reference=nuniesmith/fks*" -q)
    if [ -n "$fks_images" ]; then
        docker rmi $fks_images -f 2>/dev/null || true
    fi
    
    # Remove FKS networks
    log_info "Removing FKS networks..."
    local fks_networks=$(docker network ls --filter="name=${COMPOSE_PROJECT_NAME}" -q)
    if [ -n "$fks_networks" ]; then
        docker network rm $fks_networks 2>/dev/null || true
    fi
    
    # Clean build cache
    log_info "Cleaning Docker build cache..."
    docker builder prune -a -f
    
    # Remove dangling images and containers
    log_info "Removing dangling resources..."
    docker system prune -f
    
    log_success "✅ Docker environment reset completed"
    
    # Show space freed
    log_info "Docker system summary after reset:"
    docker system df
}

# Reset configuration files
reset_configuration_files() {
    log_info "⚙️  Configuration Reset"
    
    echo ""
    echo "Configuration reset options:"
    echo "1) Reset .env file to defaults"
    echo "2) Reset docker-compose.yml to defaults"
    echo "3) Reset YAML configurations to templates"
    echo "4) Reset all configuration files"
    echo "5) Back to reset menu"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            reset_env_file
            ;;
        2)
            reset_docker_compose_file
            ;;
        3)
            reset_yaml_configurations
            ;;
        4)
            reset_all_configuration_files
            ;;
        *)
            return 0
            ;;
    esac
}

# Reset .env file
reset_env_file() {
    log_info "🔄 Resetting .env file..."
    
    if [ -f ".env" ]; then
        local backup_name=".env.backup.$(date +%s)"
        cp .env "$backup_name"
        log_info "📁 Backed up existing .env to $backup_name"
    fi
    
    # Regenerate from YAML configs
    if command -v yq >/dev/null 2>&1; then
        generate_env_from_yaml
        log_success "✅ .env file reset from YAML configurations"
    else
        # Create basic .env file
        create_basic_env_file
        log_success "✅ Basic .env file created"
    fi
}

# Reset docker-compose.yml file
reset_docker_compose_file() {
    log_info "🐳 Resetting docker-compose.yml file..."
    
    if [ -f "$COMPOSE_FILE" ]; then
        local backup_name="${COMPOSE_FILE}.backup.$(date +%s)"
        cp "$COMPOSE_FILE" "$backup_name"
        log_info "📁 Backed up existing $COMPOSE_FILE to $backup_name"
    fi
    
    # Regenerate from YAML configs
    if command -v yq >/dev/null 2>&1; then
        generate_docker_compose
        log_success "✅ docker-compose.yml reset from YAML configurations"
    else
        # Create basic docker-compose file
        create_basic_docker_compose
        log_success "✅ Basic docker-compose.yml created"
    fi
}

# Reset YAML configurations to templates
reset_yaml_configurations() {
    log_info "📄 Resetting YAML configurations to templates..."
    
    echo ""
    echo "This will reset all YAML configuration files to default templates."
    echo "Existing files will be backed up with timestamp suffix."
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup existing files
        local timestamp=$(date +%s)
        
        [ -f "$DOCKER_CONFIG_PATH" ] && cp "$DOCKER_CONFIG_PATH" "${DOCKER_CONFIG_PATH}.backup.$timestamp"
        [ -f "$CONFIG_PATH" ] && cp "$CONFIG_PATH" "${CONFIG_PATH}.backup.$timestamp"
        
        if [ -d "$SERVICE_CONFIGS_DIR" ]; then
            for config_file in "$SERVICE_CONFIGS_DIR"/*.yaml; do
                if [ -f "$config_file" ]; then
                    cp "$config_file" "${config_file}.backup.$timestamp"
                fi
            done
        fi
        
        # Create template files
        create_template_yaml_configs
        
        log_success "✅ YAML configurations reset to templates"
        log_info "💾 Original files backed up with timestamp: $timestamp"
    else
        log_info "YAML configuration reset cancelled"
    fi
}

# Reset all configuration files
reset_all_configuration_files() {
    log_info "🔄 Resetting ALL configuration files..."
    
    echo ""
    echo "⚠️  This will reset ALL configuration files including:"
    echo "- .env file"
    echo "- docker-compose.yml"
    echo "- All YAML configuration files"
    echo ""
    echo "All existing files will be backed up."
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reset_env_file
        reset_docker_compose_file
        reset_yaml_configurations
        log_success "✅ All configuration files reset completed"
    else
        log_info "Configuration reset cancelled"
    fi
}

# Create basic .env file
create_basic_env_file() {
    cat > .env << 'EOF'
# FKS Trading Systems - Basic Environment Configuration
# Generated by reset script

# Project Configuration
COMPOSE_PROJECT_NAME=fks
COMPOSE_FILE=docker-compose.yml

# Application Settings
APP_VERSION=1.0.0
APP_ENVIRONMENT=development
APP_LOG_LEVEL=INFO
APP_TIMEZONE=America/New_York

# Database Configuration
POSTGRES_DB=financial_data
POSTGRES_USER=postgres
POSTGRES_PASSWORD=123456
POSTGRES_PORT=5432

REDIS_PASSWORD=123456
REDIS_PORT=6379

# Service Ports
API_PORT=8000
APP_PORT=9000
DATA_PORT=9001
WEB_PORT=9999
TRAINING_PORT=8088
TRANSFORMER_PORT=8089

# Docker Configuration
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1
EOF
}

# Create basic docker-compose file
create_basic_docker_compose() {
    cat > "$COMPOSE_FILE" << 'EOF'



services:
  redis:
    image: redis:latest
    container_name: redis
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD:-123456}"]
    expose:
      - "${REDIS_PORT:-6379}"
    restart: unless-stopped
    networks:
      - app_network

  postgres:
    image: postgres:latest
    container_name: postgres
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-financial_data}
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-123456}
    expose:
      - "${POSTGRES_PORT:-5432}"
    restart: unless-stopped
    networks:
      - app_network
    volumes:
      - postgres_data:/var/lib/postgresql/data

  api:
    build: .
    container_name: fks_api
    ports:
      - "${API_PORT:-8000}:8000"
    environment:
      - SERVICE_TYPE=api
      - PYTHONPATH=/app/src
    depends_on:
      - redis
      - postgres
    restart: unless-stopped
    networks:
      - app_network

networks:
  app_network:
    driver: bridge

volumes:
  postgres_data:
EOF
}

# Create template YAML configurations
create_template_yaml_configs() {
    # Create docker_config.yaml template
    mkdir -p "$(dirname "$DOCKER_CONFIG_PATH")"
    cat > "$DOCKER_CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Docker Configuration Template
system:
  app:
    version: "1.0.0"
    environment: "development"
    timezone: "America/New_York"
    log_level: "INFO"
  
  user:
    name: "appuser"
    id: 1088
    group_id: 1088

  docker_hub:
    username: "nuniesmith"
    repository: "fks"

build:
  settings:
    use_system_packages: true
    keep_container_alive: true
  
  versions:
    python: "3.11"
    cuda: "12.8.0"
    cudnn: "cudnn"
    ubuntu: "ubuntu24.04"
  
  paths:
    requirements: "./requirements.txt"
    common_dockerfile: "./deployment/docker/Dockerfile"
    common_entrypoint: "./deployment/docker/entrypoint.sh"
    nginx_dockerfile: "./deployment/docker/nginx/Dockerfile"
  
  healthcheck:
    interval: "30s"
    timeout: "10s"
    retries: 3
    start_period: "10s"

databases:
  redis:
    image_tag: "redis:latest"
    port: 6379
    password: "123456"
    healthcheck_cmd: "redis-cli -a 123456 ping"
  
  postgres:
    image_tag: "postgres:latest"
    port: 5432
    database: "financial_data"
    user: "postgres"
    password: "123456"
    healthcheck_cmd: "pg_isready -U postgres"

cpu_services:
  api:
    container_name: "fks_api"
    image_tag: "nuniesmith/fks:api"
    service_type: "api"
    port: 8000
    service_name: "api"
    healthcheck_cmd: "curl --fail http://localhost:8000/health"
  
  app:
    container_name: "fks_app"
    image_tag: "nuniesmith/fks:app"
    service_type: "app"
    port: 9000
    service_name: "app"
    healthcheck_cmd: "curl --fail http://localhost:9000/health"

gpu_services:
  training:
    container_name: "fks_training"
    image_tag: "nuniesmith/fks:training"
    service_type: "training"
    port: 8088
    service_name: "training"
    healthcheck_cmd: "curl --fail http://localhost:8088/health"
    gpu:
      enabled: true
      count: 1
      device_ids: "0"
      mixed_precision: true
      cuda_visible_devices: "0"

networks:
  frontend:
    name: "frontend_network"
    driver: "bridge"
  
  backend:
    name: "python_app_network"
    driver: "bridge"
  
  database:
    name: "database_network"
    driver: "bridge"

volumes:
  data:
    driver: "local"
  models:
    driver: "local"
  logs:
    driver: "local"
  postgres_data:
    driver: "local"
  redis_data:
    driver: "local"
EOF

    # Create app_config.yaml template
    mkdir -p "$(dirname "$CONFIG_PATH")"
    cat > "$CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Application Configuration Template
model:
  type: "transformer"
  d_model: 64
  n_head: 8
  n_layers: 3
  dropout: 0.1
  learning_rate: 0.001
  weight_decay: 0.0001

data:
  seq_length: 60
  pred_length: 1
  batch_size: 32
  num_workers: 4
  test_split: 0.15
  val_split: 0.15

training:
  epochs: 100
  early_stopping_patience: 10
  gradient_clip_val: 1.0
  lr_scheduler:
    type: "cosine"
    min_lr: 0.00001
    warmup_steps: 500

features:
  use_technical_indicators: true
  use_advanced_sentiment: true
  use_fks_features: true
  
  fks_features:
    use_base_indicators: true
    use_market_structure: true
    use_order_blocks: true
    use_liquidity_zones: true
    use_signal_engine: true

paths:
  data_path: "./data"
  model_path: "./models"
  log_path: "./logs"
  results_path: "./results"
EOF

    # Create service config templates
    mkdir -p "$SERVICE_CONFIGS_DIR"
    
    # API service config
    cat > "$SERVICE_CONFIGS_DIR/api.yaml" << 'EOF'
# API Service Configuration
service:
  name: "api"
  type: "fastapi"
  host: "0.0.0.0"
  port: 8000
  workers: 2
  
database:
  redis_url: "redis://redis:6379"
  postgres_url: "postgresql://postgres:123456@postgres:5432/financial_data"
  
logging:
  level: "INFO"
  format: "json"
EOF

    # Training service config
    cat > "$SERVICE_CONFIGS_DIR/training.yaml" << 'EOF'
# Training Service Configuration
service:
  name: "training"
  type: "ml_training"
  port: 8088
  
model:
  type: "transformer"
  save_path: "/app/models"
  checkpoint_interval: 10
  
gpu:
  enabled: true
  device_id: 0
  mixed_precision: true
  
logging:
  level: "INFO"
  format: "json"
EOF

    log_success "✅ Template YAML configurations created"
}

# Reset project data
reset_project_data() {
    log_info "📁 Project Data Reset"
    
    echo ""
    echo "Data reset options:"
    echo "1) Clear logs directory"
    echo "2) Clear models directory (keep checkpoints)"
    echo "3) Clear all models (including checkpoints)"
    echo "4) Clear results directory"
    echo "5) Clear cache directories"
    echo "6) Reset all data directories"
    echo "7) Back to reset menu"
    echo ""
    
    echo "Select option (1-7): "
    read -r REPLY
    
    case $REPLY in
        1)
            reset_logs_directory
            ;;
        2)
            reset_models_directory false
            ;;
        3)
            reset_models_directory true
            ;;
        4)
            reset_results_directory
            ;;
        5)
            reset_cache_directories
            ;;
        6)
            reset_all_data_directories
            ;;
        *)
            return 0
            ;;
    esac
}

# Reset logs directory
reset_logs_directory() {
    log_info "🗂️  Clearing logs directory..."
    
    if [ -d "logs" ]; then
        echo "This will remove all log files. Continue? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf logs/*
            log_success "✅ Logs directory cleared"
        else
            log_info "Logs reset cancelled"
        fi
    else
        log_info "Logs directory doesn't exist"
    fi
}

# Reset models directory
reset_models_directory() {
    local clear_checkpoints=$1
    
    if [ "$clear_checkpoints" = true ]; then
        log_info "🗂️  Clearing ALL models and checkpoints..."
    else
        log_info "🗂️  Clearing models (keeping checkpoints)..."
    fi
    
    if [ -d "models" ]; then
        echo "This will remove model files. Continue? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ "$clear_checkpoints" = true ]; then
                rm -rf models/*
            else
                # Keep checkpoint files
                find models -type f -not -name "checkpoint_*" -not -name "*.ckpt" -delete 2>/dev/null || true
            fi
            log_success "✅ Models directory reset"
        else
            log_info "Models reset cancelled"
        fi
    else
        log_info "Models directory doesn't exist"
    fi
}

# Reset results directory
reset_results_directory() {
    log_info "🗂️  Clearing results directory..."
    
    if [ -d "results" ]; then
        echo "This will remove all result files. Continue? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf results/*
            log_success "✅ Results directory cleared"
        else
            log_info "Results reset cancelled"
        fi
    else
        log_info "Results directory doesn't exist"
    fi
}

# Reset cache directories
reset_cache_directories() {
    log_info "🗂️  Clearing cache directories..."
    
    local cache_dirs=("__pycache__" ".pytest_cache" ".mypy_cache" ".coverage" "node_modules")
    local found_caches=()
    
    # Find existing cache directories
    for cache_dir in "${cache_dirs[@]}"; do
        if find . -name "$cache_dir" -type d | grep -q .; then
            found_caches+=("$cache_dir")
        fi
    done
    
    if [ ${#found_caches[@]} -gt 0 ]; then
        echo "Found cache directories: ${found_caches[*]}"
        echo "Remove all cache directories? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for cache_dir in "${found_caches[@]}"; do
                find . -name "$cache_dir" -type d -exec rm -rf {} + 2>/dev/null || true
            done
            log_success "✅ Cache directories cleared"
        else
            log_info "Cache reset cancelled"
        fi
    else
        log_info "No cache directories found"
    fi
}

# Reset all data directories
reset_all_data_directories() {
    echo ""
    echo "⚠️  This will clear ALL data directories including:"
    echo "- Logs"
    echo "- Models (including checkpoints)"
    echo "- Results"
    echo "- Cache directories"
    echo ""
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reset_logs_directory
        reset_models_directory true
        reset_results_directory
        reset_cache_directories
        log_success "✅ All data directories reset"
    else
        log_info "Data reset cancelled"
    fi
}

# Main reset menu
reset_menu() {
    while true; do
        echo ""
        log_info "🔄 System Reset Operations"
        echo "==========================================="
        echo "1) 🐍 Reset Python Environment"
        echo "2) 🐳 Reset Docker Environment"
        echo "3) ⚙️  Reset Configuration Files"
        echo "4) 📁 Reset Project Data"
        echo "5) 🧹 Complete System Reset (Everything)"
        echo "6) ⬅️ Back to main menu"
        echo ""
        
        echo "Select reset option (1-6): "
        read -r REPLY
        
        case $REPLY in
            1)
                reset_python_environment
                ;;
            2)
                reset_docker_environment
                ;;
            3)
                reset_configuration_files
                ;;
            4)
                reset_project_data
                ;;
            5)
                complete_system_reset
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

# Complete system reset
complete_system_reset() {
    log_warn "⚠️  COMPLETE SYSTEM RESET"
    
    echo ""
    echo "This will perform a COMPLETE reset of:"
    echo "- Python environments"
    echo "- Docker containers, images, and volumes"
    echo "- All configuration files"
    echo "- All project data"
    echo ""
    echo "🚨 THIS IS DESTRUCTIVE AND CANNOT BE UNDONE! 🚨"
    echo ""
    echo "Type 'RESET' to confirm complete system reset: "
    read -r CONFIRMATION
    
    if [ "$CONFIRMATION" = "RESET" ]; then
        log_info "🔄 Performing complete system reset..."
        
        # Reset in order
        reset_docker_environment
        reset_python_environment
        reset_all_configuration_files
        reset_all_data_directories
        
        log_success "✅ Complete system reset finished!"
        log_info "🎯 System is now in clean state - ready for fresh setup"
    else
        log_info "Complete system reset cancelled"
    fi
}