#!/bin/bash
# filepath: scripts/utils/setup.sh
# FKS Trading Systems - Setup Utilities Module
# Handles environment setup and configuration management

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly SETUP_UTILS_VERSION="3.0.0"
readonly SETUP_UTILS_LOADED="$(date +%s)"

# =============================================================================
# ENVIRONMENT SETUP HANDLERS
# =============================================================================

# Main setup dispatcher
handle_environment_setup() {
    local setup_type="${1:-auto}"
    
    log_info "🔧 Setting up $setup_type environment..."
    
    case "$setup_type" in
        "conda"|"miniconda"|"anaconda")
            setup_conda_environment
            ;;
        "venv"|"virtualenv")
            setup_virtual_environment
            ;;
        "docker")
            setup_docker_environment
            ;;
        "auto")
            auto_detect_and_setup
            ;;
        *)
            log_error "❌ Unknown setup type: $setup_type"
            show_setup_help
            return 1
            ;;
    esac
}

# Auto-detect best setup method
auto_detect_and_setup() {
    log_info "🔍 Auto-detecting best setup method..."
    
    # Check current mode
    local mode="${FKS_MODE:-development}"
    
    case "$mode" in
        "server"|"production")
            if command -v docker >/dev/null 2>&1; then
                log_info "Server mode detected - using Docker"
                setup_docker_environment
            else
                log_error "❌ Docker required for server mode"
                return 1
            fi
            ;;
        "development"|"dev")
            if command -v conda >/dev/null 2>&1; then
                log_info "Development mode - using Conda"
                setup_conda_environment
            elif command -v python3 >/dev/null 2>&1; then
                log_info "Development mode - using virtual environment"
                setup_virtual_environment
            else
                log_error "❌ No Python environment manager available"
                return 1
            fi
            ;;
        *)
            log_warn "Unknown mode: $mode, defaulting to development setup"
            setup_virtual_environment
            ;;
    esac
}

# =============================================================================
# CONDA ENVIRONMENT SETUP
# =============================================================================

setup_conda_environment() {
    log_info "🐍 Setting up Conda environment..."
    
    if ! validate_conda_availability; then
        return 1
    fi
    
    local env_name="${FKS_CONDA_ENV_NAME:-fks}"
    
    if conda_env_exists "$env_name"; then
        log_info "✅ Conda environment '$env_name' already exists"
        update_conda_environment "$env_name"
    else
        create_conda_environment "$env_name"
    fi
    
    show_conda_next_steps "$env_name"
}

# Validate Conda availability
validate_conda_availability() {
    if ! command -v conda >/dev/null 2>&1; then
        log_error "❌ Conda not found"
        show_conda_installation_help
        return 1
    fi
    
    log_debug "✅ Conda available: $(conda --version)"
    return 0
}

# Check if conda environment exists
conda_env_exists() {
    local env_name="$1"
    conda env list | grep -q "^$env_name "
}

# Create new conda environment
create_conda_environment() {
    local env_name="$1"
    
    log_info "Creating conda environment: $env_name"
    
    local python_version="${FKS_PYTHON_VERSION:-3.9}"
    
    if conda create -n "$env_name" python="$python_version" -y; then
        log_success "✅ Conda environment '$env_name' created"
        
        # Install pip in the environment
        conda install -n "$env_name" pip -y
    else
        log_error "❌ Failed to create conda environment"
        return 1
    fi
}

# Update existing conda environment
update_conda_environment() {
    local env_name="$1"
    
    if [[ -f "environment.yml" ]]; then
        log_info "Updating environment from environment.yml..."
        if conda env update -n "$env_name" -f environment.yml; then
            log_success "✅ Environment updated from environment.yml"
        else
            log_warn "⚠️  Failed to update from environment.yml"
        fi
    else
        log_debug "No environment.yml found, skipping update"
    fi
}

# Show conda next steps
show_conda_next_steps() {
    local env_name="$1"
    
    cat << EOF

💡 Next steps:
  1. Activate environment: ${GREEN}conda activate $env_name${NC}
  2. Install requirements: ${GREEN}$0 --install-requirements${NC}
  3. Start development: ${GREEN}$0 --dev${NC}

EOF
}

# =============================================================================
# VIRTUAL ENVIRONMENT SETUP
# =============================================================================

setup_virtual_environment() {
    log_info "🐍 Setting up virtual environment..."
    
    if ! validate_python_availability; then
        return 1
    fi
    
    local venv_path="${FKS_VENV_PATH:-./venv}"
    
    if [[ -d "$venv_path" ]]; then
        log_info "✅ Virtual environment exists at: $venv_path"
        upgrade_venv_pip "$venv_path"
    else
        create_virtual_environment "$venv_path"
    fi
    
    show_venv_next_steps "$venv_path"
}

# Validate Python availability
validate_python_availability() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "❌ Python 3 not found"
        show_python_installation_help
        return 1
    fi
    
    local python_version
    python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_debug "✅ Python available: $python_version"
    
    return 0
}

# Create virtual environment
create_virtual_environment() {
    local venv_path="$1"
    
    log_info "Creating virtual environment: $venv_path"
    
    if python3 -m venv "$venv_path"; then
        log_success "✅ Virtual environment created at: $venv_path"
        upgrade_venv_pip "$venv_path"
    else
        log_error "❌ Failed to create virtual environment"
        return 1
    fi
}

# Upgrade pip in virtual environment
upgrade_venv_pip() {
    local venv_path="$1"
    
    log_info "Upgrading pip in virtual environment..."
    if "$venv_path/bin/pip" install --upgrade pip >/dev/null 2>&1; then
        log_success "✅ Pip upgraded successfully"
    else
        log_warn "⚠️  Failed to upgrade pip"
    fi
}

# Show virtual environment next steps
show_venv_next_steps() {
    local venv_path="$1"
    
    cat << EOF

💡 Next steps:
  1. Activate environment: ${GREEN}source $venv_path/bin/activate${NC}
  2. Install requirements: ${GREEN}$0 --install-requirements${NC}
  3. Start development: ${GREEN}$0 --dev${NC}

EOF
}

# =============================================================================
# DOCKER ENVIRONMENT SETUP
# =============================================================================

setup_docker_environment() {
    log_info "🐳 Setting up Docker environment..."
    
    if ! validate_docker_environment; then
        return 1
    fi
    
    local compose_cmd
    compose_cmd=$(detect_docker_compose_command)
    
    if ! validate_docker_compose_config "$compose_cmd"; then
        return 1
    fi
    
    build_and_start_docker_services "$compose_cmd"
    show_docker_next_steps "$compose_cmd"
}

# Validate Docker environment
validate_docker_environment() {
    # Check Docker installation
    if ! command -v docker >/dev/null 2>&1; then
        log_error "❌ Docker not found"
        show_docker_installation_help
        return 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "❌ Docker daemon not running"
        show_docker_daemon_help
        return 1
    fi
    
    log_debug "✅ Docker environment validated"
    return 0
}

# Detect Docker Compose command
detect_docker_compose_command() {
    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    else
        log_error "❌ Docker Compose not found"
        show_docker_compose_installation_help
        return 1
    fi
}

# Validate Docker Compose configuration
validate_docker_compose_config() {
    local compose_cmd="$1"
    
    if [[ ! -f "docker-compose.yml" ]]; then
        log_warn "⚠️  No docker-compose.yml found"
        if ask_yes_no "Generate docker-compose.yml?" "y"; then
            generate_docker_compose_file
        else
            return 1
        fi
    fi
    
    # Validate configuration
    if ! $compose_cmd config >/dev/null 2>&1; then
        log_error "❌ Docker Compose configuration invalid"
        $compose_cmd config
        return 1
    fi
    
    log_success "✅ Docker Compose configuration valid"
    return 0
}

# Build and start Docker services
build_and_start_docker_services() {
    local compose_cmd="$1"
    
    log_info "Building Docker containers..."
    if ! $compose_cmd build; then
        log_error "❌ Failed to build Docker containers"
        return 1
    fi
    
    log_info "Starting Docker services..."
    if ! $compose_cmd up -d; then
        log_error "❌ Failed to start Docker services"
        return 1
    fi
    
    log_success "✅ Docker services started"
    $compose_cmd ps
}

# Show Docker next steps
show_docker_next_steps() {
    local compose_cmd="$1"
    
    cat << EOF

✅ Docker environment ready

💡 Management commands:
  • View logs: ${GREEN}$compose_cmd logs -f${NC}
  • Stop services: ${GREEN}$compose_cmd down${NC}
  • Restart: ${GREEN}$compose_cmd restart${NC}
  • View status: ${GREEN}$compose_cmd ps${NC}

EOF
}

# =============================================================================
# REQUIREMENTS MANAGEMENT
# =============================================================================

# Handle requirements installation
handle_install_requirements() {
    log_info "📦 Installing requirements..."
    
    # Detect current environment
    local env_type
    env_type=$(detect_current_environment)
    
    case "$env_type" in
        "conda")
            install_requirements_conda
            ;;
        "venv")
            install_requirements_venv
            ;;
        "docker")
            install_requirements_docker
            ;;
        "system")
            install_requirements_system
            ;;
        *)
            log_error "❌ Unknown environment type: $env_type"
            return 1
            ;;
    esac
}

# Detect current Python environment
detect_current_environment() {
    if [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
        echo "conda"
    elif [[ -n "${VIRTUAL_ENV:-}" ]]; then
        echo "venv"
    elif [[ -f "docker-compose.yml" ]] && command -v docker >/dev/null 2>&1; then
        echo "docker"
    else
        echo "system"
    fi
}

# Install requirements in conda environment
install_requirements_conda() {
    log_info "Installing requirements in conda environment: $CONDA_DEFAULT_ENV"
    
    install_python_requirements_file "requirements.txt" || return 1
    install_python_requirements_file "requirements-dev.txt" || true
    
    log_success "✅ Requirements installed in conda environment"
}

# Install requirements in virtual environment
install_requirements_venv() {
    log_info "Installing requirements in virtual environment: $VIRTUAL_ENV"
    
    install_python_requirements_file "requirements.txt" || return 1
    install_python_requirements_file "requirements-dev.txt" || true
    
    log_success "✅ Requirements installed in virtual environment"
}

# Install requirements via Docker
install_requirements_docker() {
    log_info "Installing requirements via Docker rebuild..."
    
    local compose_cmd
    compose_cmd=$(detect_docker_compose_command) || return 1
    
    if $compose_cmd build --no-cache; then
        log_success "✅ Docker containers rebuilt with updated requirements"
    else
        log_error "❌ Failed to rebuild Docker containers"
        return 1
    fi
}

# Install requirements system-wide
install_requirements_system() {
    log_warn "⚠️  Installing requirements system-wide"
    
    if ! ask_yes_no "Continue with system-wide installation?" "n"; then
        log_info "Installation cancelled"
        return 1
    fi
    
    install_python_requirements_file "requirements.txt" || return 1
    log_success "✅ Requirements installed system-wide"
}

# Install Python requirements from file
install_python_requirements_file() {
    local requirements_file="$1"
    
    if [[ ! -f "$requirements_file" ]]; then
        log_debug "Requirements file not found: $requirements_file"
        return 1
    fi
    
    log_info "Installing from $requirements_file..."
    if pip install -r "$requirements_file"; then
        log_success "✅ Installed from $requirements_file"
        return 0
    else
        log_error "❌ Failed to install from $requirements_file"
        return 1
    fi
}

# =============================================================================
# REQUIREMENTS GENERATION
# =============================================================================

# Handle requirements generation
handle_requirements_generation() {
    local mode="${FKS_MODE:-development}"
    
    log_info "📦 Generating requirements for $mode mode..."
    
    # Try to load requirements module
    if [[ -f "$SCRIPTS_RUN_DIR/python/requirements.sh" ]]; then
        source "$SCRIPTS_RUN_DIR/python/requirements.sh"
        generate_service_requirements
    else
        generate_basic_requirements "$mode"
    fi
}

# Generate basic requirements files
generate_basic_requirements() {
    local mode="$1"
    
    create_base_requirements
    
    case "$mode" in
        "development"|"dev")
            create_development_requirements
            ;;
        "server"|"production")
            create_production_requirements
            ;;
    esac
    
    # Create environment-specific files
    create_environment_files "$mode"
    
    log_success "✅ Requirements generated for $mode mode"
}

# Create base requirements.txt
create_base_requirements() {
    if [[ -f "requirements.txt" ]]; then
        log_info "requirements.txt already exists, skipping"
        return 0
    fi
    
    cat > requirements.txt << 'EOF'
# FKS Trading Systems - Core Requirements
# Generated automatically

# Core dependencies
pyyaml>=6.0
numpy>=1.21.0
pandas>=1.3.0
requests>=2.25.0

# Data processing
matplotlib>=3.3.0
seaborn>=0.11.0
scikit-learn>=1.0.0

# Utilities
python-dotenv>=0.19.0
click>=8.0.0
EOF
    
    log_info "✅ Created requirements.txt"
}

# Create development requirements
create_development_requirements() {
    if [[ -f "requirements-dev.txt" ]]; then
        log_info "requirements-dev.txt already exists, skipping"
        return 0
    fi
    
    cat > requirements-dev.txt << 'EOF'
# FKS Trading Systems - Development Requirements

# Testing
pytest>=6.0.0
pytest-cov>=2.12.0
pytest-mock>=3.6.0

# Code quality
black>=21.0.0
flake8>=3.9.0
isort>=5.9.0
pre-commit>=2.15.0

# Development tools
ipython>=7.25.0
jupyter>=1.0.0
notebook>=6.4.0

# Documentation
sphinx>=4.0.0
sphinx-rtd-theme>=0.5.0
EOF
    
    log_info "✅ Created requirements-dev.txt"
}

# Create production requirements
create_production_requirements() {
    if [[ -f "requirements-prod.txt" ]]; then
        log_info "requirements-prod.txt already exists, skipping"
        return 0
    fi
    
    cat > requirements-prod.txt << 'EOF'
# FKS Trading Systems - Production Requirements

# Web framework
fastapi>=0.68.0
uvicorn>=0.15.0
gunicorn>=20.1.0

# Database
sqlalchemy>=1.4.0
psycopg2-binary>=2.9.0
redis>=3.5.0

# Monitoring
prometheus-client>=0.11.0
sentry-sdk>=1.3.0

# Security
cryptography>=3.4.0
python-jose>=3.3.0
passlib>=1.7.0
EOF
    
    log_info "✅ Created requirements-prod.txt"
}

# Create environment-specific files
create_environment_files() {
    local mode="$1"
    
    case "$mode" in
        "development")
            create_conda_environment_file
            create_dev_dockerfile
            ;;
        "server"|"production")
            create_production_dockerfile
            create_docker_compose_file
            ;;
    esac
}

# Create conda environment.yml
create_conda_environment_file() {
    if [[ -f "environment.yml" ]]; then
        return 0
    fi
    
    cat > environment.yml << 'EOF'
name: fks
channels:
  - defaults
  - conda-forge
dependencies:
  - python=3.9
  - pip
  - numpy
  - pandas
  - pyyaml
  - matplotlib
  - seaborn
  - scikit-learn
  - pip:
    - -r requirements.txt
    - -r requirements-dev.txt
EOF
    
    log_info "✅ Created environment.yml"
}

# Create development Dockerfile
create_dev_dockerfile() {
    if [[ -f "Dockerfile.dev" ]]; then
        return 0
    fi
    
    cat > Dockerfile.dev << 'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy source code
COPY . .

# Set environment
ENV FKS_MODE=development
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["python", "-m", "scripts.run.main", "--dev"]
EOF
    
    log_info "✅ Created Dockerfile.dev"
}

# Create production Dockerfile
create_production_dockerfile() {
    if [[ -f "Dockerfile" ]]; then
        return 0
    fi
    
    cat > Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-prod.txt

# Copy source code
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' fks_user && \
    chown -R fks_user:fks_user /app
USER fks_user

# Set environment
ENV FKS_MODE=server
ENV PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "scripts.run.main", "--server"]
EOF
    
    log_info "✅ Created Dockerfile"
}

# Generate docker-compose.yml
generate_docker_compose_file() {
    if [[ -f "docker-compose.yml" ]]; then
        return 0
    fi
    
    cat > docker-compose.yml << 'EOF'



services:
  fks_app:
    build: .
    container_name: fks_app
    environment:
      - FKS_MODE=server
      - FKS_DEBUG=false
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
    ports:
      - "8000:8000"
    restart: unless-stopped
    depends_on:
      - fks_db
      - fks_redis

  fks_db:
    image: postgres:13-alpine
    container_name: fks_db
    environment:
      - POSTGRES_DB=fks
      - POSTGRES_USER=fks_user
      - POSTGRES_PASSWORD=fks_password
    volumes:
      - fks_db_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  fks_redis:
    image: redis:7-alpine
    container_name: fks_redis
    volumes:
      - fks_redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

volumes:
  fks_db_data:
  fks_redis_data:
EOF
    
    log_info "✅ Created docker-compose.yml"
}

# =============================================================================
# INSTALLATION HELP
# =============================================================================

# Show setup help
show_setup_help() {
    cat << EOF
${YELLOW}Available Setup Options:${NC}

${GREEN}Environment Types:${NC}
  • conda        - Anaconda/Miniconda environment
  • venv         - Python virtual environment
  • docker       - Docker containerized environment
  • auto         - Auto-detect best option

${GREEN}Usage:${NC}
  $0 --setup conda
  $0 --setup venv
  $0 --setup docker
  $0 --setup auto

EOF
}

# Show installation help for different tools
show_conda_installation_help() {
    cat << EOF
${YELLOW}Conda Installation:${NC}

${GREEN}Miniconda (Recommended):${NC}
  wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
  bash Miniconda3-latest-Linux-x86_64.sh

${GREEN}Or visit:${NC} https://docs.conda.io/en/latest/miniconda.html

EOF
}

show_python_installation_help() {
    cat << EOF
${YELLOW}Python Installation:${NC}

${GREEN}Ubuntu/Debian:${NC}
  sudo apt update && sudo apt install python3 python3-pip python3-venv

${GREEN}CentOS/RHEL:${NC}
  sudo yum install python3 python3-pip

${GREEN}macOS:${NC}
  brew install python3

EOF
}

show_docker_installation_help() {
    cat << EOF
${YELLOW}Docker Installation:${NC}

${GREEN}Ubuntu:${NC}
  https://docs.docker.com/engine/install/ubuntu/

${GREEN}CentOS:${NC}
  https://docs.docker.com/engine/install/centos/

${GREEN}macOS/Windows:${NC}
  https://docs.docker.com/desktop/

EOF
}

show_docker_daemon_help() {
    cat << EOF
${YELLOW}Start Docker Daemon:${NC}

${GREEN}Linux:${NC}
  sudo systemctl start docker
  sudo systemctl enable docker

${GREEN}macOS/Windows:${NC}
  Start Docker Desktop application

EOF
}

show_docker_compose_installation_help() {
    cat << EOF
${YELLOW}Docker Compose Installation:${NC}

${GREEN}Using pip:${NC}
  pip install docker-compose

${GREEN}Or download binary:${NC}
  https://docs.docker.com/compose/install/

EOF
}

# =============================================================================
# EXPORTS
# =============================================================================

# Export main functions
export -f handle_environment_setup handle_install_requirements
export -f handle_requirements_generation auto_detect_and_setup
export -f setup_conda_environment setup_virtual_environment
export -f setup_docker_environment

echo "📦 Setup utilities module loaded (v$SETUP_UTILS_VERSION)"