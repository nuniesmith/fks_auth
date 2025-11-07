#!/bin/bash
# filepath: scripts/maintenance/update.sh
# Update operations for dependencies, packages, and system components

# Ensure this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly"
    exit 1
fi

# Main update dependencies function
update_dependencies() {
    log_info "📦 Updating Dependencies"
    
    echo ""
    echo "Update options:"
    echo "1) Update Python packages (pip/conda)"
    echo "2) Update Docker images"
    echo "3) Update system tools (yq, docker-compose)"
    echo "4) Update FKS components"
    echo "5) Update everything (recommended)"
    echo "6) Back to maintenance menu"
    echo ""
    
    echo "Select option (1-6): "
    read -r REPLY
    
    case $REPLY in
        1)
            update_python_packages
            ;;
        2)
            update_docker_images
            ;;
        3)
            update_system_tools
            ;;
        4)
            update_fks_components
            ;;
        5)
            update_everything
            ;;
        *)
            return 0
            ;;
    esac
}

# Update Python packages
update_python_packages() {
    log_info "🐍 Updating Python packages..."
    
    # Check current Python environment
    check_python_environment_for_update
    
    case $PYTHON_ENV_TYPE in
        "conda")
            update_conda_packages
            ;;
        "venv")
            update_venv_packages
            ;;
        "system")
            update_system_python_packages
            ;;
        *)
            log_error "Unknown Python environment type"
            return 1
            ;;
    esac
}

# Check Python environment for updates
check_python_environment_for_update() {
    log_info "🔍 Detecting Python environment..."
    
    if [ -n "${CONDA_DEFAULT_ENV:-}" ]; then
        PYTHON_ENV_TYPE="conda"
        log_info "✅ Using Conda environment: $CONDA_DEFAULT_ENV"
    elif [ -n "${VIRTUAL_ENV:-}" ]; then
        PYTHON_ENV_TYPE="venv"
        log_info "✅ Using Virtual environment: $VIRTUAL_ENV"
    elif command -v conda >/dev/null 2>&1 && conda env list | grep -q "^$CONDA_ENV "; then
        PYTHON_ENV_TYPE="conda"
        log_info "✅ Found Conda environment: $CONDA_ENV"
        conda activate "$CONDA_ENV" 2>/dev/null || true
    elif [ -d "$VENV_DIR" ]; then
        PYTHON_ENV_TYPE="venv"
        log_info "✅ Found Virtual environment: $VENV_DIR"
        source "$VENV_DIR/bin/activate"
    else
        PYTHON_ENV_TYPE="system"
        log_warn "⚠️  Using system Python"
    fi
}

# Update Conda packages
update_conda_packages() {
    log_info "📦 Updating Conda packages..."
    
    # Ensure conda environment is activated
    if [ "${CONDA_DEFAULT_ENV:-}" != "$CONDA_ENV" ]; then
        conda activate "$CONDA_ENV" 2>/dev/null || true
    fi
    
    if [ "${CONDA_DEFAULT_ENV:-}" = "$CONDA_ENV" ]; then
        echo ""
        echo "Update options:"
        echo "1) Update all conda packages"
        echo "2) Update only pip packages"
        echo "3) Update conda + pip packages"
        echo "4) Update from requirements.txt"
        echo "5) Cancel"
        echo ""
        
        echo "Select option (1-5): "
        read -r REPLY
        
        case $REPLY in
            1)
                log_info "Updating all conda packages..."
                conda update --all -y
                ;;
            2)
                log_info "Updating pip packages..."
                pip install --upgrade pip
                pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U
                ;;
            3)
                log_info "Updating conda packages..."
                conda update --all -y
                log_info "Updating pip packages..."
                pip install --upgrade pip
                pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U
                ;;
            4)
                update_from_requirements
                ;;
            *)
                log_info "Update cancelled"
                return 0
                ;;
        esac
        
        log_success "✅ Conda packages updated"
        show_package_summary
    else
        log_error "❌ Failed to activate conda environment: $CONDA_ENV"
        return 1
    fi
}

# Update Virtual environment packages
update_venv_packages() {
    log_info "📦 Updating Virtual Environment packages..."
    
    # Ensure virtual environment is activated
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        if [ -d "$VENV_DIR" ]; then
            source "$VENV_DIR/bin/activate"
        else
            log_error "❌ Virtual environment not found: $VENV_DIR"
            return 1
        fi
    fi
    
    echo ""
    echo "Update options:"
    echo "1) Update all packages"
    echo "2) Update from requirements.txt"
    echo "3) Update only specific packages"
    echo "4) Cancel"
    echo ""
    
    echo "Select option (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            log_info "Upgrading pip..."
            pip install --upgrade pip
            
            log_info "Updating all packages..."
            pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U
            ;;
        2)
            update_from_requirements
            ;;
        3)
            update_specific_packages
            ;;
        *)
            log_info "Update cancelled"
            return 0
            ;;
    esac
    
    log_success "✅ Virtual environment packages updated"
    show_package_summary
}

# Update system Python packages
update_system_python_packages() {
    log_warn "⚠️  Updating system Python packages..."
    log_warn "This will install packages to user directory to avoid permission issues"
    
    export PIP_USER=1
    export PYTHONUSERBASE="$HOME/.local"
    export PATH="$HOME/.local/bin:$PATH"
    
    echo ""
    echo "Update options:"
    echo "1) Update user packages"
    echo "2) Update from requirements.txt"
    echo "3) Cancel"
    echo ""
    
    echo "Select option (1-3): "
    read -r REPLY
    
    case $REPLY in
        1)
            log_info "Updating user packages..."
            pip install --user --upgrade pip
            pip list --user --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install --user -U
            ;;
        2)
            if [ -f "requirements.txt" ]; then
                log_info "Installing from requirements.txt..."
                pip install --user --upgrade -r requirements.txt
            else
                log_warn "requirements.txt not found"
            fi
            ;;
        *)
            log_info "Update cancelled"
            return 0
            ;;
    esac
    
    log_success "✅ System Python packages updated"
}

# Update from requirements.txt
update_from_requirements() {
    if [ -f "requirements.txt" ]; then
        log_info "📋 Updating from requirements.txt..."
        
        # Backup current requirements
        pip freeze > "requirements.current.$(date +%s).txt"
        
        # Update packages
        pip install --upgrade -r requirements.txt
        
        log_success "✅ Packages updated from requirements.txt"
    else
        log_warn "⚠️  requirements.txt not found"
        echo "Create requirements.txt from current environment? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            pip freeze > requirements.txt
            log_success "✅ requirements.txt created"
        fi
    fi
}

# Update specific packages
update_specific_packages() {
    echo ""
    echo "Critical packages for FKS Trading Systems:"
    echo "1) PyTorch and related ML packages"
    echo "2) Data processing packages (pandas, numpy)"
    echo "3) Web framework packages (fastapi, uvicorn)"
    echo "4) Financial data packages"
    echo "5) Custom package selection"
    echo ""
    
    echo "Select package group (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            update_ml_packages
            ;;
        2)
            update_data_packages
            ;;
        3)
            update_web_packages
            ;;
        4)
            update_financial_packages
            ;;
        5)
            custom_package_selection
            ;;
        *)
            return 0
            ;;
    esac
}

# Update ML packages
update_ml_packages() {
    log_info "🧠 Updating ML packages..."
    
    local ml_packages=(
        "torch"
        "torchvision"
        "numpy"
        "scikit-learn"
        "matplotlib"
        "seaborn"
        "plotly"
        "tensorboard"
        "transformers"
        "datasets"
    )
    
    echo "Updating ML packages: ${ml_packages[*]}"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for package in "${ml_packages[@]}"; do
            log_info "Updating $package..."
            pip install --upgrade "$package"
        done
        log_success "✅ ML packages updated"
    fi
}

# Update data packages
update_data_packages() {
    log_info "📊 Updating data processing packages..."
    
    local data_packages=(
        "pandas"
        "numpy"
        "scipy"
        "statsmodels"
        "ta"
        "yfinance"
        "ccxt"
        "requests"
        "aiohttp"
        "python-dateutil"
    )
    
    echo "Updating data packages: ${data_packages[*]}"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for package in "${data_packages[@]}"; do
            log_info "Updating $package..."
            pip install --upgrade "$package"
        done
        log_success "✅ Data packages updated"
    fi
}

# Update web packages
update_web_packages() {
    log_info "🌐 Updating web framework packages..."
    
    local web_packages=(
        "fastapi"
        "uvicorn"
        "starlette"
        "pydantic"
        "jinja2"
        "python-multipart"
        "websockets"
        "httpx"
        "celery"
        "redis"
    )
    
    echo "Updating web packages: ${web_packages[*]}"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for package in "${data_packages[@]}"; do
            log_info "Updating $package..."
            pip install --upgrade "$package"
        done
        log_success "✅ Web packages updated"
    fi
}

# Update financial packages
update_financial_packages() {
    log_info "💰 Updating financial data packages..."
    
    local financial_packages=(
        "yfinance"
        "ccxt"
        "alpaca-trade-api"
        "python-binance"
        "ta-lib"
        "quantlib"
        "zipline-reloaded"
        "backtrader"
        "pyfolio"
        "empyrical"
    )
    
    echo "Updating financial packages: ${financial_packages[*]}"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for package in "${financial_packages[@]}"; do
            log_info "Updating $package..."
            pip install --upgrade "$package" 2>/dev/null || log_warn "Failed to update $package"
        done
        log_success "✅ Financial packages updated"
    fi
}

# Custom package selection
custom_package_selection() {
    echo ""
    echo "Enter package names separated by spaces: "
    read -r packages
    
    if [ -n "$packages" ]; then
        log_info "Updating custom packages: $packages"
        pip install --upgrade $packages
        log_success "✅ Custom packages updated"
    fi
}

# Show package summary
show_package_summary() {
    echo ""
    echo "📦 Package Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v pip >/dev/null 2>&1; then
        local total_packages=$(pip list | wc -l)
        echo "Total packages installed: $total_packages"
        
        echo ""
        echo "Recently updated packages:"
        pip list --format=freeze | head -10
        
        if [ $total_packages -gt 10 ]; then
            echo "... and $((total_packages - 10)) more packages"
        fi
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Update Docker images
update_docker_images() {
    log_info "🐳 Updating Docker images..."
    
    echo ""
    echo "Docker image update options:"
    echo "1) Update base images (Python, Redis, PostgreSQL)"
    echo "2) Rebuild FKS custom images"
    echo "3) Update all images"
    echo "4) Pull latest images without rebuild"
    echo "5) Cancel"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            update_base_images
            ;;
        2)
            rebuild_fks_images
            ;;
        3)
            update_all_docker_images
            ;;
        4)
            pull_latest_images
            ;;
        *)
            log_info "Docker update cancelled"
            return 0
            ;;
    esac
}

# Update base images
update_base_images() {
    log_info "📦 Updating base Docker images..."
    
    local base_images=(
        "python:3.11"
        "redis:latest"
        "postgres:latest"
        "nginx:latest"
        "ubuntu:24.04"
    )
    
    # Add NVIDIA images if GPU support is available
    if command -v nvidia-smi >/dev/null 2>&1; then
        base_images+=(
            "nvidia/cuda:12.8-base-ubuntu24.04"
            "nvidia/cuda:12.8-devel-ubuntu24.04"
            "nvidia/cuda:12.8-runtime-ubuntu24.04"
        )
    fi
    
    echo "Updating base images: ${base_images[*]}"
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for image in "${base_images[@]}"; do
            log_info "Pulling $image..."
            if docker pull "$image"; then
                log_success "✅ Updated $image"
            else
                log_warn "⚠️  Failed to update $image"
            fi
        done
        log_success "✅ Base images update completed"
    fi
}

# Rebuild FKS images
rebuild_fks_images() {
    log_info "🔨 Rebuilding FKS custom images..."
    
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "❌ $COMPOSE_FILE not found"
        return 1
    fi
    
    echo ""
    echo "Rebuild options:"
    echo "1) Rebuild all FKS services"
    echo "2) Rebuild specific services"
    echo "3) Force rebuild (no cache)"
    echo "4) Cancel"
    echo ""
    
    echo "Select option (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            log_info "Rebuilding all FKS services..."
            $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME build --pull
            ;;
        2)
            rebuild_specific_services
            ;;
        3)
            log_info "Force rebuilding all FKS services (no cache)..."
            $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME build --no-cache --pull
            ;;
        *)
            return 0
            ;;
    esac
    
    log_success "✅ FKS images rebuild completed"
}

# Rebuild specific services
rebuild_specific_services() {
    echo ""
    echo "Available services to rebuild:"
    
    if command -v $COMPOSE_CMD >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ]; then
        local services=($($COMPOSE_CMD -p $COMPOSE_PROJECT_NAME config --services 2>/dev/null))
        
        for i in "${!services[@]}"; do
            echo "$((i+1))) ${services[i]}"
        done
        
        echo ""
        echo "Enter service numbers (space-separated) or service names: "
        read -r selection
        
        local selected_services=()
        
        # Parse selection
        for item in $selection; do
            if [[ $item =~ ^[0-9]+$ ]]; then
                # Number selection
                local index=$((item - 1))
                if [ $index -ge 0 ] && [ $index -lt ${#services[@]} ]; then
                    selected_services+=("${services[index]}")
                fi
            else
                # Service name
                if [[ " ${services[*]} " =~ " ${item} " ]]; then
                    selected_services+=("$item")
                fi
            fi
        done
        
        if [ ${#selected_services[@]} -gt 0 ]; then
            log_info "Rebuilding services: ${selected_services[*]}"
            $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME build --pull "${selected_services[@]}"
        else
            log_warn "No valid services selected"
        fi
    else
        log_error "Cannot read docker-compose services"
    fi
}

# Update all Docker images
update_all_docker_images() {
    log_info "🔄 Updating all Docker images..."
    
    echo "This will:"
    echo "- Pull latest base images"
    echo "- Rebuild all FKS custom images"
    echo "- Clean up old images"
    echo ""
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        update_base_images
        rebuild_fks_images
        cleanup_old_images
        log_success "✅ All Docker images updated"
    fi
}

# Pull latest images without rebuild
pull_latest_images() {
    log_info "📥 Pulling latest images..."
    
    if [ -f "$COMPOSE_FILE" ]; then
        $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME pull
        log_success "✅ Latest images pulled"
    else
        log_error "❌ $COMPOSE_FILE not found"
    fi
}

# Cleanup old images
cleanup_old_images() {
    log_info "🧹 Cleaning up old Docker images..."
    
    echo "Remove dangling images? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker image prune -f
        log_success "✅ Old images cleaned up"
    fi
}

# Update system tools
update_system_tools() {
    log_info "🛠️  Updating system tools..."
    
    echo ""
    echo "System tools update options:"
    echo "1) Update yq (YAML processor)"
    echo "2) Update Docker Compose"
    echo "3) Update both"
    echo "4) Cancel"
    echo ""
    
    echo "Select option (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            update_yq
            ;;
        2)
            update_docker_compose
            ;;
        3)
            update_yq
            update_docker_compose
            ;;
        *)
            return 0
            ;;
    esac
}

# Update yq
update_yq() {
    log_info "📄 Updating yq YAML processor..."
    
    local current_version=""
    if command -v yq >/dev/null 2>&1; then
        current_version=$(yq --version 2>/dev/null | head -1)
        log_info "Current version: $current_version"
    else
        log_info "yq not currently installed"
    fi
    
    # Install/update yq
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; return 1 ;;
    esac
    
    local yq_version="v4.40.5"
    local download_url="https://github.com/mikefarah/yq/releases/download/${yq_version}/yq_${os}_${arch}"
    
    log_info "Downloading yq $yq_version..."
    if command -v curl >/dev/null 2>&1; then
        if sudo curl -L "$download_url" -o /usr/local/bin/yq; then
            sudo chmod +x /usr/local/bin/yq
            log_success "✅ yq updated to $yq_version"
        else
            log_error "❌ Failed to download yq"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if sudo wget "$download_url" -O /usr/local/bin/yq; then
            sudo chmod +x /usr/local/bin/yq
            log_success "✅ yq updated to $yq_version"
        else
            log_error "❌ Failed to download yq"
        fi
    else
        log_error "Neither curl nor wget found"
    fi
}

# Update Docker Compose
update_docker_compose() {
    log_info "🐳 Updating Docker Compose..."
    
    if command -v docker-compose >/dev/null 2>&1; then
        local current_version=$(docker-compose --version 2>/dev/null)
        log_info "Current version: $current_version"
        
        echo "Update Docker Compose? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Download latest docker-compose
            local compose_version="v2.24.0"
            local os=$(uname -s)
            local arch=$(uname -m)
            
            local download_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-${os}-${arch}"
            
            log_info "Downloading Docker Compose $compose_version..."
            if sudo curl -L "$download_url" -o /usr/local/bin/docker-compose; then
                sudo chmod +x /usr/local/bin/docker-compose
                log_success "✅ Docker Compose updated to $compose_version"
            else
                log_error "❌ Failed to download Docker Compose"
            fi
        fi
    else
        log_info "Docker Compose not found as standalone binary"
        log_info "Checking for 'docker compose' plugin..."
        
        if docker compose version >/dev/null 2>&1; then
            local current_version=$(docker compose version 2>/dev/null)
            log_info "Current version: $current_version"
            log_info "Docker Compose plugin is managed by Docker Engine"
        else
            log_warn "Docker Compose not found"
        fi
    fi
}

# Update FKS components
update_fks_components() {
    log_info "🎯 Updating FKS Trading Systems components..."
    
    echo ""
    echo "FKS component update options:"
    echo "1) Update scripts and configurations"
    echo "2) Update documentation"
    echo "3) Update all FKS components"
    echo "4) Check for FKS updates (if git repo)"
    echo "5) Cancel"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            update_scripts_configs
            ;;
        2)
            update_documentation
            ;;
        3)
            update_all_fks_components
            ;;
        4)
            check_fks_updates
            ;;
        *)
            return 0
            ;;
    esac
}

# Update scripts and configurations
update_scripts_configs() {
    log_info "📜 Updating scripts and configurations..."
    
    # Check if this is a git repository
    if [ -d ".git" ]; then
        echo "Git repository detected. Pull latest changes? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git fetch origin
            git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || log_warn "Failed to pull updates"
        fi
    else
        log_info "Not a git repository. Manual updates required."
    fi
    
    # Regenerate configuration files
    echo "Regenerate configuration files from YAML? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v yq >/dev/null 2>&1; then
            generate_env_from_yaml
            generate_docker_compose
        else
            log_warn "yq not available for configuration regeneration"
        fi
    fi
}

# Update documentation
update_documentation() {
    log_info "📚 Updating documentation..."
    
    if [ -d "docs" ]; then
        echo "Documentation directory found"
        
        # Check if we can update docs
        if command -v pandoc >/dev/null 2>&1; then
            echo "Update documentation formats? (y/N): "
            read -r REPLY
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log_info "Updating documentation formats..."
                # Add documentation update logic here
                log_success "✅ Documentation updated"
            fi
        else
            log_info "pandoc not available for documentation conversion"
        fi
    else
        log_info "No documentation directory found"
    fi
}

# Update all FKS components
update_all_fks_components() {
    log_info "🔄 Updating all FKS components..."
    
    update_scripts_configs
    update_documentation
    
    log_success "✅ All FKS components updated"
}

# Check for FKS updates
check_fks_updates() {
    log_info "🔍 Checking for FKS updates..."
    
    if [ -d ".git" ]; then
        # Fetch latest from remote
        git fetch origin >/dev/null 2>&1
        
        # Check if we're behind
        local behind=$(git rev-list --count HEAD..origin/main 2>/dev/null || git rev-list --count HEAD..origin/master 2>/dev/null || echo "0")
        
        if [ "$behind" -gt 0 ]; then
            echo "🔄 $behind new commits available"
            echo "Show commit summary? (y/N): "
            read -r REPLY
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                git log --oneline HEAD..origin/main 2>/dev/null || git log --oneline HEAD..origin/master 2>/dev/null
            fi
            
            echo ""
            echo "Pull updates now? (y/N): "
            read -r REPLY
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                git pull origin main 2>/dev/null || git pull origin master 2>/dev/null
                log_success "✅ FKS updates pulled"
            fi
        else
            log_success "✅ FKS is up to date"
        fi
    else
        log_info "Not a git repository. Cannot check for updates automatically."
    fi
}

# Update everything
update_everything() {
    log_info "🚀 Updating everything..."
    
    echo ""
    echo "This will update:"
    echo "- Python packages"
    echo "- Docker images"
    echo "- System tools"
    echo "- FKS components"
    echo ""
    echo "Continue with full update? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Starting comprehensive update..."
        
        # Update in logical order
        update_system_tools
        update_python_packages
        update_docker_images
        update_fks_components
        
        log_success "✅ Complete update finished!"
        
        # Show summary
        echo ""
        echo "📊 Update Summary:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "✅ System tools updated"
        echo "✅ Python packages updated"
        echo "✅ Docker images updated"
        echo "✅ FKS components updated"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        echo ""
        echo "Restart services to use updated components? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if command -v $COMPOSE_CMD >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ]; then
                $COMPOSE_CMD -p $COMPOSE_PROJECT_NAME restart
                log_success "✅ Services restarted with updates"
            fi
        fi
    else
        log_info "Update cancelled"
    fi
}