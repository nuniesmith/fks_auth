#!/bin/bash
# filepath: scripts/utils/install.sh
# Installation helpers and system setup

# Ensure this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly"
    exit 1
fi

# Show installation help
show_installation_help() {
    echo ""
    log_info "📚 Installation Help"
    echo "======================================"
    echo ""
    echo "FKS Trading Systems Requirements:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "🐳 Docker Installation:"
    detect_os_and_show_docker_install
    echo ""
    echo "🐍 Python Environment Setup:"
    show_python_setup_help
    echo ""
    echo "📄 Additional Tools:"
    show_additional_tools_help
    echo ""
    echo "🎯 FKS Specific Setup:"
    show_fks_setup_help
    echo ""
    echo "For more detailed documentation, visit:"
    echo "https://docs.docker.com/get-docker/"
    echo "https://conda.io/projects/conda/en/latest/user-guide/install/"
}

# Detect OS and show appropriate Docker installation
detect_os_and_show_docker_install() {
    local os_name=""
    local install_cmd=""
    
    if [ -f /etc/os-release ]; then
        os_name=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    elif command -v lsb_release >/dev/null 2>&1; then
        os_name=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/redhat-release ]; then
        os_name="rhel"
    elif [ "$(uname)" = "Darwin" ]; then
        os_name="macos"
    else
        os_name="unknown"
    fi
    
    case $os_name in
        "ubuntu"|"debian")
            echo "  Ubuntu/Debian:"
            echo "    sudo apt update"
            echo "    sudo apt install -y docker.io docker-compose"
            echo "    sudo systemctl start docker"
            echo "    sudo systemctl enable docker"
            echo "    sudo usermod -aG docker \$USER"
            echo "    # Log out and back in for group changes"
            ;;
        "centos"|"rhel"|"fedora")
            echo "  CentOS/RHEL/Fedora:"
            echo "    sudo yum install -y docker docker-compose"
            echo "    # or for newer versions:"
            echo "    sudo dnf install -y docker docker-compose"
            echo "    sudo systemctl start docker"
            echo "    sudo systemctl enable docker"
            echo "    sudo usermod -aG docker \$USER"
            ;;
        "arch"|"manjaro")
            echo "  Arch Linux:"
            echo "    sudo pacman -S docker docker-compose"
            echo "    sudo systemctl start docker"
            echo "    sudo systemctl enable docker"
            echo "    sudo usermod -aG docker \$USER"
            ;;
        "macos")
            echo "  macOS:"
            echo "    # Install Docker Desktop:"
            echo "    https://docs.docker.com/desktop/mac/install/"
            echo "    # Or with Homebrew:"
            echo "    brew install --cask docker"
            echo "    brew install docker-compose"
            ;;
        *)
            echo "  Generic Linux:"
            echo "    # Install Docker using convenience script:"
            echo "    curl -fsSL https://get.docker.com -o get-docker.sh"
            echo "    sudo sh get-docker.sh"
            echo "    sudo usermod -aG docker \$USER"
            ;;
    esac
    
    echo ""
    echo "  Verify installation:"
    echo "    docker --version"
    echo "    docker-compose --version"
    echo "    docker run hello-world"
}

# Show Python environment setup help
show_python_setup_help() {
    echo "🐍 Python Environment Options:"
    echo ""
    echo "  Option 1 - Conda (Recommended for ML):"
    echo "    # Install Miniconda:"
    echo "    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
    echo "    bash Miniconda3-latest-Linux-x86_64.sh"
    echo "    # Create FKS environment:"
    echo "    conda create -n fks_env python=3.11 -y"
    echo "    conda activate fks_env"
    echo ""
    echo "  Option 2 - Virtual Environment:"
    echo "    # Install Python 3.11:"
    echo "    sudo apt install python3.11 python3.11-venv python3-pip"
    echo "    # Create virtual environment:"
    echo "    python3.11 -m venv ~/.venv/fks_env"
    echo "    source ~/.venv/fks_env/bin/activate"
    echo ""
    echo "  Option 3 - System Python (Not Recommended):"
    echo "    # Install system packages:"
    echo "    sudo apt install python3 python3-pip"
    echo "    # Packages will install to user directory"
}

# Show additional tools help
show_additional_tools_help() {
    echo "📄 Additional Required Tools:"
    echo ""
    echo "  yq (YAML processor):"
    echo "    # Method 1 - Direct download (recommended):"
    echo "    sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64"
    echo "    sudo chmod +x /usr/local/bin/yq"
    echo ""
    echo "    # Method 2 - Package manager:"
    echo "    sudo apt install yq  # Ubuntu 22.04+"
    echo "    brew install yq      # macOS"
    echo ""
    echo "  Git (if not installed):"
    echo "    sudo apt install git"
    echo "    git config --global user.name \"Your Name\""
    echo "    git config --global user.email \"your.email@example.com\""
    echo ""
    echo "  curl/wget (usually pre-installed):"
    echo "    sudo apt install curl wget"
}

# Show FKS specific setup help
show_fks_setup_help() {
    echo "🎯 FKS Trading Systems Setup:"
    echo ""
    echo "  1. Clone or download FKS repository"
    echo "  2. Navigate to project directory"
    echo "  3. Run the setup script:"
    echo "     ./run.sh --help"
    echo ""
    echo "  4. For first-time setup:"
    echo "     ./run.sh --regenerate-all"
    echo ""
    echo "  5. Required data files:"
    echo "     - Place your trading data in ./data/"
    echo "     - Ensure data format matches expected schema"
    echo ""
    echo "  6. Configuration:"
    echo "     - Modify docker_config.yaml for Docker settings"
    echo "     - Modify app_config.yaml for model parameters"
    echo "     - Service configs in ./config/services/"
}

# Interactive installation wizard
installation_wizard() {
    log_info "🧙 FKS Installation Wizard"
    echo "============================================"
    echo ""
    echo "This wizard will help you install and configure"
    echo "the FKS Trading Systems requirements."
    echo ""
    
    # Check current system
    check_system_status
    
    echo ""
    echo "Installation options:"
    echo "1) 🚀 Quick setup (auto-detect and install)"
    echo "2) 🛠️  Custom setup (choose components)"
    echo "3) 🔍 System check only"
    echo "4) 📚 Show installation help"
    echo "5) ❌ Exit"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            quick_setup
            ;;
        2)
            custom_setup
            ;;
        3)
            detailed_system_check
            ;;
        4)
            show_installation_help
            ;;
        *)
            log_info "Installation wizard cancelled"
            return 0
            ;;
    esac
}

# Check current system status
check_system_status() {
    log_info "🔍 Checking current system status..."
    echo ""
    
    # Operating System
    local os_info=""
    if [ -f /etc/os-release ]; then
        os_info=$(grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '"')
    else
        os_info=$(uname -s -r)
    fi
    echo "Operating System: $os_info"
    
    # Architecture
    echo "Architecture: $(uname -m)"
    
    # Available memory
    if command -v free >/dev/null 2>&1; then
        local memory=$(free -h | awk '/^Mem:/ {print $2}')
        echo "Memory: $memory"
    fi
    
    # Available disk space
    local disk_space=$(df -h . | awk 'NR==2 {print $4}')
    echo "Available disk space: $disk_space"
    
    echo ""
    echo "Component Status:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check components
    check_component_status "Docker" "docker --version"
    check_component_status "Docker Compose" "docker-compose --version || docker compose version"
    check_component_status "Python 3" "python3 --version"
    check_component_status "pip" "pip --version || pip3 --version"
    check_component_status "Git" "git --version"
    check_component_status "yq" "yq --version"
    check_component_status "curl" "curl --version"
    check_component_status "Conda" "conda --version"
    
    # GPU check
    if command -v nvidia-smi >/dev/null 2>&1; then
        check_component_status "NVIDIA GPU" "nvidia-smi --version"
    else
        echo "❌ NVIDIA GPU: Not available"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check individual component status
check_component_status() {
    local component_name="$1"
    local check_command="$2"
    
    if eval "$check_command" >/dev/null 2>&1; then
        local version=$(eval "$check_command" 2>/dev/null | head -1)
        echo "✅ $component_name: $version"
    else
        echo "❌ $component_name: Not installed"
    fi
}

# Quick setup
quick_setup() {
    log_info "🚀 Quick Setup Mode"
    echo "============================================"
    echo ""
    echo "This will automatically detect your system and install"
    echo "the required components for FKS Trading Systems."
    echo ""
    echo "⚠️  This may require sudo privileges for system packages."
    echo ""
    echo "Continue with quick setup? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        perform_quick_setup
    else
        log_info "Quick setup cancelled"
    fi
}

# Perform quick setup
perform_quick_setup() {
    log_info "🔧 Performing quick setup..."
    
    # Update package lists
    update_package_lists
    
    # Install Docker if missing
    if ! command -v docker >/dev/null 2>&1; then
        install_docker_auto
    fi
    
    # Install Docker Compose if missing
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        install_docker_compose_auto
    fi
    
    # Install Python if missing
    if ! command -v python3 >/dev/null 2>&1; then
        install_python_auto
    fi
    
    # Install yq if missing
    if ! command -v yq >/dev/null 2>&1; then
        install_yq_auto
    fi
    
    # Install Git if missing
    if ! command -v git >/dev/null 2>&1; then
        install_git_auto
    fi
    
    # Setup Python environment
    setup_python_env_auto
    
    log_success "✅ Quick setup completed!"
    
    # Final verification
    echo ""
    log_info "🔍 Verifying installation..."
    check_system_status
    
    echo ""
    echo "Next steps:"
    echo "1. Run './run.sh --regenerate-all' to generate configurations"
    echo "2. Place your data files in ./data/"
    echo "3. Run './run.sh' to start the system"
}

# Custom setup
custom_setup() {
    log_info "🛠️  Custom Setup Mode"
    echo "============================================"
    echo ""
    
    while true; do
        echo "Available installation options:"
        echo "1) 🐳 Install Docker"
        echo "2) 🐍 Setup Python environment"
        echo "3) 📄 Install system tools (yq, git, etc.)"
        echo "4) 🎯 Setup FKS configuration"
        echo "5) 🔍 System verification"
        echo "6) ✅ Finish custom setup"
        echo ""
        
        echo "Select option (1-6): "
        read -r REPLY
        
        case $REPLY in
            1)
                install_docker_interactive
                ;;
            2)
                setup_python_interactive
                ;;
            3)
                install_tools_interactive
                ;;
            4)
                setup_fks_config_interactive
                ;;
            5)
                detailed_system_check
                ;;
            *)
                log_success "✅ Custom setup completed!"
                return 0
                ;;
        esac
        
        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}

# Update package lists
update_package_lists() {
    log_info "📦 Updating package lists..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt update -qq
    elif command -v yum >/dev/null 2>&1; then
        sudo yum update -y -q
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf update -y -q
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm
    fi
}

# Install Docker automatically
install_docker_auto() {
    log_info "🐳 Installing Docker..."
    
    if command -v apt >/dev/null 2>&1; then
        # Ubuntu/Debian
        sudo apt install -y docker.io
        sudo systemctl start docker
        sudo systemctl enable docker
        sudo usermod -aG docker "$USER"
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        sudo yum install -y docker
        sudo systemctl start docker
        sudo systemctl enable docker
        sudo usermod -aG docker "$USER"
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora
        sudo dnf install -y docker
        sudo systemctl start docker
        sudo systemctl enable docker
        sudo usermod -aG docker "$USER"
    else
        # Generic installation
        log_info "Using Docker convenience script..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker "$USER"
        rm get-docker.sh
    fi
    
    log_success "✅ Docker installed"
    log_warn "⚠️  You may need to log out and back in for Docker group changes to take effect"
}

# Install Docker Compose automatically
install_docker_compose_auto() {
    log_info "🐳 Installing Docker Compose..."
    
    local compose_version="v2.24.0"
    local os=$(uname -s)
    local arch=$(uname -m)
    
    # Download and install
    sudo curl -L "https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-${os}-${arch}" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    
    # Verify installation
    if docker-compose --version >/dev/null 2>&1; then
        log_success "✅ Docker Compose installed"
    else
        log_error "❌ Docker Compose installation failed"
    fi
}

# Install Python automatically
install_python_auto() {
    log_info "🐍 Installing Python..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt install -y python3 python3-pip python3-venv
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3 python3-pip
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm python python-pip
    fi
    
    log_success "✅ Python installed"
}

# Install yq automatically
install_yq_auto() {
    log_info "📄 Installing yq..."
    
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; return 1 ;;
    esac
    
    local yq_version="v4.40.5"
    local download_url="https://github.com/mikefarah/yq/releases/download/${yq_version}/yq_${os}_${arch}"
    
    sudo curl -L "$download_url" -o /usr/local/bin/yq
    sudo chmod +x /usr/local/bin/yq
    
    log_success "✅ yq installed"
}

# Install Git automatically
install_git_auto() {
    log_info "📂 Installing Git..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt install -y git
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y git
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y git
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm git
    fi
    
    log_success "✅ Git installed"
}

# Setup Python environment automatically
setup_python_env_auto() {
    log_info "🐍 Setting up Python environment..."
    
    # Try to detect and setup conda first
    if command -v conda >/dev/null 2>&1; then
        setup_conda_env_auto
    else
        setup_venv_auto
    fi
}

# Setup conda environment automatically
setup_conda_env_auto() {
    log_info "🐍 Setting up Conda environment..."
    
    # Create environment if it doesn't exist
    if ! conda env list | grep -q "^$CONDA_ENV "; then
        conda create -n "$CONDA_ENV" python=3.11 -y
    fi
    
    # Activate and install basic packages
    conda activate "$CONDA_ENV"
    conda install -y numpy pandas scikit-learn
    pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
    
    log_success "✅ Conda environment setup completed"
}

# Setup virtual environment automatically
setup_venv_auto() {
    log_info "🐍 Setting up Virtual environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
    fi
    
    # Activate and install basic packages
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install numpy pandas scikit-learn torch torchvision
    
    log_success "✅ Virtual environment setup completed"
}

# Interactive Docker installation
install_docker_interactive() {
    log_info "🐳 Docker Installation"
    echo "======================================"
    
    if command -v docker >/dev/null 2>&1; then
        echo "✅ Docker is already installed: $(docker --version)"
        return 0
    fi
    
    echo ""
    echo "Docker installation methods:"
    echo "1) Package manager (recommended)"
    echo "2) Convenience script"
    echo "3) Manual installation guide"
    echo "4) Skip Docker installation"
    echo ""
    
    echo "Select method (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            install_docker_auto
            ;;
        2)
            install_docker_convenience_script
            ;;
        3)
            show_docker_manual_guide
            ;;
        *)
            log_info "Docker installation skipped"
            ;;
    esac
}

# Install Docker using convenience script
install_docker_convenience_script() {
    log_info "🐳 Installing Docker using convenience script..."
    
    echo "This will download and run the Docker installation script."
    echo "Continue? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker "$USER"
        rm get-docker.sh
        log_success "✅ Docker installed via convenience script"
    fi
}

# Show Docker manual installation guide
show_docker_manual_guide() {
    echo ""
    echo "📚 Manual Docker Installation Guide:"
    echo "======================================"
    detect_os_and_show_docker_install
}

# Interactive Python setup
setup_python_interactive() {
    log_info "🐍 Python Environment Setup"
    echo "======================================"
    
    echo ""
    echo "Python environment options:"
    echo "1) 🐍 Setup Conda environment (recommended for ML)"
    echo "2) 🐍 Setup Virtual environment"
    echo "3) 🐍 Use system Python"
    echo "4) 📚 Show Python installation guide"
    echo "5) Skip Python setup"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            setup_conda_interactive
            ;;
        2)
            setup_venv_interactive
            ;;
        3)
            setup_system_python_interactive
            ;;
        4)
            show_python_setup_help
            ;;
        *)
            log_info "Python setup skipped"
            ;;
    esac
}

# Interactive conda setup
setup_conda_interactive() {
    if ! command -v conda >/dev/null 2>&1; then
        echo "Conda not found. Install Miniconda first:"
        echo "https://docs.conda.io/en/latest/miniconda.html"
        return 1
    fi
    
    echo "Environment name [$CONDA_ENV]: "
    read -r env_name
    env_name=${env_name:-$CONDA_ENV}
    
    echo "Python version [3.11]: "
    read -r python_version
    python_version=${python_version:-3.11}
    
    if conda env list | grep -q "^$env_name "; then
        echo "Environment '$env_name' already exists. Recreate? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            conda env remove -n "$env_name" -y
        else
            return 0
        fi
    fi
    
    conda create -n "$env_name" python="$python_version" -y
    conda activate "$env_name"
    
    log_success "✅ Conda environment '$env_name' created"
}

# Interactive virtual environment setup
setup_venv_interactive() {
    echo "Virtual environment directory [$VENV_DIR]: "
    read -r venv_dir
    venv_dir=${venv_dir:-$VENV_DIR}
    
    if [ -d "$venv_dir" ]; then
        echo "Directory '$venv_dir' already exists. Recreate? (y/N): "
        read -r REPLY
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$venv_dir"
        else
            return 0
        fi
    fi
    
    python3 -m venv "$venv_dir"
    source "$venv_dir/bin/activate"
    pip install --upgrade pip
    
    log_success "✅ Virtual environment created at '$venv_dir'"
}

# Interactive system Python setup
setup_system_python_interactive() {
    log_warn "⚠️  Using system Python is not recommended for development"
    echo "Continue anyway? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        export PIP_USER=1
        export PYTHONUSERBASE="$HOME/.local"
        export PATH="$HOME/.local/bin:$PATH"
        
        pip install --user --upgrade pip
        log_info "✅ System Python configured for user packages"
    fi
}

# Interactive tools installation
install_tools_interactive() {
    log_info "🛠️  System Tools Installation"
    echo "======================================"
    
    echo ""
    echo "Available tools to install:"
    echo "1) yq (YAML processor) - Required"
    echo "2) Git - Recommended"
    echo "3) curl/wget - Usually pre-installed"
    echo "4) All tools"
    echo "5) Skip tools installation"
    echo ""
    
    echo "Select option (1-5): "
    read -r REPLY
    
    case $REPLY in
        1)
            install_yq_auto
            ;;
        2)
            install_git_auto
            ;;
        3)
            install_curl_wget
            ;;
        4)
            install_yq_auto
            install_git_auto
            install_curl_wget
            ;;
        *)
            log_info "Tools installation skipped"
            ;;
    esac
}

# Install curl and wget
install_curl_wget() {
    log_info "🌐 Installing curl and wget..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt install -y curl wget
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y curl wget
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y curl wget
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm curl wget
    fi
    
    log_success "✅ curl and wget installed"
}

# Interactive FKS configuration setup
setup_fks_config_interactive() {
    log_info "🎯 FKS Configuration Setup"
    echo "======================================"
    
    echo ""
    echo "Configuration setup options:"
    echo "1) Generate default configuration files"
    echo "2) Import existing configuration"
    echo "3) Manual configuration guide"
    echo "4) Skip configuration setup"
    echo ""
    
    echo "Select option (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            generate_default_configs
            ;;
        2)
            import_existing_config
            ;;
        3)
            show_manual_config_guide
            ;;
        *)
            log_info "Configuration setup skipped"
            ;;
    esac
}

# Generate default configurations
generate_default_configs() {
    log_info "📄 Generating default configuration files..."
    
    # This would call the YAML generation functions
    if command -v yq >/dev/null 2>&1; then
        # Call the template creation functions from reset.sh
        create_template_yaml_configs
        generate_env_from_yaml
        generate_docker_compose
        log_success "✅ Default configurations generated"
    else
        log_error "❌ yq required for configuration generation"
        echo "Install yq first, then retry configuration setup"
    fi
}

# Import existing configuration
import_existing_config() {
    echo "Configuration import directory: "
    read -r config_dir
    
    if [ -d "$config_dir" ]; then
        log_info "Importing configuration from $config_dir..."
        
        # Copy configuration files
        [ -f "$config_dir/docker_config.yaml" ] && cp "$config_dir/docker_config.yaml" ./
        [ -f "$config_dir/app_config.yaml" ] && cp "$config_dir/app_config.yaml" ./
        [ -d "$config_dir/services" ] && cp -r "$config_dir/services" ./config/
        
        log_success "✅ Configuration imported"
    else
        log_error "❌ Directory not found: $config_dir"
    fi
}

# Show manual configuration guide
show_manual_config_guide() {
    echo ""
    echo "📚 Manual Configuration Guide:"
    echo "======================================"
    show_fks_setup_help
}

# Detailed system check
detailed_system_check() {
    log_info "🔍 Detailed System Check"
    echo "============================================"
    echo ""
    
    # System information
    echo "System Information:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    
    if [ -f /proc/cpuinfo ]; then
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//')
        local cpu_cores=$(nproc)
        echo "CPU: $cpu_model ($cpu_cores cores)"
    fi
    
    if command -v free >/dev/null 2>&1; then
        echo "Memory: $(free -h | awk '/^Mem:/ {print $2 " total, " $3 " used, " $7 " available"}')"
    fi
    
    echo "Disk: $(df -h . | awk 'NR==2 {print $2 " total, " $3 " used, " $4 " available (" $5 " used)"}')"
    
    echo ""
    
    # Detailed component check
    check_system_status
    
    # Network connectivity check
    echo ""
    echo "Network Connectivity:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "✅ Internet connectivity: Working"
    else
        echo "❌ Internet connectivity: Failed"
    fi
    
    if ping -c 1 github.com >/dev/null 2>&1; then
        echo "✅ GitHub connectivity: Working"
    else
        echo "❌ GitHub connectivity: Failed"
    fi
    
    # Docker specific checks
    if command -v docker >/dev/null 2>&1; then
        echo ""
        echo "Docker Details:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if docker info >/dev/null 2>&1; then
            echo "✅ Docker daemon: Running"
            echo "Docker root: $(docker info --format '{{.DockerRootDir}}')"
            echo "Storage driver: $(docker info --format '{{.Driver}}')"
            
            # Check if user is in docker group
            if groups | grep -q docker; then
                echo "✅ User in docker group: Yes"
            else
                echo "❌ User in docker group: No (run: sudo usermod -aG docker \$USER)"
            fi
        else
            echo "❌ Docker daemon: Not running"
        fi
    fi
    
    # Python specific checks
    if command -v python3 >/dev/null 2>&1; then
        echo ""
        echo "Python Details:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        echo "Python executable: $(which python3)"
        echo "Python version: $(python3 --version)"
        echo "pip version: $(pip3 --version 2>/dev/null || echo "Not available")"
        
        # Check virtual environment
        if [ -n "${VIRTUAL_ENV:-}" ]; then
            echo "Virtual environment: $VIRTUAL_ENV"
        elif [ -n "${CONDA_DEFAULT_ENV:-}" ]; then
            echo "Conda environment: $CONDA_DEFAULT_ENV"
        else
            echo "Environment: System Python"
        fi
        
        # Check important Python packages
        echo ""
        echo "Key Python packages:"
        local packages=("numpy" "pandas" "torch" "sklearn" "fastapi")
        for package in "${packages[@]}"; do
            if python3 -c "import $package" 2>/dev/null; then
                local version=$(python3 -c "import $package; print($package.__version__)" 2>/dev/null || echo "unknown")
                echo "✅ $package: $version"
            else
                echo "❌ $package: Not installed"
            fi
        done
    fi
    
    echo ""
    echo "🎯 FKS System Readiness:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local readiness_score=0
    local total_checks=5
    
    # Check Docker
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        echo "✅ Docker: Ready"
        ((readiness_score++))
    else
        echo "❌ Docker: Not ready"
    fi
    
    # Check Python
    if command -v python3 >/dev/null 2>&1; then
        echo "✅ Python: Ready"
        ((readiness_score++))
    else
        echo "❌ Python: Not ready"
    fi
    
    # Check yq
    if command -v yq >/dev/null 2>&1; then
        echo "✅ yq: Ready"
        ((readiness_score++))
    else
        echo "❌ yq: Not ready"
    fi
    
    # Check configuration
    if [ -f "docker_config.yaml" ] && [ -f "app_config.yaml" ]; then
        echo "✅ Configuration: Ready"
        ((readiness_score++))
    else
        echo "❌ Configuration: Not ready"
    fi
    
    # Check data directory
    if [ -d "data" ] && [ "$(ls -A data/)" ]; then
        echo "✅ Data: Ready"
        ((readiness_score++))
    else
        echo "❌ Data: Not ready (no data files found)"
    fi
    
    echo ""
    echo "Overall Readiness: $readiness_score/$total_checks ($(( readiness_score * 100 / total_checks ))%)"
    
    if [ $readiness_score -eq $total_checks ]; then
        log_success "🎉 System is fully ready for FKS Trading Systems!"
    elif [ $readiness_score -ge 3 ]; then
        log_warn "⚠️  System is mostly ready, but some components need attention"
    else
        log_error "❌ System needs significant setup before running FKS"
        echo ""
        echo "Run the installation wizard to fix issues: ./run.sh --install"
    fi
}