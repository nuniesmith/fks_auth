#!/usr/bin/env bash
# =============================================================================
# GitHub Runner Setup Script for Ubuntu 24.04 (Oryx)
# Installs and configures all necessary tools for development:
# - Python, Rust, Kubernetes, Docker, and more
# 
# Handles "externally managed environment" for Python (PEP 668)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration (adjust as needed)
# -----------------------------------------------------------------------------
PYTHON_VERSION="3.11"                   # Python version to install
# Format: space-separated list of system packages (apt installable)
PYTHON_SYSTEM_PACKAGES="python3-numpy python3-pandas python3-matplotlib python3-pytest python3-venv python3-full"
# Format: space-separated list of pipx packages to install in isolated environments
PYTHON_PIPX_PACKAGES="black flake8 mypy poetry pipenv ruff"
# Format: space-separated list of packages for project virtual environments
PYTHON_VENV_PACKAGES="numpy pandas matplotlib scikit-learn jupyter pytest pytest-xdist pytest-cov"
RUST_VERSION="stable"                   # Rust version (stable, beta, nightly)
DOCKER_COMPOSE_VERSION="v2.26.0"        # Docker Compose version
KUBECTL_VERSION="v1.29.1"               # Kubectl version
HELM_VERSION="v3.14.2"                  # Helm version
K9S_VERSION="v0.31.4"                   # K9s version
NODE_VERSION="20.x"                     # Node.js version

# -----------------------------------------------------------------------------
# Colors for better output
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
log_section() {
    echo -e "\n${BLUE}${BOLD}==> $1${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    if [ "${2:-continue}" = "exit" ]; then
        exit 1
    fi
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to add to PATH if not already in it
add_to_path() {
    if [[ ":$PATH:" != *":$1:"* ]]; then
        export PATH="$1:$PATH"
        echo "export PATH=$1:\$PATH" >> ~/.bashrc
        log_info "Added $1 to PATH"
    fi
}

# -----------------------------------------------------------------------------
# Check for root or sudo privileges
# -----------------------------------------------------------------------------
log_section "Checking privileges"

if [ "$(id -u)" -eq 0 ]; then
    log_info "Running as root"
    SUDO=""
elif command_exists sudo; then
    log_info "Running with sudo"
    SUDO="sudo"
else
    log_error "This script requires root privileges or sudo" "exit"
fi

# -----------------------------------------------------------------------------
# System update and basic dependencies
# -----------------------------------------------------------------------------
log_section "Updating system and installing basic dependencies"

${SUDO} apt-get update
${SUDO} apt-get upgrade -y

# Install essential packages
${SUDO} apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    lsb-release \
    make \
    software-properties-common \
    unzip \
    vim \
    wget \
    zip \
    build-essential \
    pkg-config \
    libssl-dev \
    libffi-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    liblzma-dev

log_info "Basic dependencies installed"

# -----------------------------------------------------------------------------
# Python installation and setup (Ubuntu 24.04 externally managed environment)
# -----------------------------------------------------------------------------
log_section "Installing Python ${PYTHON_VERSION} (Ubuntu 24.04 Externally Managed Environment)"

# Install Python and essential packages through APT (system-wide)
${SUDO} apt-get install -y python${PYTHON_VERSION} python${PYTHON_VERSION}-dev python${PYTHON_VERSION}-venv python3-pip python3-full pipx

# Install Python system packages via APT
${SUDO} apt-get install -y ${PYTHON_SYSTEM_PACKAGES}

# Create symbolic links if needed
if ! command_exists python; then
    ${SUDO} ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python
fi

if ! command_exists python3; then
    ${SUDO} ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3
fi

# Add ~/.local/bin to PATH and make it available in the current session
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Ensure pipx uses correct PATH - explicitly run as the current user
pipx ensurepath

# Install isolated Python tools using pipx
log_info "Installing isolated Python tools using pipx"
for package in ${PYTHON_PIPX_PACKAGES}; do
    log_info "Installing $package via pipx..."
    pipx install $package
done

# Also install pytest with xdist as a dependency
log_info "Installing pytest with dependencies via pipx..."
pipx install pytest --include-deps
pipx inject pytest pytest-xdist pytest-cov

# Create a default development virtual environment for projects
log_info "Creating a default Python virtual environment for projects"
mkdir -p ~/python-environments
cd ~/python-environments
python3 -m venv default-env
source default-env/bin/activate
pip install --upgrade pip setuptools wheel
# Install common packages in the virtual environment
pip install ${PYTHON_VENV_PACKAGES}
deactivate

# Create a helper script for Python project setup
cat > ~/create-python-project.sh << 'EOF'
#!/usr/bin/env bash
# Script to create a new Python project with proper virtual environment
# Usage: create-python-project.sh project_name

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 project_name"
    exit 1
fi

PROJECT_NAME="$1"
BASE_DIR="$HOME/projects"
PROJECT_DIR="$BASE_DIR/$PROJECT_NAME"
VENV_DIR="$PROJECT_DIR/.venv"

mkdir -p "$BASE_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo "Creating virtual environment for $PROJECT_NAME..."
python3 -m venv "$VENV_DIR"

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "Upgrading pip, setuptools, and wheel..."
pip install --upgrade pip setuptools wheel

echo "Setting up basic project structure..."
mkdir -p "$PROJECT_NAME"
mkdir -p tests
mkdir -p docs

# Create basic files
cat > pyproject.toml << EOT
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "${PROJECT_NAME}"
version = "0.1.0"
description = "Description of your project"
readme = "README.md"
authors = [
    {name = "Your Name", email = "your.email@example.com"}
]
license = {text = "MIT"}
requires-python = ">=3.8"
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
]

[project.urls]
"Homepage" = "https://github.com/yourusername/${PROJECT_NAME}"
"Bug Tracker" = "https://github.com/yourusername/${PROJECT_NAME}/issues"
EOT

cat > README.md << EOT
# ${PROJECT_NAME}

Description of your project.

## Installation

\`\`\`bash
pip install ${PROJECT_NAME}
\`\`\`

## Usage

\`\`\`python
import ${PROJECT_NAME}
\`\`\`

## License

MIT
EOT

cat > .gitignore << EOT
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
dist/
build/
*.egg-info/

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
.pytest_cache/

# Environments
.env
.venv
env/
venv/
ENV/

# IDE
.idea/
.vscode/
*.swp
*.swo
EOT

cat > "$PROJECT_NAME/__init__.py" << EOT
"""${PROJECT_NAME} package."""

__version__ = "0.1.0"
EOT

cat > tests/__init__.py << EOT
"""Test package for ${PROJECT_NAME}."""
EOT

cat > tests/test_basic.py << EOT
"""Basic tests for ${PROJECT_NAME}."""

import pytest
from ${PROJECT_NAME} import __version__

def test_version():
    """Test version is a string."""
    assert isinstance(__version__, str)
EOT

echo "Project setup complete! To activate the virtual environment, run:"
echo "source $VENV_DIR/bin/activate"

echo "To install development dependencies, run:"
echo "pip install pytest pytest-cov black flake8"

echo "Happy coding!"
EOF

chmod +x ~/create-python-project.sh

log_info "Python ${PYTHON_VERSION} installed and configured according to PEP 668 standards"
log_info "Created helper script ~/create-python-project.sh for new Python projects"
python3 --version
pipx --version

# -----------------------------------------------------------------------------
# Rust installation and setup
# -----------------------------------------------------------------------------
log_section "Installing Rust and Cargo"

if ! command_exists rustc; then
    # Install Rust using rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}
    source $HOME/.cargo/env
    
    # Add to PATH in case it's not done automatically
    add_to_path "$HOME/.cargo/bin"
    
    # Install common Rust tools
    rustup component add clippy rustfmt
    cargo install cargo-audit cargo-edit cargo-watch
else
    log_info "Rust is already installed, updating..."
    rustup update
fi

log_info "Rust installed and configured"
rustc --version
cargo --version

# -----------------------------------------------------------------------------
# Docker installation and setup
# -----------------------------------------------------------------------------
log_section "Installing Docker"

if ! command_exists docker; then
    # Remove any old versions
    ${SUDO} apt-get remove -y docker docker-engine docker.io containerd runc || true
    
    # Add Docker's official GPG key
    ${SUDO} mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | ${SUDO} gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Add the repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | ${SUDO} tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    ${SUDO} apt-get update
    ${SUDO} apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add user to docker group
    ${SUDO} usermod -aG docker $USER
    log_warn "You may need to log out and back in for the docker group changes to take effect"
    
    # Install Docker Compose v2 (standalone)
    ${SUDO} curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" -o /usr/local/bin/docker-compose
    ${SUDO} chmod +x /usr/local/bin/docker-compose
else
    log_info "Docker is already installed"
fi

# Start and enable Docker service
${SUDO} systemctl enable docker
${SUDO} systemctl start docker

log_info "Docker installed and configured"
docker --version
docker compose version || docker-compose --version || true

# -----------------------------------------------------------------------------
# Kubernetes tools installation
# -----------------------------------------------------------------------------
log_section "Installing Kubernetes tools"

# Install kubectl
if ! command_exists kubectl; then
    ${SUDO} curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/$(dpkg --print-architecture)/kubectl"
    ${SUDO} chmod +x kubectl
    ${SUDO} mv kubectl /usr/local/bin/
else
    log_info "kubectl is already installed"
fi

# Install Helm
if ! command_exists helm; then
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod +x get_helm.sh
    ./get_helm.sh
    rm get_helm.sh
else
    log_info "Helm is already installed"
fi

# Install k9s (Kubernetes CLI to manage clusters)
if ! command_exists k9s; then
    curl -fsSL -o k9s.tar.gz "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_$(dpkg --print-architecture).tar.gz"
    tar -xzf k9s.tar.gz
    ${SUDO} mv k9s /usr/local/bin/
    rm -f k9s.tar.gz LICENSE README.md || true
else
    log_info "k9s is already installed"
fi

# Install Kustomize
if ! command_exists kustomize; then
    curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
    ${SUDO} mv kustomize /usr/local/bin/
else
    log_info "Kustomize is already installed"
fi

# Install Minikube (for local Kubernetes development)
if ! command_exists minikube; then
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    ${SUDO} install minikube-linux-amd64 /usr/local/bin/minikube
    rm -f minikube-linux-amd64
else
    log_info "Minikube is already installed"
fi

log_info "Kubernetes tools installed"
kubectl version --client || true
helm version || true
k9s version || true
kustomize version || true
minikube version || true

# -----------------------------------------------------------------------------
# Node.js installation (for GitHub Action runners and frontend development)
# -----------------------------------------------------------------------------
log_section "Installing Node.js ${NODE_VERSION}"

if ! command_exists node; then
    # Install Node.js using NodeSource
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION} | ${SUDO} bash -
    ${SUDO} apt-get install -y nodejs
    
    # Install common global packages
    ${SUDO} npm install -g yarn pnpm npm@latest
else
    log_info "Node.js is already installed"
fi

log_info "Node.js installed and configured"
node --version
npm --version
yarn --version || true
pnpm --version || true

# -----------------------------------------------------------------------------
# Additional development tools
# -----------------------------------------------------------------------------
log_section "Installing additional development tools"

# Install GitHub CLI
if ! command_exists gh; then
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | ${SUDO} dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | ${SUDO} tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    ${SUDO} apt-get update
    ${SUDO} apt-get install -y gh
else
    log_info "GitHub CLI is already installed"
fi

# Install AWS CLI
if ! command_exists aws; then
    log_info "Installing AWS CLI..."
    
    # Create temporary directory
    temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download AWS CLI based on architecture
    if [[ "$(uname -m)" == "x86_64" ]]; then
        wget -q "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -O "awscliv2.zip"
    else
        wget -q "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -O "awscliv2.zip"
    fi
    
    # Check and install
    if [[ -s "awscliv2.zip" ]] && unzip -t "awscliv2.zip" > /dev/null 2>&1; then
        unzip -q "awscliv2.zip"
        ${SUDO} ./aws/install
    else
        log_error "AWS CLI download failed or file is corrupted"
    fi
    
    # Clean up
    cd - > /dev/null
    rm -rf "$temp_dir"
else
    log_info "AWS CLI is already installed"
fi

# Install Terraform
if ! command_exists terraform; then
    ${SUDO} apt-get install -y gnupg software-properties-common
    wget -O- https://apt.releases.hashicorp.com/gpg | \
        gpg --dearmor | \
        ${SUDO} tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
        https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
        ${SUDO} tee /etc/apt/sources.list.d/hashicorp.list > /dev/null
    ${SUDO} apt-get update
    ${SUDO} apt-get install -y terraform
else
    log_info "Terraform is already installed"
fi

log_info "Additional development tools installed"
gh --version || true
aws --version || true
terraform --version || true

# -----------------------------------------------------------------------------
# GitHub Actions Runner dependencies
# -----------------------------------------------------------------------------
log_section "Installing GitHub Actions Runner dependencies"

# Install additional dependencies required by GitHub Actions
${SUDO} apt-get install -y \
    libasound2t64 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcairo2 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libglib2.0-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    openssl \
    xvfb

log_info "GitHub Actions Runner dependencies installed"

# -----------------------------------------------------------------------------
# Python guide to help users understand externally managed environments
# -----------------------------------------------------------------------------
log_section "Creating Python guide for Ubuntu 24.04"

cat > ~/python-guide-ubuntu24.04.md << 'EOF'
# Python on Ubuntu 24.04: Externally Managed Environment Guide

Ubuntu 24.04 implements [PEP 668](https://peps.python.org/pep-0668/), which means the system Python is "externally managed" by APT.
This guide explains how to properly work with Python in this environment.

## Installing Python Packages

There are three main ways to install Python packages on Ubuntu 24.04:

### 1. System-wide packages (via APT)

For packages that are available in Ubuntu repositories:

```bash
sudo apt install python3-package-name
```

Examples:
```bash
sudo apt install python3-numpy python3-pandas python3-matplotlib
```

### 2. Isolated applications (via pipx)

For Python applications you want to use system-wide but isolated:

```bash
pipx install package-name
```

Examples:
```bash
pipx install black
pipx install poetry
pipx install flake8
```

### 3. Project-specific packages (via virtual environments)

For project-specific dependencies:

```bash
# Create a virtual environment
python3 -m venv myproject-env

# Activate it
source myproject-env/bin/activate

# Now you can use pip normally within the virtual environment
pip install numpy pandas matplotlib
```

## Virtual Environment Helper

We've created a helper script to set up Python projects with virtual environments:

```bash
~/create-python-project.sh my-new-project
```

This will:
1. Create a new project directory
2. Set up a virtual environment
3. Create basic project structure
4. Add common files like README.md, pyproject.toml, etc.

## Python Development Best Practices on Ubuntu 24.04

1. **NEVER** use `pip install` outside a virtual environment
2. **ALWAYS** use virtual environments for development
3. Use `pipx` for CLI tools and applications
4. Use `apt` for system-wide packages when available

## Using the Default Development Environment

We've set up a default development environment you can use:

```bash
source ~/python-environments/default-env/bin/activate
```

This environment has common packages pre-installed.
EOF

log_info "Python guide created at ~/python-guide-ubuntu24.04.md"

# -----------------------------------------------------------------------------
# Final setup and validation
# -----------------------------------------------------------------------------
log_section "Performing final setup and validation"

# Create a directory for GitHub Actions work
mkdir -p ~/actions-runner/_work

# Create a validation file
cat > ~/runner-setup-validation.txt << EOF
GitHub Runner Setup Validation
=============================
Date: $(date)
Hostname: $(hostname)
User: $(whoami)

Installed Versions:
------------------
OS: $(lsb_release -ds)
Python: $(python3 --version 2>&1)
pip: $(pip --version 2>&1)
pipx: $(pipx --version 2>&1)
Rust: $(rustc --version 2>&1)
Cargo: $(cargo --version 2>&1)
Docker: $(docker --version 2>&1)
Docker Compose: $(docker compose version 2>&1 || docker-compose --version 2>&1 || echo "Not found")
kubectl: $(kubectl version --client 2>&1 || echo "Not found")
Helm: $(helm version 2>&1 || echo "Not found")
Node.js: $(node --version 2>&1 || echo "Not found")
npm: $(npm --version 2>&1 || echo "Not found")
GitHub CLI: $(gh --version 2>&1 || echo "Not found")
AWS CLI: $(aws --version 2>&1 || echo "Not found")
Terraform: $(terraform --version 2>&1 || echo "Not found")

PATH:
-----
$PATH
EOF

log_info "Created validation file at ~/runner-setup-validation.txt"

# Create a helpful alias for runner diagnostics
cat >> ~/.bashrc << 'EOF'

# GitHub Runner diagnostic alias
alias runner-diag='echo -e "\nGitHub Runner Diagnostics\n=======================\n" && 
                  echo -e "System:\n-------" &&
                  echo "OS: $(lsb_release -ds)" &&
                  echo "Kernel: $(uname -r)" &&
                  echo "Memory: $(free -h | grep Mem | awk '"'"'{print $2}'"'"')" &&
                  echo "Disk: $(df -h / | tail -n 1 | awk '"'"'{print $4}'"'"') free" &&
                  echo -e "\nTools:\n------" &&
                  echo "Python: $(python3 --version 2>&1)" &&
                  echo "Rust: $(rustc --version 2>&1)" &&
                  echo "Docker: $(docker --version 2>&1)" &&
                  echo "kubectl: $(kubectl version --client 2>&1 || echo "Not found")" &&
                  echo "Node.js: $(node --version 2>&1 || echo "Not found")" &&
                  echo -e "\nDocker info:\n-----------" &&
                  docker info 2>/dev/null | grep -E "Server Version|OS|Architecture|CPUs|Total Memory" | sed "s/^/ /" || echo " Docker not running"'

# Python helper aliases
alias create-venv='python3 -m venv .venv && echo "Virtual environment created. Run \"source .venv/bin/activate\" to activate."'
alias activate-default='source ~/python-environments/default-env/bin/activate'

# Useful runner aliases
alias runner-logs='journalctl -u actions.runner._* -f'
alias docker-clean='docker system prune -af'
EOF

log_info "Added useful aliases for runner management"

# Remind about Docker permissions
if groups | grep -qv docker; then
    log_warn "You need to log out and back in for Docker permissions to take effect"
fi

log_section "Setup completed successfully!"
echo -e "${GREEN}Your GitHub Runner has been set up with all required tools.${NC}"
echo -e "${YELLOW}Please review the validation file at ~/runner-setup-validation.txt${NC}"
echo -e "${YELLOW}You may need to log out and back in for all changes to take effect.${NC}"

echo -e "\n${BLUE}${BOLD}Important Notes for Python on Ubuntu 24.04:${NC}"
echo -e "${YELLOW}1. System Python is 'externally managed' (PEP 668)${NC}"
echo -e "${YELLOW}2. Use apt for system packages: sudo apt install python3-package${NC}"
echo -e "${YELLOW}3. Use pipx for applications: pipx install package${NC}"
echo -e "${YELLOW}4. Use virtual environments for development: python3 -m venv myenv${NC}"
echo -e "${YELLOW}5. See ~/python-guide-ubuntu24.04.md for detailed instructions${NC}"

# Create a script to start the GitHub runner service if it exists
if [ -f ~/actions-runner/svc.sh ]; then
    log_info "Found GitHub Actions Runner service script"
    echo -e "${BLUE}To start the runner service, execute:${NC}"
    echo -e "  ~/actions-runner/svc.sh install"
    echo -e "  ~/actions-runner/svc.sh start"
fi

echo -e "\n${GREEN}${BOLD}Happy building!${NC}\n"