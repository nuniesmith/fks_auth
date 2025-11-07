#!/bin/bash
# Oryx Laptop Development Environment Setup & Deployment Script
# Optimized for Manjaro Linux

set -euo pipefail

# Configuration
GITHUB_USER="${GITHUB_USER:-}"
GITHUB_REPO="${GITHUB_REPO:-fks}"
PROJECT_PATH="${PROJECT_PATH:-$HOME/fks}"
SSH_PORT="${SSH_PORT:-22}"
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_VERSION:-2.29.1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

# Check if running on Manjaro/Arch
check_system() {
    log_info "Checking system compatibility..."
    
    # Detect distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log_info "Detected: $NAME"
        
        # Check if it's Manjaro or Arch-based
        if [[ "$ID" != "manjaro" ]] && [[ "$ID_LIKE" != *"arch"* ]] && [[ "$ID" != "arch" ]]; then
            log_warn "This script is optimized for Manjaro/Arch Linux"
            log_warn "Detected: $ID. Some features may not work correctly."
            read -p "Continue anyway? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    # Check for required commands
    if ! command -v pacman &> /dev/null; then
        log_error "pacman not found. This script requires an Arch-based system."
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        log_warn "Docker is not installed. Installing..."
        install_docker_manjaro
    else
        log_info "Docker is already installed"
    fi
    
    if ! command -v git &> /dev/null; then
        log_warn "Git is not installed. Installing..."
        sudo pacman -S --noconfirm git
    fi
    
    # Check if NVIDIA GPU is available
    if command -v nvidia-smi &> /dev/null; then
        log_info "NVIDIA GPU detected"
        check_nvidia_container_toolkit
    else
        log_info "No NVIDIA GPU detected (or nvidia-smi not installed)"
    fi
}

# Install Docker on Manjaro
install_docker_manjaro() {
    log_info "Installing Docker on Manjaro..."
    
    # Update system
    sudo pacman -Sy
    
    # Install Docker
    sudo pacman -S --noconfirm docker docker-compose
    
    # Enable and start Docker service
    sudo systemctl enable docker.service
    sudo systemctl start docker.service
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    log_warn "Docker installed. You may need to log out and back in for group changes to take effect."
}

# Check and install NVIDIA Container Toolkit
check_nvidia_container_toolkit() {
    log_info "Checking for NVIDIA Container Toolkit..."
    
    # Check if nvidia-container-toolkit is installed
    if ! pacman -Qi nvidia-container-toolkit &> /dev/null; then
        log_warn "nvidia-container-toolkit not found. Installing from AUR..."
        
        # Check if yay is installed
        if ! command -v yay &> /dev/null; then
            log_info "Installing yay (AUR helper)..."
            # Install yay if not present
            sudo pacman -S --needed --noconfirm git base-devel
            git clone https://aur.archlinux.org/yay.git /tmp/yay
            cd /tmp/yay
            makepkg -si --noconfirm
            cd -
            rm -rf /tmp/yay
        fi
        
        # Install nvidia-container-toolkit from AUR
        yay -S --noconfirm nvidia-container-toolkit
        
        # Configure Docker to use nvidia runtime
        configure_nvidia_docker
    else
        log_info "nvidia-container-toolkit is already installed"
    fi
}

# Configure Docker for NVIDIA
configure_nvidia_docker() {
    log_info "Configuring Docker for NVIDIA GPU support..."
    
    # Create Docker daemon configuration
    sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "features": {
        "buildkit": true
    },
    "default-runtime": "nvidia",
    "runtimes": {
        "nvidia": {
            "path": "/usr/bin/nvidia-container-runtime",
            "runtimeArgs": []
        }
    }
}
EOF
    
    # Restart Docker
    sudo systemctl restart docker
    
    # Test nvidia-docker
    log_info "Testing NVIDIA Docker integration..."
    if docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi &> /dev/null; then
        log_info "NVIDIA Docker integration working correctly!"
    else
        log_warn "NVIDIA Docker test failed. GPU support may not work properly."
    fi
}

# Setup SSH for GitHub Actions
setup_ssh() {
    log_info "Setting up SSH access for GitHub Actions..."
    
    # Create .ssh directory if it doesn't exist
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Generate SSH key if not exists
    SSH_KEY_PATH="$HOME/.ssh/github_actions_deploy"
    if [ ! -f "$SSH_KEY_PATH" ]; then
        ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "actions_user-deploy"
        log_info "SSH key generated at: $SSH_KEY_PATH"
    fi
    
    # Add to authorized_keys
    if ! grep -q "actions_user-deploy" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
        cat "$SSH_KEY_PATH.pub" >> "$HOME/.ssh/authorized_keys"
        chmod 600 "$HOME/.ssh/authorized_keys"
        log_info "SSH key added to authorized_keys"
    fi
    
    # Ensure SSH daemon is running
    if ! systemctl is-active --quiet sshd; then
        log_info "Starting SSH daemon..."
        sudo systemctl enable sshd
        sudo systemctl start sshd
    fi
    
    # Display the private key to add to GitHub Secrets
    echo ""
    log_info "Add this private key to GitHub Secrets as 'DEV_SSH_KEY':"
    echo "========================================"
    cat "$SSH_KEY_PATH"
    echo "========================================"
    echo ""
    
    # Get connection information
    LOCAL_IP=$(ip route get 1 | awk '{print $7;exit}' 2>/dev/null || hostname -I | awk '{print $1}')
    log_info "Connection Information:"
    log_info "  Local IP: $LOCAL_IP (add as 'DEV_SERVER_HOST')"
    log_info "  Username: $USER (add as 'DEV_SERVER_USER')"
    log_info "  SSH Port: $SSH_PORT (add as 'DEV_SERVER_PORT')"
    log_info "  Project Path: $PROJECT_PATH (add as 'DEV_PROJECT_PATH')"
}

# Setup project directory
setup_project() {
    log_info "Setting up project directory..."
    
    if [ ! -d "$PROJECT_PATH" ]; then
        log_info "Creating project directory at $PROJECT_PATH"
        mkdir -p "$PROJECT_PATH"
        
        if [ -n "$GITHUB_USER" ]; then
            log_info "Cloning repository..."
            git clone "https://github.com/$GITHUB_USER/$GITHUB_REPO.git" "$PROJECT_PATH"
        else
            log_warn "GITHUB_USER not set. Skipping repository clone."
            log_warn "Set GITHUB_USER environment variable and run again, or clone manually."
        fi
    else
        log_info "Project directory already exists at $PROJECT_PATH"
    fi
    
    # Create necessary directories
    cd "$PROJECT_PATH"
    mkdir -p logs data models outputs/checkpoints backups
    
    # Set permissions
    chmod -R 755 "$PROJECT_PATH"
}

# Configure firewall for Manjaro
setup_firewall() {
    log_info "Configuring firewall..."
    
    # Check if ufw is installed
    if ! command -v ufw &> /dev/null; then
        log_info "Installing UFW firewall..."
        sudo pacman -S --noconfirm ufw
    fi
    
    # Configure firewall rules
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow SSH
    sudo ufw allow $SSH_PORT/tcp comment "SSH"
    
    # Allow Docker services
    sudo ufw allow 80/tcp comment "Nginx HTTP"
    sudo ufw allow 443/tcp comment "Nginx HTTPS"
    sudo ufw allow 8000/tcp comment "API Service"
    sudo ufw allow 9000/tcp comment "App Service"
    sudo ufw allow 9999/tcp comment "Web UI"
    
    # Enable firewall
    if ! sudo ufw status | grep -q "Status: active"; then
        log_warn "Enabling UFW firewall..."
        echo "y" | sudo ufw enable
    fi
    
    log_info "Firewall configured. Current rules:"
    sudo ufw status numbered
}

# Create helper scripts
create_helper_scripts() {
    log_info "Creating helper scripts..."
    
    cd "$PROJECT_PATH"
    
    # Update script
    cat > update.sh << 'EOF'
#!/bin/bash
# Quick update script for FKS Trading Systems

set -e

echo "🔄 Updating FKS Trading Systems..."

# Check for uncommitted changes
if [[ -n $(git status -s) ]]; then
    echo "⚠️  Uncommitted changes detected. Please commit or stash them first."
    exit 1
fi

# Pull latest changes
CURRENT_BRANCH=$(git branch --show-current)
echo "📥 Pulling latest changes from $CURRENT_BRANCH..."
git pull origin $CURRENT_BRANCH

# Update docker images
echo "🐳 Pulling latest Docker images..."
docker-compose pull

# Restart services
echo "🚀 Restarting services..."
docker-compose up -d --remove-orphans

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Show status
echo "📊 Service status:"
docker-compose ps

echo "✅ Update complete!"
EOF
    chmod +x update.sh
    
    # Monitor script
    cat > monitor.sh << 'EOF'
#!/bin/bash
# Monitor FKS Trading Systems services

clear
echo "📊 FKS Trading Systems Monitor"
echo "============================="
echo "Time: $(date)"

# Service health
echo -e "\n🏥 Service Health:"
docker-compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

# Resource usage
echo -e "\n💻 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Recent logs from any unhealthy services
UNHEALTHY=$(docker-compose ps --format json | jq -r 'select(.Health != "healthy" and .Health != null) | .Service' 2>/dev/null)
if [ -n "$UNHEALTHY" ]; then
    echo -e "\n⚠️  Unhealthy Services:"
    for service in $UNHEALTHY; do
        echo -e "\n--- $service logs (last 10 lines) ---"
        docker-compose logs --tail=10 $service 2>&1
    done
fi

# Disk usage
echo -e "\n💾 Disk Usage:"
df -h | grep -E "^/dev|Filesystem"

# GPU status (if available)
if command -v nvidia-smi &> /dev/null; then
    echo -e "\n🎮 GPU Status:"
    nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv
fi

# Docker system info
echo -e "\n🐳 Docker System:"
docker system df
EOF
    chmod +x monitor.sh
    
    # Cleanup script
    cat > cleanup.sh << 'EOF'
#!/bin/bash
# Cleanup Docker resources safely

echo "🧹 Cleaning up Docker resources..."

# Stop all services first
echo "Stopping services..."
docker-compose down

# Remove stopped containers
echo "Removing stopped containers..."
docker container prune -f

# Remove unused images (older than 24h)
echo "Removing old unused images..."
docker image prune -a -f --filter "until=24h"

# Remove unused networks
echo "Removing unused networks..."
docker network prune -f

# Remove build cache
echo "Cleaning build cache..."
docker builder prune -f --filter "until=24h"

# Show disk usage
echo -e "\n💾 Disk usage after cleanup:"
docker system df

echo "✅ Cleanup complete!"
EOF
    chmod +x cleanup.sh
    
    log_info "Helper scripts created:"
    log_info "  - update.sh: Quick update and restart"
    log_info "  - monitor.sh: Monitor services and resources"
    log_info "  - cleanup.sh: Clean up Docker resources"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."
    
    sudo tee /etc/systemd/system/fks_trading.service > /dev/null <<EOF
[Unit]
Description=FKS Trading Systems
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_PATH
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
User=$USER
Group=docker

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    log_info "Systemd service created. Use 'sudo systemctl enable fks_trading' to enable auto-start."
}

# Main setup function
main() {
    echo "🚀 Oryx Laptop Development Environment Setup for Manjaro"
    echo "======================================================"
    
    check_system
    setup_ssh
    setup_project
    create_helper_scripts
    create_systemd_service
    setup_firewall
    
    echo ""
    log_info "✅ Setup complete!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Add the SSH key and connection details shown above to GitHub Secrets"
    echo "2. Update your GitHub Actions workflow with the deployment job"
    echo "3. Test the SSH connection:"
    echo "   ssh -i ~/.ssh/github_actions_deploy -p $SSH_PORT $USER@localhost"
    echo ""
    echo "🛠️ Useful commands:"
    echo "- Start services: cd $PROJECT_PATH && docker-compose up -d"
    echo "- Monitor: $PROJECT_PATH/monitor.sh"
    echo "- Update: $PROJECT_PATH/update.sh"
    echo "- Cleanup: $PROJECT_PATH/cleanup.sh"
    echo "- Enable auto-start: sudo systemctl enable fks_trading"
    echo ""
    
    # Check if user needs to re-login for docker group
    if ! groups | grep -q docker; then
        log_warn "You need to log out and back in for Docker group changes to take effect!"
        log_warn "Or run: newgrp docker"
    fi
}

# Run main function
main "$@"