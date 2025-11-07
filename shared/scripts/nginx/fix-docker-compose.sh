#!/bin/bash
# Fix Docker Compose installation on Arch Linux
# Ensures we have the modern docker compose plugin working

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

log_info "🐳 Fixing Docker Compose installation on Arch Linux..."

# Check current Docker installation
log_info "🔍 Checking current Docker installation..."
docker --version || log_error "Docker not installed!"

# Check current Compose status
log_info "🔍 Checking Docker Compose status..."
if docker compose version &>/dev/null; then
    log_success "Modern Docker Compose (docker compose) is working!"
    docker compose version
    exit 0
elif command -v docker-compose &>/dev/null; then
    log_warn "Only legacy docker-compose found"
    docker-compose --version
else
    log_error "No Docker Compose found!"
fi

# Update system first
log_info "🔄 Updating system packages..."
sudo pacman -Sy --noconfirm

# Remove old docker-compose if it exists
if command -v docker-compose &>/dev/null && [[ -f "/usr/bin/docker-compose" ]]; then
    log_info "🗑️ Removing old docker-compose..."
    sudo pacman -Rns --noconfirm docker-compose || true
fi

# Install latest Docker
log_info "📦 Installing/updating Docker..."
sudo pacman -S --noconfirm docker

# Enable Docker service
log_info "🔧 Enabling Docker service..."
sudo systemctl enable docker
sudo systemctl start docker

# Add current user to docker group if not already
if ! groups "$USER" | grep -q "docker"; then
    log_info "👥 Adding $USER to docker group..."
    sudo usermod -aG docker "$USER"
    log_warn "You may need to log out and back in for group changes to take effect"
fi

# Install Docker Compose plugin manually
log_info "📥 Installing Docker Compose plugin..."

# Create plugins directory
sudo mkdir -p /usr/local/lib/docker/cli-plugins

# Get latest version
COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d'"' -f4 | sed 's/v//')
log_info "📥 Downloading Docker Compose v$COMPOSE_VERSION..."

# Download and install
sudo curl -SL "https://github.com/docker/compose/releases/download/v$COMPOSE_VERSION/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose

sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Also install system-wide for compatibility
sudo ln -sf /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

# Test installation
log_info "🧪 Testing Docker Compose installation..."
if docker compose version &>/dev/null; then
    log_success "✅ Modern Docker Compose (docker compose) is working!"
    docker compose version
elif command -v docker-compose &>/dev/null; then
    log_success "✅ Legacy Docker Compose (docker-compose) is working!"
    docker-compose --version
else
    log_error "❌ Docker Compose installation failed!"
    exit 1
fi

# Test Docker
log_info "🧪 Testing Docker..."
if docker info &>/dev/null; then
    log_success "✅ Docker is working!"
else
    log_error "❌ Docker is not working properly!"
    exit 1
fi

log_success "🎉 Docker Compose installation complete!"
log_info "💡 You can now use either 'docker compose' or 'docker-compose' commands"
