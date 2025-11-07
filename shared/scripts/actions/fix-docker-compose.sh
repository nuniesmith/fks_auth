#!/bin/bash
# Universal Docker Compose fix for all services
# Can be called from any service deployment

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

log_info "🐳 Universal Docker Compose fix for Arch Linux..."

# Check if we're on Arch Linux
if ! command -v pacman &>/dev/null; then
    log_warn "Not running on Arch Linux, skipping pacman-specific fixes"
    exit 0
fi

# Update system
log_info "🔄 Updating system packages..."
pacman -Sy --noconfirm

# Remove conflicting packages
log_info "🗑️ Removing potentially conflicting packages..."
pacman -Rns --noconfirm docker-compose 2>/dev/null || true

# Install Docker
log_info "📦 Installing Docker..."
pacman -S --noconfirm docker

# Start Docker service
log_info "🔧 Starting Docker service..."
systemctl enable docker
systemctl start docker

# Wait for Docker to be ready
log_info "⏳ Waiting for Docker to be ready..."
for i in {1..30}; do
    if docker info &>/dev/null; then
        log_success "Docker is ready!"
        break
    fi
    echo "Waiting for Docker... ($i/30)"
    sleep 2
done

# Install Docker Compose plugin
log_info "📥 Installing Docker Compose plugin..."

# Create plugins directory
mkdir -p /usr/local/lib/docker/cli-plugins

# Get latest version
COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d'"' -f4 | sed 's/v//' | head -1)
log_info "📥 Installing Docker Compose v$COMPOSE_VERSION..."

# Download and install with retries
for attempt in {1..3}; do
    if curl -SL "https://github.com/docker/compose/releases/download/v$COMPOSE_VERSION/docker-compose-linux-x86_64" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose; then
        log_success "Download successful on attempt $attempt"
        break
    else
        log_warn "Download failed on attempt $attempt"
        if [ $attempt -eq 3 ]; then
            log_error "All download attempts failed"
            exit 1
        fi
        sleep 5
    fi
done

chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Also create system-wide symlink for compatibility
ln -sf /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

# Test Docker Compose
log_info "🧪 Testing Docker Compose..."
if docker compose version &>/dev/null; then
    log_success "✅ Modern Docker Compose (docker compose) is working!"
    docker compose version
elif command -v docker-compose &>/dev/null; then
    log_success "✅ Legacy Docker Compose (docker-compose) is working!"
    docker-compose --version
else
    log_error "❌ Docker Compose test failed!"
    exit 1
fi

# Create detection function for other scripts
cat > /usr/local/bin/detect-docker-compose << 'EOF'
#!/bin/bash
# Docker Compose detection helper

if docker compose version &> /dev/null 2>&1; then
    echo "docker compose"
elif command -v docker-compose &> /dev/null; then
    echo "docker-compose"
else
    echo ""
fi
EOF
chmod +x /usr/local/bin/detect-docker-compose

log_success "🎉 Docker Compose fix complete!"
log_info "💡 Use 'detect-docker-compose' to get the correct command in scripts"
