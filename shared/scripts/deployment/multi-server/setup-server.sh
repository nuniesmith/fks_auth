#!/bin/bash

# FKS Multi-Server Setup Script
# Configures individual servers for specific roles

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SERVER_TYPE=""
HOSTNAME=""
TAILSCALE_KEY=""

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-type)
            SERVER_TYPE="$2"
            shift 2
            ;;
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --tailscale-key)
            TAILSCALE_KEY="$2"
            shift 2
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$SERVER_TYPE" ] || [ -z "$HOSTNAME" ] || [ -z "$TAILSCALE_KEY" ]; then
    log "ERROR" "Missing required parameters"
    exit 1
fi

log "INFO" "Setting up FKS $SERVER_TYPE server: $HOSTNAME"

# Update system
log "INFO" "Updating system packages..."
pacman -Syu --noconfirm

# Install essential packages
log "INFO" "Installing essential packages..."
pacman -S --noconfirm docker docker-compose git curl wget jq vim htop

# Configure hostname
log "INFO" "Setting hostname to $HOSTNAME..."
echo "$HOSTNAME" > /etc/hostname
hostnamectl set-hostname "$HOSTNAME"

# Start and enable Docker
log "INFO" "Starting Docker service..."
systemctl start docker
systemctl enable docker

# Install Tailscale
log "INFO" "Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh

# Join Tailscale network
log "INFO" "Joining Tailscale network..."
tailscale up --authkey="$TAILSCALE_KEY" --hostname="$HOSTNAME"

# Create FKS user and directories
log "INFO" "Creating FKS user and directories..."
useradd -m -s /bin/bash fks_user || true
usermod -aG docker fks_user || true

# Create application directory
mkdir -p /home/fks_user/fks
chown -R fks_user:fks_user /home/fks_user/fks

# Create systemd service for auto-deployment
log "INFO" "Creating FKS deployment service..."

case "$SERVER_TYPE" in
    "auth")
        SERVICE_DESCRIPTION="FKS Auth Services"
        COMPOSE_FILE="docker-compose.auth.yml"
        ;;
    "api")
        SERVICE_DESCRIPTION="FKS API Services"
        COMPOSE_FILE="docker-compose.api.yml"
        ;;
    "web")
        SERVICE_DESCRIPTION="FKS Web Services"
        COMPOSE_FILE="docker-compose.web.yml"
        ;;
    *)
        log "ERROR" "Unknown server type: $SERVER_TYPE"
        exit 1
        ;;
esac

cat > /etc/systemd/system/fks_${SERVER_TYPE}.service << EOF
[Unit]
Description=$SERVICE_DESCRIPTION
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/fks_user/fks
User=fks_user
Group=fks_user
ExecStart=/usr/bin/docker-compose -f $COMPOSE_FILE up -d
ExecStop=/usr/bin/docker-compose -f $COMPOSE_FILE down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Create startup script for the specific server type
cat > /home/fks_user/start-${SERVER_TYPE}.sh << EOF
#!/bin/bash

# FKS $SERVER_TYPE Server Startup Script
# Optimized for $SERVER_TYPE services

set -e

cd /home/fks_user/fks

# Pull latest images
echo "📥 Pulling latest $SERVER_TYPE images..."
docker-compose -f $COMPOSE_FILE pull

# Start services
echo "🚀 Starting $SERVER_TYPE services..."
docker-compose -f $COMPOSE_FILE up -d

# Show status
echo "📊 Service status:"
docker-compose -f $COMPOSE_FILE ps

echo "✅ FKS $SERVER_TYPE services started successfully!"
EOF

chmod +x /home/fks_user/start-${SERVER_TYPE}.sh
chown fks_user:fks_user /home/fks_user/start-${SERVER_TYPE}.sh

# Create stop script
cat > /home/fks_user/stop-${SERVER_TYPE}.sh << EOF
#!/bin/bash

# FKS $SERVER_TYPE Server Stop Script

set -e

cd /home/fks_user/fks

echo "🛑 Stopping $SERVER_TYPE services..."
docker-compose -f $COMPOSE_FILE down

echo "✅ FKS $SERVER_TYPE services stopped successfully!"
EOF

chmod +x /home/fks_user/stop-${SERVER_TYPE}.sh
chown fks_user:fks_user /home/fks_user/stop-${SERVER_TYPE}.sh

# Install server-specific packages and optimizations
case "$SERVER_TYPE" in
    "auth")
        log "INFO" "Configuring auth server optimizations..."
        # Lightweight setup for auth server
        # Optimize for low memory usage
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
        ;;
    "api")
        log "INFO" "Configuring API server optimizations..."
        # Install Python and database tools
        pacman -S --noconfirm python python-pip postgresql-libs redis
        # Optimize for database connections and API performance
        echo 'net.core.somaxconn=1024' >> /etc/sysctl.conf
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
        ;;
    "web")
        log "INFO" "Configuring web server optimizations..."
        # Install Node.js for potential frontend builds
        pacman -S --noconfirm nodejs npm
        # Optimize for web serving
        echo 'net.core.somaxconn=1024' >> /etc/sysctl.conf
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
        ;;
esac

# Apply sysctl changes
sysctl -p

# Enable systemd service
systemctl daemon-reload
systemctl enable fks_${SERVER_TYPE}.service

# Create health check script
cat > /home/fks_user/health-check-${SERVER_TYPE}.sh << EOF
#!/bin/bash

# FKS $SERVER_TYPE Server Health Check

cd /home/fks_user/fks

echo "🏥 FKS $SERVER_TYPE Server Health Check"
echo "========================================="

# Check Docker status
if systemctl is-active --quiet docker; then
    echo "✅ Docker: Running"
else
    echo "❌ Docker: Not running"
fi

# Check Tailscale status
if systemctl is-active --quiet tailscaled; then
    TAILSCALE_STATUS=\$(tailscale status --json 2>/dev/null | jq -r '.BackendState // "unknown"')
    if [ "\$TAILSCALE_STATUS" = "Running" ]; then
        TAILSCALE_IP=\$(tailscale ip -4 2>/dev/null)
        echo "✅ Tailscale: Connected (\$TAILSCALE_IP)"
    else
        echo "⚠️ Tailscale: \$TAILSCALE_STATUS"
    fi
else
    echo "❌ Tailscale: Not running"
fi

# Check service containers
echo ""
echo "🐳 Container Status:"
if [ -f "$COMPOSE_FILE" ]; then
    docker-compose -f $COMPOSE_FILE ps
else
    echo "⚠️ No compose file found"
fi

# Check disk space
echo ""
echo "💾 Disk Usage:"
df -h / | tail -1

# Check memory usage
echo ""
echo "🧠 Memory Usage:"
free -h

# Check load average
echo ""
echo "⚡ Load Average:"
uptime

echo ""
echo "Health check completed at \$(date)"
EOF

chmod +x /home/fks_user/health-check-${SERVER_TYPE}.sh
chown fks_user:fks_user /home/fks_user/health-check-${SERVER_TYPE}.sh

# Configure SSH for deployment user
log "INFO" "Configuring SSH access..."
mkdir -p /home/fks_user/.ssh
chmod 700 /home/fks_user/.ssh
chown fks_user:fks_user /home/fks_user/.ssh

# Configure firewall for server type
log "INFO" "Configuring firewall..."
# Install and configure ufw
pacman -S --noconfirm ufw

# Reset UFW to defaults
ufw --force reset

# Allow SSH
ufw allow ssh

# Allow Tailscale
ufw allow in on tailscale0

case "$SERVER_TYPE" in
    "auth")
        # Allow Authentik ports
        ufw allow 9000/tcp  # Authentik
        ufw allow 443/tcp   # HTTPS
        ufw allow 80/tcp    # HTTP (redirect to HTTPS)
        ;;
    "api")
        # Allow API and data service ports
        ufw allow 8000/tcp  # API
        ufw allow 9001/tcp  # Data service
        ufw allow 5432/tcp  # PostgreSQL (for internal connections)
        ufw allow 6379/tcp  # Redis (for internal connections)
        ;;
    "web")
        # Allow web service ports
        ufw allow 3000/tcp  # React dev server
        ufw allow 443/tcp   # HTTPS
        ufw allow 80/tcp    # HTTP
        ;;
esac

# Enable firewall
ufw --force enable

log "INFO" "✅ FKS $SERVER_TYPE server setup completed!"
log "INFO" "🔗 Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'Not available yet')"
log "INFO" "🔧 Use systemctl start fks_${SERVER_TYPE} to start services"
log "INFO" "🏥 Use /home/fks_user/health-check-${SERVER_TYPE}.sh for health checks"
