#!/bin/bash

# FKS Trading Systems - Stage 2: Finalize Setup with Docker Deployment
# This script runs after Stage 1 reboot to complete the server setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a /var/log/fks_stage2.log
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a /var/log/fks_stage2.log
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a /var/log/fks_stage2.log
}

# Start logging
log "============================================"
log "Starting FKS Trading Systems Setup - Stage 2"
log "============================================"

# Read environment variables
if [ -f /root/.fks_env ]; then
    source /root/.fks_env
else
    error "Environment file not found!"
    exit 1
fi

# Function to fix Docker iptables
fix_docker_iptables() {
    log "Checking Docker iptables configuration..."
    
    # Ensure Docker is running
    if ! systemctl is-active --quiet docker; then
        log "Starting Docker service..."
        systemctl start docker
        sleep 5
    fi
    
    # Check if Docker iptables chains exist
    if ! iptables -L DOCKER-FORWARD -n &>/dev/null; then
        warn "Docker iptables chains missing. Restarting Docker..."
        systemctl restart docker
        sleep 10
        
        # Verify fix
        if iptables -L DOCKER-FORWARD -n &>/dev/null; then
            log "✅ Docker iptables chains restored"
        else
            error "Failed to restore Docker iptables chains"
            return 1
        fi
    else
        log "✅ Docker iptables chains are properly configured"
    fi
}

# Function to setup Tailscale
setup_tailscale() {
    if [ -n "$TAILSCALE_AUTH_KEY" ]; then
        log "Setting up Tailscale VPN..."
        
        # Enable IP forwarding for Tailscale
        echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf
        echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-tailscale.conf
        sysctl -p /etc/sysctl.d/99-tailscale.conf
        
        # Authenticate with Tailscale
        tailscale up --authkey "$TAILSCALE_AUTH_KEY" --ssh --accept-routes --accept-dns=false
        
        # Get Tailscale IP
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "Not available")
        log "✅ Tailscale configured. IP: $TAILSCALE_IP"
    else
        warn "Tailscale auth key not provided, skipping VPN setup"
    fi
}

# Function to configure firewall
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Basic security rules
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Docker services
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
    
    # Tailscale
    iptables -A INPUT -p udp --dport 41641 -j ACCEPT
    iptables -A INPUT -i tailscale+ -j ACCEPT
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/iptables.rules
    
    log "✅ Firewall configured"
}

# Function to clone/update FKS repository
setup_fks_repository() {
    log "Setting up FKS repository..."
    
    FKS_DIR="/home/fks_user/fks"
    
    if [ ! -d "$FKS_DIR" ]; then
        log "Cloning FKS repository..."
        sudo -u fks_user git clone https://github.com/nuniesmith/fks.git "$FKS_DIR"
    else
        log "Updating existing FKS repository..."
        sudo -u fks_user bash -c "cd $FKS_DIR && git pull"
    fi
    
    # Set proper permissions
    chmod -R 755 "$FKS_DIR"
    chown -R fks_user:fks_user "$FKS_DIR"
    
    log "✅ FKS repository ready"
}

# Function to setup Docker authentication
setup_docker_auth() {
    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_TOKEN" ]; then
        log "Setting up Docker Hub authentication..."
        
        # Login for root
        echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
        
        # Setup for fks_user
        sudo -u fks_user bash << DOCKER_AUTH
        mkdir -p ~/.docker
        echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
DOCKER_AUTH
        
        log "✅ Docker Hub authentication configured"
    else
        warn "Docker Hub credentials not provided"
    fi
}

# Function to deploy FKS application
deploy_fks_application() {
    log "Deploying FKS application..."
    
    FKS_DIR="/home/fks_user/fks"
    
    # Check if .env exists
    if [ ! -f "$FKS_DIR/.env" ]; then
        warn ".env file not found. Creating from example..."
        if [ -f "$FKS_DIR/.env.example" ]; then
            sudo -u fks_user cp "$FKS_DIR/.env.example" "$FKS_DIR/.env"
        else
            error "No .env or .env.example found!"
            return 1
        fi
    fi
    
    # Deploy using start.sh script if available
    if [ -f "$FKS_DIR/start.sh" ]; then
        log "Using start.sh script..."
        cd "$FKS_DIR"
        sudo -u fks_user ./start.sh
    else
        # Fallback to docker compose
        log "Using docker compose directly..."
        sudo -u fks_user bash << 'DEPLOY'
        cd /home/fks_user/fks
        
        # Stop any existing containers
        docker compose down --remove-orphans 2>/dev/null || true
        
        # Pull latest images
        echo "Pulling latest images..."
        docker compose pull
        
        # Start services
        echo "Starting services..."
        docker compose up -d
        
        # Wait for initialization
        sleep 20
        
        # Show status
        docker compose ps
DEPLOY
    fi
    
    log "✅ FKS application deployment completed"
}

# Function to setup monitoring
setup_monitoring() {
    if [ -n "$NETDATA_CLAIM_TOKEN" ] && [ -n "$NETDATA_CLAIM_ROOM" ]; then
        log "Setting up Netdata monitoring..."
        
        # Install Netdata if not present
        if ! command -v netdata &>/dev/null; then
            bash <(curl -Ss https://get.netdata.cloud/kickstart.sh) --dont-wait --stable-channel
        fi
        
        # Claim to Netdata Cloud
        netdata-claim.sh -token="$NETDATA_CLAIM_TOKEN" -rooms="$NETDATA_CLAIM_ROOM" -url="https://app.netdata.cloud"
        
        log "✅ Netdata monitoring configured"
    else
        warn "Netdata credentials not provided, skipping monitoring setup"
    fi
}

# Main execution
main() {
    # Fix Docker iptables first
    fix_docker_iptables
    
    # Setup Tailscale VPN
    setup_tailscale
    
    # Configure firewall
    configure_firewall
    
    # Setup Docker authentication
    setup_docker_auth
    
    # Setup FKS repository
    setup_fks_repository
    
    # Deploy FKS application
    deploy_fks_application
    
    # Setup monitoring
    setup_monitoring
    
    # Mark completion
    touch /root/.fks_stage2-complete
    echo "$(date): Stage 2 completed successfully" >> /root/.fks_stage2-complete
    
    # Disable this service
    systemctl disable fks_stage2.service
    
    log "============================================"
    log "✅ Stage 2 completed successfully!"
    log "============================================"
    log "Server is ready for use!"
    
    if [ -n "$TAILSCALE_IP" ]; then
        log "Tailscale IP: $TAILSCALE_IP"
        log "SSH via Tailscale: ssh jordan@$TAILSCALE_IP"
    fi
    
    log "Web Interface: http://$(hostname -I | awk '{print $1}')"
    log "API: http://$(hostname -I | awk '{print $1}'):8000"
}

# Run main function
main "$@"
