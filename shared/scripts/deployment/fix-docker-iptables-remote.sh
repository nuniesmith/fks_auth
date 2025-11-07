#!/bin/bash
# fix-docker-iptables-remote.sh - Fix Docker iptables issues on remote server

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Function to fix Docker iptables on remote server
fix_remote_docker_iptables() {
    local server="${1:-}"
    local user="${2:-fks_user}"
    
    if [ -z "$server" ]; then
        error "Server IP/hostname required"
        echo "Usage: $0 <server> [user]"
        exit 1
    fi
    
    log "🔧 Fixing Docker iptables on remote server: $server"
    
    # Create fix script
    cat > /tmp/fix-docker-iptables.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🔧 Starting Docker iptables fix..."

# Stop all Docker containers
echo "📦 Stopping all containers..."
docker stop $(docker ps -aq) 2>/dev/null || true

# Remove all Docker networks except default ones
echo "🌐 Removing custom networks..."
docker network prune -f
docker network ls --format '{{.Name}}' | grep -v -E '^(bridge|host|none)$' | xargs -r docker network rm 2>/dev/null || true

# Stop Docker service
echo "🛑 Stopping Docker service..."
sudo systemctl stop docker

# Clear all Docker-related iptables rules
echo "🧹 Clearing Docker iptables rules..."
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -F
sudo iptables -X

# Remove Docker chains if they exist
for chain in DOCKER DOCKER-ISOLATION-STAGE-1 DOCKER-ISOLATION-STAGE-2 DOCKER-USER; do
    sudo iptables -F $chain 2>/dev/null || true
    sudo iptables -X $chain 2>/dev/null || true
done

# Reset iptables to default
echo "🔄 Resetting iptables to default..."
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Start Docker service
echo "🚀 Starting Docker service..."
sudo systemctl start docker

# Wait for Docker to initialize
sleep 5

# Verify Docker iptables chains were recreated
echo "✅ Verifying Docker iptables chains..."
sudo iptables -L DOCKER -n >/dev/null 2>&1 && echo "✓ DOCKER chain exists" || echo "✗ DOCKER chain missing"
sudo iptables -L DOCKER-USER -n >/dev/null 2>&1 && echo "✓ DOCKER-USER chain exists" || echo "✗ DOCKER-USER chain missing"
sudo iptables -L DOCKER-ISOLATION-STAGE-1 -n >/dev/null 2>&1 && echo "✓ DOCKER-ISOLATION-STAGE-1 chain exists" || echo "✗ DOCKER-ISOLATION-STAGE-1 chain missing"

echo "✅ Docker iptables fix completed!"
EOF
    
    # Copy and execute the fix script on remote server
    log "📤 Copying fix script to remote server..."
    scp /tmp/fix-docker-iptables.sh ${user}@${server}:/tmp/
    
    log "🔧 Executing fix on remote server..."
    ssh ${user}@${server} "chmod +x /tmp/fix-docker-iptables.sh && bash /tmp/fix-docker-iptables.sh"
    
    # Clean up
    rm -f /tmp/fix-docker-iptables.sh
    ssh ${user}@${server} "rm -f /tmp/fix-docker-iptables.sh"
    
    log "✅ Docker iptables fix completed on remote server!"
    log ""
    log "📋 Next steps:"
    log "  1. Re-run your deployment script"
    log "  2. The Docker networks should now be created successfully"
    log ""
    log "💡 If the issue persists, you may need to:"
    log "  - Check firewall rules: sudo iptables -L -n"
    log "  - Restart the server: sudo reboot"
    log "  - Check Docker daemon logs: sudo journalctl -u docker -n 100"
}

# Main execution
main() {
    fix_remote_docker_iptables "$@"
}

main "$@"
