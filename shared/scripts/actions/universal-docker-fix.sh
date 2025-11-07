#!/bin/bash
# Universal Docker Compose Fix Script
# Works across nginx, FKS, and ATS projects

set -e

echo "🔧 Universal Docker Compose Fix"
echo "==============================="

# Function to detect and fix Docker Compose issues
fix_docker_compose() {
    echo "🔍 Detecting Docker Compose setup..."
    
    # Check if Docker Compose V2 (plugin) is available
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "✅ Docker Compose V2 (plugin) detected: $(docker compose version)"
        export COMPOSE_CMD="docker compose"
        return 0
    fi
    
    # Check if Docker Compose V1 (standalone) is available
    if command -v docker-compose >/dev/null 2>&1; then
        echo "✅ Docker Compose V1 (standalone) detected: $(docker-compose --version)"
        export COMPOSE_CMD="docker-compose"
        return 0
    fi
    
    # No Docker Compose found, attempt to install
    echo "❌ No Docker Compose found, attempting installation..."
    
    # Install Docker Compose plugin
    echo "📦 Installing Docker Compose plugin..."
    mkdir -p ~/.docker/cli-plugins/
    
    # Download latest Docker Compose
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    echo "⬇️ Downloading Docker Compose ${COMPOSE_VERSION}..."
    
    curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
        -o ~/.docker/cli-plugins/docker-compose
    
    chmod +x ~/.docker/cli-plugins/docker-compose
    
    # Verify installation
    if docker compose version >/dev/null 2>&1; then
        echo "✅ Docker Compose plugin installed successfully"
        export COMPOSE_CMD="docker compose"
        return 0
    fi
    
    # Fallback: Install standalone docker-compose
    echo "📦 Installing standalone docker-compose as fallback..."
    sudo curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    
    if docker-compose --version >/dev/null 2>&1; then
        echo "✅ Standalone docker-compose installed successfully"
        export COMPOSE_CMD="docker-compose"
        return 0
    fi
    
    echo "❌ Failed to install Docker Compose"
    return 1
}

# Function to fix Docker networking issues (common across all projects)
fix_docker_networking() {
    echo "🌐 Checking Docker networking..."
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        echo "❌ Docker daemon not running"
        return 1
    fi
    
    # Check if Docker iptables chains exist
    if ! sudo iptables -t nat -L DOCKER >/dev/null 2>&1; then
        echo "⚠️ Docker iptables chains missing, performing reset..."
        
        # Stop Docker
        sudo systemctl stop docker docker.socket || true
        
        # Clean up iptables
        sudo iptables -t nat -F DOCKER 2>/dev/null || true
        sudo iptables -t filter -F DOCKER 2>/dev/null || true
        sudo iptables -t nat -X DOCKER 2>/dev/null || true
        sudo iptables -t filter -X DOCKER 2>/dev/null || true
        
        # Clean up network interfaces
        for interface in $(ip link show | grep br- | cut -d: -f2 | tr -d " " 2>/dev/null || true); do
            echo "  Removing bridge: $interface"
            sudo ip link delete "$interface" 2>/dev/null || true
        done
        
        # Restart Docker
        sudo systemctl start docker.socket docker
        sleep 10
        
        echo "✅ Docker networking reset completed"
    else
        echo "✅ Docker networking is healthy"
    fi
}

# Function to test Docker Compose with a simple service
test_docker_compose() {
    echo "🧪 Testing Docker Compose functionality..."
    
    # Create a temporary compose file
    cat > /tmp/test-compose.yml << 'EOF'
services:
  test:
    image: alpine:latest
    command: echo "Docker Compose test successful"
EOF
    
    # Test the compose command
    if $COMPOSE_CMD -f /tmp/test-compose.yml run --rm test; then
        echo "✅ Docker Compose test successful"
        rm -f /tmp/test-compose.yml
        return 0
    else
        echo "❌ Docker Compose test failed"
        rm -f /tmp/test-compose.yml
        return 1
    fi
}

# Main execution
main() {
    echo "🚀 Starting universal Docker Compose fix..."
    
    # Fix Docker Compose availability
    if ! fix_docker_compose; then
        echo "❌ Failed to fix Docker Compose"
        exit 1
    fi
    
    # Fix Docker networking
    if ! fix_docker_networking; then
        echo "❌ Failed to fix Docker networking"
        exit 1
    fi
    
    # Test functionality
    if ! test_docker_compose; then
        echo "❌ Docker Compose test failed"
        exit 1
    fi
    
    echo ""
    echo "🎉 Universal Docker fix completed successfully!"
    echo "   Compose command: $COMPOSE_CMD"
    echo "   Usage: $COMPOSE_CMD --version"
    echo ""
}

# Export the compose command for other scripts to use
export_compose_cmd() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        echo ""
    fi
}

# If script is called with 'detect' argument, just return the command
if [[ "${1:-}" == "detect" ]]; then
    export_compose_cmd
else
    main "$@"
fi
