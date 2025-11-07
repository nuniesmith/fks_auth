#!/bin/bash

# Quick start script for just the API services
# Run with: bash start-api-servers.sh or wsl bash start-api-servers.sh

echo "🚀 Starting FKS API Services..."

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  Port $port is already in use"
        return 1
    fi
    return 0
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=15
    local attempt=1
    
    echo "⏳ Waiting for $name to be ready..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo "✅ $name is ready!"
            return 0
        fi
        sleep 1
        ((attempt++))
    done
    echo "❌ $name failed to start within $max_attempts seconds"
    return 1
}

# Install Node.js dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing Node.js dependencies..."
    npm install express cors http-proxy-middleware
fi

# Start Python API server
echo "🐍 Starting Python API server..."
cd python || { echo "❌ Python directory not found"; exit 1; }

if ! check_port 8002; then
    echo "❌ Port 8002 is busy. Stop the existing service first."
    exit 1
fi

python3 main.py &
PYTHON_PID=$!
echo "   Python API PID: $PYTHON_PID"
cd ..

# Start VS Code server proxy  
echo "🖥️  Starting VS Code proxy server..."
if ! check_port 8081; then
    echo "❌ Port 8081 is busy. Stop the existing service first."
    kill $PYTHON_PID 2>/dev/null
    exit 1
fi

node vscode-proxy.js &
PROXY_PID=$!
echo "   VS Code Proxy PID: $PROXY_PID"

# Wait for services to be ready
wait_for_service "http://localhost:8002/healthz" "Python API"
wait_for_service "http://localhost:8081/healthz" "VS Code Proxy"

# Save PIDs for cleanup
echo "$PYTHON_PID" > .api-pids
echo "$PROXY_PID" >> .api-pids

echo ""
echo "✅ API Services started successfully!"
echo ""
echo "📍 Service URLs:"
echo "   Python API Health:    http://localhost:8002/healthz"
echo "   VS Code Proxy Health: http://localhost:8081/healthz"
echo ""
echo "💡 Next steps:"
echo "   1. Start your React app: cd web && npm start"
echo "   2. Or use Docker: docker-compose up"
echo ""
echo "🛑 To stop API services: bash stop-api-servers.sh"
