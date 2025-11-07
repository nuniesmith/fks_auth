#!/bin/bash

# Stop just the API services
echo "🛑 Stopping FKS API Services..."

# Function to kill process by PID if it exists
kill_if_exists() {
    local pid=$1
    local name=$2
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "   Stopping $name (PID: $pid)..."
        kill "$pid" 2>/dev/null
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
        fi
    else
        echo "   $name not running"
    fi
}

# Stop services from API PID file
if [ -f ".api-pids" ]; then
    echo "📋 Reading API process IDs..."
    API_PIDS=($(cat .api-pids))
    if [ ${#API_PIDS[@]} -ge 2 ]; then
        kill_if_exists "${API_PIDS[0]}" "Python API"
        kill_if_exists "${API_PIDS[1]}" "VS Code Proxy"
    fi
    rm -f .api-pids
else
    echo "📋 No .api-pids file found, checking ports..."
    # Kill processes on API ports
    for port in 8002 8081; do
        PID=$(lsof -ti:$port 2>/dev/null)
        if [ -n "$PID" ]; then
            echo "   Killing process on port $port (PID: $PID)..."
            kill "$PID" 2>/dev/null
        fi
    done
fi

echo "✅ API services stopped!"
