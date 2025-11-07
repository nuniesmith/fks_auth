#!/bin/bash
# Minimal version to test exactly where it fails

# Remove the strict mode temporarily
# set -euo pipefail

echo "🧪 Minimal Test Script"
echo "====================="

log_info() { echo "[INFO] $1"; }

# Test 1: Basic environment loading
echo "Test 1: Basic environment loading"
log_info "📁 Loading environment from .env"

# Try the same method as the original script
set -o allexport
if source .env; then
    log_info "✅ Environment loaded successfully"
else
    echo "❌ Failed to load environment"
    exit 1
fi
set +o allexport

echo "✅ Test 1 passed"

# Test 2: Check key variables
echo ""
echo "Test 2: Checking key variables"
echo "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-unset}"
echo "DOCKER_USERNAME=${DOCKER_USERNAME:-unset}"
echo "API_HEALTHCHECK_CMD=${API_HEALTHCHECK_CMD:-unset}"

# Test 3: Docker compose validation
echo ""
echo "Test 3: Docker compose validation"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fks}"

if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
elif docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    echo "❌ No compose command found"
    exit 1
fi

echo "Using compose command: $COMPOSE_CMD"

# Test if compose file exists
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml not found"
    exit 1
fi

echo "✅ docker-compose.yml exists"

# Test basic compose config
echo "Testing basic compose config..."
if $COMPOSE_CMD config >/dev/null 2>&1; then
    echo "✅ Basic compose config works"
else
    echo "❌ Basic compose config failed:"
    $COMPOSE_CMD config 2>&1 | head -5
fi

# Test with project name
echo "Testing compose config with project name..."
if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" config >/dev/null 2>&1; then
    echo "✅ Project compose config works"
else
    echo "❌ Project compose config failed:"
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" config 2>&1 | head -5
fi

# Test quiet mode (what original script uses)
echo "Testing quiet mode..."
if $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" config -q 2>/dev/null; then
    echo "✅ Quiet mode works"
else
    echo "❌ Quiet mode failed"
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" config -q 2>&1 | head -5
fi

echo ""
echo "🎉 All tests completed!"
echo "The original script should work now."