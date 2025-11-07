#!/bin/bash

# Test script for auto_update.sh
# This script helps verify that the auto_update script works correctly

echo "=== FKS Auto Update Test Script ==="
echo "Testing auto_update.sh functionality..."

# Test 1: Check if script exists and is executable
echo ""
echo "Test 1: Checking if auto_update.sh exists and is executable..."
if [ -f "./auto_update.sh" ]; then
    echo "✓ auto_update.sh exists"
    if [ -x "./auto_update.sh" ]; then
        echo "✓ auto_update.sh is executable"
    else
        echo "✗ auto_update.sh is not executable"
        echo "  Run: chmod +x ./auto_update.sh"
    fi
else
    echo "✗ auto_update.sh not found"
    exit 1
fi

# Test 2: Check git repository
echo ""
echo "Test 2: Checking git repository..."
if [ -d ".git" ]; then
    echo "✓ Git repository detected"
    current_branch=$(git branch --show-current)
    echo "  Current branch: $current_branch"
    
    # Check if we can fetch from remote
    if git fetch --dry-run origin main 2>/dev/null; then
        echo "✓ Can connect to remote repository"
    else
        echo "✗ Cannot connect to remote repository"
        echo "  Check your internet connection and git configuration"
    fi
else
    echo "✗ Not a git repository"
    exit 1
fi

# Test 3: Check Docker availability
echo ""
echo "Test 3: Checking Docker availability..."
if command -v docker >/dev/null 2>&1; then
    echo "✓ Docker is installed"
    if docker info >/dev/null 2>&1; then
        echo "✓ Docker is running"
    else
        echo "✗ Docker is not running"
        echo "  Run: sudo systemctl start docker"
    fi
else
    echo "✗ Docker is not installed"
    echo "  Install Docker to use container-based deployment"
fi

# Test 4: Check Docker Compose
echo ""
echo "Test 4: Checking Docker Compose..."
if command -v docker-compose >/dev/null 2>&1; then
    echo "✓ docker-compose is available"
    compose_version=$(docker-compose --version)
    echo "  Version: $compose_version"
elif docker compose version >/dev/null 2>&1; then
    echo "✓ docker compose (v2) is available"
    compose_version=$(docker compose version)
    echo "  Version: $compose_version"
else
    echo "✗ Neither docker-compose nor docker compose is available"
    echo "  Install Docker Compose for container management"
fi

# Test 5: Check docker-compose.yml
echo ""
echo "Test 5: Checking docker-compose.yml..."
if [ -f "docker-compose.yml" ]; then
    echo "✓ docker-compose.yml exists"
    # Basic validation
    if docker-compose config >/dev/null 2>&1 || docker compose config >/dev/null 2>&1; then
        echo "✓ docker-compose.yml is valid"
    else
        echo "✗ docker-compose.yml has syntax errors"
        echo "  Run: docker-compose config"
    fi
else
    echo "✗ docker-compose.yml not found"
    echo "  Create a docker-compose.yml file for container deployment"
fi

# Test 6: Check start.sh
echo ""
echo "Test 6: Checking start.sh..."
if [ -f "./start.sh" ]; then
    echo "✓ start.sh exists"
    if [ -x "./start.sh" ]; then
        echo "✓ start.sh is executable"
    else
        echo "✗ start.sh is not executable"
        echo "  Run: chmod +x ./start.sh"
    fi
else
    echo "! start.sh not found (optional - used as fallback)"
fi

# Test 7: Check logs directory
echo ""
echo "Test 7: Checking logs directory..."
if [ -d "logs" ]; then
    echo "✓ logs directory exists"
else
    echo "! logs directory doesn't exist (will be created automatically)"
fi

# Test 8: Check permissions
echo ""
echo "Test 8: Checking permissions..."
if [ -w "." ]; then
    echo "✓ Current directory is writable"
else
    echo "✗ Current directory is not writable"
    echo "  Check file permissions and ownership"
fi

# Test 9: Environment detection
echo ""
echo "Test 9: Environment detection..."
if [ "$EUID" -eq 0 ]; then
    echo "✓ Running as root (GitHub Actions mode)"
else
    echo "✓ Running as regular user"
fi

# Test 10: Dry run test
echo ""
echo "Test 10: Dry run test..."
echo "This would run: ./auto_update.sh --dry-run (if implemented)"
echo "For now, you can test manually by running: ./auto_update.sh"

# Summary
echo ""
echo "=== Test Summary ==="
echo "If all tests passed, your auto_update.sh should work correctly."
echo "To test the full deployment:"
echo "1. Run: ./auto_update.sh"
echo "2. Check logs: tail -f logs/auto_update.log"
echo "3. Verify services: docker-compose ps"
echo ""
echo "For GitHub Actions deployment:"
echo "1. Set up SERVER_HOST and SERVER_SSH_KEY secrets"
echo "2. Push to main branch"
echo "3. Monitor in GitHub Actions tab"
echo ""
echo "Test completed at $(date)"
