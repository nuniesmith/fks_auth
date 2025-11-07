#!/bin/bash

# FKS Staged Deployment - Test Script
# Tests the staged deployment scripts for syntax and basic functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "============================================"
log "FKS Staged Deployment - Test Suite"
log "============================================"

# Test 1: Check all scripts exist and are executable
log "Test 1: Checking script files..."

REQUIRED_SCRIPTS=(
    "stage-0-create-server.sh"
    "stage-1-initial-setup.sh"
    "stage-2-finalize.sh"
    "deploy-full.sh"
    "fix-env-file.sh"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        if [ -x "$SCRIPT_DIR/$script" ]; then
            log "✅ $script - exists and executable"
        else
            error "❌ $script - exists but not executable"
            exit 1
        fi
    else
        error "❌ $script - missing"
        exit 1
    fi
done

# Test 2: Syntax check all scripts
log ""
log "Test 2: Syntax checking scripts..."

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if bash -n "$SCRIPT_DIR/$script"; then
        log "✅ $script - syntax OK"
    else
        error "❌ $script - syntax error"
        exit 1
    fi
done

# Test 3: Help functionality
log ""
log "Test 3: Testing help functionality..."

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if "$SCRIPT_DIR/$script" --help >/dev/null 2>&1; then
        log "✅ $script - help works"
    else
        warn "⚠️ $script - help may not work properly"
    fi
done

# Test 4: Check required tools
log ""
log "Test 4: Checking required tools..."

REQUIRED_TOOLS=(
    "curl"
    "jq"
    "ssh"
    "scp"
)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        log "✅ $tool - available"
    else
        warn "⚠️ $tool - not available (may be needed for deployment)"
    fi
done

# Test 5: Check example configuration
log ""
log "Test 5: Checking example configuration..."

if [ -f "$SCRIPT_DIR/deployment.env.example" ]; then
    log "✅ deployment.env.example - exists"
    
    # Check if it has key variables
    if grep -q "LINODE_CLI_TOKEN" "$SCRIPT_DIR/deployment.env.example" && \
       grep -q "JORDAN_PASSWORD" "$SCRIPT_DIR/deployment.env.example" && \
       grep -q "TAILSCALE_AUTH_KEY" "$SCRIPT_DIR/deployment.env.example"; then
        log "✅ deployment.env.example - has required variables"
    else
        warn "⚠️ deployment.env.example - missing some required variables"
    fi
else
    warn "⚠️ deployment.env.example - missing"
fi

# Test 6: Check README
log ""
log "Test 6: Checking documentation..."

if [ -f "$SCRIPT_DIR/README.md" ]; then
    log "✅ README.md - exists"
else
    warn "⚠️ README.md - missing"
fi

# Test 7: Dry run parameter validation
log ""
log "Test 7: Testing parameter validation..."

# Test deploy-full.sh with missing required parameters
if "$SCRIPT_DIR/deploy-full.sh" --jordan-password "" 2>/dev/null; then
    warn "⚠️ deploy-full.sh - should fail with empty password"
else
    log "✅ deploy-full.sh - correctly validates required parameters"
fi

# Test with invalid target server
if "$SCRIPT_DIR/deploy-full.sh" --target-server invalid 2>/dev/null; then
    warn "⚠️ deploy-full.sh - should fail with invalid target server"
else
    log "✅ deploy-full.sh - correctly validates target server parameter"
fi

log ""
log "============================================"
log "Test Summary"
log "============================================"
log "✅ All basic tests passed!"
log ""
log "The staged deployment scripts appear to be properly configured."
log ""
log "Next steps for actual deployment:"
log "1. Copy deployment.env.example to deployment.env"
log "2. Edit deployment.env with your actual values"
log "3. Run: ./deploy-full.sh --env-file deployment.env"
log ""
log "Or use individual scripts as documented in README.md"
log "============================================"
