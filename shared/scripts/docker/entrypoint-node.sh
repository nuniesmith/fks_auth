#!/bin/bash
# =================================================================
# Node.js Service Entrypoint for React Web Service
# =================================================================

set -euo pipefail

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "🟢 Starting Node.js React Web Service..."

# Default environment variables
export NODE_ENV="${NODE_ENV:-development}"
export WEB_PORT="${WEB_PORT:-3000}"
export WEB_HOST="${WEB_HOST:-0.0.0.0}"
export REACT_APP_API_URL="${REACT_APP_API_URL:-http://localhost:8000}"

log "📋 Configuration:"
log "  - Node Environment: $NODE_ENV"
log "  - Web Port: $WEB_PORT"
log "  - Web Host: $WEB_HOST"
log "  - API URL: $REACT_APP_API_URL"

# Set working directory
cd /app/src/web/react || {
    log "❌ React app directory not found at /app/src/web/react"
    log "Available directories:"
    ls -la /app/src/ || true
    ls -la /app/src/web/ || true
    exit 1
}

log "📁 Working directory: $(pwd)"
log "📋 React app files:"
ls -la . || true

# Check if package.json exists
if [ ! -f "package.json" ]; then
    log "❌ package.json not found in React app directory"
    exit 1
fi

log "✅ Found package.json"

# Helper: robust installer with retries and fallbacks
try_npm_install() {
    local attempt=1
    local max_attempts=3

    # Ensure npm uses a clean, writable cache and sane network settings
    export npm_config_cache=/tmp/.npm
    mkdir -p /tmp/.npm
    npm config set registry https://registry.npmjs.org/ >/dev/null 2>&1 || true
    npm config set prefer-online true >/dev/null 2>&1 || true
    npm config set fetch-retries 5 >/dev/null 2>&1 || true
    npm config set fetch-timeout 600000 >/dev/null 2>&1 || true
    npm config set maxsockets 1 >/dev/null 2>&1 || true

    while [ $attempt -le $max_attempts ]; do
        log "📦 Installing dependencies (attempt ${attempt}/${max_attempts})..."

        if [ -f package-lock.json ] && [ $attempt -eq 1 ]; then
            # First attempt: clean deterministic install
            if [ "$(id -u)" != "0" ]; then
                npm ci --legacy-peer-deps --no-audit --no-fund && return 0
            else
                npm ci --legacy-peer-deps --no-audit --no-fund --unsafe-perm=true --allow-root && return 0
            fi
        else
            # Subsequent attempts or no lockfile
            if [ "$(id -u)" != "0" ]; then
                npm install --legacy-peer-deps --no-audit --no-fund --prefer-online --progress=false && return 0
            else
                npm install --legacy-peer-deps --no-audit --no-fund --prefer-online --progress=false --unsafe-perm=true --allow-root && return 0
            fi
        fi

        log "⚠️ npm install failed on attempt ${attempt}. Cleaning cache and preparing retry..."
        npm --version || true
        node --version || true

        # Clean npm cache and partial installs
        npm cache clean --force || true
        rm -rf node_modules 2>/dev/null || true

        # For attempts >=2, drop lockfile to refresh transitive deps
        if [ $attempt -ge 2 ] && [ -f package-lock.json ]; then
            log "🧹 Removing package-lock.json to avoid corrupt/incompatible pins"
            rm -f package-lock.json 2>/dev/null || true
        fi

        # Final attempt option: allow insecure npm (DEV ONLY) when explicitly enabled
        if [ $attempt -eq $max_attempts ] && [ "${ALLOW_INSECURE_NPM:-false}" = "true" ]; then
            log "🔓 Enabling temporary strict-ssl=false for final retry (DEV ONLY)"
            npm config set strict-ssl false >/dev/null 2>&1 || true
        fi

        attempt=$((attempt + 1))
        sleep 2
    done

    return 1
}

# Check if we need to fix permissions on node_modules
if [ -d "node_modules" ] && [ ! -w "node_modules" ]; then
    log "🔧 Fixing permissions on node_modules directory..."
    # If running as root, chown to appuser, otherwise try to make it writable
    if [ "$(id -u)" = "0" ]; then
        chown -R appuser:appuser node_modules || true
    else
        # Try to remove and recreate if we can't write
        rm -rf node_modules 2>/dev/null || log "   ⚠️  Could not remove existing node_modules (this is OK for named volumes)"
    fi
fi

# Install dependencies if node_modules doesn't exist or is empty
if [ ! -d "node_modules" ] || [ -z "$(ls -A node_modules 2>/dev/null)" ]; then
    log "📦 Installing React app dependencies (with retry logic)..."

    if try_npm_install; then
        log "✅ Dependencies installed successfully"
    else
        log "❌ Failed to install dependencies after multiple attempts"
        log "💡 Tip: set ALLOW_INSECURE_NPM=true to relax SSL checks for a final retry (development only)"
        exit 1
    fi

    # Fix ownership of node_modules if we're running as root
    if [ "$(id -u)" = "0" ] && [ -d node_modules ]; then
        chown -R 1000:1001 node_modules 2>/dev/null || true
    fi
else
    log "✅ Dependencies already installed"
fi

# Build React app for production if NODE_ENV is production
if [ "$NODE_ENV" = "production" ]; then
    log "🏗️ Building React app for production..."
    
    # Set build environment variables
    export REACT_APP_API_URL="$REACT_APP_API_URL"
    export TSC_COMPILE_ON_ERROR=true
    
    npm run build || {
        log "❌ Failed to build React app"
        exit 1
    }
    
    log "✅ React app built successfully"
    
    # Serve the built app using Vite's preview server
    log "🚀 Starting production server..."
    npm run preview -- --host="$WEB_HOST" --port="$WEB_PORT"
    
else
    log "🚀 Starting React development server..."
    
    # Set development environment variables for Vite
    export VITE_API_URL="$REACT_APP_API_URL"
    export VITE_VSCODE_URL="http://localhost:8081"
    export VITE_API_TIMEOUT="30000"
    export CHOKIDAR_USEPOLLING=true
    export ESLINT_NO_DEV_ERRORS=true
    export DISABLE_ESLINT_PLUGIN=true
    
    # Create writable cache directory if needed
    if [ -d "node_modules/.cache" ]; then
        chmod -R 777 node_modules/.cache || true
    fi
    
    # Start the Vite development server with specific host binding for HMR
    npm run dev -- --host="$WEB_HOST" --port="$WEB_PORT"
fi
