#!/bin/bash

# FKS Trading Systems - Manual Deployment Script
# Quick script to deploy to the dev server when GitHub Actions skips deployment

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
log_info() { echo -e "${BLUE}ℹ️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_error() { echo -e "${RED}❌ [$(date +'%H:%M:%S')] $1${NC}"; }

# Default values
TARGET_HOST=""
TARGET_USER="fks_user"
REPO_DIR="/home/fks_user/fks"
FORCE_PULL=false
VERBOSE=false

# Usage function
usage() {
    cat << EOF
FKS Manual Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
  --host HOST              Target server hostname/IP (required)
  --user USER              SSH user (default: fks_user)
  --repo-dir DIR           Repository directory (default: /home/fks_user/fks)
  --force-pull             Force git pull even if working directory is dirty
  --verbose                Enable verbose output
  --help                   Show this help message

EXAMPLES:
  # Deploy to dev server
  $0 --host dev.fkstrading.xyz

#!/usr/bin/env bash
# Shim: manual-deploy moved to deployment/manual/manual-deploy.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/deployment/manual/manual-deploy.sh"
if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
    log_error "Please ensure:"
    log_error "  1. Server is accessible"
    log_error "  2. SSH keys are configured or password authentication is enabled"
    log_error "  3. User $TARGET_USER exists on the server"
    exit 1
fi

log "✅ SSH connectivity confirmed"

# Function to run commands on remote server
run_remote() {
    local cmd="$1"
    log_info "Running: $cmd"
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "$cmd"
}

# Check if repository exists
log_info "Checking repository status..."
if ! run_remote "test -d '$REPO_DIR'" 2>/dev/null; then
    log_warning "Repository directory $REPO_DIR does not exist"
    log_info "Cloning repository..."
    
    # Create parent directory and clone
    run_remote "mkdir -p $(dirname '$REPO_DIR')"
    
    if ! run_remote "git clone https://github.com/nuniesmith/fks.git '$REPO_DIR'"; then
        log_error "Failed to clone repository"
        exit 1
    fi
    
    log "✅ Repository cloned successfully"
else
    log "✅ Repository directory exists"
fi

# Update repository
log_info "Updating repository..."
run_remote "cd '$REPO_DIR' && pwd"

# Check for uncommitted changes
if [ "$FORCE_PULL" = false ]; then
    log_info "Checking for uncommitted changes..."
    if run_remote "cd '$REPO_DIR' && git status --porcelain" | grep -q .; then
        log_warning "Repository has uncommitted changes:"
        run_remote "cd '$REPO_DIR' && git status --short"
        log_warning "Use --force-pull to override, or commit/stash changes first"
        exit 1
    fi
fi

# Fetch and update
log_info "Fetching latest changes..."
run_remote "cd '$REPO_DIR' && git fetch origin"

if [ "$FORCE_PULL" = true ]; then
    log_warning "Force pulling (will overwrite local changes)..."
    run_remote "cd '$REPO_DIR' && git reset --hard origin/main"
else
    log_info "Pulling latest changes..."
    run_remote "cd '$REPO_DIR' && git pull origin main"
fi

log "✅ Repository updated successfully"

# Check for start script
log_info "Checking deployment method..."
if run_remote "cd '$REPO_DIR' && test -f start.sh"; then
    log_info "Found start.sh script"
    
    # Make executable and run
    log_info "Making start.sh executable..."
    run_remote "cd '$REPO_DIR' && chmod +x start.sh"
    
    log_info "Running start.sh..."
    if run_remote "cd '$REPO_DIR' && ./start.sh"; then
        log "✅ Services deployed via start.sh"
    else
        log_error "start.sh failed"
        exit 1
    fi
    
elif run_remote "cd '$REPO_DIR' && test -f docker-compose.yml"; then
    log_info "Found docker-compose.yml"
    
    # Stop, pull, and restart services
    log_info "Stopping existing services..."
    run_remote "cd '$REPO_DIR' && (docker compose down --timeout 30 2>/dev/null || docker-compose down --timeout 30 2>/dev/null || true)"
    
    log_info "Pulling latest Docker images..."
    if ! run_remote "cd '$REPO_DIR' && (docker compose pull 2>/dev/null || docker-compose pull 2>/dev/null)"; then
        log_warning "Docker pull failed, continuing with existing images..."
    fi
    
    log_info "Starting services..."
    if run_remote "cd '$REPO_DIR' && (docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null)"; then
        log "✅ Services deployed via docker-compose"
    else
        log_error "docker-compose up failed"
        exit 1
    fi
    
else
    log_error "No deployment configuration found (no start.sh or docker-compose.yml)"
    exit 1
fi

# Wait for services to start
log_info "Waiting for services to initialize..."
sleep 10

# Check service status
log_info "Checking service status..."
if run_remote "cd '$REPO_DIR' && (docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null || docker ps)"; then
    log "✅ Service status check completed"
else
    log_warning "Could not check service status"
fi

log "🎉 Manual deployment completed successfully!"

# Show access information
echo ""
log_info "🌐 Access Information:"
log_info "  SSH: ssh $TARGET_USER@$TARGET_HOST"
log_info "  Web Interface: http://$TARGET_HOST:3000"
log_info "  VNC Web: http://$TARGET_HOST:6080"
log_info "  API: http://$TARGET_HOST:8002"

echo ""
log_info "📋 Next Steps:"
log_info "  1. Test the web interfaces"
log_info "  2. Check service logs: ssh $TARGET_USER@$TARGET_HOST 'cd $REPO_DIR && docker compose logs -f'"
log_info "  3. Monitor system resources"
