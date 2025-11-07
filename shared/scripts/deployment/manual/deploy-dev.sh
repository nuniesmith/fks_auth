#!/bin/bash

# =================================================================
# FKS Trading Systems - Manual Deployment Script
# =================================================================
# This script can be run manually on the development server
# for quick deployments when you don't want to use GitHub Actions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Default values
REPO_DIR="/home/jordan/fks"
BRANCH="main"
PULL_IMAGES=true
RESTART_SERVICES=true
FORCE_RESTART=false
SERVICES_TO_RESTART=""
CLEANUP=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--branch)
            BRANCH="$2"
            shift 2
            ;;
        --no-pull)
            PULL_IMAGES=false
            shift
            ;;
        --no-restart)
            RESTART_SERVICES=false
            shift
            ;;
        -f|--force)
            FORCE_RESTART=true
            shift
            ;;
        -s|--services)
            SERVICES_TO_RESTART="$2"
            shift 2
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        -h|--help)
            echo "FKS Trading Systems Deployment Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -b, --branch BRANCH     Git branch to deploy (default: main)"
            echo "  --no-pull              Skip pulling Docker images"
            echo "  --no-restart           Skip restarting services"
            echo "  -f, --force            Force restart even if no changes"
            echo "  -s, --services LIST    Comma-separated list of services to restart"
            echo "  --no-cleanup           Skip Docker cleanup"
            echo "  -h, --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Full deployment"
            echo "  $0 -b develop                        # Deploy develop branch"
            echo "  $0 -s api,web                        # Only restart api and web"
            echo "  $0 --no-pull -f                      # Force restart without pulling"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

log "Starting FKS Trading Systems deployment..."
log "Repository: $REPO_DIR"
log "Branch: $BRANCH"
log "Pull images: $PULL_IMAGES"
log "Restart services: $RESTART_SERVICES"
log "Force restart: $FORCE_RESTART"
log "Services to restart: ${SERVICES_TO_RESTART:-all}"
log "Cleanup: $CLEANUP"

# Check if we're in the right directory
if [ ! -d "$REPO_DIR" ]; then
    error "Repository directory $REPO_DIR not found!"
    exit 1
fi

cd "$REPO_DIR"

if [ ! -d ".git" ]; then
    error "Not a git repository in $REPO_DIR"
    exit 1
fi

# Store current commit
CURRENT_COMMIT=$(git rev-parse HEAD)
log "Current commit: $CURRENT_COMMIT"

# Update repository
log "Fetching latest changes..."
git fetch origin

# Check for updates
LATEST_COMMIT=$(git rev-parse origin/$BRANCH)
log "Latest commit on $BRANCH: $LATEST_COMMIT"

HAS_UPDATES=false
if [ "$CURRENT_COMMIT" != "$LATEST_COMMIT" ]; then
    HAS_UPDATES=true
    log "New commits found!"
    
    # Show what changed
    info "Changes since last deployment:"
    git log --oneline $CURRENT_COMMIT..$LATEST_COMMIT
    
    # Pull changes
    log "Pulling latest code..."
    git reset --hard origin/$BRANCH
    
    NEW_COMMIT=$(git rev-parse HEAD)
    log "Updated to commit: $NEW_COMMIT"
else
    info "No new commits found"
fi

# Pull Docker images if requested
NEW_IMAGES=false
if [ "$PULL_IMAGES" = true ]; then
    log "Pulling Docker images..."
    
    # Get list of current image IDs
    declare -A CURRENT_IMAGES
    SERVICES="api data worker app web ninja-dev ninja-python ninja-build-api"
    
    for service in $SERVICES; do
        CURRENT_IMAGES[$service]=$(docker images --format "{{.ID}}" nuniesmith/fks:${service}-latest 2>/dev/null || echo "")
    done
    
    # Pull latest images
    if docker compose pull; then
        # Check if any images were updated
        for service in $SERVICES; do
            NEW_IMAGE_ID=$(docker images --format "{{.ID}}" nuniesmith/fks:${service}-latest 2>/dev/null || echo "")
            if [ "${CURRENT_IMAGES[$service]}" != "$NEW_IMAGE_ID" ]; then
                log "New image pulled for $service"
                NEW_IMAGES=true
            fi
        done
        
        if [ "$NEW_IMAGES" = true ]; then
            log "New Docker images available"
        else
            info "No new Docker images"
        fi
    else
        warn "Failed to pull some Docker images"
    fi
fi

# Determine if we need to restart services
SHOULD_RESTART=false
if [ "$RESTART_SERVICES" = true ]; then
    if [ "$FORCE_RESTART" = true ]; then
        SHOULD_RESTART=true
        log "Force restart requested"
    elif [ "$HAS_UPDATES" = true ]; then
        SHOULD_RESTART=true
        log "Code updates detected, restart needed"
    elif [ "$NEW_IMAGES" = true ]; then
        SHOULD_RESTART=true
        log "New Docker images detected, restart needed"
    else
        info "No changes detected, skipping restart"
    fi
fi

if [ "$SHOULD_RESTART" = true ]; then
    # Get currently running services
    RUNNING_SERVICES=$(docker compose ps --services --filter "status=running" 2>/dev/null || echo "")
    
    if [ -n "$RUNNING_SERVICES" ]; then
        log "Currently running services: $RUNNING_SERVICES"
        
        # Stop services
        log "Stopping services..."
        docker compose down --timeout 30
        
        # Wait for cleanup
        sleep 5
    else
        info "No services currently running"
    fi
    
    # Cleanup if requested
    if [ "$CLEANUP" = true ]; then
        log "Cleaning up Docker resources..."
        docker system prune -f --volumes
    fi
    
    # Start services
    if [ -n "$SERVICES_TO_RESTART" ]; then
        log "Starting specific services: $SERVICES_TO_RESTART"
        # Convert comma-separated to space-separated
        SERVICES_LIST=$(echo "$SERVICES_TO_RESTART" | tr ',' ' ')
        docker compose up -d $SERVICES_LIST
    else
        log "Starting all services..."
        docker compose up -d
    fi
    
    # Wait for services to start
    log "Waiting for services to start..."
    sleep 15
    
    # Check status
    log "Service status:"
    docker compose ps
    
    # Check for failed services
    FAILED_SERVICES=$(docker compose ps --services --filter "status=exited" 2>/dev/null || echo "")
    if [ -n "$FAILED_SERVICES" ]; then
        error "Failed services detected: $FAILED_SERVICES"
        log "Failed service logs:"
        for service in $FAILED_SERVICES; do
            echo "=== $service logs ==="
            docker compose logs --tail=20 $service
        done
        exit 1
    fi
fi

# Final status
log "=== DEPLOYMENT SUMMARY ==="
log "Repository: $(git rev-parse HEAD)"
log "Branch: $BRANCH"
log "Has updates: $HAS_UPDATES"
log "New images: $NEW_IMAGES"
log "Services restarted: $SHOULD_RESTART"

if [ "$SHOULD_RESTART" = true ]; then
    log "Final service status:"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
fi

log "Deployment completed successfully!"

# Quick health check
info "Performing quick health check..."
sleep 5

if curl -f -s http://localhost:8000/health >/dev/null 2>&1; then
    log "✅ API service: Healthy"
else
    warn "❌ API service: Not responding"
fi

if curl -f -s http://localhost:3000 >/dev/null 2>&1; then
    log "✅ Web service: Healthy"
else
    warn "❌ Web service: Not responding"
fi

log "Health check completed!"
