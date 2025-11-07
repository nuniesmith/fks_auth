#!/bin/bash

# Auto-update script for FKS repository
# This script checks for updates from GitHub and restarts the application if needed
# Compatible with GitHub Actions Ubuntu runner (root user) and local execution

# Configuration - Auto-detect environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}"
USER_HOME="${HOME}"

# Function to log messages with timestamp (define early)
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$$] $1" | tee -a "$LOG_FILE"
}

# Detect if running as root (GitHub Actions runner)
if [ "$EUID" -eq 0 ]; then
    # Running as root - likely GitHub Actions
    LOG_FILE="${REPO_DIR}/logs/auto_update.log"
    LOCK_FILE="/tmp/auto_update_root.lock"
else
    # Running as regular user
    LOG_FILE="${REPO_DIR}/logs/auto_update.log"
    LOCK_FILE="/tmp/auto_update.lock"
fi

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Now we can safely use log function
if [ "$EUID" -eq 0 ]; then
    log "Running as root user (GitHub Actions mode)"
else
    log "Running as regular user"
fi

# Function to check if Docker is running
check_docker() {
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            log "Docker is running"
            return 0
        else
            log "Docker is installed but not running"
            return 1
        fi
    else
        log "Docker is not installed"
        return 1
    fi
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        log "Using docker-compose"
        echo "docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        log "Using docker compose (v2)"
        echo "docker compose"
    else
        log "ERROR: Neither docker-compose nor docker compose is available"
        return 1
    fi
}

# Function to stop Docker services
stop_docker_services() {
    local compose_cmd="$1"
    log "Stopping Docker services..."
    
    if [ -f "docker-compose.yml" ]; then
        $compose_cmd down --remove-orphans 2>&1 | tee -a "$LOG_FILE"
    else
        log "No docker-compose.yml found, skipping Docker stop"
    fi
}

# Function to start Docker services
start_docker_services() {
    local compose_cmd="$1"
    log "Starting Docker services..."
    
    if [ -f "docker-compose.yml" ]; then
        # Pull latest images
        log "Pulling latest Docker images..."
        $compose_cmd pull 2>&1 | tee -a "$LOG_FILE"
        
        # Start services
        log "Starting Docker containers..."
        $compose_cmd up -d --build 2>&1 | tee -a "$LOG_FILE"
        
        # Show status
        log "Docker services status:"
        $compose_cmd ps 2>&1 | tee -a "$LOG_FILE"
    else
        log "No docker-compose.yml found, skipping Docker start"
    fi
}

# Function to cleanup on exit
cleanup() {
    rm -f "$LOCK_FILE"
}

# Set up trap for cleanup
trap cleanup EXIT

# Check if script is already running
if [ -f "$LOCK_FILE" ]; then
    log "Auto-update script is already running. Exiting."
    exit 1
fi

# Create lock file
touch "$LOCK_FILE"

log "Starting auto-update check..."
log "Repository directory: $REPO_DIR"
log "Log file: $LOG_FILE"
log "Lock file: $LOCK_FILE"

# Check if deployment status manager is available
if [ -f "$REPO_DIR/scripts/deployment_status.sh" ]; then
    log "Using deployment status manager"
    "$REPO_DIR/scripts/deployment_status.sh" deploy
    exit $?
fi

# Continue with legacy deployment logic if status manager not available
log "Using legacy deployment logic"

# Change to repository directory
cd "$REPO_DIR" || {
    log "ERROR: Cannot change to repository directory: $REPO_DIR"
    exit 1
}

# Ensure we're in a git repository
if [ ! -d ".git" ]; then
    log "ERROR: Not a git repository. Current directory: $(pwd)"
    exit 1
fi

# Configure git for GitHub Actions environment
if [ "$EUID" -eq 0 ]; then
    log "Configuring git for GitHub Actions environment..."
    git config --global --add safe.directory "$REPO_DIR"
    git config --global user.email "actions_user@github.com"
    git config --global user.name "GitHub Actions"
fi

# Fetch latest changes from remote
log "Fetching latest changes from remote..."
git fetch origin main 2>&1 | tee -a "$LOG_FILE"

# Check if there are updates available
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse origin/main)

log "Local commit: $LOCAL_COMMIT"
log "Remote commit: $REMOTE_COMMIT"

if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
    log "Repository is up to date. No action needed."
    exit 0
fi

log "Updates found. Pulling latest changes..."

# Pull the latest changes
git pull origin main 2>&1 | tee -a "$LOG_FILE"

# Check if pull was successful
if [ $? -eq 0 ]; then
    log "Successfully pulled latest changes."
    
    # Make sure scripts are executable
    chmod +x "./start.sh" 2>/dev/null || true
    chmod +x "./auto_update.sh" 2>/dev/null || true
    
    # Check if Docker is available
    if check_docker; then
        # Get Docker Compose command
        if compose_cmd=$(check_docker_compose); then
            log "Using Docker for service management"
            
            # Stop existing services
            stop_docker_services "$compose_cmd"
            
            # Start services with latest code
            start_docker_services "$compose_cmd"
            
            log "Docker services restarted successfully"
        else
            log "ERROR: Docker Compose not available"
            exit 1
        fi
    else
        log "Docker not available, falling back to start.sh"
        
        # Kill any existing processes that might be running
        pkill -f "start.sh" || true
        sleep 2
        
        # Start the application
        if [ -f "./start.sh" ]; then
            log "Starting application with ./start.sh..."
            nohup ./start.sh >> "$LOG_FILE" 2>&1 &
            log "Application restart initiated with ./start.sh"
        else
            log "WARNING: start.sh not found, skipping application restart"
        fi
    fi
    
    log "Application restart completed."
else
    log "ERROR: Failed to pull latest changes."
    exit 1
fi

log "Auto-update process completed successfully."
