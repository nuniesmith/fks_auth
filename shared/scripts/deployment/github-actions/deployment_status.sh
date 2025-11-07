#!/bin/bash

# Deployment Status Manager
# This script manages deployment phases and server state tracking

LOCK_FILE="/tmp/deployment_status.lock"
STATUS_FILE="/tmp/deployment_status.json"
LOG_FILE="/root/fks/logs/deployment_status.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to create lock
create_lock() {
    echo $$ > "$LOCK_FILE"
}

# Function to remove lock
remove_lock() {
    rm -f "$LOCK_FILE"
}

# Function to check if locked
is_locked() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Locked
        else
            rm -f "$LOCK_FILE"  # Remove stale lock
            return 1  # Not locked
        fi
    fi
    return 1  # Not locked
}

# Function to update deployment status
update_status() {
    local phase="$1"
    local status="$2"
    local message="$3"
    
    cat > "$STATUS_FILE" << EOF
{
    "phase": "$phase",
    "status": "$status",
    "message": "$message",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "pid": $$
}
EOF
    
    log "Status updated: $phase - $status - $message"
}

# Function to get current status
get_status() {
    if [ -f "$STATUS_FILE" ]; then
        cat "$STATUS_FILE"
    else
        echo '{"phase": "unknown", "status": "unknown", "message": "No status file found"}'
    fi
}

# Function to wait for server readiness
wait_for_server_ready() {
    local max_wait=300  # 5 minutes
    local wait_time=0
    
    log "Waiting for server to be ready for deployment..."
    
    while [ $wait_time -lt $max_wait ]; do
        if [ ! -f "/tmp/server_setup_in_progress" ]; then
            log "Server is ready for deployment"
            return 0
        fi
        
        log "Server setup still in progress, waiting... ($wait_time/$max_wait seconds)"
        sleep 10
        wait_time=$((wait_time + 10))
    done
    
    log "Timeout waiting for server readiness"
    return 1
}

# Function to handle server setup phase
handle_setup_phase() {
    update_status "setup" "in_progress" "Server setup initiated"
    
    # Create setup lock
    touch "/tmp/server_setup_in_progress"
    
    # Your existing server setup logic here
    log "Server setup phase completed"
    
    # Remove setup lock
    rm -f "/tmp/server_setup_in_progress"
    
    update_status "setup" "completed" "Server setup completed successfully"
}

# Function to handle deployment phase
handle_deployment_phase() {
    update_status "deployment" "in_progress" "Application deployment initiated"
    
    # Wait for server to be ready
    if ! wait_for_server_ready; then
        update_status "deployment" "failed" "Server not ready for deployment"
        return 1
    fi
    
    # Run the actual deployment
    if [ -f "/root/fks/auto_update.sh" ]; then
        cd /root/fks
        if ./auto_update.sh; then
            update_status "deployment" "completed" "Application deployment completed successfully"
            return 0
        else
            update_status "deployment" "failed" "Auto update script failed"
            return 1
        fi
    else
        update_status "deployment" "failed" "Auto update script not found"
        return 1
    fi
}

# Function to handle cleanup phase
handle_cleanup_phase() {
    update_status "cleanup" "in_progress" "Cleanup initiated"
    
    # Remove all lock files
    rm -f "/tmp/server_setup_in_progress"
    rm -f "/tmp/auto_update*.lock"
    
    # Stop any running services gracefully
    if [ -f "/root/fks/docker-compose.yml" ]; then
        cd /root/fks
        if command -v docker-compose >/dev/null 2>&1; then
            docker-compose down --remove-orphans || true
        elif docker compose version >/dev/null 2>&1; then
            docker compose down --remove-orphans || true
        fi
    fi
    
    update_status "cleanup" "completed" "Cleanup completed successfully"
}

# Main function
main() {
    local action="$1"
    
    # Check if already locked
    if is_locked; then
        log "Deployment status manager is already running"
        exit 1
    fi
    
    # Create lock
    create_lock
    trap remove_lock EXIT
    
    case "$action" in
        "setup")
            handle_setup_phase
            ;;
        "deploy")
            handle_deployment_phase
            ;;
        "cleanup")
            handle_cleanup_phase
            ;;
        "status")
            get_status
            ;;
        "wait")
            wait_for_server_ready
            ;;
        *)
            echo "Usage: $0 {setup|deploy|cleanup|status|wait}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
