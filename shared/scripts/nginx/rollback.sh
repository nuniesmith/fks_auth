#!/bin/bash
# scripts/rollback.sh - Intelligent rollback script

set -euo pipefail

# Configuration
DEPLOY_DIR="/opt/nginx-deployment"
BACKUP_DIR="/opt/backups/deployments"
NGINX_DIR="/etc/nginx"
WEB_DIR="/var/www/html"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }

# List available backups
list_backups() {
    echo "Available backups:"
    echo "=================="
    
    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
        error "No backups found!"
        exit 1
    fi
    
    # List backups with details
    for backup in $(ls -t "$BACKUP_DIR"); do
        if [ -d "$BACKUP_DIR/$backup" ]; then
            timestamp=$(echo "$backup" | grep -oE '[0-9]{8}-[0-9]{6}' || echo "unknown")
            commit=$(cat "$BACKUP_DIR/$backup/commit.txt" 2>/dev/null || echo "unknown")
            size=$(du -sh "$BACKUP_DIR/$backup" | cut -f1)
            
            echo "  📁 $backup"
            echo "     Timestamp: $timestamp"
            echo "     Commit:    $commit"
            echo "     Size:      $size"
            echo ""
        fi
    done
}

# Validate backup
validate_backup() {
    local backup_name="$1"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if [ ! -d "$backup_path" ]; then
        error "Backup not found: $backup_name"
        return 1
    fi
    
    # Check required directories
    for dir in nginx html; do
        if [ ! -d "$backup_path/$dir" ]; then
            error "Backup missing $dir directory"
            return 1
        fi
    done
    
    # Validate nginx configuration
    if ! nginx -t -c "$backup_path/nginx/nginx.conf" 2>/dev/null; then
        warning "Nginx configuration in backup may have issues"
    fi
    
    return 0
}

# Perform rollback
perform_rollback() {
    local backup_name="$1"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log "Starting rollback to: $backup_name"
    
    # Create current backup before rollback
    local safety_backup="rollback-safety-$(date +%Y%m%d-%H%M%S)"
    log "Creating safety backup: $safety_backup"
    
    mkdir -p "$BACKUP_DIR/$safety_backup"
    cp -r "$NGINX_DIR" "$BACKUP_DIR/$safety_backup/nginx"
    cp -r "$WEB_DIR" "$BACKUP_DIR/$safety_backup/html"
    
    # Stop nginx
    log "Stopping nginx..."
    systemctl stop nginx
    
    # Restore files
    log "Restoring nginx configuration..."
    rm -rf "$NGINX_DIR.old"
    mv "$NGINX_DIR" "$NGINX_DIR.old"
    cp -r "$backup_path/nginx" "$NGINX_DIR"
    
    log "Restoring web files..."
    rm -rf "$WEB_DIR.old"
    mv "$WEB_DIR" "$WEB_DIR.old"
    cp -r "$backup_path/html" "$WEB_DIR"
    
    # Set permissions
    chown -R nginx:nginx "$WEB_DIR"
    find "$WEB_DIR" -type d -exec chmod 755 {} \;
    find "$WEB_DIR" -type f -exec chmod 644 {} \;
    
    # Test configuration
    log "Testing nginx configuration..."
    if ! nginx -t; then
        error "Nginx configuration test failed!"
        
        # Attempt to restore from safety backup
        warning "Attempting to restore from safety backup..."
        rm -rf "$NGINX_DIR"
        cp -r "$BACKUP_DIR/$safety_backup/nginx" "$NGINX_DIR"
        rm -rf "$WEB_DIR"
        cp -r "$BACKUP_DIR/$safety_backup/html" "$WEB_DIR"
        
        if nginx -t; then
            success "Restored from safety backup"
        else
            error "Critical: Unable to restore working configuration!"
            exit 1
        fi
    fi
    
    # Start nginx
    log "Starting nginx..."
    systemctl start nginx
    
    # Verify nginx is running
    sleep 2
    if systemctl is-active --quiet nginx; then
        success "Nginx started successfully"
    else
        error "Nginx failed to start!"
        systemctl status nginx
        exit 1
    fi
    
    # Health check
    log "Performing health check..."
    if curl -sf http://localhost/health > /dev/null; then
        success "Health check passed"
    else
        warning "Health check failed"
    fi
    
    # Update rollback log
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) - Rolled back to $backup_name" >> "$BACKUP_DIR/rollback.log"
    
    # Clean up old directories
    rm -rf "$NGINX_DIR.old" "$WEB_DIR.old"
    
    success "Rollback completed successfully!"
}

# Interactive mode
interactive_rollback() {
    list_backups
    
    echo -n "Enter backup name to rollback to (or 'latest' for most recent): "
    read backup_choice
    
    if [ "$backup_choice" = "latest" ]; then
        backup_choice=$(ls -t "$BACKUP_DIR" | head -n1)
        log "Selected latest backup: $backup_choice"
    fi
    
    if ! validate_backup "$backup_choice"; then
        exit 1
    fi
    
    echo -n "Are you sure you want to rollback to $backup_choice? (yes/no): "
    read confirmation
    
    if [ "$confirmation" != "yes" ]; then
        warning "Rollback cancelled"
        exit 0
    fi
    
    perform_rollback "$backup_choice"
}

# Main
case "${1:-interactive}" in
    list)
        list_backups
        ;;
    validate)
        if [ -z "${2:-}" ]; then
            error "Usage: $0 validate <backup-name>"
            exit 1
        fi
        validate_backup "$2"
        ;;
    rollback)
        if [ -z "${2:-}" ]; then
            error "Usage: $0 rollback <backup-name>"
            exit 1
        fi
        validate_backup "$2" && perform_rollback "$2"
        ;;
    interactive|*)
        interactive_rollback
        ;;
esac