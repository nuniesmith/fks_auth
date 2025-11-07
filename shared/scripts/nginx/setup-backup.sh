#!/bin/bash
# setup-backup.sh - Automated backup system setup
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-backup"
readonly SCRIPT_VERSION="3.0.0"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# BACKUP CONFIGURATION
# ============================================================================
setup_backup_directories() {
    log "Setting up backup directories..."
    
    local dirs=(
        "/opt/backups/system"
        "/opt/backups/nginx"
        "/opt/backups/ssl"
        "/opt/backups/database"
        "/opt/backups/logs"
        "/opt/backups/scripts"
        "/var/log/backups"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done
    
    # Set proper ownership
    chown -R root:root /opt/backups
    chmod 750 /opt/backups
    
    success "Backup directories created"
}

# ============================================================================
# BACKUP SCRIPTS
# ============================================================================
create_main_backup_script() {
    log "Creating main backup script..."
    
    cat > /opt/backups/backup-system.sh << 'EOF'
#!/bin/bash
# Comprehensive backup script for 7gram Dashboard
# Version: 3.0.0

set -euo pipefail

# Configuration
BACKUP_BASE_DIR="/opt/backups"
LOG_FILE="/var/log/backups/backup-$(date +%Y%m%d).log"
RETENTION_DAYS=30
MAX_BACKUP_SIZE="2G"
COMPRESSION_LEVEL=6

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging setup
mkdir -p "$(dirname "$LOG_FILE")"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Load configuration
load_config() {
    if [[ -f "/etc/nginx-automation/deployment-config.json" ]]; then
        DOMAIN_NAME=$(jq -r '.domain // "7gram.xyz"' "/etc/nginx-automation/deployment-config.json" 2>/dev/null || echo "7gram.xyz")
        GITHUB_REPO=$(jq -r '.github.repository // "nuniesmith/nginx"' "/etc/nginx-automation/deployment-config.json" 2>/dev/null || echo "nuniesmith/nginx")
    else
        DOMAIN_NAME="7gram.xyz"
        GITHUB_REPO="nuniesmith/nginx"
    fi
}

# Create backup manifest
create_manifest() {
    local backup_dir="$1"
    local manifest_file="$backup_dir/MANIFEST.json"
    
    cat > "$manifest_file" << EOL
{
    "backup_info": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "hostname": "$(hostname)",
        "domain": "$DOMAIN_NAME",
        "backup_version": "3.0.0",
        "backup_type": "full_system"
    },
    "system_info": {
        "os": "$(lsb_release -ds 2>/dev/null || echo 'Unknown')",
        "kernel": "$(uname -r)",
        "uptime": "$(uptime -p)"
    },
    "backup_contents": {
        "nginx_config": "$([ -d /etc/nginx ] && echo 'included' || echo 'not_found')",
        "web_content": "$([ -d /var/www/html ] && echo 'included' || echo 'not_found')",
        "ssl_certificates": "$([ -d /etc/letsencrypt ] && echo 'included' || echo 'not_found')",
        "system_config": "$([ -d /etc/systemd ] && echo 'included' || echo 'not_found')",
        "deployment_config": "$([ -d /etc/nginx-automation ] && echo 'included' || echo 'not_found')"
    }
}
EOL
}

# Backup NGINX configuration
backup_nginx() {
    local backup_dir="$1/nginx"
    mkdir -p "$backup_dir"
    
    log "Backing up NGINX configuration..."
    
    if [[ -d "/etc/nginx" ]]; then
        cp -r /etc/nginx "$backup_dir/" 2>/dev/null || {
            error "Failed to backup NGINX configuration"
            return 1
        }
        
        # Test configuration backup
        if nginx -t -c "$backup_dir/nginx/nginx.conf" 2>/dev/null; then
            success "NGINX configuration backup verified"
        else
            warning "NGINX configuration backup may be invalid"
        fi
    else
        warning "NGINX configuration directory not found"
        return 1
    fi
    
    return 0
}

# Backup web content
backup_web_content() {
    local backup_dir="$1/web"
    mkdir -p "$backup_dir"
    
    log "Backing up web content..."
    
    if [[ -d "/var/www/html" ]]; then
        # Calculate size first
        local size
        size=$(du -sh /var/www/html | cut -f1)
        log "Web content size: $size"
        
        cp -r /var/www/html "$backup_dir/" 2>/dev/null || {
            error "Failed to backup web content"
            return 1
        }
        success "Web content backup completed"
    else
        warning "Web content directory not found"
        return 1
    fi
    
    return 0
}

# Backup SSL certificates
backup_ssl_certificates() {
    local backup_dir="$1/ssl"
    mkdir -p "$backup_dir"
    
    log "Backing up SSL certificates..."
    
    if [[ -d "/etc/letsencrypt" ]]; then
        cp -r /etc/letsencrypt "$backup_dir/" 2>/dev/null || {
            error "Failed to backup SSL certificates"
            return 1
        }
        
        # List certificates in backup
        if command -v certbot &>/dev/null; then
            certbot certificates > "$backup_dir/certificate-list.txt" 2>/dev/null || true
        fi
        
        success "SSL certificates backup completed"
    else
        warning "SSL certificates directory not found"
    fi
    
    return 0
}

# Backup system configuration
backup_system_config() {
    local backup_dir="$1/system"
    mkdir -p "$backup_dir"
    
    log "Backing up system configuration..."
    
    # Important system files
    local config_files=(
        "/etc/systemd/system"
        "/etc/cron.d"
        "/etc/sudoers.d"
        "/etc/hosts"
        "/etc/hostname"
        "/etc/passwd"
        "/etc/group"
        "/etc/shadow"
        "/etc/gshadow"
        "/etc/fstab"
        "/etc/nginx-automation"
    )
    
    for config in "${config_files[@]}"; do
        if [[ -e "$config" ]]; then
            local dest_dir="$backup_dir$(dirname "$config")"
            mkdir -p "$dest_dir"
            cp -r "$config" "$dest_dir/" 2>/dev/null || {
                warning "Failed to backup $config"
            }
        fi
    done
    
    # Save package list
    pacman -Qq > "$backup_dir/installed-packages.txt" 2>/dev/null || true
    
    # Save service status
    systemctl list-units --type=service --state=enabled --no-pager > "$backup_dir/enabled-services.txt" 2>/dev/null || true
    
    success "System configuration backup completed"
}

# Backup deployment and repository
backup_deployment() {
    local backup_dir="$1/deployment"
    mkdir -p "$backup_dir"
    
    log "Backing up deployment configuration..."
    
    # Backup deployment directory
    if [[ -d "/opt/nginx-deployment" ]]; then
        cp -r /opt/nginx-deployment "$backup_dir/" 2>/dev/null || {
            warning "Failed to backup deployment directory"
        }
    fi
    
    # Backup previous deployment backups (metadata only)
    if [[ -d "/opt/backups/deployments" ]]; then
        find /opt/backups/deployments -name "metadata.json" -exec cp {} "$backup_dir/" \; 2>/dev/null || true
    fi
    
    success "Deployment backup completed"
}

# Backup logs
backup_logs() {
    local backup_dir="$1/logs"
    mkdir -p "$backup_dir"
    
    log "Backing up important logs..."
    
    # Important log directories
    local log_dirs=(
        "/var/log/nginx"
        "/var/log/linode-setup"
        "/var/log/monitoring"
        "/var/log/backups"
    )
    
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            local dest_name=$(basename "$log_dir")
            cp -r "$log_dir" "$backup_dir/$dest_name" 2>/dev/null || {
                warning "Failed to backup logs from $log_dir"
            }
        fi
    done
    
    # System logs (recent only)
    journalctl --since="7 days ago" --no-pager > "$backup_dir/systemd-journal.log" 2>/dev/null || true
    
    success "Logs backup completed"
}

# Create compressed archive
create_archive() {
    local backup_dir="$1"
    local archive_name="$2"
    
    log "Creating compressed archive: $archive_name"
    
    cd "$(dirname "$backup_dir")"
    local backup_dirname=$(basename "$backup_dir")
    
    # Create tar.gz archive
    if tar -czf "$archive_name" "$backup_dirname" 2>/dev/null; then
        # Verify archive
        if tar -tzf "$archive_name" >/dev/null 2>&1; then
            local archive_size
            archive_size=$(du -sh "$archive_name" | cut -f1)
            success "Archive created successfully: $archive_name ($archive_size)"
            
            # Remove uncompressed backup directory
            rm -rf "$backup_dir"
            
            return 0
        else
            error "Archive verification failed"
            return 1
        fi
    else
        error "Failed to create archive"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
    
    local cleanup_dirs=("system" "nginx" "ssl" "database" "logs")
    local removed_count=0
    
    for dir in "${cleanup_dirs[@]}"; do
        local backup_path="$BACKUP_BASE_DIR/$dir"
        if [[ -d "$backup_path" ]]; then
            # Remove files older than retention period
            local old_files
            old_files=$(find "$backup_path" -name "*.tar.gz" -mtime +$RETENTION_DAYS 2>/dev/null)
            
            if [[ -n "$old_files" ]]; then
                echo "$old_files" | while read -r file; do
                    if [[ -f "$file" ]]; then
                        rm -f "$file"
                        ((removed_count++))
                        log "Removed old backup: $(basename "$file")"
                    fi
                done
            fi
        fi
    done
    
    if [[ $removed_count -gt 0 ]]; then
        success "Cleaned up $removed_count old backup files"
    else
        log "No old backups to clean up"
    fi
}

# Check backup integrity
verify_backup() {
    local archive_path="$1"
    
    log "Verifying backup integrity: $(basename "$archive_path")"
    
    # Check if file exists and is readable
    if [[ ! -f "$archive_path" ]]; then
        error "Backup file not found: $archive_path"
        return 1
    fi
    
    # Verify tar archive
    if tar -tzf "$archive_path" >/dev/null 2>&1; then
        success "Backup integrity verified"
        return 0
    else
        error "Backup integrity check failed"
        return 1
    fi
}

# Send backup notification
send_backup_notification() {
    local status="$1"
    local message="$2"
    local backup_size="${3:-unknown}"
    
    # Load Discord webhook from config
    local webhook_url=""
    if [[ -f "/etc/nginx-automation/deployment-config.json" ]]; then
        webhook_url=$(jq -r '.discord_webhook // empty' "/etc/nginx-automation/deployment-config.json" 2>/dev/null)
    fi
    
    if [[ -n "$webhook_url" ]]; then
        local color="3066993"  # Green
        local emoji="✅"
        
        if [[ "$status" != "success" ]]; then
            color="15158332"  # Red
            emoji="❌"
        fi
        
        local notification="$emoji Backup Report - $(hostname)

**Status:** $status
**Size:** $backup_size
**Timestamp:** $(date)
**Domain:** $DOMAIN_NAME

$message"
        
        curl -s -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"Backup Report\",\"description\":\"$notification\",\"color\":$color}]}" \
            "$webhook_url" >/dev/null 2>&1 || true
    fi
}

# Main backup function
perform_full_backup() {
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_name="full-backup-$timestamp"
    local backup_dir="$BACKUP_BASE_DIR/system/$backup_name"
    local archive_path="$BACKUP_BASE_DIR/system/${backup_name}.tar.gz"
    
    log "Starting full system backup: $backup_name"
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    # Load configuration
    load_config
    
    # Create manifest
    create_manifest "$backup_dir"
    
    # Perform individual backups
    local backup_status=0
    local backup_components=()
    
    if backup_nginx "$backup_dir"; then
        backup_components+=("NGINX configuration")
    else
        ((backup_status++))
    fi
    
    if backup_web_content "$backup_dir"; then
        backup_components+=("Web content")
    else
        ((backup_status++))
    fi
    
    if backup_ssl_certificates "$backup_dir"; then
        backup_components+=("SSL certificates")
    else
        ((backup_status++))
    fi
    
    if backup_system_config "$backup_dir"; then
        backup_components+=("System configuration")
    else
        ((backup_status++))
    fi
    
    if backup_deployment "$backup_dir"; then
        backup_components+=("Deployment configuration")
    else
        ((backup_status++))
    fi
    
    if backup_logs "$backup_dir"; then
        backup_components+=("System logs")
    else
        ((backup_status++))
    fi
    
    # Create archive
    if create_archive "$backup_dir" "$archive_path"; then
        # Verify backup
        if verify_backup "$archive_path"; then
            local backup_size
            backup_size=$(du -sh "$archive_path" | cut -f1)
            
            success "Full backup completed successfully"
            log "Backup location: $archive_path"
            log "Backup size: $backup_size"
            log "Components backed up: ${backup_components[*]}"
            
            # Send success notification
            send_backup_notification "success" "Full backup completed successfully. Components: ${backup_components[*]}" "$backup_size"
            
            # Cleanup old backups
            cleanup_old_backups
            
            return 0
        else
            error "Backup verification failed"
            send_backup_notification "failed" "Backup verification failed" "unknown"
            return 1
        fi
    else
        error "Failed to create backup archive"
        send_backup_notification "failed" "Failed to create backup archive" "unknown"
        return 1
    fi
}

# Quick backup function (configuration only)
perform_quick_backup() {
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_name="quick-backup-$timestamp"
    local backup_dir="$BACKUP_BASE_DIR/nginx/$backup_name"
    local archive_path="$BACKUP_BASE_DIR/nginx/${backup_name}.tar.gz"
    
    log "Starting quick backup: $backup_name"
    
    mkdir -p "$backup_dir"
    load_config
    
    # Backup only essential configuration
    local backup_status=0
    
    if backup_nginx "$backup_dir"; then
        success "Quick backup: NGINX configuration backed up"
    else
        ((backup_status++))
    fi
    
    # Backup deployment configuration
    if [[ -d "/etc/nginx-automation" ]]; then
        cp -r /etc/nginx-automation "$backup_dir/" 2>/dev/null || ((backup_status++))
    fi
    
    # Create manifest
    create_manifest "$backup_dir"
    
    # Create archive
    if create_archive "$backup_dir" "$archive_path"; then
        local backup_size
        backup_size=$(du -sh "$archive_path" | cut -f1)
        success "Quick backup completed: $archive_path ($backup_size)"
        return 0
    else
        error "Quick backup failed"
        return 1
    fi
}

# Restore function
restore_backup() {
    local archive_path="$1"
    local restore_dir="${2:-/tmp/restore-$(date +%s)}"
    
    log "Restoring backup from: $archive_path"
    log "Restore directory: $restore_dir"
    
    # Verify backup first
    if ! verify_backup "$archive_path"; then
        error "Backup verification failed, cannot restore"
        return 1
    fi
    
    # Create restore directory
    mkdir -p "$restore_dir"
    
    # Extract archive
    if tar -xzf "$archive_path" -C "$restore_dir"; then
        success "Backup extracted to: $restore_dir"
        
        # Show restore instructions
        echo ""
        echo "Backup restored to: $restore_dir"
        echo ""
        echo "To complete the restore process:"
        echo "1. Review the extracted files"
        echo "2. Manually copy configurations as needed"
        echo "3. Restart services after restore"
        echo ""
        echo "Example restore commands:"
        echo "  sudo cp -r $restore_dir/*/nginx/nginx /etc/"
        echo "  sudo cp -r $restore_dir/*/web/html /var/www/"
        echo "  sudo systemctl restart nginx"
        
        return 0
    else
        error "Failed to extract backup"
        return 1
    fi
}

# List available backups
list_backups() {
    echo "Available Backups:"
    echo "=================="
    
    local backup_types=("system" "nginx" "ssl" "database" "logs")
    
    for backup_type in "${backup_types[@]}"; do
        local backup_path="$BACKUP_BASE_DIR/$backup_type"
        if [[ -d "$backup_path" ]]; then
            echo ""
            echo "$backup_type backups:"
            find "$backup_path" -name "*.tar.gz" -printf '%T+ %s %p\n' 2>/dev/null | \
                sort -r | head -10 | while read -r date size path; do
                local human_size
                human_size=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null || echo "$size bytes")
                echo "  $(basename "$path") - $date - $human_size"
            done
        fi
    done
}

# Usage information
show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  full                    - Perform full system backup (default)"
    echo "  quick                   - Perform quick configuration backup"
    echo "  restore <archive>       - Restore from backup archive"
    echo "  list                    - List available backups"
    echo "  verify <archive>        - Verify backup integrity"
    echo "  cleanup                 - Clean up old backups"
    echo ""
    echo "Examples:"
    echo "  $0 full                                    # Full backup"
    echo "  $0 quick                                   # Quick backup"
    echo "  $0 restore /opt/backups/system/backup.tar.gz"
    echo "  $0 verify /opt/backups/system/backup.tar.gz"
}

# Main execution
main() {
    local command="${1:-full}"
    
    case "$command" in
        full)
            perform_full_backup
            ;;
        quick)
            perform_quick_backup
            ;;
        restore)
            if [[ -z "${2:-}" ]]; then
                error "Archive path required for restore"
                show_usage
                exit 1
            fi
            restore_backup "$2" "${3:-}"
            ;;
        verify)
            if [[ -z "${2:-}" ]]; then
                error "Archive path required for verification"
                show_usage
                exit 1
            fi
            verify_backup "$2"
            ;;
        list)
            list_backups
            ;;
        cleanup)
            cleanup_old_backups
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    chmod +x /opt/backups/backup-system.sh
    
    success "Main backup script created"
}

create_incremental_backup_script() {
    log "Creating incremental backup script..."
    
    cat > /opt/backups/backup-incremental.sh << 'EOF'
#!/bin/bash
# Incremental backup script using rsync

set -euo pipefail

BACKUP_BASE="/opt/backups/incremental"
SOURCE_DIRS=("/etc/nginx" "/var/www/html" "/etc/nginx-automation" "/opt/nginx-deployment")
LOG_FILE="/var/log/backups/incremental-$(date +%Y%m%d).log"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$(dirname "$LOG_FILE")"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

perform_incremental_backup() {
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_dir="$BACKUP_BASE/$timestamp"
    local link_dir="$BACKUP_BASE/latest"
    
    log "Starting incremental backup: $timestamp"
    
    mkdir -p "$backup_dir"
    
    for source_dir in "${SOURCE_DIRS[@]}"; do
        if [[ -d "$source_dir" ]]; then
            local dest_name=$(basename "$source_dir")
            log "Backing up: $source_dir"
            
            # Use rsync with hard links for space efficiency
            rsync -av --delete --link-dest="$link_dir/$dest_name" \
                "$source_dir/" "$backup_dir/$dest_name/" || {
                error "Failed to backup $source_dir"
            }
        else
            log "Skipping non-existent directory: $source_dir"
        fi
    done
    
    # Update latest link
    rm -f "$link_dir"
    ln -sf "$backup_dir" "$link_dir"
    
    # Create backup info
    cat > "$backup_dir/backup-info.txt" << EOL
Incremental Backup Information
==============================
Timestamp: $(date)
Hostname: $(hostname)
Backup Directory: $backup_dir
Source Directories: ${SOURCE_DIRS[*]}

Disk Usage:
$(du -sh "$backup_dir")
EOL
    
    success "Incremental backup completed: $backup_dir"
    
    # Cleanup old incremental backups (keep 14 days)
    find "$BACKUP_BASE" -maxdepth 1 -type d -name "20*" -mtime +14 -exec rm -rf {} \; 2>/dev/null || true
}

perform_incremental_backup
EOF
    
    chmod +x /opt/backups/backup-incremental.sh
    
    success "Incremental backup script created"
}

create_backup_restore_script() {
    log "Creating backup restore script..."
    
    cat > /opt/backups/restore-backup.sh << 'EOF'
#!/bin/bash
# Interactive backup restore script

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

show_available_backups() {
    echo "Available Backup Archives:"
    echo "=========================="
    
    local count=0
    find /opt/backups -name "*.tar.gz" -printf '%T+ %s %p\n' 2>/dev/null | \
        sort -r | while read -r date size path; do
        ((count++))
        local human_size
        human_size=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null || echo "$size bytes")
        echo "[$count] $(basename "$path") - $(date -d "${date%.*}" '+%Y-%m-%d %H:%M') - $human_size"
        echo "    Path: $path"
        
        # Show backup type from path
        local backup_type
        if [[ "$path" =~ /system/ ]]; then
            backup_type="Full System Backup"
        elif [[ "$path" =~ /nginx/ ]]; then
            backup_type="NGINX Configuration Backup"
        elif [[ "$path" =~ /ssl/ ]]; then
            backup_type="SSL Certificate Backup"
        else
            backup_type="Unknown"
        fi
        echo "    Type: $backup_type"
        echo ""
    done
}

interactive_restore() {
    echo "7gram Dashboard Backup Restore"
    echo "=============================="
    echo ""
    
    show_available_backups
    
    echo "Please enter the full path to the backup archive you want to restore:"
    read -r backup_path
    
    if [[ ! -f "$backup_path" ]]; then
        error "Backup file not found: $backup_path"
        exit 1
    fi
    
    echo ""
    warning "WARNING: This will restore the backup and may overwrite current configuration!"
    echo "Current NGINX configuration will be backed up before restore."
    echo ""
    echo "Backup to restore: $(basename "$backup_path")"
    echo "Archive size: $(du -sh "$backup_path" | cut -f1)"
    echo ""
    
    read -p "Do you want to proceed? (yes/NO): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log "Restore cancelled by user"
        exit 0
    fi
    
    # Create safety backup of current state
    log "Creating safety backup of current configuration..."
    /opt/backups/backup-system.sh quick
    
    # Perform restore
    log "Extracting backup archive..."
    local restore_dir="/tmp/restore-$(date +%s)"
    mkdir -p "$restore_dir"
    
    if tar -xzf "$backup_path" -C "$restore_dir"; then
        success "Backup extracted to: $restore_dir"
        
        # Find the backup directory (it might be nested)
        local backup_content_dir
        backup_content_dir=$(find "$restore_dir" -type d -name "*backup*" | head -n1)
        
        if [[ -z "$backup_content_dir" ]]; then
            backup_content_dir="$restore_dir"
        fi
        
        echo ""
        echo "Backup contents:"
        ls -la "$backup_content_dir"
        echo ""
        
        # Interactive restore of components
        if [[ -d "$backup_content_dir/nginx" ]]; then
            read -p "Restore NGINX configuration? (y/N): " restore_nginx
            if [[ "$restore_nginx" =~ ^[Yy] ]]; then
                log "Restoring NGINX configuration..."
                sudo cp -r "$backup_content_dir/nginx/nginx/"* /etc/nginx/ 2>/dev/null || {
                    error "Failed to restore NGINX configuration"
                }
                
                if nginx -t; then
                    success "NGINX configuration restored and verified"
                else
                    error "NGINX configuration test failed after restore"
                    read -p "Continue anyway? (y/N): " continue_anyway
                    if [[ ! "$continue_anyway" =~ ^[Yy] ]]; then
                        exit 1
                    fi
                fi
            fi
        fi
        
        if [[ -d "$backup_content_dir/web" ]]; then
            read -p "Restore web content? (y/N): " restore_web
            if [[ "$restore_web" =~ ^[Yy] ]]; then
                log "Restoring web content..."
                sudo cp -r "$backup_content_dir/web/html/"* /var/www/html/ 2>/dev/null || {
                    error "Failed to restore web content"
                }
                sudo chown -R http:http /var/www/html
                success "Web content restored"
            fi
        fi
        
        if [[ -d "$backup_content_dir/ssl" ]]; then
            read -p "Restore SSL certificates? (y/N): " restore_ssl
            if [[ "$restore_ssl" =~ ^[Yy] ]]; then
                warning "Restoring SSL certificates requires careful consideration"
                echo "This will overwrite current certificates and may cause service interruption"
                read -p "Are you sure? (yes/NO): " ssl_confirm
                if [[ "$ssl_confirm" == "yes" ]]; then
                    log "Restoring SSL certificates..."
                    sudo cp -r "$backup_content_dir/ssl/letsencrypt/"* /etc/letsencrypt/ 2>/dev/null || {
                        error "Failed to restore SSL certificates"
                    }
                    success "SSL certificates restored"
                fi
            fi
        fi
        
        # Restart services
        echo ""
        read -p "Restart NGINX service? (Y/n): " restart_nginx
        if [[ ! "$restart_nginx" =~ ^[Nn] ]]; then
            log "Restarting NGINX..."
            if sudo systemctl restart nginx; then
                success "NGINX restarted successfully"
            else
                error "Failed to restart NGINX"
            fi
        fi
        
        # Cleanup
        echo ""
        read -p "Remove temporary restore files? (Y/n): " cleanup
        if [[ ! "$cleanup" =~ ^[Nn] ]]; then
            rm -rf "$restore_dir"
            success "Temporary files cleaned up"
        else
            log "Temporary files kept at: $restore_dir"
        fi
        
        success "Restore process completed!"
        
    else
        error "Failed to extract backup archive"
        exit 1
    fi
}

# Command line mode
if [[ $# -gt 0 ]]; then
    backup_path="$1"
    if [[ ! -f "$backup_path" ]]; then
        error "Backup file not found: $backup_path"
        exit 1
    fi
    
    log "Performing non-interactive restore of: $backup_path"
    /opt/backups/backup-system.sh restore "$backup_path"
else
    interactive_restore
fi
EOF
    
    chmod +x /opt/backups/restore-backup.sh
    
    success "Backup restore script created"
}

# ============================================================================
# BACKUP SCHEDULING
# ============================================================================
setup_backup_scheduling() {
    log "Setting up backup scheduling..."
    
    # Add backup jobs to cron
    local cron_jobs=(
        "0 2 * * 0 /opt/backups/backup-system.sh full >/dev/null 2>&1"           # Weekly full backup
        "0 3 * * 1-6 /opt/backups/backup-system.sh quick >/dev/null 2>&1"       # Daily quick backup
        "*/15 * * * * /opt/backups/backup-incremental.sh >/dev/null 2>&1"       # 15-minute incremental
    )
    
    for job in "${cron_jobs[@]}"; do
        (crontab -l 2>/dev/null; echo "$job") | crontab -
    done
    
    success "Backup scheduling configured"
    log "Schedule:"
    log "  - Full backup: Weekly (Sunday 2:00 AM)"
    log "  - Quick backup: Daily (3:00 AM, Monday-Saturday)"
    log "  - Incremental backup: Every 15 minutes"
}

create_backup_monitoring() {
    log "Creating backup monitoring script..."
    
    cat > /opt/backups/monitor-backups.sh << 'EOF'
#!/bin/bash
# Backup monitoring and verification script

set -euo pipefail

LOG_FILE="/var/log/backups/monitor-$(date +%Y%m%d).log"
mkdir -p "$(dirname "$LOG_FILE")"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }

check_backup_health() {
    log "Checking backup system health..."
    
    local issues=0
    
    # Check backup directories
    local required_dirs=("/opt/backups/system" "/opt/backups/nginx" "/var/log/backups")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            error "Required backup directory missing: $dir"
            ((issues++))
        else
            success "Backup directory exists: $dir"
        fi
    done
    
    # Check recent backups
    local cutoff_time=$(($(date +%s) - 86400))  # 24 hours ago
    local recent_backups
    recent_backups=$(find /opt/backups -name "*.tar.gz" -newermt "@$cutoff_time" 2>/dev/null | wc -l)
    
    if [[ $recent_backups -gt 0 ]]; then
        success "Found $recent_backups recent backup(s)"
    else
        error "No recent backups found (last 24 hours)"
        ((issues++))
    fi
    
    # Check backup scripts
    local scripts=("/opt/backups/backup-system.sh" "/opt/backups/backup-incremental.sh")
    for script in "${scripts[@]}"; do
        if [[ -x "$script" ]]; then
            success "Backup script executable: $script"
        else
            error "Backup script missing or not executable: $script"
            ((issues++))
        fi
    done
    
    # Check disk space
    local backup_usage
    backup_usage=$(du -s /opt/backups 2>/dev/null | awk '{print $1}' || echo 0)
    local backup_usage_gb=$((backup_usage / 1024 / 1024))
    
    log "Backup storage usage: ${backup_usage_gb}GB"
    
    if [[ $backup_usage_gb -gt 5 ]]; then
        warning "Backup storage usage is high: ${backup_usage_gb}GB"
    fi
    
    # Test latest backup integrity
    local latest_backup
    latest_backup=$(find /opt/backups -name "*.tar.gz" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
    
    if [[ -n "$latest_backup" ]]; then
        log "Testing latest backup integrity: $(basename "$latest_backup")"
        if tar -tzf "$latest_backup" >/dev/null 2>&1; then
            success "Latest backup integrity verified"
        else
            error "Latest backup integrity check failed"
            ((issues++))
        fi
    fi
    
    # Send notification if issues found
    if [[ $issues -gt 0 ]]; then
        send_backup_alert "$issues"
        return 1
    else
        success "Backup system health check passed"
        return 0
    fi
}

send_backup_alert() {
    local issue_count="$1"
    
    # Load Discord webhook from config
    local webhook_url=""
    if [[ -f "/etc/nginx-automation/deployment-config.json" ]]; then
        webhook_url=$(jq -r '.discord_webhook // empty' "/etc/nginx-automation/deployment-config.json" 2>/dev/null)
    fi
    
    if [[ -n "$webhook_url" ]]; then
        local message="🚨 Backup System Alert - $(hostname)

**Issues Found:** $issue_count
**Timestamp:** $(date)

Please check the backup system status and logs.

Log file: $LOG_FILE"
        
        curl -s -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"Backup System Alert\",\"description\":\"$message\",\"color\":15158332}]}" \
            "$webhook_url" >/dev/null 2>&1 || true
    fi
}

# Main execution
check_backup_health
EOF
    
    chmod +x /opt/backups/monitor-backups.sh
    
    # Add monitoring to cron (daily)
    (crontab -l 2>/dev/null; echo "0 4 * * * /opt/backups/monitor-backups.sh >/dev/null 2>&1") | crontab -
    
    success "Backup monitoring configured"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting backup system setup..."
    
    # Check if backup is enabled
    if [[ "${ENABLE_BACKUP:-true}" != "true" ]]; then
        log "Backup system is disabled, skipping backup setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "Backup system disabled"
        return 0
    fi
    
    # Setup backup infrastructure
    setup_backup_directories
    
    # Create backup scripts
    create_main_backup_script
    create_incremental_backup_script
    create_backup_restore_script
    
    # Setup scheduling and monitoring
    setup_backup_scheduling
    create_backup_monitoring
    
    # Create initial backup
    log "Creating initial system backup..."
    if /opt/backups/backup-system.sh quick; then
        success "Initial backup created successfully"
    else
        warning "Initial backup failed, but setup will continue"
    fi
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "Backup system setup completed successfully"
    log "Backup commands:"
    log "  Full backup: /opt/backups/backup-system.sh full"
    log "  Quick backup: /opt/backups/backup-system.sh quick"
    log "  Restore backup: /opt/backups/restore-backup.sh"
    log "  List backups: /opt/backups/backup-system.sh list"
    log "  Monitor backups: /opt/backups/monitor-backups.sh"
}

# Execute main function
main "$@"