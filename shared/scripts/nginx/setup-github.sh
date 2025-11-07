#!/bin/bash
# setup-github.sh - GitHub Actions deployment setup
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-github"
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
# GITHUB DEPLOYMENT USER SETUP
# ============================================================================
create_deployment_user() {
    log "Creating GitHub deployment user..."
    
    # Create github-deploy user if it doesn't exist
    if ! id github-deploy &>/dev/null; then
        useradd -m -s /bin/bash github-deploy
        usermod -aG wheel github-deploy
        success "Created github-deploy user"
    else
        log "github-deploy user already exists"
    fi
    
    # Create necessary directories
    local dirs=("/opt/nginx-deployment" "/opt/backups/deployments")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chown github-deploy:github-deploy "$dir"
    done
    
    success "Deployment directories created"
}

setup_ssh_keys() {
    log "Setting up SSH keys for deployment..."
    
    # Create .ssh directory
    sudo -u github-deploy mkdir -p /home/github-deploy/.ssh
    
    # Generate SSH keys for GitHub deployment
    local key_path="/home/github-deploy/.ssh/github_deploy"
    if [[ ! -f "$key_path" ]]; then
        local domain="${DOMAIN_NAME:-localhost}"
        
        # Generate SSH key with retries
        local retries=3
        for ((i=1; i<=retries; i++)); do
            if sudo -u github-deploy ssh-keygen -t ed25519 \
                -C "actions_user@$domain" \
                -f "$key_path" \
                -N ""; then
                success "SSH key generated successfully"
                break
            elif [[ $i -eq $retries ]]; then
                error "SSH key generation failed after $retries attempts"
                return 1
            else
                warning "SSH key generation attempt $i/$retries failed, retrying..."
                sleep 2
            fi
        done
    else
        log "SSH key already exists"
    fi
    
    # Set up SSH configuration
    cat > /home/github-deploy/.ssh/config << 'EOF'
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_deploy
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
    
    # Set proper permissions
    chown -R github-deploy:github-deploy /home/github-deploy/.ssh
    chmod 700 /home/github-deploy/.ssh
    chmod 600 /home/github-deploy/.ssh/*
    
    success "SSH configuration completed"
}

setup_sudo_permissions() {
    log "Setting up sudo permissions for deployment user..."
    
    # Create sudoers file for github-deploy user
    cat > /etc/sudoers.d/github-deploy << 'EOF'
# Allow github-deploy to manage nginx and deployment operations without password

# NGINX management
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl start nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl status nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active nginx
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/nginx -t
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/nginx -s *

# File operations for deployment
github-deploy ALL=(ALL) NOPASSWD: /bin/cp -r * /etc/nginx/*
github-deploy ALL=(ALL) NOPASSWD: /bin/mkdir -p /etc/nginx/*
github-deploy ALL=(ALL) NOPASSWD: /bin/chown -R * /var/www/html*
github-deploy ALL=(ALL) NOPASSWD: /bin/chmod -R * /var/www/html*
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/find /var/www/html -type d -exec chmod 755 {} \;
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/find /var/www/html -type f -exec chmod 644 {} \;
github-deploy ALL=(ALL) NOPASSWD: /bin/rm -rf /opt/nginx-deployment/*
github-deploy ALL=(ALL) NOPASSWD: /bin/rsync -av * /etc/nginx*
github-deploy ALL=(ALL) NOPASSWD: /bin/rsync -av * /var/www/html*

# Backup operations
github-deploy ALL=(ALL) NOPASSWD: /bin/cp -r /etc/nginx /opt/backups/deployments/*
github-deploy ALL=(ALL) NOPASSWD: /bin/cp -r /var/www/html /opt/backups/deployments/*
github-deploy ALL=(ALL) NOPASSWD: /bin/tar -czf /opt/backups/deployments/* *

# SSL certificate management
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/certbot renew
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/certbot certificates

# Log access
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/tail -f /var/log/nginx/*
github-deploy ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u nginx*
EOF
    
    # Validate sudoers file
    if visudo -c -f /etc/sudoers.d/github-deploy; then
        chmod 440 /etc/sudoers.d/github-deploy
        success "Sudo permissions configured"
    else
        error "Sudoers file validation failed"
        rm -f /etc/sudoers.d/github-deploy
        return 1
    fi
}

# ============================================================================
# DEPLOYMENT SCRIPTS
# ============================================================================
create_deployment_script() {
    log "Creating enhanced deployment script..."
    
    cat > /opt/nginx-deployment/deploy.sh << 'EOF'
#!/bin/bash
# Enhanced deployment script with comprehensive features
# Version: 3.0.0

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly DEPLOY_DIR="/opt/nginx-deployment"
readonly NGINX_DIR="/etc/nginx"
readonly WEB_DIR="/var/www/html"
readonly BACKUP_DIR="/opt/backups/deployments"
readonly CONFIG_DIR="/etc/nginx-automation"
readonly MAX_BACKUPS=20
readonly HEALTH_CHECK_TIMEOUT=60
readonly HEALTH_CHECK_INTERVAL=5

# ============================================================================
# COLORS AND LOGGING
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }
info() { echo -e "${PURPLE}ℹ${NC} $1"; }

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================
load_config() {
    if [[ -f "$CONFIG_DIR/deployment-config.json" ]]; then
        DOMAIN_NAME=$(jq -r '.domain // "7gram.xyz"' "$CONFIG_DIR/deployment-config.json" 2>/dev/null || echo "7gram.xyz")
        GITHUB_REPO=$(jq -r '.github.repository // "nuniesmith/nginx"' "$CONFIG_DIR/deployment-config.json" 2>/dev/null || echo "nuniesmith/nginx")
    else
        DOMAIN_NAME="7gram.xyz"
        GITHUB_REPO="nuniesmith/nginx"
    fi
    
    export DOMAIN_NAME GITHUB_REPO
}

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================
create_backup() {
    local backup_name="deploy-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log "Creating deployment backup: $backup_name"
    mkdir -p "$backup_path"
    
    # Backup NGINX configuration
    if [[ -d "$NGINX_DIR" ]]; then
        cp -r "$NGINX_DIR" "$backup_path/nginx" 2>/dev/null || true
    fi
    
    # Backup web content
    if [[ -d "$WEB_DIR" ]]; then
        cp -r "$WEB_DIR" "$backup_path/html" 2>/dev/null || true
    fi
    
    # Save current git commit if in git repo
    if [[ -d "$DEPLOY_DIR/.git" ]]; then
        cd "$DEPLOY_DIR"
        git rev-parse HEAD > "$backup_path/commit.txt" 2>/dev/null || true
        git log -1 --pretty=format:"%h %s" > "$backup_path/commit-info.txt" 2>/dev/null || true
    fi
    
    # Save deployment metadata
    cat > "$backup_path/metadata.json" << EOL
{
    "backup_name": "$backup_name",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "domain": "$DOMAIN_NAME",
    "repository": "$GITHUB_REPO",
    "user": "$(whoami)",
    "hostname": "$(hostname)"
}
EOL
    
    # Cleanup old backups
    cleanup_old_backups
    
    echo "$backup_name"
}

cleanup_old_backups() {
    if [[ -d "$BACKUP_DIR" ]]; then
        local backup_count
        backup_count=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "deploy-*" | wc -l)
        
        if [[ $backup_count -gt $MAX_BACKUPS ]]; then
            log "Cleaning up old backups (keeping $MAX_BACKUPS most recent)"
            find "$BACKUP_DIR" -maxdepth 1 -type d -name "deploy-*" -printf '%T@ %p\n' | \
                sort -n | head -n -$MAX_BACKUPS | cut -d' ' -f2- | \
                xargs rm -rf 2>/dev/null || true
        fi
    fi
}

# ============================================================================
# ROLLBACK FUNCTIONS
# ============================================================================
rollback() {
    local backup_name="${1:-}"
    
    if [[ -z "$backup_name" ]]; then
        # Get latest backup
        backup_name=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "deploy-*" -printf '%T@ %p\n' | \
            sort -n | tail -n1 | cut -d' ' -f2- | xargs basename 2>/dev/null || echo "")
    fi
    
    if [[ -z "$backup_name" ]] || [[ ! -d "$BACKUP_DIR/$backup_name" ]]; then
        error "Backup not found: $backup_name"
        list_backups
        return 1
    fi
    
    log "Rolling back to: $backup_name"
    
    # Create backup of current state before rollback
    local rollback_backup
    rollback_backup=$(create_backup)
    log "Created rollback backup: $rollback_backup"
    
    # Restore NGINX configuration
    if [[ -d "$BACKUP_DIR/$backup_name/nginx" ]]; then
        log "Restoring NGINX configuration..."
        sudo cp -r "$BACKUP_DIR/$backup_name/nginx/"* "$NGINX_DIR/" 2>/dev/null || true
    fi
    
    # Restore web content
    if [[ -d "$BACKUP_DIR/$backup_name/html" ]]; then
        log "Restoring web content..."
        sudo cp -r "$BACKUP_DIR/$backup_name/html/"* "$WEB_DIR/" 2>/dev/null || true
        fix_permissions
    fi
    
    # Test and reload NGINX
    if test_nginx_config; then
        if reload_nginx; then
            success "Rollback completed successfully"
            
            # Verify rollback
            if perform_health_check; then
                success "Rollback verification passed"
                return 0
            else
                error "Rollback verification failed"
                return 1
            fi
        else
            error "Failed to reload NGINX after rollback"
            return 1
        fi
    else
        error "NGINX configuration test failed after rollback"
        return 1
    fi
}

list_backups() {
    log "Available deployment backups:"
    
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(find "$BACKUP_DIR" -maxdepth 1 -name "deploy-*" -type d 2>/dev/null)" ]]; then
        warning "No deployment backups found"
        return 1
    fi
    
    echo ""
    echo "Backup Name                    | Date Created        | Commit"
    echo "-------------------------------|--------------------|-----------------"
    
    find "$BACKUP_DIR" -maxdepth 1 -name "deploy-*" -type d -printf '%T@ %p\n' | \
        sort -rn | while read -r timestamp path; do
        local backup_name
        backup_name=$(basename "$path")
        local date_created
        date_created=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
        local commit_info=""
        if [[ -f "$path/commit-info.txt" ]]; then
            commit_info=$(cat "$path/commit-info.txt" 2>/dev/null | cut -c1-15)
        fi
        printf "%-30s | %-18s | %s\n" "$backup_name" "$date_created" "$commit_info"
    done
    
    echo ""
}

# ============================================================================
# DEPLOYMENT FUNCTIONS
# ============================================================================
deploy() {
    local environment="${1:-production}"
    local version="${2:-latest}"
    
    log "Starting deployment to $environment environment"
    info "Version: $version"
    info "Repository: $GITHUB_REPO"
    
    # Create backup before deployment
    local backup_name
    backup_name=$(create_backup)
    
    # Clone/update repository
    if ! update_repository; then
        error "Failed to update repository"
        return 1
    fi
    
    # Deploy configuration and content
    if ! deploy_files; then
        error "Failed to deploy files"
        log "Rolling back to backup: $backup_name"
        rollback "$backup_name"
        return 1
    fi
    
    # Test and reload NGINX
    if ! test_and_reload_nginx; then
        error "Failed to reload NGINX"
        log "Rolling back to backup: $backup_name"
        rollback "$backup_name"
        return 1
    fi
    
    # Perform health checks
    if ! perform_health_check; then
        warning "Health check failed, but deployment may still be functional"
        # Don't rollback on health check failure, just warn
    fi
    
    # Update deployment status
    save_deployment_status "success" "$backup_name" "$version"
    
    success "Deployment completed successfully!"
    info "Backup created: $backup_name"
    
    return 0
}

update_repository() {
    log "Updating repository..."
    
    if [[ ! -d "$DEPLOY_DIR/.git" ]] && [[ -n "$GITHUB_REPO" ]]; then
        log "Cloning repository: $GITHUB_REPO"
        if git clone "https://github.com/$GITHUB_REPO.git" "$DEPLOY_DIR"; then
            success "Repository cloned successfully"
        else
            error "Failed to clone repository"
            return 1
        fi
    elif [[ -d "$DEPLOY_DIR/.git" ]]; then
        log "Pulling latest changes..."
        cd "$DEPLOY_DIR"
        
        # Fetch latest changes
        if git fetch origin; then
            # Reset to latest origin/main or origin/master
            if git rev-parse --verify origin/main >/dev/null 2>&1; then
                git reset --hard origin/main
            elif git rev-parse --verify origin/master >/dev/null 2>&1; then
                git reset --hard origin/master
            else
                error "No main or master branch found"
                return 1
            fi
            success "Repository updated successfully"
        else
            warning "Failed to pull latest changes, using existing files"
        fi
    else
        warning "No repository configured"
        return 1
    fi
    
    return 0
}

deploy_files() {
    log "Deploying files..."
    
    # Deploy NGINX configuration
    if [[ -d "$DEPLOY_DIR/config/nginx" ]]; then
        log "Deploying NGINX configuration..."
        mkdir -p "$NGINX_DIR"
        
        # Use rsync for better deployment
        if rsync -av --delete --exclude="*.log" --exclude="*.backup" \
            "$DEPLOY_DIR/config/nginx/" "$NGINX_DIR/"; then
            success "NGINX configuration deployed"
        else
            error "Failed to deploy NGINX configuration"
            return 1
        fi
    fi
    
    # Deploy web files
    if [[ -d "$DEPLOY_DIR/html" ]]; then
        log "Deploying web files..."
        mkdir -p "$WEB_DIR"
        
        if rsync -av --delete --exclude="*.log" --exclude="*.backup" \
            "$DEPLOY_DIR/html/" "$WEB_DIR/"; then
            success "Web files deployed"
            fix_permissions
        else
            error "Failed to deploy web files"
            return 1
        fi
    elif [[ -d "$DEPLOY_DIR/public" ]]; then
        log "Deploying public files..."
        mkdir -p "$WEB_DIR"
        
        if rsync -av --delete --exclude="*.log" --exclude="*.backup" \
            "$DEPLOY_DIR/public/" "$WEB_DIR/"; then
            success "Public files deployed"
            fix_permissions
        else
            error "Failed to deploy public files"
            return 1
        fi
    fi
    
    return 0
}

fix_permissions() {
    log "Setting file permissions..."
    
    # Determine correct user (Arch uses 'http', others might use 'www-data' or 'nginx')
    local web_user="http"
    if id nginx &>/dev/null; then
        web_user="nginx"
    elif id www-data &>/dev/null; then
        web_user="www-data"
    fi
    
    # Set ownership
    sudo chown -R "$web_user:$web_user" "$WEB_DIR" 2>/dev/null || true
    
    # Set directory permissions
    sudo find "$WEB_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true
    
    # Set file permissions
    sudo find "$WEB_DIR" -type f -exec chmod 644 {} \; 2>/dev/null || true
    
    success "File permissions updated"
}

# ============================================================================
# NGINX MANAGEMENT
# ============================================================================
test_nginx_config() {
    log "Testing NGINX configuration..."
    
    if sudo nginx -t 2>/dev/null; then
        success "NGINX configuration is valid"
        return 0
    else
        error "NGINX configuration test failed"
        sudo nginx -t
        return 1
    fi
}

reload_nginx() {
    log "Reloading NGINX..."
    
    if sudo systemctl reload nginx; then
        success "NGINX reloaded successfully"
        return 0
    else
        error "Failed to reload NGINX"
        return 1
    fi
}

test_and_reload_nginx() {
    if test_nginx_config; then
        if reload_nginx; then
            # Wait for nginx to fully reload
            sleep 2
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# ============================================================================
# HEALTH CHECKS
# ============================================================================
perform_health_check() {
    log "Performing health checks..."
    
    local end_time=$(($(date +%s) + HEALTH_CHECK_TIMEOUT))
    local success_count=0
    local required_successes=3
    
    while [[ $(date +%s) -lt $end_time ]]; do
        if health_check_endpoint; then
            ((success_count++))
            if [[ $success_count -ge $required_successes ]]; then
                success "Health check passed ($success_count/$required_successes successful)"
                return 0
            fi
        else
            success_count=0
        fi
        
        sleep "$HEALTH_CHECK_INTERVAL"
    done
    
    error "Health check failed after ${HEALTH_CHECK_TIMEOUT}s timeout"
    return 1
}

health_check_endpoint() {
    # Try multiple endpoints
    local endpoints=("http://localhost/health" "http://localhost/" "https://localhost/health" "https://localhost/")
    
    for endpoint in "${endpoints[@]}"; do
        if curl -sf --max-time 5 "$endpoint" >/dev/null 2>&1; then
            return 0
        fi
    done
    
    return 1
}

# ============================================================================
# STATUS MANAGEMENT
# ============================================================================
save_deployment_status() {
    local status="$1"
    local backup_name="$2"
    local version="${3:-unknown}"
    
    local status_file="$CONFIG_DIR/deployment-status.json"
    
    cat > "$status_file" << EOL
{
    "status": "$status",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_name": "$backup_name",
    "version": "$version",
    "repository": "$GITHUB_REPO",
    "domain": "$DOMAIN_NAME",
    "user": "$(whoami)",
    "hostname": "$(hostname)"
}
EOL
}

show_status() {
    echo "=== Deployment Status ==="
    echo ""
    
    # Show current deployment status
    if [[ -f "$CONFIG_DIR/deployment-status.json" ]]; then
        local status_data
        status_data=$(cat "$CONFIG_DIR/deployment-status.json")
        
        echo "Last Deployment:"
        echo "  Status: $(echo "$status_data" | jq -r '.status')"
        echo "  Timestamp: $(echo "$status_data" | jq -r '.timestamp')"
        echo "  Version: $(echo "$status_data" | jq -r '.version')"
        echo "  Backup: $(echo "$status_data" | jq -r '.backup_name')"
        echo ""
    fi
    
    # Show NGINX status
    echo "NGINX Status:"
    if systemctl is-active --quiet nginx; then
        echo "  ✅ Running"
    else
        echo "  ❌ Not running"
    fi
    
    echo "  Config test: $(nginx -t 2>&1 || echo "Failed")"
    echo ""
    
    # Show repository status
    if [[ -d "$DEPLOY_DIR/.git" ]]; then
        echo "Repository Status:"
        cd "$DEPLOY_DIR"
        echo "  Current commit: $(git rev-parse --short HEAD 2>/dev/null || echo "Unknown")"
        echo "  Branch: $(git branch --show-current 2>/dev/null || echo "Unknown")"
        echo "  Last commit: $(git log -1 --pretty=format:"%h %s" 2>/dev/null || echo "Unknown")"
        echo ""
    fi
    
    # Show recent backups
    echo "Recent Backups:"
    find "$BACKUP_DIR" -maxdepth 1 -name "deploy-*" -type d -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | head -5 | while read -r timestamp path; do
        local backup_name
        backup_name=$(basename "$path")
        local date_created
        date_created=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
        echo "  $backup_name ($date_created)"
    done
}

# ============================================================================
# MAIN COMMAND HANDLER
# ============================================================================
show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  deploy [env] [version]  - Deploy latest changes (default: production)"
    echo "  rollback [backup]       - Rollback to previous deployment"
    echo "  status                  - Show deployment status"
    echo "  list-backups           - List available backups"
    echo "  health                 - Perform health check"
    echo "  test-config            - Test NGINX configuration"
    echo "  reload                 - Reload NGINX"
    echo ""
    echo "Examples:"
    echo "  $0 deploy                    # Deploy to production"
    echo "  $0 deploy staging           # Deploy to staging"
    echo "  $0 rollback                 # Rollback to latest backup"
    echo "  $0 rollback deploy-20231201-120000  # Rollback to specific backup"
    echo "  $0 health                   # Check application health"
}

main() {
    # Load configuration
    load_config
    
    # Ensure running as github-deploy user
    if [[ "$(whoami)" != "github-deploy" ]] && [[ "$(whoami)" != "root" ]]; then
        error "This script should be run as github-deploy user or root"
        exit 1
    fi
    
    local command="${1:-deploy}"
    
    case "$command" in
        deploy)
            deploy "${2:-production}" "${3:-latest}"
            ;;
        rollback)
            rollback "${2:-}"
            ;;
        status)
            show_status
            ;;
        list-backups)
            list_backups
            ;;
        health)
            if perform_health_check; then
                success "Health check passed"
                exit 0
            else
                error "Health check failed"
                exit 1
            fi
            ;;
        test-config)
            test_nginx_config
            ;;
        reload)
            test_and_reload_nginx
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    chmod +x /opt/nginx-deployment/deploy.sh
    chown github-deploy:github-deploy /opt/nginx-deployment/deploy.sh
    
    success "Deployment script created"
}

# ============================================================================
# WEBHOOK RECEIVER
# ============================================================================
create_webhook_receiver() {
    log "Creating webhook receiver for GitHub Actions..."
    
    cat > /opt/nginx-deployment/webhook-receiver.py << 'EOF'
#!/usr/bin/env python3
"""
GitHub Webhook Receiver for 7gram Dashboard
Handles webhook events from GitHub Actions for automated deployment
"""

import hmac
import hashlib
import json
import subprocess
import sys
import os
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import threading
import time

# Configuration
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
DEPLOY_SCRIPT = '/opt/nginx-deployment/deploy.sh'
HOST = '127.0.0.1'
PORT = 9999
LOG_FILE = '/var/log/webhook-receiver.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to use our logging system"""
        logging.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'service': 'webhook-receiver'
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle webhook POST requests"""
        if self.path != '/webhook':
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error_response(400, 'Empty request body')
                return
            
            body = self.rfile.read(content_length)
            
            # Verify signature if secret is configured
            if WEBHOOK_SECRET and not self.verify_signature(body):
                logging.warning("Invalid webhook signature")
                self.send_error_response(401, 'Invalid signature')
                return
            
            # Process webhook
            response = self.process_webhook(body)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"Error processing webhook: {e}")
            self.send_error_response(500, f'Internal server error: {str(e)}')
    
    def verify_signature(self, body):
        """Verify GitHub webhook signature"""
        signature = self.headers.get('X-Hub-Signature-256', '')
        if not signature.startswith('sha256='):
            return False
        
        expected_signature = 'sha256=' + hmac.new(
            WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def process_webhook(self, body):
        """Process GitHub webhook payload"""
        try:
            payload = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON payload: {e}")
            return {'status': 'error', 'error': 'Invalid JSON'}
        
        event_type = self.headers.get('X-GitHub-Event', 'unknown')
        repo_name = payload.get('repository', {}).get('full_name', 'unknown')
        
        logging.info(f"Received {event_type} event for {repo_name}")
        
        # Handle different event types
        if event_type == 'push':
            return self.handle_push_event(payload)
        elif event_type == 'workflow_run':
            return self.handle_workflow_event(payload)
        elif event_type == 'ping':
            return self.handle_ping_event(payload)
        else:
            logging.info(f"Ignoring {event_type} event")
            return {
                'status': 'ignored',
                'message': f'Event type {event_type} not handled',
                'event': event_type
            }
    
    def handle_push_event(self, payload):
        """Handle push events"""
        ref = payload.get('ref', 'unknown')
        repo_name = payload.get('repository', {}).get('full_name', 'unknown')
        
        # Only deploy on push to main/master
        if ref in ['refs/heads/main', 'refs/heads/master']:
            logging.info(f"Triggering deployment for {repo_name} ({ref})")
            
            # Trigger deployment asynchronously
            threading.Thread(
                target=self.trigger_deployment,
                args=(repo_name, ref, payload.get('head_commit', {}))
            ).start()
            
            return {
                'status': 'deployment_triggered',
                'repository': repo_name,
                'ref': ref,
                'message': 'Deployment started in background'
            }
        else:
            logging.info(f"Ignoring push to {ref}")
            return {
                'status': 'ignored',
                'message': f'Push to {ref} ignored (only main/master trigger deployment)',
                'repository': repo_name,
                'ref': ref
            }
    
    def handle_workflow_event(self, payload):
        """Handle workflow run events"""
        workflow = payload.get('workflow_run', {})
        conclusion = workflow.get('conclusion')
        status = workflow.get('status')
        name = workflow.get('name', 'unknown')
        
        if status == 'completed' and conclusion == 'success':
            # Deployment workflow completed successfully
            if 'deploy' in name.lower():
                logging.info(f"Deployment workflow '{name}' completed successfully")
                return {
                    'status': 'workflow_completed',
                    'workflow': name,
                    'conclusion': conclusion
                }
        
        return {
            'status': 'workflow_event_received',
            'workflow': name,
            'status': status,
            'conclusion': conclusion
        }
    
    def handle_ping_event(self, payload):
        """Handle ping events (webhook test)"""
        logging.info("Received ping event - webhook is working")
        return {
            'status': 'pong',
            'message': 'Webhook receiver is working',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def trigger_deployment(self, repo_name, ref, commit_info):
        """Trigger deployment in background"""
        try:
            commit_id = commit_info.get('id', 'unknown')[:8]
            commit_message = commit_info.get('message', 'No message')
            
            logging.info(f"Starting deployment: {commit_id} - {commit_message}")
            
            # Run deployment script
            result = subprocess.run(
                ['sudo', '-u', 'github-deploy', DEPLOY_SCRIPT, 'deploy'],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                logging.info(f"Deployment successful: {commit_id}")
                self.send_notification('success', f"Deployment successful: {commit_id}", commit_message)
            else:
                logging.error(f"Deployment failed: {commit_id}")
                logging.error(f"STDOUT: {result.stdout}")
                logging.error(f"STDERR: {result.stderr}")
                self.send_notification('error', f"Deployment failed: {commit_id}", result.stderr)
                
        except subprocess.TimeoutExpired:
            logging.error(f"Deployment timeout: {commit_id}")
            self.send_notification('error', f"Deployment timeout: {commit_id}", "Deployment took longer than 10 minutes")
        except Exception as e:
            logging.error(f"Deployment error: {e}")
            self.send_notification('error', f"Deployment error: {commit_id}", str(e))
    
    def send_notification(self, level, title, message):
        """Send notification (Discord webhook if configured)"""
        try:
            # Load Discord webhook from config
            config_file = '/etc/nginx-automation/deployment-config.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    webhook_url = config.get('discord_webhook')
                    
                    if webhook_url:
                        import urllib.request
                        
                        color = 3066993 if level == 'success' else 15158332
                        emoji = '✅' if level == 'success' else '❌'
                        
                        payload = {
                            'embeds': [{
                                'title': f'{emoji} {title}',
                                'description': message,
                                'color': color,
                                'timestamp': datetime.utcnow().isoformat(),
                                'footer': {'text': 'GitHub Webhook Deployment'}
                            }]
                        }
                        
                        req = urllib.request.Request(
                            webhook_url,
                            data=json.dumps(payload).encode(),
                            headers={'Content-Type': 'application/json'}
                        )
                        
                        urllib.request.urlopen(req, timeout=10)
                        logging.info("Notification sent successfully")
                        
        except Exception as e:
            logging.warning(f"Failed to send notification: {e}")
    
    def send_error_response(self, code, message):
        """Send error response"""
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {
            'status': 'error',
            'error': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())

def main():
    """Main function"""
    logging.info(f"Starting webhook receiver on {HOST}:{PORT}")
    logging.info(f"Deploy script: {DEPLOY_SCRIPT}")
    logging.info(f"Webhook secret configured: {'Yes' if WEBHOOK_SECRET else 'No'}")
    
    server = HTTPServer((HOST, PORT), WebhookHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Webhook receiver stopped by user")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server.shutdown()
        logging.info("Webhook receiver stopped")

if __name__ == '__main__':
    main()
EOF
    
    chmod +x /opt/nginx-deployment/webhook-receiver.py
    chown github-deploy:github-deploy /opt/nginx-deployment/webhook-receiver.py
    
    success "Webhook receiver created"
}

create_webhook_service() {
    log "Creating webhook receiver systemd service..."
    
    cat > /etc/systemd/system/webhook-receiver.service << 'EOF'
[Unit]
Description=GitHub Webhook Receiver for 7gram Dashboard
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=github-deploy
Group=github-deploy
WorkingDirectory=/opt/nginx-deployment
Environment="WEBHOOK_SECRET="
ExecStart=/usr/bin/python3 /opt/nginx-deployment/webhook-receiver.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/nginx-deployment /var/log /opt/backups

[Install]
WantedBy=multi-user.target
EOF
    
    # Add webhook secret if provided
    if [[ -n "${GITHUB_WEBHOOK_SECRET:-}" ]]; then
        sed -i "s/Environment=\"WEBHOOK_SECRET=\"/Environment=\"WEBHOOK_SECRET=${GITHUB_WEBHOOK_SECRET}\"/" \
            /etc/systemd/system/webhook-receiver.service
    fi
    
    systemctl daemon-reload
    systemctl enable webhook-receiver
    
    success "Webhook receiver service created and enabled"
}

# ============================================================================
# DEPLOYMENT INFO
# ============================================================================
create_deployment_info() {
    log "Creating deployment information file..."
    
    local public_key=""
    if [[ -f /home/github-deploy/.ssh/github_deploy.pub ]]; then
        public_key=$(cat /home/github-deploy/.ssh/github_deploy.pub)
    fi
    
    local public_ip
    public_ip=$(get_public_ip || echo "YOUR_SERVER_IP")
    
    cat > /opt/nginx-deployment/deployment-info.txt << EOF
=== 7gram Dashboard Deployment Information ===
Generated: $(date)
Version: $SCRIPT_VERSION

Server Information:
- Hostname: ${HOSTNAME:-nginx}
- Domain: ${DOMAIN_NAME:-7gram.xyz}
- Public IP: $public_ip
- Repository: ${GITHUB_REPO:-nuniesmith/nginx}

GitHub Repository Setup:
1. Add the following SSH public key as a Deploy Key in your repository:
   Settings → Deploy keys → Add deploy key

$public_key

2. Configure the following secrets in your repository:
   Settings → Secrets and variables → Actions

   SSH_PRIVATE_KEY: (contents of /home/github-deploy/.ssh/github_deploy)
   SSH_USER: github-deploy
   SSH_HOST: $public_ip

3. Optional: Configure webhook secret for enhanced security:
   WEBHOOK_SECRET: (generate a random string)

Webhook Configuration:
- Webhook URL: http://$public_ip:9999/webhook
- Content type: application/json
- Events: Push events, Workflow runs
- Secret: (if configured)

Test SSH Connection:
ssh -i <private_key_file> github-deploy@$public_ip

Management Commands (on server):
- Check status: 7gram-status
- Deploy manually: sudo -u github-deploy /opt/nginx-deployment/deploy.sh
- Rollback: sudo -u github-deploy /opt/nginx-deployment/deploy.sh rollback
- Health check: sudo -u github-deploy /opt/nginx-deployment/deploy.sh health
- List backups: sudo -u github-deploy /opt/nginx-deployment/deploy.sh list-backups

Webhook Commands:
- Check webhook status: systemctl status webhook-receiver
- View webhook logs: journalctl -u webhook-receiver -f
- Test webhook: curl http://localhost:9999/health

Files and Directories:
- Deployment script: /opt/nginx-deployment/deploy.sh
- Webhook receiver: /opt/nginx-deployment/webhook-receiver.py
- Backups: /opt/backups/deployments/
- Logs: /var/log/webhook-receiver.log
- SSH keys: /home/github-deploy/.ssh/

Repository Structure Expected:
nginx/
├── config/
│   └── nginx/          # NGINX configuration files
├── html/               # Web content (or public/)
├── scripts/            # Setup scripts
└── .github/
    └── workflows/      # GitHub Actions workflows

For more information, visit: https://github.com/${GITHUB_REPO:-nuniesmith/nginx}
EOF
    
    chown github-deploy:github-deploy /opt/nginx-deployment/deployment-info.txt
    chmod 644 /opt/nginx-deployment/deployment-info.txt
    
    success "Deployment information saved to /opt/nginx-deployment/deployment-info.txt"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting GitHub Actions deployment setup..."
    
    # Check if GitHub Actions is enabled
    if [[ "${ENABLE_GITHUB_ACTIONS:-true}" != "true" ]]; then
        log "GitHub Actions is disabled, skipping GitHub setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "GitHub Actions disabled"
        return 0
    fi
    
    # Create deployment user and setup
    create_deployment_user
    setup_ssh_keys
    setup_sudo_permissions
    
    # Create deployment scripts
    create_deployment_script
    create_webhook_receiver
    create_webhook_service
    
    # Create documentation
    create_deployment_info
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "GitHub Actions deployment setup completed successfully"
    log "Check /opt/nginx-deployment/deployment-info.txt for setup instructions"
    log "Use '/opt/nginx-deployment/deploy.sh' for manual deployment"
}

# Execute main function
main "$@"