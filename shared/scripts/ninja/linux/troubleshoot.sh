#!/bin/bash

# Ninja Trading StackScript - Troubleshooting and Recovery Script
# Use this script to diagnose and fix SSH/deployment issues

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

NINJA_USER="ninja"

diagnose_current_state() {
    log "=== DIAGNOSING CURRENT STATE ==="
    
    echo "System Information:"
    echo "  Hostname: $(hostname)"
    echo "  Current user: $(whoami)"
    echo "  Date: $(date)"
    echo ""
    
    echo "Service Status:"
    echo "  SSH: $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo 'inactive')"
    echo "  Docker: $(systemctl is-active docker 2>/dev/null || echo 'inactive')"
    echo "  Stage 2: $(systemctl is-active ninja-stage2.service 2>/dev/null || echo 'inactive')"
    echo ""
    
    echo "File System Check:"
    echo "  Ninja user exists: $(id ninja &>/dev/null && echo 'yes' || echo 'no')"
    echo "  SSH directory: $(ls -ld /home/ninja/.ssh 2>/dev/null || echo 'not found')"
    echo "  SSH key exists: $(ls -l /home/ninja/.ssh/id_ed25519* 2>/dev/null || echo 'not found')"
    echo "  Repository: $(ls -ld /home/ninja/ninja 2>/dev/null || echo 'not found')"
    echo ""
}

fix_ssh_permissions() {
    log "=== FIXING SSH PERMISSIONS ==="
    
    local ninja_home="/home/$NINJA_USER"
    local ssh_dir="$ninja_home/.ssh"
    
    if [[ ! -d "$ninja_home" ]]; then
        error "Ninja user home directory not found"
        return 1
    fi
    
    # Ensure ninja user owns their home directory
    chown -R "$NINJA_USER:$NINJA_USER" "$ninja_home"
    
    if [[ -d "$ssh_dir" ]]; then
        log "Fixing SSH directory permissions..."
        
        # Fix ownership and permissions
        chown -R "$NINJA_USER:$NINJA_USER" "$ssh_dir"
        chmod 700 "$ssh_dir"
        
        # Fix individual file permissions
        if [[ -f "$ssh_dir/id_ed25519" ]]; then
            chmod 600 "$ssh_dir/id_ed25519"
            log "Fixed private key permissions"
        fi
        
        if [[ -f "$ssh_dir/id_ed25519.pub" ]]; then
            chmod 644 "$ssh_dir/id_ed25519.pub"
            log "Fixed public key permissions"
        fi
        
        if [[ -f "$ssh_dir/config" ]]; then
            chmod 600 "$ssh_dir/config"
            log "Fixed SSH config permissions"
        fi
        
        if [[ -f "$ssh_dir/known_hosts" ]]; then
            chmod 644 "$ssh_dir/known_hosts"
            log "Fixed known_hosts permissions"
        fi
        
        success "SSH permissions fixed"
    else
        warning "SSH directory not found - will create it"
        regenerate_ssh_keys
    fi
}

regenerate_ssh_keys() {
    log "=== REGENERATING SSH KEYS ==="
    
    local ninja_home="/home/$NINJA_USER"
    local ssh_dir="$ninja_home/.ssh"
    
    # Create SSH directory
    sudo -u "$NINJA_USER" mkdir -p "$ssh_dir"
    sudo -u "$NINJA_USER" chmod 700 "$ssh_dir"
    
    # Remove old keys if they exist
    sudo -u "$NINJA_USER" rm -f "$ssh_dir/id_ed25519"*
    
    # Generate new SSH key
    log "Generating new SSH key..."
    sudo -u "$NINJA_USER" ssh-keygen -t ed25519 -C "ninja@$(hostname)" -f "$ssh_dir/id_ed25519" -N ""
    
    # Set permissions
    sudo -u "$NINJA_USER" chmod 600 "$ssh_dir/id_ed25519"
    sudo -u "$NINJA_USER" chmod 644 "$ssh_dir/id_ed25519.pub"
    
    # Create SSH config
    sudo -u "$NINJA_USER" tee "$ssh_dir/config" > /dev/null << 'EOF'
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
    
    sudo -u "$NINJA_USER" chmod 600 "$ssh_dir/config"
    
    # Add GitHub to known hosts
    sudo -u "$NINJA_USER" ssh-keyscan -H github.com >> "$ssh_dir/known_hosts" 2>/dev/null || true
    sudo -u "$NINJA_USER" chmod 644 "$ssh_dir/known_hosts" 2>/dev/null || true
    
    # Ensure ownership
    chown -R "$NINJA_USER:$NINJA_USER" "$ssh_dir"
    
    success "SSH keys regenerated successfully"
}

show_ssh_key() {
    log "=== SSH PUBLIC KEY ==="
    
    if [[ -f "/home/$NINJA_USER/.ssh/id_ed25519.pub" ]]; then
        echo "Copy this key and add it to GitHub:"
        echo "https://github.com/nuniesmith/ninja/settings/keys"
        echo ""
        echo "SSH Public Key:"
        echo "==============="
        cat "/home/$NINJA_USER/.ssh/id_ed25519.pub"
        echo "==============="
        echo ""
        echo "Title suggestion: ninja-trading-$(hostname)-$(date +%Y%m%d)"
        echo "Make sure to check 'Allow write access'"
    else
        error "SSH public key not found"
        return 1
    fi
}

test_github_connection() {
    log "=== TESTING GITHUB CONNECTION ==="
    
    local ssh_test_output
    ssh_test_output=$(sudo -u "$NINJA_USER" ssh -T git@github.com -o ConnectTimeout=10 -o BatchMode=yes 2>&1 || true)
    
    echo "SSH Test Output:"
    echo "=================="
    echo "$ssh_test_output"
    echo "=================="
    
    if echo "$ssh_test_output" | grep -q "successfully authenticated"; then
        success "GitHub SSH connection successful!"
        return 0
    elif echo "$ssh_test_output" | grep -q "Permission denied"; then
        warning "SSH key not added to GitHub or incorrect permissions"
        return 1
    else
        warning "Connection test inconclusive"
        return 1
    fi
}

manual_repository_clone() {
    log "=== ATTEMPTING MANUAL REPOSITORY CLONE ==="
    
    local ninja_dir="/home/$NINJA_USER/ninja"
    local repo_url="git@github.com:nuniesmith/ninja.git"
    
    # Remove existing directory
    rm -rf "$ninja_dir"
    
    # Configure git
    sudo -u "$NINJA_USER" git config --global user.name "Ninja Trading System"
    sudo -u "$NINJA_USER" git config --global user.email "ninja@$(hostname)"
    sudo -u "$NINJA_USER" git config --global init.defaultBranch main
    
    # Attempt clone
    log "Cloning repository..."
    if sudo -u "$NINJA_USER" git clone "$repo_url" "$ninja_dir"; then
        success "Repository cloned successfully!"
        chown -R "$NINJA_USER:$NINJA_USER" "$ninja_dir"
        
        cd "$ninja_dir"
        echo "Repository information:"
        echo "  Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
        echo "  Latest commit: $(git log -1 --format='%h - %s' 2>/dev/null || echo 'unknown')"
        
        return 0
    else
        error "Repository clone failed"
        return 1
    fi
}

restart_stage2() {
    log "=== RESTARTING STAGE 2 SERVICE ==="
    
    if systemctl restart ninja-stage2.service; then
        success "Stage 2 service restarted"
        log "Monitor with: journalctl -u ninja-stage2.service -f"
    else
        error "Failed to restart Stage 2 service"
        return 1
    fi
}

show_help() {
    echo "Ninja Trading StackScript - Troubleshooting Tool"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  diagnose    - Show current system state"
    echo "  fix-ssh     - Fix SSH permissions"
    echo "  regen-keys  - Regenerate SSH keys"
    echo "  show-key    - Display SSH public key"
    echo "  test-github - Test GitHub SSH connection"
    echo "  clone       - Manually clone repository"
    echo "  restart     - Restart Stage 2 service"
    echo "  full-fix    - Run complete fix sequence"
    echo "  help        - Show this help"
    echo ""
}

full_fix() {
    log "=== RUNNING COMPLETE FIX SEQUENCE ==="
    
    diagnose_current_state
    echo ""
    
    fix_ssh_permissions || regenerate_ssh_keys
    echo ""
    
    show_ssh_key
    echo ""
    
    log "Please add the SSH key to GitHub, then press Enter to continue..."
    read -r
    
    test_github_connection
    echo ""
    
    if manual_repository_clone; then
        log "Repository clone successful! Restarting Stage 2..."
        restart_stage2
    else
        warning "Repository clone failed. Check SSH key configuration."
    fi
}

# Main execution
case "${1:-help}" in
    "diagnose"|"diag")
        diagnose_current_state
        ;;
    "fix-ssh"|"fix")
        fix_ssh_permissions
        ;;
    "regen-keys"|"regen")
        regenerate_ssh_keys
        show_ssh_key
        ;;
    "show-key"|"key")
        show_ssh_key
        ;;
    "test-github"|"test")
        test_github_connection
        ;;
    "clone")
        manual_repository_clone
        ;;
    "restart")
        restart_stage2
        ;;
    "full-fix"|"fix-all")
        full_fix
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        show_help
        ;;
esac
