#!/bin/bash

# FKS Trading Systems - SSH Key Setup Script
# This script helps generate and configure SSH keys for deployment

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

# Function to generate SSH key pair
generate_ssh_key() {
    local key_name=$1
    local key_comment=$2
    local key_path="$HOME/.ssh/${key_name}"
    
    log "Generating SSH key pair: $key_name"
    
    if [ -f "$key_path" ]; then
        warn "SSH key already exists at $key_path"
        read -p "Overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    ssh-keygen -t ed25519 -f "$key_path" -N "" -C "$key_comment"
    
    log "SSH key pair generated:"
    log "  Private key: $key_path"
    log "  Public key: $key_path.pub"
    
    echo
    echo "========================================="
    echo "PUBLIC KEY (for GitHub Secrets):"
    echo "========================================="
    cat "$key_path.pub"
    echo "========================================="
    echo
}

# Function to display existing keys
list_existing_keys() {
    log "Existing SSH keys in $HOME/.ssh:"
    
    if ls "$HOME/.ssh"/*.pub 2>/dev/null; then
        echo
        for pub_key in "$HOME/.ssh"/*.pub; do
            if [ -f "$pub_key" ]; then
                key_name=$(basename "$pub_key" .pub)
                echo "Key: $key_name"
                echo "Public key: $(cat "$pub_key")"
                echo "---"
            fi
        done
    else
        warn "No SSH keys found"
    fi
}

# Function to copy public key to clipboard (if available)
copy_to_clipboard() {
    local key_file=$1
    
    if command -v xclip &> /dev/null; then
        cat "$key_file" | xclip -selection clipboard
        log "Public key copied to clipboard (xclip)"
    elif command -v pbcopy &> /dev/null; then
        cat "$key_file" | pbcopy
        log "Public key copied to clipboard (pbcopy)"
    elif command -v clip.exe &> /dev/null; then
        cat "$key_file" | clip.exe
        log "Public key copied to clipboard (Windows clip.exe)"
    else
        warn "No clipboard utility found. Please copy the key manually."
    fi
}

# Function to add key to GitHub repo as deploy key
add_deploy_key_instructions() {
    local key_name=$1
    local repo_url=$2
    
    echo
    echo "========================================="
    echo "GITHUB DEPLOY KEY SETUP INSTRUCTIONS:"
    echo "========================================="
    echo "1. Go to: https://github.com/nuniesmith/fks/settings/keys"
    echo "2. Click 'Add deploy key'"
    echo "3. Title: '$key_name'"
    echo "4. Key: (paste the public key above)"
    echo "5. ✅ Check 'Allow write access' (required for deployment)"
    echo "6. Click 'Add key'"
    echo "========================================="
    echo
}

# Function to add key to GitHub Secrets
add_secret_instructions() {
    local secret_name=$1
    local description=$2
    
    echo
    echo "========================================="
    echo "GITHUB SECRETS SETUP INSTRUCTIONS:"
    echo "========================================="
    echo "1. Go to: https://github.com/nuniesmith/fks/settings/secrets/actions"
    echo "2. Click 'New repository secret'"
    echo "3. Name: '$secret_name'"
    echo "4. Value: (paste the public key above)"
    echo "5. Description: '$description'"
    echo "6. Click 'Add secret'"
    echo "========================================="
    echo
}

# Main script
main() {
    log "FKS Trading Systems - SSH Key Setup"
    
    # Create .ssh directory if it doesn't exist
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    
    echo
    echo "What would you like to do?"
    echo "1. Generate new SSH key for GitHub Actions (actions_user)"
    echo "2. Generate new SSH key for Jordan (personal access)"
    echo "3. List existing SSH keys"
    echo "4. Set up SSH keys for server deployment"
    echo "5. Exit"
    echo
    
    read -p "Enter your choice (1-5): " choice
    
    case $choice in
        1)
            log "Generating SSH key for GitHub Actions..."
            generate_ssh_key "actions_user_fks" "actions_user@fks_trading-system"
            
            # Instructions for GitHub setup
            add_secret_instructions "ACTIONS_USER_SSH_PUB" "SSH public key for GitHub Actions to access FKS server"
            add_deploy_key_instructions "actions_user@fks_trading-system" "https://github.com/nuniesmith/fks"
            
            copy_to_clipboard "$HOME/.ssh/actions_user_fks.pub"
            ;;
        2)
            log "Generating SSH key for Jordan..."
            generate_ssh_key "jordan_fks" "jordan@fks_trading-system"
            
            add_secret_instructions "JORDAN_SSH_PUB" "Jordan's SSH public key for server access"
            
            copy_to_clipboard "$HOME/.ssh/jordan_fks.pub"
            ;;
        3)
            list_existing_keys
            ;;
        4)
            log "Setting up SSH keys for server deployment..."
            
            # Check if we have the required keys
            ACTIONS_KEY="$HOME/.ssh/actions_user_fks.pub"
            JORDAN_KEY="$HOME/.ssh/jordan_fks.pub"
            
            if [ ! -f "$ACTIONS_KEY" ]; then
                warn "actions_user SSH key not found. Generating..."
                generate_ssh_key "actions_user_fks" "actions_user@fks_trading-system"
                echo
            fi
            
            if [ ! -f "$JORDAN_KEY" ]; then
                warn "jordan SSH key not found. Generating..."
                generate_ssh_key "jordan_fks" "jordan@fks_trading-system"
                echo
            fi
            
            # Display setup instructions
            echo
            echo "========================================="
            echo "COMPLETE SERVER SETUP INSTRUCTIONS:"
            echo "========================================="
            echo
            echo "1. ADD GITHUB SECRETS:"
            echo "   - Go to: https://github.com/nuniesmith/fks/settings/secrets/actions"
            echo "   - Add these secrets:"
            echo
            echo "   Secret: ACTIONS_USER_SSH_PUB"
            echo "   Value:"
            if [ -f "$ACTIONS_KEY" ]; then
                cat "$ACTIONS_KEY"
            fi
            echo
            echo "   Secret: JORDAN_SSH_PUB"
            echo "   Value:"
            if [ -f "$JORDAN_KEY" ]; then
                cat "$JORDAN_KEY"
            fi
            echo
            echo "2. ADD DEPLOY KEY:"
            echo "   - Go to: https://github.com/nuniesmith/fks/settings/keys"
            echo "   - Add deploy key with write access using the ACTIONS_USER_SSH_PUB key"
            echo
            echo "3. RUN DEPLOYMENT:"
            echo "   - Go to: https://github.com/nuniesmith/fks/actions"
            echo "   - Run the 'FKS Trading Systems - Production Pipeline' workflow"
            echo "   - Select 'full-deploy' mode"
            echo
            echo "========================================="
            ;;
        5)
            log "Exiting..."
            exit 0
            ;;
        *)
            error "Invalid choice. Please enter 1-5."
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
