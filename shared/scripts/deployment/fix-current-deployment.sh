#!/bin/bash

# Fix current deployment repository structure
# This script moves the repository content from fks_temp to the correct location

set -e

echo "🔧 Fixing current deployment repository structure..."

# Check if we're running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root or with sudo"
    echo "💡 Run: sudo bash $0"
    exit 1
fi

# Check current state
echo "📋 Current state analysis:"
echo "  - /home/fks_user/fks exists: $([ -d '/home/fks_user/fks' ] && echo 'YES' || echo 'NO')"
echo "  - /home/fks_user/fks/fks_temp exists: $([ -d '/home/fks_user/fks/fks_temp' ] && echo 'YES' || echo 'NO')"
echo "  - /home/actions_user/fks_temp exists: $([ -d '/home/actions_user/fks_temp' ] && echo 'YES' || echo 'NO')"

# Function to move repository content
move_repository_content() {
    local source_dir="$1"
    local target_dir="/home/fks_user/fks"
    
    echo "📦 Moving repository content..."
    echo "  From: $source_dir"
    echo "  To: $target_dir"
    
    # Create backup of current fks directory
    if [ -d "$target_dir" ]; then
        echo "💾 Creating backup of current fks directory..."
        mv "$target_dir" "${target_dir}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Move the repository content
    echo "📁 Moving repository..."
    mv "$source_dir" "$target_dir"
    
    # Set proper ownership and permissions
    echo "🔐 Setting proper ownership and permissions..."
    chown -R fks_user:fks_user "$target_dir"
    chmod -R 755 "$target_dir"
    
    # Set more restrictive permissions for sensitive files
    if [ -f "$target_dir/.env" ]; then
        chmod 600 "$target_dir/.env"
    fi
    
    if [ -d "$target_dir/.git" ]; then
        chmod -R 700 "$target_dir/.git"
    fi
    
    echo "✅ Repository moved successfully!"
}

# Try to find and move the repository content
if [ -d "/home/fks_user/fks/fks_temp" ]; then
    echo "✅ Found repository in /home/fks_user/fks/fks_temp"
    
    # Check if fks_temp contains the actual repository
    if [ -d "/home/fks_user/fks/fks_temp/.git" ] || [ -f "/home/fks_user/fks/fks_temp/docker-compose.yml" ]; then
        echo "✅ Confirmed: fks_temp contains the repository"
        
        # Move content from fks_temp to parent directory
        echo "📦 Moving content from fks_temp to fks directory..."
        
        # Create temporary directory to store current fks content
        temp_backup="/tmp/fks_current_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$temp_backup"
        
        # Move current fks content to temp (excluding fks_temp)
        find /home/fks_user/fks -maxdepth 1 -not -name "fks_temp" -not -name "." -not -name ".." -exec mv {} "$temp_backup/" \;
        
        # Move fks_temp content to fks directory
        mv /home/fks_user/fks/fks_temp/* /home/fks_user/fks/
        mv /home/fks_user/fks/fks_temp/.[^.]* /home/fks_user/fks/ 2>/dev/null || true
        
        # Remove empty fks_temp directory
        rmdir /home/fks_user/fks/fks_temp
        
        # Restore any important files from backup
        if [ -f "$temp_backup/.env" ]; then
            echo "📄 Restoring .env file from backup..."
            cp "$temp_backup/.env" /home/fks_user/fks/.env
        fi
        
        # Set proper ownership and permissions
        echo "🔐 Setting proper ownership and permissions..."
        chown -R fks_user:fks_user /home/fks_user/fks
        chmod -R 755 /home/fks_user/fks
        
        # Set more restrictive permissions for sensitive files
        if [ -f "/home/fks_user/fks/.env" ]; then
            chmod 600 /home/fks_user/fks/.env
        fi
        
        if [ -d "/home/fks_user/fks/.git" ]; then
            chmod -R 700 /home/fks_user/fks/.git
        fi
        
        echo "✅ Repository structure fixed successfully!"
        
    else
        echo "❌ fks_temp doesn't contain the repository"
    fi
    
elif [ -d "/home/actions_user/fks_temp" ]; then
    echo "✅ Found repository in /home/actions_user/fks_temp"
    move_repository_content "/home/actions_user/fks_temp"
    
else
    echo "❌ Repository not found in expected locations"
    echo "🔍 Searching for repository..."
    
    # Search for repository
    find /home -name "docker-compose.yml" -o -name ".git" -type d 2>/dev/null | head -10
    
    echo "💡 Manual intervention required"
    exit 1
fi

# Verify the fix
echo ""
echo "🔍 Verification:"
echo "=================="
echo "Repository location: /home/fks_user/fks"
echo "Owner: $(stat -c '%U:%G' /home/fks_user/fks)"
echo "Permissions: $(stat -c '%a' /home/fks_user/fks)"
echo ""
echo "Contents (first 10 items):"
ls -la /home/fks_user/fks | head -11
echo ""

# Check for key files
echo "📋 Key files check:"
echo "  - docker-compose.yml: $([ -f '/home/fks_user/fks/docker-compose.yml' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - .env file: $([ -f '/home/fks_user/fks/.env' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - scripts directory: $([ -d '/home/fks_user/fks/scripts' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - src directory: $([ -d '/home/fks_user/fks/src' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - .git directory: $([ -d '/home/fks_user/fks/.git' ] && echo '✅ Found' || echo '❌ Missing')"

echo ""
echo "🎉 Repository structure fix completed!"
echo "💡 You can now run: sudo -u fks_user bash -c 'cd /home/fks_user/fks && ./scripts/orchestration/start.sh'"
