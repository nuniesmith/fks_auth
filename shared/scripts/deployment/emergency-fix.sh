#!/bin/bash

# Emergency fix script for FKS deployment repository structure
# Run this as root on your server to fix the current deployment

set -e

echo "🔧 Emergency FKS Repository Fix"
echo "================================"

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    echo "💡 Run: sudo bash $0"
    exit 1
fi

echo "🔍 Current situation analysis:"
echo "  - /home/fks_user/fks exists: $([ -d '/home/fks_user/fks' ] && echo 'YES' || echo 'NO')"
echo "  - /home/fks_user/fks owner: $([ -d '/home/fks_user/fks' ] && stat -c '%U:%G' /home/fks_user/fks || echo 'N/A')"
echo "  - /home/actions_user/fks_temp exists: $([ -d '/home/actions_user/fks_temp' ] && echo 'YES' || echo 'NO')"

# Function to search for the repository
find_repository() {
    echo "🔍 Searching for FKS repository..."
    
    # Search for key FKS files
    DOCKER_COMPOSE_LOCATIONS=$(find /home -name "docker-compose.yml" -type f 2>/dev/null | head -5)
    GIT_LOCATIONS=$(find /home -name ".git" -type d 2>/dev/null | head -5)
    
    if [ -n "$DOCKER_COMPOSE_LOCATIONS" ]; then
        echo "📋 Found docker-compose.yml files:"
        echo "$DOCKER_COMPOSE_LOCATIONS"
    fi
    
    if [ -n "$GIT_LOCATIONS" ]; then
        echo "📋 Found .git directories:"
        echo "$GIT_LOCATIONS"
    fi
    
    # Check for FKS-specific structure
    for location in $DOCKER_COMPOSE_LOCATIONS; do
        DIR=$(dirname "$location")
        if [ -f "$DIR/docker-compose.yml" ] && [ -d "$DIR/scripts" ]; then
            echo "✅ Found FKS repository at: $DIR"
            return 0
        fi
    done
    
    return 1
}

# Try to find the repository
echo ""
REPO_FOUND=""
if find_repository; then
    # Get the repository location
    for location in $(find /home -name "docker-compose.yml" -type f 2>/dev/null); do
        DIR=$(dirname "$location")
        if [ -f "$DIR/docker-compose.yml" ] && [ -d "$DIR/scripts" ]; then
            REPO_FOUND="$DIR"
            break
        fi
    done
fi

if [ -n "$REPO_FOUND" ] && [ "$REPO_FOUND" != "/home/fks_user/fks" ]; then
    echo "✅ Found FKS repository at: $REPO_FOUND"
    echo "📦 Moving repository to correct location..."
    
    # Backup current fks directory if it exists
    if [ -d "/home/fks_user/fks" ]; then
        echo "💾 Backing up current fks directory..."
        mv /home/fks_user/fks /home/fks_user/fks.backup.$(date +%Y%m%d_%H%M%S)
    fi
    
    # Move the repository
    echo "📁 Moving repository from $REPO_FOUND to /home/fks_user/fks..."
    mv "$REPO_FOUND" /home/fks_user/fks
    
    # Fix ownership and permissions
    echo "🔐 Fixing ownership and permissions..."
    chown -R fks_user:fks_user /home/fks_user/fks
    chmod -R 755 /home/fks_user/fks
    
    # Fix sensitive files
    if [ -f "/home/fks_user/fks/.env" ]; then
        chmod 600 /home/fks_user/fks/.env
    fi
    
    if [ -d "/home/fks_user/fks/.git" ]; then
        chmod -R 700 /home/fks_user/fks/.git
    fi
    
    echo "✅ Repository moved and fixed!"
    
elif [ -d "/home/fks_user/fks" ] && [ "$(stat -c '%U' /home/fks_user/fks)" = "root" ]; then
    echo "🔧 Repository exists but owned by root - fixing ownership..."
    
    # Fix ownership and permissions
    chown -R fks_user:fks_user /home/fks_user/fks
    chmod -R 755 /home/fks_user/fks
    
    # Fix sensitive files
    if [ -f "/home/fks_user/fks/.env" ]; then
        chmod 600 /home/fks_user/fks/.env
    fi
    
    if [ -d "/home/fks_user/fks/.git" ]; then
        chmod -R 700 /home/fks_user/fks/.git
    fi
    
    echo "✅ Ownership fixed!"
    
else
    echo "❌ No FKS repository found or repository already in correct location"
    echo ""
    echo "🔍 Manual intervention needed:"
    echo "1. Check if the repository was cloned properly"
    echo "2. Look for the repository in other locations"
    echo "3. Re-run the deployment if necessary"
    echo ""
    echo "🔍 Current directory contents:"
    echo "Actions user home:"
    ls -la /home/actions_user/ 2>/dev/null || echo "actions_user directory not found"
    echo ""
    echo "FKS user home:"
    ls -la /home/fks_user/ 2>/dev/null || echo "fks_user directory not found"
    
    exit 1
fi

# Clone repository if it doesn't exist
if [ ! -d "/home/fks_user/fks" ] || [ ! -f "/home/fks_user/fks/docker-compose.yml" ]; then
    echo "🔄 Repository not found - attempting to clone..."
    
    # Try to clone the repository
    cd /tmp
    if git clone https://github.com/nuniesmith/fks.git fks_clone 2>/dev/null; then
        echo "✅ Repository cloned successfully"
        
        # Move to correct location
        if [ -d "/home/fks_user/fks" ]; then
            rm -rf /home/fks_user/fks
        fi
        
        mv fks_clone /home/fks_user/fks
        
        # Fix ownership and permissions
        chown -R fks_user:fks_user /home/fks_user/fks
        chmod -R 755 /home/fks_user/fks
        
        echo "✅ Repository cloned and setup completed!"
        
    else
        echo "❌ Failed to clone repository"
        echo "💡 This might be a private repository requiring authentication"
        echo "🛠️ Manual intervention required"
        exit 1
    fi
fi

# Final verification
echo ""
echo "🔍 Final verification:"
echo "======================"
echo "Repository location: /home/fks_user/fks"
echo "Owner: $(stat -c '%U:%G' /home/fks_user/fks)"
echo "Permissions: $(stat -c '%a' /home/fks_user/fks)"
echo ""
echo "Contents:"
ls -la /home/fks_user/fks | head -15
echo ""

# Check for key files
echo "📋 Key files check:"
echo "  - docker-compose.yml: $([ -f '/home/fks_user/fks/docker-compose.yml' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - .env file: $([ -f '/home/fks_user/fks/.env' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - scripts directory: $([ -d '/home/fks_user/fks/scripts' ] && echo '✅ Found' || echo '❌ Missing')"
echo "  - src directory: $([ -d '/home/fks_user/fks/src' ] && echo '✅ Found' || echo '❌ Missing')"

echo ""
echo "🎉 Emergency fix completed!"
echo "💡 You can now try to start the services:"
echo "   sudo -u fks_user bash -c 'cd /home/fks_user/fks && ./scripts/orchestration/start.sh'"
