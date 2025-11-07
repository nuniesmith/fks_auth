#!/bin/bash

# Fix repository location script
# This script moves the repository from fks_temp to the correct location

set -e

echo "🔧 Fixing repository location..."

# Check if fks_temp exists
if [ -d "/home/actions_user/fks_temp" ]; then
    echo "✅ Found repository in fks_temp"
    
    # Ensure fks_user home directory exists
    sudo mkdir -p /home/fks_user
    
    # Remove existing final directory if it exists
    sudo rm -rf /home/fks_user/fks
    
    # Move repository to final location
    echo "📦 Moving repository to /home/fks_user/fks..."
    sudo mv /home/actions_user/fks_temp /home/fks_user/fks
    
    # Set proper ownership and permissions
    echo "🔐 Setting proper ownership and permissions..."
    sudo chown -R fks_user:fks_user /home/fks_user/fks
    sudo chmod 755 /home/fks_user
    sudo chmod 755 /home/fks_user/fks
    
    echo "✅ Repository moved successfully!"
    echo "📍 Repository is now at: /home/fks_user/fks"
    
    # Verify the move
    if [ -d "/home/fks_user/fks" ]; then
        echo "✅ Verification: Repository exists at correct location"
        echo "📋 Contents:"
        ls -la /home/fks_user/fks/ | head -10
    else
        echo "❌ Verification failed: Repository not found at expected location"
        exit 1
    fi
    
elif [ -d "/home/fks_user/fks" ]; then
    echo "✅ Repository already exists at correct location"
    echo "📋 Contents:"
    ls -la /home/fks_user/fks/ | head -10
    
else
    echo "❌ Repository not found in either location"
    echo "🔍 Checking both locations..."
    echo "fks_temp exists: $([ -d '/home/actions_user/fks_temp' ] && echo 'YES' || echo 'NO')"
    echo "fks exists: $([ -d '/home/fks_user/fks' ] && echo 'YES' || echo 'NO')"
    
    # Look for any fks directories
    echo "🔍 Searching for fks directories..."
    find /home -name "*fks*" -type d 2>/dev/null | head -10
    
    exit 1
fi

echo "✅ Repository location fix completed!"
