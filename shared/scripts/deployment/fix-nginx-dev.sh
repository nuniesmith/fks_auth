#!/bin/bash

# Fix nginx configuration for development mode
# This script updates the nginx configuration to disable SSL and fix the restarting issue

set -e

# Configuration
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    
    echo "📡 $description"
    
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$TARGET_HOST" "$command"; then
            echo "✅ Success: $description"
            return 0
        else
            echo "❌ Failed: $description"
            return 1
        fi
    else
        echo "❌ No password available for SSH"
        return 1
    fi
}

main() {
    echo "🔧 Fixing nginx configuration for development mode..."
    
    execute_ssh "
        echo '🔧 Updating nginx configuration for development...'
        
        # Navigate to the project directory
        cd /home/fks_user/fks
        
        # Update .env file to disable SSL
        sudo -u fks_user bash -c '
            if [ -f .env ]; then
                # Update existing .env file
                sed -i \"s/ENABLE_SSL=true/ENABLE_SSL=false/g\" .env
                sed -i \"s/SSL_STAGING=true/SSL_STAGING=false/g\" .env
                sed -i \"s/DOMAIN_NAME=.*/DOMAIN_NAME=localhost/g\" .env
                
                # Add nginx timeout settings if they don'\''t exist
                if ! grep -q \"PROXY_CONNECT_TIMEOUT\" .env; then
                    echo \"PROXY_CONNECT_TIMEOUT=30s\" >> .env
                fi
                if ! grep -q \"PROXY_SEND_TIMEOUT\" .env; then
                    echo \"PROXY_SEND_TIMEOUT=30s\" >> .env
                fi
                if ! grep -q \"PROXY_READ_TIMEOUT\" .env; then
                    echo \"PROXY_READ_TIMEOUT=30s\" >> .env
                fi
                
                echo \"✅ Updated .env file for development mode\"
            else
                echo \"❌ .env file not found\"
                exit 1
            fi
        '
        
        # Stop and remove the problematic nginx container
        echo '🛑 Stopping nginx container...'
        sudo -u fks_user docker stop fks_nginx || true
        sudo -u fks_user docker rm fks_nginx || true
        
        # Restart services with updated configuration
        echo '🚀 Restarting services with updated configuration...'
        sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            
            # Source the updated environment
            export $(cat .env | xargs)
            
            # Restart nginx service specifically
            docker compose up -d nginx
            
            # Wait a moment for service to start
            sleep 10
            
            # Check the status
            echo \"📊 Service status after restart:\"
            docker compose ps
        '
        
        echo '✅ Nginx configuration updated and restarted'
    " "Fix nginx configuration for development"
    
    echo "✅ Nginx fix completed successfully!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
