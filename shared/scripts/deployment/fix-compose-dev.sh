#!/bin/bash

# Fix Docker Compose configuration for development deployment
# This script updates the start.sh script to use development configurations

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
    echo "🔧 Fixing Docker Compose configuration for development..."
    
    execute_ssh "
        echo '🔧 Updating Docker Compose configuration for development...'
        
        # Navigate to the project directory
        cd /home/fks_user/fks
        
        # Update start.sh to use development compose files
        sudo -u fks_user bash -c '
            # Check if we have a development compose file
            if [ -f docker-compose.dev.yml ]; then
                echo \"📋 Found development compose file\"
                
                # Update the start.sh script to use development configuration
                sed -i \"s/COMPOSE_CMD=\\\"\\\$COMPOSE_CMD -f docker-compose.yml -f docker-compose.prod.yml\\\"/COMPOSE_CMD=\\\"\\\$COMPOSE_CMD -f docker-compose.yml -f docker-compose.dev.yml\\\"/g\" scripts/orchestration/start.sh
                
                echo \"✅ Updated start.sh to use development compose files\"
            else
                echo \"⚠️ No development compose file found, will use base configuration\"
            fi
        '
        
        # Stop all services
        echo '🛑 Stopping all services...'
        sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            docker compose down --timeout 30 || true
            docker compose -f docker-compose.yml -f docker-compose.dev.yml down --timeout 30 || true
        '
        
        # Clean up and restart
        echo '🧹 Cleaning up Docker resources...'
        sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            docker system prune -f || true
            docker network prune -f || true
        '
        
        # Start services with development configuration
        echo '🚀 Starting services with development configuration...'
        sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            
            # Source the environment
            export $(cat .env | xargs)
            
            # Use development compose files
            if [ -f docker-compose.dev.yml ]; then
                echo \"🔧 Using development compose configuration\"
                docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
            else
                echo \"🔧 Using base compose configuration\"
                docker compose up -d
            fi
            
            # Wait for services to start
            sleep 20
            
            # Check status
            echo \"📊 Service status:\"
            docker compose ps
            
            # Check nginx logs specifically
            echo \"📋 Nginx logs:\"
            docker logs fks_nginx --tail 20 || true
        '
        
        echo '✅ Docker Compose configuration updated for development'
    " "Fix Docker Compose for development"
    
    echo "✅ Docker Compose fix completed successfully!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
