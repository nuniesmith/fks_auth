#!/bin/bash
set -euo pipefail

# Service deployment script
# Usage: ./deploy-service.sh <service_name> <server_ip>

SERVICE_NAME="${1:-}"
SERVER_IP="${2:-}"

if [[ -z "$SERVICE_NAME" || -z "$SERVER_IP" ]]; then
  echo "❌ Missing required parameters"
  echo "Usage: $0 <service_name> <server_ip>"
  exit 1
fi

echo "🚀 Deploying $SERVICE_NAME service..."
echo "Server IP: $SERVER_IP"

# Ensure SSH key exists
if [[ ! -f ~/.ssh/deployment_key ]]; then
  echo "❌ SSH deployment key not found"
  exit 1
fi

echo "✅ SSH deployment key found"

# Clone service repository to server
echo "📥 Cloning $SERVICE_NAME repository..."
ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
  # Ensure service user home directory exists
  mkdir -p /home/${SERVICE_NAME}_user
  cd /home/${SERVICE_NAME}_user
  
  # Remove existing repo if it exists for fresh clone
  if [[ -d '$SERVICE_NAME' ]]; then
    echo 'Removing existing $SERVICE_NAME directory for fresh clone...'
    rm -rf $SERVICE_NAME
  fi
  
  # Clone the service repository from nuniesmith/$SERVICE_NAME
  echo 'Cloning nuniesmith/$SERVICE_NAME repository...'
  if git clone https://github.com/nuniesmith/$SERVICE_NAME.git; then
    echo '✅ Repository cloned successfully'
  else
    echo '❌ Repository clone failed!'
    exit 1
  fi
  
  cd $SERVICE_NAME
  
  # Verify we have the essential files
  echo '🔍 Checking repository contents...'
  ls -la
  
  if [[ -f 'start.sh' ]]; then
    echo '✅ Found start.sh - ready for deployment'
    chmod +x start.sh
  else
    echo '⚠️ start.sh not found in repository'
  fi
  
  if [[ -f 'docker-compose.yml' ]]; then
    echo '✅ Found docker-compose.yml'
  else
    echo '⚠️ docker-compose.yml not found'
  fi
  
  # Set ownership to service user
  echo '👤 Setting ownership to service user...'
  chown -R ${SERVICE_NAME}_user:${SERVICE_NAME}_user /home/${SERVICE_NAME}_user/$SERVICE_NAME
  
  # Add service user to docker group if not already there
  echo '🐳 Ensuring service user has Docker access...'
  usermod -aG docker ${SERVICE_NAME}_user 2>/dev/null || echo 'User already in docker group'
  
  echo '✅ Repository setup completed'
"

# Deploy the service using start.sh as the primary method
echo "🚀 Starting $SERVICE_NAME service deployment..."
ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "
  cd /home/${SERVICE_NAME}_user/$SERVICE_NAME
  
  echo '🔍 Current directory contents:'
  pwd
  ls -la
  
  # Verify Docker networking is working before switching users
  echo '🔧 Final Docker network verification...'
  if ! docker info >/dev/null 2>&1; then
    echo '❌ Docker still not responding properly'
    systemctl restart docker
    sleep 10
  fi
  
  # Ensure docker daemon socket permissions for service user
  echo '🐳 Setting Docker socket permissions...'
  chmod 666 /var/run/docker.sock 2>/dev/null || true
  
  # Run as the service user for proper permissions
  echo '🎭 Switching to service user for deployment...'
  
  # Use start.sh as the primary deployment method
  if [[ -f 'start.sh' ]]; then
    echo '🚀 Deploying with start.sh script...'
    chmod +x start.sh
    
    # Run start.sh as the service user with proper environment
    su - ${SERVICE_NAME}_user -c 'cd /home/${SERVICE_NAME}_user/$SERVICE_NAME && ./start.sh'
    
    echo '✅ start.sh deployment completed'
  elif [[ -f 'docker-compose.yml' ]]; then
    echo '🐳 Deploying with Docker Compose as root (due to networking requirements)...'
    
    # Stop existing containers first
    docker-compose down 2>/dev/null || true
    
    # Start services (run as root to avoid Docker permission issues)
    docker-compose up -d
    
    echo '✅ Docker Compose deployment completed'
  else
    echo '❌ No deployment method found (start.sh or docker-compose.yml missing)'
    echo '🔍 Available files:'
    ls -la
    exit 1
  fi
"

# Verify deployment
echo "🔍 Verifying service deployment..."
DEPLOYMENT_SUCCESS=false
for i in {1..5}; do
  if ssh -i ~/.ssh/deployment_key -o StrictHostKeyChecking=no root@$SERVER_IP "docker ps | grep -q '$SERVICE_NAME' || systemctl is-active $SERVICE_NAME 2>/dev/null"; then
    echo "✅ Service is running (attempt $i)"
    DEPLOYMENT_SUCCESS=true
    break
  fi
  echo "Attempt $i/5: Waiting for service to start..."
  sleep 10
done

if [[ "$DEPLOYMENT_SUCCESS" == "true" ]]; then
  echo "✅ $SERVICE_NAME service deployment completed successfully"
else
  echo "⚠️ Service deployment may have issues - check server logs"
fi
