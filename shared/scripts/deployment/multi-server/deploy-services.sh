#!/bin/bash

# FKS Multi-Server Service Deployment Script
# Deploys services to specific servers in the multi-server architecture

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
SERVER_TYPE=""
SERVER_IP=""
COMPOSE_FILE=""
SUBDOMAIN=""

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

# Show help
show_help() {
    cat << EOF
FKS Multi-Server Service Deployment Script

Usage: $0 [options]

Options:
    --server-type TYPE          Server type (auth|api|web)
    --server-ip IP              Server IP address
    --compose-file FILE         Docker compose file to deploy
    --subdomain SUBDOMAIN       Subdomain for this server
    --help                      Show this help message

Examples:
    # Deploy auth services
    $0 --server-type auth --server-ip 192.168.1.100 --compose-file docker-compose.auth.yml --subdomain auth.fkstrading.xyz

    # Deploy API services
    $0 --server-type api --server-ip 192.168.1.101 --compose-file docker-compose.api.yml --subdomain api.fkstrading.xyz

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server-type)
                SERVER_TYPE="$2"
                shift 2
                ;;
            --server-ip)
                SERVER_IP="$2"
                shift 2
                ;;
            --compose-file)
                COMPOSE_FILE="$2"
                shift 2
                ;;
            --subdomain)
                SUBDOMAIN="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Validate inputs
validate_inputs() {
    if [ -z "$SERVER_TYPE" ]; then
        log "ERROR" "Server type is required (--server-type)"
        exit 1
    fi
    
    if [[ ! "$SERVER_TYPE" =~ ^(auth|api|web)$ ]]; then
        log "ERROR" "Invalid server type. Must be: auth, api, or web"
        exit 1
    fi
    
    if [ -z "$SERVER_IP" ]; then
        log "ERROR" "Server IP is required (--server-ip)"
        exit 1
    fi
    
    if [ -z "$COMPOSE_FILE" ]; then
        log "ERROR" "Compose file is required (--compose-file)"
        exit 1
    fi
    
    if [ ! -f "$PROJECT_ROOT/$COMPOSE_FILE" ]; then
        log "ERROR" "Compose file not found: $PROJECT_ROOT/$COMPOSE_FILE"
        exit 1
    fi
    
    if [ -z "$SUBDOMAIN" ]; then
        log "ERROR" "Subdomain is required (--subdomain)"
        exit 1
    fi
    
    # Check required environment variables
    if [ -z "$DOCKER_USERNAME" ]; then
        log "ERROR" "DOCKER_USERNAME environment variable is required"
        exit 1
    fi
    
    if [ -z "$DOCKER_TOKEN" ]; then
        log "ERROR" "DOCKER_TOKEN environment variable is required"
        exit 1
    fi
    
    if [ -z "$ACTIONS_USER_PASSWORD" ]; then
        log "ERROR" "ACTIONS_USER_PASSWORD environment variable is required"
        exit 1
    fi
}

# Test SSH connectivity
test_ssh_connection() {
    log "INFO" "Testing SSH connection to $SERVER_IP..."
    
    if timeout 10 sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 fks_user@"$SERVER_IP" "echo 'SSH connection successful'" 2>/dev/null; then
        log "INFO" "SSH connection established"
        return 0
    else
        log "ERROR" "SSH connection failed"
        return 1
    fi
}

# Create deployment package
create_deployment_package() {
    log "INFO" "Creating deployment package for $SERVER_TYPE server..."
    
    local package_dir="deployment-package-$SERVER_TYPE"
    rm -rf "$package_dir"
    mkdir -p "$package_dir"
    
    # Copy compose file and related configs
    cp "$PROJECT_ROOT/$COMPOSE_FILE" "$package_dir/"
    
    # Copy environment files
    if [ -f "$PROJECT_ROOT/.env" ]; then
        cp "$PROJECT_ROOT/.env" "$package_dir/"
    fi
    
    # Copy server-specific environment files
    if [ -f "$PROJECT_ROOT/.env.$SERVER_TYPE" ]; then
        cp "$PROJECT_ROOT/.env.$SERVER_TYPE" "$package_dir/"
    fi
    
    # Copy configuration directories relevant to this server type
    case "$SERVER_TYPE" in
        "auth")
            # Copy auth-related configs
            if [ -d "$PROJECT_ROOT/config/authelia" ]; then
                cp -r "$PROJECT_ROOT/config/authelia" "$package_dir/"
            fi
            if [ -d "$PROJECT_ROOT/config/nginx/auth" ]; then
                cp -r "$PROJECT_ROOT/config/nginx/auth" "$package_dir/"
            fi
            ;;
        "api")
            # Copy API-related configs
            if [ -d "$PROJECT_ROOT/config/api" ]; then
                cp -r "$PROJECT_ROOT/config/api" "$package_dir/"
            fi
            if [ -d "$PROJECT_ROOT/config/database" ]; then
                cp -r "$PROJECT_ROOT/config/database" "$package_dir/"
            fi
            ;;
        "web")
            # Copy web-related configs
            if [ -d "$PROJECT_ROOT/config/nginx/web" ]; then
                cp -r "$PROJECT_ROOT/config/nginx/web" "$package_dir/"
            fi
            if [ -d "$PROJECT_ROOT/src/web" ]; then
                # Copy built web assets if they exist
                if [ -d "$PROJECT_ROOT/src/web/react/dist" ]; then
                    mkdir -p "$package_dir/web-assets"
                    cp -r "$PROJECT_ROOT/src/web/react/dist"/* "$package_dir/web-assets/"
                fi
            fi
            ;;
    esac
    
    # Create deployment script for the server
    cat > "$package_dir/deploy-$SERVER_TYPE.sh" << EOF
#!/bin/bash

# FKS $SERVER_TYPE Server Deployment Script
set -e

cd /home/fks_user/fks

echo "🚀 Deploying FKS $SERVER_TYPE services..."

# Login to Docker Hub
echo "🔐 Authenticating with Docker Hub..."
echo "\$DOCKER_TOKEN" | docker login --username "\$DOCKER_USERNAME" --password-stdin

# Set environment variables
export COMPOSE_PROJECT_NAME=fks
export DOMAIN_NAME="$SUBDOMAIN"
export SERVER_TYPE="$SERVER_TYPE"

# Source environment file if it exists
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Source server-specific environment if it exists
if [ -f ".env.$SERVER_TYPE" ]; then
    set -a
    source .env.$SERVER_TYPE
    set +a
fi

# Stop existing services
echo "🛑 Stopping existing services..."
docker-compose -f $COMPOSE_FILE down --remove-orphans || true

# Clean up old images to save space
echo "🧹 Cleaning up old images..."
docker image prune -f || true

# Pull latest images
echo "📥 Pulling latest images..."
docker-compose -f $COMPOSE_FILE pull || echo "⚠️ Some image pulls failed, continuing..."

# Start services
echo "🚀 Starting $SERVER_TYPE services..."
docker-compose -f $COMPOSE_FILE up -d

# Wait for services to start
echo "⏳ Waiting for services to initialize..."
sleep 30

# Health check
echo "🏥 Performing health check..."
docker-compose -f $COMPOSE_FILE ps

# Show logs for troubleshooting
echo "📝 Recent logs:"
docker-compose -f $COMPOSE_FILE logs --tail=20

echo "✅ FKS $SERVER_TYPE services deployed successfully!"
echo "🌐 Services should be accessible at: https://$SUBDOMAIN"
EOF
    
    chmod +x "$package_dir/deploy-$SERVER_TYPE.sh"
    
    # Create tar package
    tar -czf "$package_dir.tar.gz" -C "$package_dir" .
    
    log "INFO" "Deployment package created: $package_dir.tar.gz"
}

# Transfer deployment package to server
transfer_package() {
    local package_file="deployment-package-$SERVER_TYPE.tar.gz"
    
    log "INFO" "Transferring deployment package to server..."
    
    # Transfer package
    sshpass -p "$ACTIONS_USER_PASSWORD" scp -o StrictHostKeyChecking=no \
        "$package_file" fks_user@"$SERVER_IP":/tmp/
    
    # Extract on server
    sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        fks_user@"$SERVER_IP" "
        cd /home/fks_user/fks
        tar -xzf /tmp/$package_file
        rm /tmp/$package_file
    "
    
    log "INFO" "Package transferred and extracted"
}

# Deploy services on server
deploy_services() {
    log "INFO" "Deploying $SERVER_TYPE services on server..."
    
    # Execute deployment script on server
    sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        fks_user@"$SERVER_IP" "
        cd /home/fks_user/fks
        
        # Set environment variables
        export DOCKER_USERNAME='$DOCKER_USERNAME'
        export DOCKER_TOKEN='$DOCKER_TOKEN'
        export COMPOSE_PROJECT_NAME=fks
        export DOMAIN_NAME='$SUBDOMAIN'
        export SERVER_TYPE='$SERVER_TYPE'
        
        # Run deployment script
        chmod +x deploy-$SERVER_TYPE.sh
        ./deploy-$SERVER_TYPE.sh
    "
    
    log "INFO" "Deployment completed"
}

# Verify deployment
verify_deployment() {
    log "INFO" "Verifying $SERVER_TYPE deployment..."
    
    # Get service status
    local service_status
    service_status=$(sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        fks_user@"$SERVER_IP" "
        cd /home/fks_user/fks
        docker-compose -f $COMPOSE_FILE ps --format 'table {{.Names}}\t{{.Status}}'
    " 2>/dev/null || echo "Failed to get service status")
    
    log "INFO" "Service status:"
    echo "$service_status"
    
    # Test basic connectivity based on server type
    case "$SERVER_TYPE" in
        "auth")
            # Test Authentik
            if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
                fks_user@"$SERVER_IP" "timeout 5 curl -s http://localhost:9000/api/v3/ping/ >/dev/null" 2>/dev/null; then
                log "INFO" "✅ Authentik service is responding"
            else
                log "WARN" "⚠️ Authentik service not responding yet"
            fi
            ;;
        "api")
            # Test API service
            if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
                fks_user@"$SERVER_IP" "timeout 5 curl -s http://localhost:8000/health >/dev/null" 2>/dev/null; then
                log "INFO" "✅ API service is responding"
            else
                log "WARN" "⚠️ API service not responding yet"
            fi
            
            # Test data service
            if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
                fks_user@"$SERVER_IP" "timeout 5 curl -s http://localhost:9001/health >/dev/null" 2>/dev/null; then
                log "INFO" "✅ Data service is responding"
            else
                log "WARN" "⚠️ Data service not responding yet"
            fi
            ;;
        "web")
            # Test web service
            if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no \
                fks_user@"$SERVER_IP" "timeout 5 curl -s http://localhost:3000 >/dev/null" 2>/dev/null; then
                log "INFO" "✅ Web service is responding"
            else
                log "WARN" "⚠️ Web service not responding yet"
            fi
            ;;
    esac
    
    log "INFO" "Verification completed"
}

# Cleanup local files
cleanup() {
    log "INFO" "Cleaning up local deployment files..."
    rm -rf "deployment-package-$SERVER_TYPE"
    rm -f "deployment-package-$SERVER_TYPE.tar.gz"
}

# Main function
main() {
    parse_args "$@"
    validate_inputs
    
    log "INFO" "🚀 Deploying FKS $SERVER_TYPE services..."
    log "INFO" "Target: $SERVER_IP ($SUBDOMAIN)"
    log "INFO" "Compose file: $COMPOSE_FILE"
    
    # Test SSH connection
    if ! test_ssh_connection; then
        log "ERROR" "Cannot establish SSH connection to server"
        exit 1
    fi
    
    # Create and transfer deployment package
    create_deployment_package
    transfer_package
    
    # Deploy services
    deploy_services
    
    # Verify deployment
    verify_deployment
    
    # Cleanup
    cleanup
    
    log "INFO" "✅ FKS $SERVER_TYPE services deployment completed!"
    log "INFO" "🌐 Services should be accessible at: https://$SUBDOMAIN"
    log "INFO" "🔒 Remember: Access requires Tailscale VPN connection"
}

# Run main function
main "$@"
