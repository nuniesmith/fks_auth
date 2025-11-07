#!/bin/bash
# Fix Docker Permission Issues Script
# This script aligns permissions between host fks_user (UID 1001) and container appuser (UID 1088)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Docker Permission Fix Script ===${NC}"
echo "This script will fix permission mismatches between host and Docker containers"
echo ""

# Get current user info
CURRENT_USER=$(whoami)
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

echo -e "${YELLOW}Current host user: ${CURRENT_USER} (UID: ${CURRENT_UID}, GID: ${CURRENT_GID})${NC}"

# Check if running as fks_user
if [ "$CURRENT_USER" != "fks_user" ]; then
    echo -e "${RED}Warning: This script should be run as fks_user${NC}"
    echo "Please run: sudo su - fks_user"
    exit 1
fi

# Function to update docker-compose override
create_docker_compose_override() {
    local override_file="docker-compose.override.yml"
    
    echo -e "${BLUE}Creating Docker Compose override file...${NC}"
    
    cat > "$override_file" << 'EOF'
# Docker Compose Override - Fixes permission issues
# This file ensures containers run with the same UID/GID as the host fks_user

services:
  # Python services - override user
  api:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
  
  worker:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
  
  data:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
  
  ninja-api:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
  
  # Web service - most important for your current issue
  web:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
    volumes:
      # Ensure write permissions for npm operations
      - ./src/web/react:/app/src/web/react:rw
      - ./src/web/react/node_modules:/app/src/web/react/node_modules:rw
  
  # Training/ML services
  training:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
  
  transformer:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001

  # Node network service (Rust)
  node-network:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
EOF

    echo -e "${GREEN}✓ Created $override_file${NC}"
}

# Function to fix existing file permissions
fix_file_permissions() {
    echo -e "${BLUE}Fixing file permissions...${NC}"
    
    # Directories that need write access
    local WRITE_DIRS=(
        "src/web/react"
        "src/web/react/node_modules"
        "data"
        "logs"
        "models"
        "tmp"
    )
    
    for dir in "${WRITE_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo -e "  Fixing permissions for: $dir"
            # Ensure fks_user owns the directory
            find "$dir" -type d -exec chmod 775 {} \; 2>/dev/null || true
            find "$dir" -type f -exec chmod 664 {} \; 2>/dev/null || true
        fi
    done
    
    # Ensure executable scripts remain executable
    find scripts -type f -name "*.sh" -exec chmod 775 {} \; 2>/dev/null || true
    
    echo -e "${GREEN}✓ File permissions fixed${NC}"
}

# Function to create entrypoint wrapper that fixes permissions at runtime
create_permission_fix_entrypoint() {
    local entrypoint_file="scripts/docker/fix-permissions-entrypoint.sh"
    
    echo -e "${BLUE}Creating permission fix entrypoint...${NC}"
    
    mkdir -p scripts/docker
    
    cat > "$entrypoint_file" << 'EOF'
#!/bin/bash
# Runtime permission fix for Docker containers

# If running as root, fix permissions and switch to appuser
if [ "$(id -u)" = "0" ]; then
    echo "[Permission Fix] Running as root, fixing permissions..."
    
    # Create appuser with the correct UID if it doesn't exist
    if ! id -u appuser >/dev/null 2>&1; then
        groupadd -g ${GROUP_ID:-1001} appuser
        useradd -u ${USER_ID:-1001} -g ${GROUP_ID:-1001} -m -s /bin/bash appuser
    fi
    
    # Fix ownership of critical directories
    chown -R ${USER_ID:-1001}:${GROUP_ID:-1001} /app/src/web/react 2>/dev/null || true
    chown -R ${USER_ID:-1001}:${GROUP_ID:-1001} /app/data 2>/dev/null || true
    chown -R ${USER_ID:-1001}:${GROUP_ID:-1001} /app/logs 2>/dev/null || true
    
    # Switch to appuser and run the original command
    exec gosu appuser "$@"
else
    # Not root, just run the command
    exec "$@"
fi
EOF

    chmod +x "$entrypoint_file"
    echo -e "${GREEN}✓ Created $entrypoint_file${NC}"
}

# Function to update .env file with correct UID/GID
update_env_file() {
    echo -e "${BLUE}Updating .env file...${NC}"
    
    # Check if .env exists
    if [ ! -f .env ]; then
        echo -e "${YELLOW}Creating .env file from template...${NC}"
        cp .env.example .env
    fi
    
    # Add or update USER_ID and GROUP_ID
    if grep -q "^USER_ID=" .env; then
        sed -i "s/^USER_ID=.*/USER_ID=1001/" .env
    else
        echo "USER_ID=1001" >> .env
    fi
    
    if grep -q "^GROUP_ID=" .env; then
        sed -i "s/^GROUP_ID=.*/GROUP_ID=1001/" .env
    else
        echo "GROUP_ID=1001" >> .env
    fi
    
    echo -e "${GREEN}✓ Updated .env file${NC}"
}

# Function to rebuild affected containers
rebuild_containers() {
    echo -e "${BLUE}Rebuilding affected containers...${NC}"
    
    # Stop affected containers
    docker compose stop web api worker data ninja-api 2>/dev/null || true
    
    # Remove them to force recreation with new settings
    docker compose rm -f web api worker data ninja-api 2>/dev/null || true
    
    # Rebuild with new settings
    docker compose build --no-cache web
    
    echo -e "${GREEN}✓ Containers rebuilt${NC}"
}

# Main execution
echo -e "${BLUE}Starting permission fix process...${NC}"
echo ""

# Step 1: Create docker-compose override
create_docker_compose_override

# Step 2: Fix file permissions
fix_file_permissions

# Step 3: Create permission fix entrypoint
create_permission_fix_entrypoint

# Step 4: Update .env file
update_env_file

# Step 5: Offer to rebuild containers
echo ""
echo -e "${YELLOW}Permission fixes applied!${NC}"
echo ""
echo "Next steps:"
echo "1. Rebuild and restart containers:"
echo "   docker compose down"
echo "   docker compose build web"
echo "   docker compose up -d"
echo ""
echo "2. If you still have issues, you can force all containers to use UID 1001:"
echo "   Add to your docker-compose.yml under each service:"
echo "   user: \"1001:1001\""
echo ""

# Ask if user wants to rebuild now
read -p "Do you want to rebuild and restart containers now? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rebuild_containers
    echo -e "${BLUE}Restarting services...${NC}"
    docker compose up -d
    echo -e "${GREEN}✓ Services restarted${NC}"
    echo ""
    echo "Check the logs with: docker compose logs -f web"
fi

echo -e "${GREEN}✓ Permission fix complete!${NC}"
