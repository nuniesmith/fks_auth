#!/bin/bash
# Docker Cache & Data Cleanup Script
# This script performs thorough Docker cleanup while preserving the installation
# Warning: This will remove ALL Docker containers, images, volumes, and cache

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Check if we need sudo for system operations at the beginning
echo "🔐 Checking permissions..."
if ! sudo -n true 2>/dev/null; then
    echo "This script requires sudo privileges for system operations."
    echo "Please enter your password when prompted:"
    sudo -v
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Configurable backup directory (override with BACKUP_DIR env)
BACKUP_TS=$(date +%F-%H%M%S)
BACKUP_DIR_DEFAULT="${PWD}/backups/docker-${BACKUP_TS}"
BACKUP_DIR="${BACKUP_DIR:-$BACKUP_DIR_DEFAULT}"
# Default: skip backups unless explicitly enabled or chosen interactively
SKIP_BACKUP="${SKIP_BACKUP:-1}"

# Ensure backup directory exists
ensure_backup_dir() {
    mkdir -p "$BACKUP_DIR" || true
    print_status "Backups will be saved to: $BACKUP_DIR"
}

# Check docker availability
is_docker_ready() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Check if a container is running
container_running() {
    local name="$1"
    docker ps --format '{{.Names}}' | grep -q "^${name}$" 2>/dev/null
}

# Generic volume backup: tar.gz contents of a named volume into $BACKUP_DIR
backup_volume() {
    local vol_name="$1"
    local out_prefix="$2"
    if docker volume inspect "$vol_name" >/dev/null 2>&1; then
        print_status "Backing up volume: $vol_name -> ${out_prefix}.tgz"
        docker run --rm \
          -v "$vol_name":/data:ro \
          -v "$BACKUP_DIR":/backup \
          alpine sh -lc "cd /data && tar czf /backup/${out_prefix}-${BACKUP_TS}.tgz ." 2>/dev/null || true
    else
        print_warning "Volume not found, skipping: $vol_name"
    fi
}

# Resolve Authentik DB container name heuristically
resolve_authelia_db_container() {
    # Priority: explicit env override
    if [ -n "${AUTHELIA_DB_CONTAINER:-}" ]; then
        echo "$AUTHELIA_DB_CONTAINER"
        return 0
    fi
    # Look for common patterns
    local candidate
    candidate=$(docker ps --format '{{.Names}}' | grep -E 'authelia.*(db|postgres|pg|pgsql)' | head -n1 || true)
    if [ -n "$candidate" ]; then
        echo "$candidate"
        return 0
    fi
    # Try docker compose service names (default Compose v2 naming)
    candidate=$(docker ps --format '{{.Names}}' | grep -E 'fks.*authelia.*(db|postgres)' | head -n1 || true)
    if [ -n "$candidate" ]; then
        echo "$candidate"
        return 0
    fi
    # Fallback to a common explicit name used in docs
    echo "fks_authelia_db"
}

# Authentik: logical DB backup via pg_dump if DB container is running; else fall back to volume tar
backup_authelia_db() {
    local db_container
    db_container=$(resolve_authelia_db_container)
    if container_running "$db_container"; then
        print_status "Creating Authentik DB dump from running container: $db_container"
        docker exec -t "$db_container" sh -lc "pg_dump -U ${AUTHELIA_DB_USER:-authelia} -F c -d ${AUTHELIA_DB_NAME:-authelia} -f /tmp/authelia.dump" 2>/dev/null || true
        if docker exec -t "$db_container" test -f /tmp/authelia.dump 2>/dev/null; then
            docker cp "$db_container":/tmp/authelia.dump "$BACKUP_DIR"/authelia-db-${BACKUP_TS}.dump 2>/dev/null || true
            print_success "Authentik DB dump saved: $BACKUP_DIR/authelia-db-${BACKUP_TS}.dump"
        else
            print_warning "pg_dump did not produce a dump file; falling back to raw volume backup"
            backup_volume fks_authelia_postgres_data authelia-pgdata
        fi
    else
        print_warning "DB container $db_container not running; performing raw volume backup"
        backup_volume fks_authelia_postgres_data authelia-pgdata
    fi
}

# Authentik asset volumes backup
backup_authelia_assets() {
    backup_volume fks_authelia_media authelia-media
    backup_volume fks_authelia_custom_templates authelia-templates
    backup_volume fks_authelia_certs authelia-certs
    # Optional: redis state (usually ephemeral)
    backup_volume fks_authelia_redis_data authelia-redis
}

# Orchestrate all Authentik backups
backup_authelia_all() {
    if ! is_docker_ready; then
        print_warning "Docker not available; skipping Authentik backup"
        return 0
    fi
    print_status "Starting Authentik backup..."
    ensure_backup_dir
    backup_authelia_db
    backup_authelia_assets
    print_success "Authentik backup complete"
}

# Backup other FKS/Ninja volumes (excluding ones handled above)
backup_other_named_volumes() {
    if ! is_docker_ready; then
        return 0
    fi
    print_status "Scanning for additional FKS/Ninja volumes to back up..."
    local exclude="^(fks_authelia_postgres_data|fks_authelia_media|fks_authelia_custom_templates|fks_authelia_certs|fks_authelia_redis_data)$"
    local vols
    vols=$(docker volume ls --format '{{.Name}}' | grep -E '^(fks|ninja)' || true)
    if [ -z "$vols" ]; then
        print_status "No additional FKS/Ninja volumes found"
        return 0
    fi
    while IFS= read -r vol; do
        if echo "$vol" | grep -Eq "$exclude"; then
            continue
        fi
        backup_volume "$vol" "$vol"
    done <<< "$vols"
    print_success "Additional volumes backup complete"
}

# Function to get directory size
get_size() {
    if [ -d "$1" ]; then
        du -sh "$1" 2>/dev/null | cut -f1 || echo "0B"
    else
        echo "N/A"
    fi
}

# Function to safely remove directory
safe_remove() {
    local dir="$1"
    local desc="$2"
    
    if [ -d "$dir" ]; then
        local size=$(get_size "$dir")
        print_status "Removing $desc ($size): $dir"
        if sudo rm -rf "$dir" 2>/dev/null; then
            print_success "$desc removed"
        else
            print_warning "Could not remove $dir"
        fi
    else
        print_status "$desc directory not found: $dir"
    fi
}

# Function to run Docker command safely (without exiting on failure)
docker_safe() {
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            "$@" 2>/dev/null || true
        else
            print_warning "Docker daemon not accessible for command: $*"
        fi
    else
        print_warning "Docker command not available: $*"
    fi
}

# Function to clean FKS-specific Docker resources
clean_fks_resources() {
    print_status "Cleaning FKS-specific Docker resources..."
    
    # Stop FKS compose services if running
    if [ -f "docker-compose.yml" ] || [ -f "docker-compose.override.yml" ]; then
        print_status "Stopping FKS Docker Compose services..."
        docker-compose down --remove-orphans 2>/dev/null || true
        docker compose down --remove-orphans 2>/dev/null || true
    fi
    
    # Remove FKS-specific containers
    docker_safe docker ps -a --filter "name=fks" -q | xargs -r docker rm -f
    docker_safe docker ps -a --filter "name=ninja" -q | xargs -r docker rm -f
    
    # Remove FKS-specific images
    docker_safe docker images --filter "reference=nuniesmith/fks*" -q | xargs -r docker rmi -f
    docker_safe docker images --filter "reference=*fks*" -q | xargs -r docker rmi -f
    
    # Remove FKS-specific volumes
    docker_safe docker volume ls --filter "name=fks" -q | xargs -r docker volume rm -f
    docker_safe docker volume ls --filter "name=ninja" -q | xargs -r docker volume rm -f
    
    # Remove FKS-specific networks
    docker_safe docker network ls --filter "name=fks" -q | xargs -r docker network rm
    
    print_success "FKS-specific resources cleaned"
}

echo "=================================================================="
echo "🐳 DOCKER CLEANUP SCRIPT - CACHE & DATA RESET"
echo "=================================================================="
echo ""
print_warning "This will clean ALL Docker cache and data but keep Docker installed!"
print_warning "This includes:"
echo "  • All containers (running and stopped)"
echo "  • All images and layers"
echo "  • All volumes and build cache"
echo "  • All custom networks"
echo "  • Docker system cache and logs"
echo "  • Temporary Docker files"
echo ""
print_status "Docker will be restarted but remain installed and configured"
echo ""

# Show current Docker disk usage
echo "📊 CURRENT DOCKER DISK USAGE:"
echo "----------------------------------------"
docker_dirs=(
    "/var/lib/docker"
    "/var/lib/containerd" 
    "/opt/containerd"
    "/var/log/docker"
    "/var/run/docker"
    "/tmp/docker*"
    "$HOME/.docker"
)

total_before=0
for dir in "${docker_dirs[@]}"; do
    if [[ "$dir" == *"*"* ]]; then
        # Handle wildcard directories
        for d in $dir; do
            if [ -d "$d" ]; then
                size=$(get_size "$d")
                echo "  $d: $size"
            fi
        done
    else
        size=$(get_size "$dir")
        echo "  $dir: $size"
    fi
done

if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo ""
    print_status "Docker system usage:"
    docker system df 2>/dev/null || echo "Could not get Docker system info"
fi

echo ""
print_warning "⚠️  CONFIRMATION REQUIRED ⚠️"
echo "This will permanently delete all Docker containers, images, and volumes."
echo "Are you sure you want to continue? (yes/no)"
read -r confirmation

if [[ ! "$confirmation" =~ ^[Yy][Ee][Ss]$ ]]; then
    print_status "Operation cancelled by user"
    exit 0
fi

echo ""

# Ask whether to run backups (default: No). In non-interactive mode, keep default.
if [ -t 0 ]; then
    print_status "Do you want to create backups before cleanup? (y/N)"
    read -r do_backup
    if [[ "$do_backup" =~ ^([Yy]|[Yy][Ee][Ss])$ ]]; then
        SKIP_BACKUP="0"
        print_status "Backups ENABLED"
    else
        SKIP_BACKUP="1"
        print_status "Backups DISABLED"
    fi
else
    print_status "Non-interactive mode detected; skipping backups by default (set SKIP_BACKUP=0 to enable)"
fi

# ------------------------------------------------------------------
# BACKUP PHASE (non-destructive) — runs BEFORE any cleanup
# ------------------------------------------------------------------
if [ "$SKIP_BACKUP" = "1" ]; then
    print_warning "Skipping backup phase (SKIP_BACKUP=1)"
else
    backup_authelia_all
    backup_other_named_volumes
    echo ""
    print_status "Backup phase done. Artifacts in: $BACKUP_DIR"
fi

print_status "Starting comprehensive Docker cleanup..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

# 1. Clean FKS-specific resources first
clean_fks_resources

# 2. Clean up via Docker CLI (before stopping daemon)
print_status "Performing comprehensive Docker CLI cleanup..."

# Remove all containers
containers=$(docker ps -a -q 2>/dev/null || true)
if [ -n "$containers" ]; then
    print_status "Stopping and removing all containers..."
    docker stop $containers 2>/dev/null || true
    docker rm -f $containers 2>/dev/null || true
    print_success "All containers removed via CLI"
else
    print_status "No containers found"
fi

# Remove all images
images=$(docker images -q 2>/dev/null || true)
if [ -n "$images" ]; then
    print_status "Removing all Docker images..."
    docker rmi -f $images 2>/dev/null || true
    print_success "All images removed via CLI"
else
    print_status "No images found"
fi

# Remove all volumes
volumes=$(docker volume ls -q 2>/dev/null || true)
if [ -n "$volumes" ]; then
    print_status "Removing all Docker volumes..."
    docker volume rm -f $volumes 2>/dev/null || true
    print_success "All volumes removed via CLI"
else
    print_status "No volumes found"
fi

# Remove all custom networks
networks=$(docker network ls --filter type=custom -q 2>/dev/null || true)
if [ -n "$networks" ]; then
    print_status "Removing custom Docker networks..."
    docker network rm $networks 2>/dev/null || true
    print_success "All custom networks removed"
else
    print_status "No custom networks found"
fi

# Clean build cache and system prune
print_status "Performing comprehensive system cleanup..."
docker builder prune -a -f 2>/dev/null || true
docker system prune -a -f --volumes 2>/dev/null || true
print_success "Docker CLI cleanup completed"

# 2. Stop Docker service
print_status "Stopping Docker service..."
if sudo systemctl is-active --quiet docker 2>/dev/null; then
    sudo systemctl stop docker
    print_success "Docker service stopped"
else
    print_status "Docker service was not running"
fi

# Also stop containerd if it exists
if sudo systemctl is-active --quiet containerd 2>/dev/null; then
    print_status "Stopping containerd service..."
    sudo systemctl stop containerd
    print_success "Containerd service stopped"
fi

# 3. Kill any remaining Docker processes
print_status "Killing any remaining Docker processes..."
sudo pkill -f docker 2>/dev/null || true
sudo pkill -f containerd 2>/dev/null || true
sleep 2  # Give processes time to terminate
print_success "Docker processes terminated"

# 4. SELECTIVE FILESYSTEM CLEANUP (Keep Docker installation intact)
print_status "Starting selective filesystem cleanup..."

# Clean Docker data but preserve configuration
if [ -d "/var/lib/docker" ]; then
    print_status "Cleaning Docker data directory contents..."
    # Remove specific subdirectories but keep the main directory structure
    for subdir in containers image network volumes buildkit overlay2 swarm tmp trust plugins; do
        if [ -d "/var/lib/docker/$subdir" ]; then
            safe_remove "/var/lib/docker/$subdir" "Docker $subdir data"
        fi
    done
else
    print_status "Docker data directory not found"
fi

# Clean containerd data but preserve installation
if [ -d "/var/lib/containerd" ]; then
    print_status "Cleaning containerd data..."
    for subdir in io.containerd.snapshotter.v1.overlayfs io.containerd.content.v1.content io.containerd.metadata.v1.bolt; do
        if [ -d "/var/lib/containerd/$subdir" ]; then
            safe_remove "/var/lib/containerd/$subdir" "Containerd $subdir data"
        fi
    done
fi

# Clean Docker logs but keep log directory
if [ -d "/var/log/docker" ]; then
    print_status "Cleaning Docker logs..."
    sudo find /var/log/docker -type f -name "*.log*" -delete 2>/dev/null || true
    print_success "Docker logs cleaned"
fi

# Clean container logs
if [ -d "/var/lib/docker/containers" ]; then
    print_status "Cleaning container logs..."
    sudo find /var/lib/docker/containers -name "*.log" -delete 2>/dev/null || true
fi

# Temporary Docker files
print_status "Cleaning temporary Docker files..."
sudo find /tmp -name "*docker*" -type d -exec rm -rf {} + 2>/dev/null || true
sudo find /tmp -name "*docker*" -type f -delete 2>/dev/null || true

# 5. Clean Docker system cache (but preserve installation)
print_status "Cleaning Docker system cache..."

# Clean any remaining cache files
if [ -d "/root/.docker" ]; then
    safe_remove "/root/.docker/buildx" "Docker buildx cache"
    safe_remove "/root/.docker/cli-plugins" "Docker CLI plugins cache"
fi

if [ -d "$HOME/.docker" ]; then
    print_status "Cleaning user Docker cache..."
    rm -rf "$HOME/.docker/buildx" 2>/dev/null || true
    rm -rf "$HOME/.docker/cli-plugins" 2>/dev/null || true
fi

# 6. Restart Docker service
print_status "Restarting Docker service..."
if sudo systemctl restart docker 2>/dev/null; then
    print_success "Docker service restarted"
else
    print_warning "Could not restart Docker service"
fi

if sudo systemctl restart containerd 2>/dev/null; then
    print_success "Containerd service restarted"
else
    print_warning "Could not restart containerd service"
fi

# Wait a moment for Docker to start
sleep 3

if sudo systemctl is-active --quiet docker 2>/dev/null; then
    print_success "Docker service is running"
    print_status "Docker has been reset to a clean state"
    
    # Verify Docker is working
    if docker info &> /dev/null; then
        print_success "Docker is responding to commands"
    else
        print_warning "Docker service is running but not responding yet"
    fi
else
    print_warning "Docker service failed to start properly"
fi

echo ""
echo "📊 CLEANUP SUMMARY:"
echo "----------------------------------------"

# Show Docker status
if sudo systemctl is-active --quiet docker 2>/dev/null; then
    print_success "Docker service: Running"
else
    print_warning "Docker service: Not running"
fi

# Show current Docker disk usage
if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo ""
    print_status "Current Docker system usage:"
    docker system df 2>/dev/null || echo "Could not get Docker system info"
fi

# Show disk space freed
if [ -d "/var/lib/docker" ]; then
    new_size=$(get_size "/var/lib/docker")
    echo "Docker data directory size: $new_size"
else
    echo "Docker data directory: Not found"
fi

echo ""
print_success "🎉 DOCKER CLEANUP COMPLETE!"
echo ""
print_status "What was cleaned:"
echo "  ✅ All Docker containers, images, and volumes"
echo "  ✅ All Docker networks and build cache"  
echo "  ✅ Docker data and cache files"
echo "  ✅ Docker runtime files and logs"
echo "  ✅ Temporary Docker files"
echo "  ✅ Docker build cache and metadata"
echo ""
print_status "What was preserved:"
echo "  🔒 Docker installation and binaries"
echo "  🔒 Docker configuration files"
echo "  🔒 Docker systemd services"
echo "  🔒 User docker group membership"
echo ""
print_status "Next steps:"
echo "  • Docker is ready to use immediately"
echo "  • You'll need to pull images again as needed"
echo "  • All previous containers and data have been cleared"
echo "  • Run 'docker info' to verify everything is working"