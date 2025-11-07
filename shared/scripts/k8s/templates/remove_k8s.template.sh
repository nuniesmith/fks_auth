#!/bin/bash
set -e

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
REMOVE_DOCKER=${REMOVE_DOCKER:-"false"}
REMOVE_MINIKUBE=${REMOVE_MINIKUBE:-"true"}
REMOVE_CONFIG_ONLY=${REMOVE_CONFIG_ONLY:-"false"}
FORCE=${FORCE:-"false"}

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

prompt() {
    echo -e "${BLUE}[PROMPT]${NC} $1"
}

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root. Use sudo."
    fi
}

# Display script usage
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -d, --docker     Also remove Docker (default: false)"
    echo "  -m, --minikube   Also remove Minikube (default: true)"
    echo "  -c, --config     Remove only configuration files, keep binaries (default: false)"
    echo "  -f, --force      Don't ask for confirmation (default: false)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  REMOVE_DOCKER      Set to 'true' to remove Docker"
    echo "  REMOVE_MINIKUBE    Set to 'false' to keep Minikube"
    echo "  REMOVE_CONFIG_ONLY Set to 'true' to keep binaries"
    echo "  FORCE              Set to 'true' to skip confirmation"
    echo ""
    echo "Examples:"
    echo "  $0 --docker      # Remove Kubernetes and Docker"
    echo "  $0 --config      # Remove only Kubernetes configurations"
    echo "  FORCE=true $0    # Remove Kubernetes without confirmation"
    exit 0
}

# Confirm cleanup
confirm_cleanup() {
    if [ "$FORCE" = "true" ]; then
        return 0
    fi
    
    echo ""
    warn "This will remove Kubernetes components from your system."
    
    if [ "$REMOVE_DOCKER" = "true" ]; then
        warn "Docker will also be removed."
    fi
    
    if [ "$REMOVE_MINIKUBE" = "true" ]; then
        warn "Minikube will also be removed."
    fi
    
    if [ "$REMOVE_CONFIG_ONLY" = "true" ]; then
        warn "Only configuration files will be removed, binaries will be kept."
    else
        warn "Both configuration files and binaries will be removed."
    fi
    
    echo ""
    prompt "Are you sure you want to continue? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "Cleanup cancelled."
        exit 0
    fi
}

# Stop and disable a systemd service
stop_disable_service() {
    local service=$1
    
    log "Checking $service service..."
    
    if systemctl is-active --quiet "$service"; then
        log "Stopping $service service..."
        if ! systemctl stop "$service"; then
            warn "Failed to stop $service service. Continuing anyway."
        fi
    else
        log "$service service is not running."
    fi
    
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log "Disabling $service service..."
        if ! systemctl disable "$service"; then
            warn "Failed to disable $service service. Continuing anyway."
        fi
    else
        log "$service service is not enabled."
    fi
}

# Remove a directory if it exists
remove_dir() {
    local dir=$1
    
    if [ -d "$dir" ]; then
        log "Removing directory: $dir"
        rm -rf "$dir" || warn "Failed to remove directory: $dir"
    else
        log "Directory does not exist, skipping: $dir"
    fi
}

# Remove Kubernetes configuration directories
remove_k8s_configs() {
    log "Removing Kubernetes configuration directories..."
    
    # Common Kubernetes directories
    remove_dir "/etc/cni"
    remove_dir "/etc/kubernetes"
    remove_dir "/var/lib/etcd"
    remove_dir "/var/lib/kubelet"
    remove_dir "$HOME/.kube"
    
    # Remove from root user's home if different
    if [ "$HOME" != "/root" ]; then
        remove_dir "/root/.kube"
    fi
    
    # Clean systemd configurations
    log "Cleaning systemd configurations..."
    
    if [ -d "/etc/systemd/system/kubelet.service.d" ]; then
        rm -rf /etc/systemd/system/kubelet.service.d/* || warn "Failed to remove kubelet systemd drop-ins."
    fi
    
    if [ -f "/etc/systemd/system/kubelet.service" ]; then
        rm -f /etc/systemd/system/kubelet.service || warn "Failed to remove kubelet systemd service file."
    fi
    
    # Reload systemd configuration
    log "Reloading systemd daemon..."
    systemctl daemon-reload || warn "Failed to reload systemd daemon."
    systemctl reset-failed || warn "Failed to reset failed systemd services."
}

# Remove Kubernetes binaries
remove_k8s_binaries() {
    if [ "$REMOVE_CONFIG_ONLY" = "true" ]; then
        log "Skipping binary removal as --config option was specified."
        return 0
    fi
    
    log "Removing Kubernetes binaries..."
    
    # For Manjaro, we should use pacman to remove packages if they were installed that way
    if command -v pacman &> /dev/null; then
        log "Detected pacman package manager, using it to remove Kubernetes packages..."
        
        # Check if packages are installed before removing them
        for pkg in kubectl kubeadm kubelet kubernetes-cni; do
            if pacman -Qi "$pkg" &> /dev/null; then
                log "Removing package: $pkg"
                pacman -R --noconfirm "$pkg" || warn "Failed to remove package: $pkg"
            else
                log "Package not installed: $pkg"
            fi
        done
    else
        # Fallback to manual binary removal
        log "Package manager not detected, manually removing binaries..."
        
        for bin in kubectl kubeadm kubelet; do
            if [ -f "/usr/bin/$bin" ] || [ -f "/usr/local/bin/$bin" ]; then
                log "Removing binary: $bin"
                rm -f /usr/bin/$bin /usr/local/bin/$bin || warn "Failed to remove binary: $bin"
            else
                log "Binary not found: $bin"
            fi
        done
    fi
}

# Remove Minikube
remove_minikube() {
    if [ "$REMOVE_MINIKUBE" != "true" ]; then
        log "Skipping Minikube removal."
        return 0
    fi
    
    log "Cleaning up Minikube..."
    
    # Stop Minikube if it's running
    if command -v minikube &> /dev/null; then
        if minikube status | grep -q "Running"; then
            log "Stopping Minikube..."
            minikube stop || warn "Failed to stop Minikube."
        fi
        
        log "Deleting Minikube cluster..."
        minikube delete --all || warn "Failed to delete Minikube clusters."
        
        # Remove Minikube binary
        if [ "$REMOVE_CONFIG_ONLY" != "true" ]; then
            log "Removing Minikube binary..."
            rm -f /usr/local/bin/minikube || warn "Failed to remove Minikube binary."
        fi
    else
        log "Minikube not found."
    fi
    
    # Remove Minikube data directory
    remove_dir "$HOME/.minikube"
    if [ "$HOME" != "/root" ]; then
        remove_dir "/root/.minikube"
    fi
}

# Remove Docker
remove_docker() {
    if [ "$REMOVE_DOCKER" != "true" ]; then
        log "Keeping Docker installation."
        return 0
    fi
    
    log "Cleaning up Docker..."
    
    # Stop and disable Docker service
    stop_disable_service "docker"
    
    # For Manjaro, we should use pacman to remove Docker packages
    if command -v pacman &> /dev/null; then
        log "Removing Docker packages..."
        
        for pkg in docker docker-compose containerd; do
            if pacman -Qi "$pkg" &> /dev/null; then
                log "Removing package: $pkg"
                pacman -R --noconfirm "$pkg" || warn "Failed to remove package: $pkg"
            else
                log "Package not installed: $pkg"
            fi
        done
    else
        warn "Package manager not detected, skipping Docker package removal."
    fi
    
    # Remove Docker data directories
    log "Removing Docker data directories..."
    remove_dir "/var/lib/docker"
    remove_dir "/etc/docker"
}

# Main cleanup function
cleanup_kubernetes() {
    log "Starting Kubernetes cleanup..."
    
    # Stop and disable services
    stop_disable_service "kubelet"
    stop_disable_service "etcd"
    
    # Remove Minikube (if specified)
    remove_minikube
    
    # Remove configurations
    remove_k8s_configs
    
    # Remove binaries
    remove_k8s_binaries
    
    # Remove Docker (if specified)
    remove_docker
    
    log "Kubernetes cleanup completed successfully."
    
    if [ "$REMOVE_DOCKER" != "true" ]; then
        warn "Docker is still installed. If you want to remove it as well, run with --docker option."
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--docker)
            REMOVE_DOCKER="true"
            shift
            ;;
        -m|--minikube)
            REMOVE_MINIKUBE="true"
            shift
            ;;
        -c|--config)
            REMOVE_CONFIG_ONLY="true"
            shift
            ;;
        -f|--force)
            FORCE="true"
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            warn "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Main execution
check_root
confirm_cleanup
cleanup_kubernetes
exit 0