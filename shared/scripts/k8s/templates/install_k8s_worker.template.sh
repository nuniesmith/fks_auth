#!/bin/bash
set -e

# Configuration Variables (can be overridden through environment variables)
MASTER_IP=${MASTER_IP:-"100.115.54.104"}
MASTER_PORT=${MASTER_PORT:-"6443"}
KUBE_TOKEN=${KUBE_TOKEN:-""}
CA_CERT_HASH=${CA_CERT_HASH:-""}
JOIN_COMMAND_FILE=${JOIN_COMMAND_FILE:-""}

# Functions
log() {
    echo -e "\e[1;32m[INFO]\e[0m $1"
}

error() {
    echo -e "\e[1;31m[ERROR]\e[0m $1" >&2
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use sudo."
    fi
}

# Install AUR helper if needed
install_aur_helper() {
    if ! command -v yay &> /dev/null; then
        log "Installing yay AUR helper..."
        sudo pacman -S --needed --noconfirm git base-devel || error "Failed to install git and base-devel"
        
        # Create temporary directory for yay installation
        local TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"
        
        git clone https://aur.archlinux.org/yay.git || error "Failed to clone yay repository"
        cd yay
        makepkg -si --noconfirm || error "Failed to install yay"
        
        # Clean up
        cd /
        rm -rf "$TEMP_DIR"
        
        log "yay installed successfully"
    else
        log "yay is already installed"
    fi
}

# Pre-requisites
install_prerequisites() {
    log "Updating package list and installing prerequisites..."
    sudo pacman -Syu --noconfirm || error "Failed to update package list."
    sudo pacman -S --needed --noconfirm curl wget git iptables iproute2 || error "Failed to install prerequisites."
}

# Install Docker
install_docker() {
    log "Installing Docker..."
    sudo pacman -S --needed --noconfirm docker || error "Failed to install Docker."
    
    log "Configuring Docker to use systemd as the cgroup driver..."
    sudo mkdir -p /etc/docker
    cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF
    log "Enabling and starting Docker..."
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add current user to docker group for non-root access
    sudo usermod -aG docker "$USER" || log "Could not add user to docker group. You may need to use sudo with docker commands."
}

# Configure system settings for Kubernetes
configure_system_settings() {
    log "Disabling swap..."
    sudo swapoff -a || true
    sudo sed -i '/ swap / s/^/#/' /etc/fstab || true
    
    # Disable firewall (Manjaro typically uses ufw)
    log "Disabling firewall..."
    if command -v ufw &> /dev/null; then
        sudo ufw disable || log "Failed to disable ufw, you may need to configure firewall rules manually."
    else
        log "ufw not found. If you're using another firewall, disable it or configure it for Kubernetes."
    fi
    
    log "Configuring IPv4 forwarding and bridge filters..."
    echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/k8s.conf
    sudo modprobe overlay
    sudo modprobe br_netfilter
    
    cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
    sudo sysctl --system || error "Failed to apply sysctl settings."
}

# Install Kubernetes tools
install_kubernetes_tools() {
    log "Installing Kubernetes tools (kubeadm, kubelet, kubectl)..."
    
    # First check if the tools are available in the official repositories
    if pacman -Ss kubelet kubeadm kubectl | grep -q "^extra/"; then
        sudo pacman -S --needed --noconfirm kubelet kubeadm kubectl || error "Failed to install Kubernetes tools from official repos."
    else
        # If not available in official repos, install from AUR using yay
        install_aur_helper
        yay -S --needed --noconfirm kubelet kubeadm kubectl || error "Failed to install Kubernetes tools from AUR."
    fi
    
    # Enable and start kubelet
    sudo systemctl enable kubelet
    sudo systemctl start kubelet
}

# Join Kubernetes Cluster
join_k8s_cluster() {
    log "Preparing to join Kubernetes cluster..."
    
    # If join command file is provided, use it
    if [[ -n "$JOIN_COMMAND_FILE" && -f "$JOIN_COMMAND_FILE" ]]; then
        log "Using join command from file: $JOIN_COMMAND_FILE"
        chmod +x "$JOIN_COMMAND_FILE"
        bash "$JOIN_COMMAND_FILE" || error "Failed to join cluster using command from file."
        return
    fi
    
    # If no token is provided, prompt for it
    if [[ -z "$KUBE_TOKEN" ]]; then
        read -p "Enter the Kubernetes token: " KUBE_TOKEN
        if [[ -z "$KUBE_TOKEN" ]]; then
            error "Kubernetes token is required to join the cluster."
        fi
    fi
    
    # If no CA cert hash is provided, prompt for it
    if [[ -z "$CA_CERT_HASH" ]]; then
        read -p "Enter the CA certificate hash (sha256:...): " CA_CERT_HASH
        if [[ -z "$CA_CERT_HASH" ]]; then
            error "CA certificate hash is required to join the cluster."
        fi
    fi
    
    log "Joining Kubernetes cluster at $MASTER_IP:$MASTER_PORT..."
    sudo kubeadm join "$MASTER_IP:$MASTER_PORT" \
        --token "$KUBE_TOKEN" \
        --discovery-token-ca-cert-hash "$CA_CERT_HASH" || error "Failed to join Kubernetes cluster."
}

# Main script logic
main() {
    check_root
    log "Starting Kubernetes worker node setup on Manjaro..."
    install_prerequisites
    install_docker
    configure_system_settings
    install_kubernetes_tools
    join_k8s_cluster
    log "Worker node setup complete. The node has joined the Kubernetes cluster."
}

# Entry point
main "$@"