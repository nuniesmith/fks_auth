#!/bin/bash
set -e

# Configuration Variables
ADVERTISE_ADDRESS=${ADVERTISE_ADDRESS:-"100.115.54.104"}
POD_SUBNET=${POD_SUBNET:-"10.24.0.0/16"}
SERVICE_SUBNET=${SERVICE_SUBNET:-"10.96.0.0/12"}

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

# Install and configure Docker
install_configure_docker() {
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
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add current user to docker group to run docker without sudo
    sudo usermod -aG docker "$USER" || log "Could not add user to docker group. You may need to use sudo with docker commands."
}

# Configure system settings for Kubernetes
configure_system_settings() {
    log "Disabling swap..."
    sudo swapoff -a || true
    sudo sed -i '/ swap / s/^/#/' /etc/fstab || true
    
    # Manjaro doesn't use SELinux by default, so we can skip SELinux configuration
    
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

# Install Minikube
install_minikube() {
    log "Installing Minikube..."
    curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube /usr/local/bin/ || error "Failed to install Minikube."
    rm -f minikube
    
    # Install kubectl if not already installed
    if ! command -v kubectl &> /dev/null; then
        log "Installing kubectl..."
        sudo pacman -S --needed --noconfirm kubectl || error "Failed to install kubectl"
    fi
}

# Start Minikube
start_minikube() {
    log "Starting Minikube with Docker driver..."
    # Ensure we use the advertise address if specified
    if [[ -n "$ADVERTISE_ADDRESS" ]]; then
        minikube start --driver=docker --apiserver-ips="$ADVERTISE_ADDRESS" || error "Failed to start Minikube."
    else
        minikube start --driver=docker || error "Failed to start Minikube."
    fi
    
    minikube status || error "Minikube is not running properly."
    
    log "Configuring kubectl for Minikube..."
    kubectl config use-context minikube || error "Failed to set Minikube context."
    
    log "Creating namespaces for fks_development, fks_staging, and fks_production..."
    kubectl create namespace fks_development || log "Namespace fks_development already exists."
    kubectl create namespace fks_staging || log "Namespace fks_staging already exists."
    kubectl create namespace fks_production || log "Namespace fks_production already exists."
    
    # Set the default namespace to fks_development
    kubectl config set-context --current --namespace=fks_development || log "Failed to set default namespace to fks_development."
    log "Default namespace set to fks_development."
    
    # Generate and save join command for worker nodes
    log "Generating join command for worker nodes..."
    mkdir -p /var/k8s
    minikube ip > /var/k8s/master_ip
    kubectl -n kube-system get secrets -o jsonpath="{.items[?(@.type==\"bootstrap.kubernetes.io/token\")].data.token-id}" | base64 -d > /var/k8s/token_id
    kubectl -n kube-system get secrets -o jsonpath="{.items[?(@.type==\"bootstrap.kubernetes.io/token\")].data.token-secret}" | base64 -d > /var/k8s/token_secret
    openssl x509 -pubkey -in /var/lib/minikube/certs/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //' > /var/k8s/ca_cert_hash
    
    cat <<EOF > /var/k8s/join_command.sh
#!/bin/bash
sudo kubeadm join $(minikube ip):8443 --token $(cat /var/k8s/token_id).$(cat /var/k8s/token_secret) --discovery-token-ca-cert-hash sha256:$(cat /var/k8s/ca_cert_hash)
EOF
    chmod +x /var/k8s/join_command.sh
    log "Join command saved to /var/k8s/join_command.sh"
}

# Validate Minikube setup
validate_minikube() {
    log "Validating Minikube setup..."
    kubectl get nodes || error "Failed to list nodes. Minikube may not be operational."
    kubectl get pods -A || error "Failed to list pods. Minikube or network might be misconfigured."
    
    # Display Minikube dashboard URL
    log "Minikube dashboard available at:"
    minikube dashboard --url
}

# Main script logic
main() {
    check_root
    log "Starting Kubernetes master setup on Manjaro..."
    install_prerequisites
    install_aur_helper
    install_configure_docker
    configure_system_settings
    install_minikube
    start_minikube
    validate_minikube
    log "Setup complete: Minikube is running and namespaces created."
    log "To access the dashboard, run: minikube dashboard"
    log "To connect worker nodes, use the join command in /var/k8s/join_command.sh"
}

# Entry point
main "$@"