#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Utilities
# Description: Common utility functions for Kubernetes management scripts
# ============================================================

# ----------------------------------------------------------------------
# COLORS AND FORMATTING
# ----------------------------------------------------------------------
# Colors for better output
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export RED='\033[0;31m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export BOLD='\033[1m'
export NC='\033[0m' # No Color

# ----------------------------------------------------------------------
# LOGGING FUNCTIONS
# ----------------------------------------------------------------------
log_info() {
    echo -e "${GREEN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE" >&2
}

print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo
    echo -e "${BOLD}${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo -e "${BOLD}${CYAN}$(printf ' %.0s' $(seq 1 $padding))$title${NC}"
    echo -e "${BOLD}${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo
}

# ----------------------------------------------------------------------
# UTILITY FUNCTIONS
# ----------------------------------------------------------------------
# Check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Command '$1' not found. Please install it and try again."
        return 1
    fi
    return 0
}

# Check if required script exists and is executable
check_script() {
    local script_path="$1"
    local script_name="$2"
    
    if [[ ! -f "$script_path" ]]; then
        log_error "$script_name script not found at: $script_path"
        return 1
    fi
    
    if [[ ! -x "$script_path" ]]; then
        log_warn "$script_name script is not executable. Setting execute permission."
        chmod +x "$script_path"
        if [[ ! -x "$script_path" ]]; then
            log_error "Failed to set execute permission on $script_name script."
            return 1
        fi
    fi
    
    return 0
}

# Check if Kubernetes tools are installed
check_k8s_tools() {
    log_info "Checking for required Kubernetes tools..."
    
    local missing_tools=()
    for cmd in kubectl minikube; do
        if ! check_command "$cmd"; then
            missing_tools+=("$cmd")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        echo -e "${YELLOW}Would you like to install the missing tools? (y/n)${NC}"
        read -r install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            install_missing_tools "${missing_tools[@]}"
        else
            log_error "Cannot proceed without required tools. Exiting."
            return 1
        fi
    else
        log_info "All required Kubernetes tools are installed."
    fi
    
    return 0
}

# Install missing Kubernetes tools
install_missing_tools() {
    log_info "Installing missing tools: $*"
    
    # Check if we have sudo or are root
    local sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
        if check_command "sudo"; then
            sudo_cmd="sudo"
        else
            log_error "Neither root privileges nor sudo available. Cannot install tools."
            return 1
        fi
    fi
    
    # Update package lists
    log_info "Updating package lists..."
    $sudo_cmd pacman -Sy
    
    # Install tools one by one
    for tool in "$@"; do
        case "$tool" in
            kubectl)
                log_info "Installing kubectl..."
                $sudo_cmd pacman -S --needed --noconfirm kubectl || {
                    log_error "Failed to install kubectl from repositories. Trying AUR..."
                    if check_command "yay"; then
                        yay -S --needed --noconfirm kubectl || log_error "Failed to install kubectl from AUR."
                    else
                        log_error "AUR helper 'yay' not found. Cannot install kubectl from AUR."
                    fi
                }
                ;;
            minikube)
                log_info "Installing minikube..."
                $sudo_cmd pacman -S --needed --noconfirm minikube || {
                    log_error "Failed to install minikube from repositories. Installing from binary..."
                    local tmp_dir
                    tmp_dir="$(mktemp -d)"
                    curl -Lo "$tmp_dir/minikube" https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
                    chmod +x "$tmp_dir/minikube"
                    $sudo_cmd install "$tmp_dir/minikube" /usr/local/bin/
                    rm -rf "$tmp_dir"
                    if ! check_command "minikube"; then
                        log_error "Failed to install minikube from binary."
                    fi
                }
                ;;
            *)
                log_warn "Unknown tool: $tool. Skipping."
                ;;
        esac
    done
    
    # Verify installation
    for tool in "$@"; do
        if ! check_command "$tool"; then
            log_error "Failed to install $tool. Please install it manually."
        else
            log_info "$tool installed successfully."
        fi
    done
}

# Check the success of the last command
check_success() {
    local message="$1"
    local status=${2:-$?}
    if [[ $status -eq 0 ]]; then
        log_info "$message succeeded."
        return 0
    else
        log_error "$message failed with status code $status."
        echo -e "${YELLOW}Do you want to retry? (y/n)${NC}"
        read -r retry
        if [[ "$retry" =~ ^[Yy]$ ]]; then
            return 1
        else
            return 0
        fi
    fi
}

# Export all configuration variables to environment
export_variables() {
    log_info "Exporting configuration variables to environment..."
    
    # Export directories and file paths
    export BASE_DIR
    export SCRIPT_DIR
    export MASTER_SCRIPT
    export WORKER_SCRIPT
    export REMOVE_SCRIPT
    export APPLY_RESOURCES_SCRIPT
    
    # Export Kubernetes configurations
    export KUBE_HOME
    export KUBE_CONFIG
    export MINIKUBE_HOME
    export K8S_BASE_PATH
    export LOG_DIR
    export LOG_FILE
    
    # Export IP and networking configurations
    export DEFAULT_IP
    
    # Export namespace and resource configurations
    export NAMESPACE
    export MANIFESTS_DIR
    export APPLY_SECRETS
    export VALIDATE
    
    # Export network configurations
    export ADVERTISE_ADDRESS
    export POD_SUBNET
    export SERVICE_SUBNET
    
    # Export master node configurations
    export MASTER_IP
    export MASTER_PORT
    export KUBE_TOKEN
    export CA_CERT_HASH
    export JOIN_COMMAND_FILE
    
    # Export removal configurations
    export REMOVE_DOCKER
    export REMOVE_MINIKUBE
    export REMOVE_CONFIG_ONLY
    export FORCE
    
    log_info "Variables exported successfully"
}

# Check directory structure
check_directory_structure() {
    log_info "Checking directory structure..."
    
    log_info "Base paths:"
    echo "BASE_DIR: $BASE_DIR"
    echo "K8S_BASE_PATH: $K8S_BASE_PATH"
    echo "MANIFESTS_DIR: $MANIFESTS_DIR"
    
    log_info "Directory tree:"
    find "$K8S_BASE_PATH" -type d | sort
    
    log_info "YAML files found:"
    find "$K8S_BASE_PATH" -name "*.yaml" -o -name "*.yml" | sort
    
    log_info "If you see a mismatch between your file structure and expected paths,"
    log_info "you may need to adjust paths in the configuration section of this script."
}

# Function to access the kubernetes dashboard
access_k8s_dashboard() {
    log_info "Setting up access to Kubernetes Dashboard..."
    
    # Check if we can connect to the cluster
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Is it running?"
        return 1
    fi
    
    # Create dashboard service account and role binding if not exists
    if ! kubectl get serviceaccount admin-user -n kube-system &>/dev/null; then
        log_info "Creating admin-user service account for dashboard access..."
        cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
EOF
    fi
    
    # Create token for dashboard access
    log_info "Generating access token..."
    TOKEN=$(kubectl create token admin-user -n kube-system)
    
    # Start the dashboard proxy in the background
    log_info "Starting dashboard proxy..."
    kubectl proxy &
    PROXY_PID=$!
    
    # Display access information
    log_info "Dashboard is available at: http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
    log_info "Use the following token to sign in:"
    echo -e "${YELLOW}$TOKEN${NC}"
    
    # Give user options
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo -e " ${BOLD}[1]${NC} Open dashboard in browser (if available)"
    echo -e " ${BOLD}[2]${NC} Port-forward the dashboard service directly (8443 → 443)"
    echo -e " ${BOLD}[3]${NC} Return to main menu"
    echo ""
    echo -e "${BLUE}Enter your choice:${NC} "
    read -r dashboard_choice
    
    case "$dashboard_choice" in
        1)
            # Attempt to open browser
            if command -v xdg-open &>/dev/null; then
                xdg-open "http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/" &
            elif command -v open &>/dev/null; then
                open "http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/" &
            else
                log_warn "Could not automatically open browser. Please use the URL above."
            fi
            ;;
        2)
            # Kill the proxy if it's running
            if [ -n "$PROXY_PID" ]; then
                kill $PROXY_PID &>/dev/null
            fi
            
            # Port-forward the dashboard service
            log_info "Port-forwarding dashboard service to localhost:8443..."
            kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
            ;;
        3)
            # Kill the proxy if it's running
            if [ -n "$PROXY_PID" ]; then
                kill $PROXY_PID &>/dev/null
            fi
            return 0
            ;;
        *)
            log_error "Invalid choice."
            # Kill the proxy if it's running
            if [ -n "$PROXY_PID" ]; then
                kill $PROXY_PID &>/dev/null
            fi
            ;;
    esac
}

# Function to change the current namespace
change_namespace() {
    log_info "Current namespace: $NAMESPACE"
    
    # Show available namespaces
    log_info "Available namespaces:"
    kubectl get namespaces -o name | sed 's|namespace/||'
    
    # Ask for the new namespace
    echo -e "${BLUE}Enter the namespace to switch to (or leave empty to keep current):${NC} "
    read -r new_namespace
    
    if [ -z "$new_namespace" ]; then
        log_info "Keeping current namespace: $NAMESPACE"
        return 0
    fi
    
    # Check if the namespace exists
    if ! kubectl get namespace "$new_namespace" &>/dev/null; then
        log_warn "Namespace $new_namespace does not exist. Would you like to create it? (y/n)"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            if ! kubectl create namespace "$new_namespace"; then
                log_error "Failed to create namespace $new_namespace."
                return 1
            fi
            log_info "Namespace $new_namespace created."
        else
            log_warn "Operation cancelled."
            return 1
        fi
    fi
    
    # Update the current namespace
    NAMESPACE="$new_namespace"
    export NAMESPACE
    
    # Set as default in kubectl config
    kubectl config set-context --current --namespace="$NAMESPACE"
    
    log_info "Switched to namespace: $NAMESPACE"
}