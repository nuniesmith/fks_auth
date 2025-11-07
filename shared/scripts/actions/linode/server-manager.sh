#!/bin/bash
# linode-server-manager.sh - Linode server lifecycle management

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

# Configuration
DEFAULT_REGION="ca-central"
DEFAULT_TYPE="g6-standard-2"
DEFAULT_IMAGE="linode/arch"

# Help function
show_help() {
    cat << EOF
Linode Server Manager - Standardized Server Operations

Usage: $0 <command> [options]

Commands:
  create      Create a new server
  list        List all servers
  destroy     Destroy a server
  info        Get server information
  ssh         Connect to a server via SSH
  setup       Setup server with standardized configuration

Options:
  --service <name>        Service name (required for create)
  --type <type>           Server type (default: $DEFAULT_TYPE)
  --region <region>       Region (default: $DEFAULT_REGION)
  --image <image>         OS image (default: $DEFAULT_IMAGE)
  --password <password>   Root password
  --backups              Enable backups
  --help                 Show this help

Examples:
  $0 create --service fks --type g6-standard-2 --backups
  $0 list
  $0 info --service fks
  $0 destroy --service fks
  $0 ssh --service fks

Environment Variables:
  LINODE_CLI_TOKEN           Linode API token (required)
  SERVICE_ROOT_PASSWORD  Default root password
EOF
}

# Check requirements
check_requirements() {
    if [[ -z "${LINODE_CLI_TOKEN:-}" ]]; then
        error "LINODE_CLI_TOKEN environment variable is required"
        exit 1
    fi
    
    if ! command -v linode-cli &> /dev/null; then
        error "linode-cli is required but not installed"
        echo "Install with: pip install linode-cli"
        exit 1
    fi
    
    # Configure linode-cli if needed
    if [[ ! -f ~/.config/linode-cli/config ]]; then
        mkdir -p ~/.config/linode-cli
        cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
default-user = DEFAULT
region = $DEFAULT_REGION
type = $DEFAULT_TYPE
image = $DEFAULT_IMAGE

[DEFAULT]
token = $LINODE_CLI_TOKEN
EOF
        chmod 600 ~/.config/linode-cli/config
        success "Linode CLI configured"
    fi
}

# Create server
create_server() {
    local service_name="$1"
    local server_type="${2:-$DEFAULT_TYPE}"
    local region="${3:-$DEFAULT_REGION}"
    local image="${4:-$DEFAULT_IMAGE}"
    local root_password="${5:-${SERVICE_ROOT_PASSWORD:-}}"
    local enable_backups="${6:-false}"
    
    if [[ -z "$root_password" ]]; then
        error "Root password is required"
        exit 1
    fi
    
    local server_label="${service_name}-$(date +%Y%m%d-%H%M)"
    
    info "Creating Linode server: $server_label"
    info "Type: $server_type, Region: $region, Image: $image"
    
    # Check if server already exists
    if linode-cli linodes list --text --no-headers | grep -q "$service_name"; then
        warning "Server with name containing '$service_name' already exists"
        linode-cli linodes list --text | grep "$service_name"
        return 1
    fi
    
    # Create server
    local result
    result=$(linode-cli linodes create \
        --type "$server_type" \
        --region "$region" \
        --image "$image" \
        --label "$server_label" \
        --root_pass "$root_password" \
        --backups_enabled="$enable_backups" \
        --text --no-headers)
    
    local server_id
    server_id=$(echo "$result" | cut -f1)
    
    success "Server created with ID: $server_id"
    
    # Wait for server to be running
    info "Waiting for server to be ready..."
    while true; do
        local status
        status=$(linode-cli linodes view "$server_id" --text --no-headers | cut -f2)
        if [[ "$status" == "running" ]]; then
            break
        fi
        echo "Status: $status - waiting..."
        sleep 10
    done
    
    local server_ip
    server_ip=$(linode-cli linodes view "$server_id" --text --no-headers | cut -f5)
    
    success "Server is ready!"
    echo "Server ID: $server_id"
    echo "Server IP: $server_ip"
    echo "Label: $server_label"
    
    # Wait for SSH
    info "Waiting for SSH access..."
    for i in {1..30}; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           -o PasswordAuthentication=no -o PreferredAuthentications=password \
           root@"$server_ip" "echo 'SSH ready'" 2>/dev/null; then
            success "SSH access confirmed"
            break
        fi
        echo "Attempt $i/30 - SSH not ready yet..."
        sleep 20
    done
    
    echo
    success "Server creation complete!"
    info "Next steps:"
    echo "1. Run: $0 setup --service $service_name"
    echo "2. SSH to server: ssh root@$server_ip"
}

# List servers
list_servers() {
    info "Listing all Linode servers:"
    echo
    
    if linode-cli linodes list --text 2>/dev/null | grep -q "id"; then
        linode-cli linodes list --text
    else
        warning "No servers found or unable to retrieve server list"
    fi
}

# Get server info
get_server_info() {
    local service_name="$1"
    
    info "Getting information for service: $service_name"
    
    local server_info
    server_info=$(linode-cli linodes list --text --no-headers | grep "$service_name" | head -1)
    
    if [[ -z "$server_info" ]]; then
        warning "No server found for service: $service_name"
        return 1
    fi
    
    local server_id server_label server_status server_ip
    server_id=$(echo "$server_info" | cut -f1)
    server_label=$(echo "$server_info" | cut -f2)
    server_status=$(echo "$server_info" | cut -f3)
    server_ip=$(echo "$server_info" | cut -f5)
    
    echo
    echo "Server Information:"
    echo "=================="
    echo "Service: $service_name"
    echo "Label: $server_label"
    echo "ID: $server_id"
    echo "Status: $server_status"
    echo "IP: $server_ip"
    echo
    
    # Get detailed info
    info "Detailed server information:"
    linode-cli linodes view "$server_id"
}

# Destroy server
destroy_server() {
    local service_name="$1"
    local confirm="${2:-}"
    
    warning "This will PERMANENTLY DESTROY the server for service: $service_name"
    
    local server_info
    server_info=$(linode-cli linodes list --text --no-headers | grep "$service_name" | head -1)
    
    if [[ -z "$server_info" ]]; then
        warning "No server found for service: $service_name"
        return 1
    fi
    
    local server_id server_label
    server_id=$(echo "$server_info" | cut -f1)
    server_label=$(echo "$server_info" | cut -f2)
    
    echo "Target server:"
    echo "Label: $server_label"
    echo "ID: $server_id"
    echo
    
    if [[ "$confirm" != "DESTROY" ]]; then
        read -p "Type 'DESTROY' to confirm: " -r confirm
    fi
    
    if [[ "$confirm" != "DESTROY" ]]; then
        error "Destruction cancelled"
        return 1
    fi
    
    info "Destroying server $server_label..."
    linode-cli linodes delete "$server_id"
    success "Server destroyed"
}

# SSH to server
ssh_to_server() {
    local service_name="$1"
    local user="${2:-root}"
    
    local server_info
    server_info=$(linode-cli linodes list --text --no-headers | grep "$service_name" | head -1)
    
    if [[ -z "$server_info" ]]; then
        error "No server found for service: $service_name"
        return 1
    fi
    
    local server_ip
    server_ip=$(echo "$server_info" | cut -f5)
    
    info "Connecting to $service_name server at $server_ip as $user..."
    ssh "$user@$server_ip"
}

# Setup server with standardized configuration
setup_server() {
    local service_name="$1"
    
    info "Setting up standardized configuration for: $service_name"
    
    local server_info
    server_info=$(linode-cli linodes list --text --no-headers | grep "$service_name" | head -1)
    
    if [[ -z "$server_info" ]]; then
        error "No server found for service: $service_name"
        return 1
    fi
    
    local server_ip
    server_ip=$(echo "$server_info" | cut -f5)
    
    info "Setting up server at $server_ip..."
    
    # Create setup script
    cat > /tmp/server-setup.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🔄 Updating system packages..."
pacman -Syu --noconfirm

echo "📦 Installing essential packages..."
pacman -S --noconfirm curl wget git docker docker-compose \
  tailscale ufw fail2ban sudo base-devel

echo "👥 Creating user accounts..."
# Users will be created by the main deployment workflow

echo "🐳 Starting Docker..."
systemctl enable docker
systemctl start docker

echo "🔥 Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

echo "🔗 Setting up Tailscale..."
systemctl enable tailscaled
systemctl start tailscaled

echo "✅ Basic setup complete"
EOF
    
    # Run setup
    scp /tmp/server-setup.sh root@"$server_ip":/tmp/
    ssh root@"$server_ip" "chmod +x /tmp/server-setup.sh && /tmp/server-setup.sh"
    
    success "Server setup complete"
    info "Server is ready for service deployment"
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    check_requirements
    
    local command="$1"
    shift
    
    # Parse arguments
    local service_name=""
    local server_type="$DEFAULT_TYPE"
    local region="$DEFAULT_REGION"
    local image="$DEFAULT_IMAGE"
    local password="${SERVICE_ROOT_PASSWORD:-}"
    local backups="false"
    local user="root"
    local confirm=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --service)
                service_name="$2"
                shift 2
                ;;
            --type)
                server_type="$2"
                shift 2
                ;;
            --region)
                region="$2"
                shift 2
                ;;
            --image)
                image="$2"
                shift 2
                ;;
            --password)
                password="$2"
                shift 2
                ;;
            --user)
                user="$2"
                shift 2
                ;;
            --confirm)
                confirm="$2"
                shift 2
                ;;
            --backups)
                backups="true"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Execute command
    case $command in
        create)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for create command"
                exit 1
            fi
            create_server "$service_name" "$server_type" "$region" "$image" "$password" "$backups"
            ;;
        list)
            list_servers
            ;;
        info)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for info command"
                exit 1
            fi
            get_server_info "$service_name"
            ;;
        destroy)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for destroy command"
                exit 1
            fi
            destroy_server "$service_name" "$confirm"
            ;;
        ssh)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for ssh command"
                exit 1
            fi
            ssh_to_server "$service_name" "$user"
            ;;
        setup)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for setup command"
                exit 1
            fi
            setup_server "$service_name"
            ;;
        *)
            error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
