#!/bin/bash
# user-manager.sh - Standardized user account management

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

# Default configuration
DEFAULT_SHELL="/bin/bash"

# Help function
show_help() {
    cat << EOF
User Account Manager - Standardized User Management

Usage: $0 <command> [options]

Commands:
  create-all      Create all standard users (root, jordan, actions_user, service_user)
  create-user     Create a specific user
  setup-ssh       Setup SSH keys for a user
  setup-sudo      Configure sudo access for a user
  list-users      List all users on the system
  test-access     Test user access and permissions

Options:
  --service <name>        Service name (for service_user creation)
  --user <username>       Username
  --password <password>   User password
  --ssh-key <key>         SSH public key
  --sudo                  Grant sudo access
  --docker                Add to docker group
  --shell <shell>         User shell (default: $DEFAULT_SHELL)
  --help                  Show this help

Examples:
  $0 create-all --service fks
  $0 create-user --user myuser --password mypass --sudo --docker
  $0 setup-ssh --user jordan --ssh-key "ssh-ed25519 AAAA..."
  $0 test-access --user actions_user

Environment Variables:
  JORDAN_PASSWORD         Password for jordan user
  ACTIONS_USER_PASSWORD   Password for actions_user
  SERVICE_ROOT_PASSWORD   Password for root user
EOF
}

# Generate secure password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Create a user account
create_user() {
    local username="$1"
    local password="$2"
    local shell="${3:-$DEFAULT_SHELL}"
    local sudo_access="${4:-false}"
    local docker_access="${5:-false}"
    
    info "Creating user: $username"
    
    # Create user if doesn't exist
    if id "$username" &>/dev/null; then
        warning "User $username already exists"
    else
        useradd -m -s "$shell" "$username"
        success "User $username created"
    fi
    
    # Set password
    if [[ -n "$password" ]]; then
        echo "$username:$password" | chpasswd
        success "Password set for $username"
    fi
    
    # Configure sudo access
    if [[ "$sudo_access" == "true" ]]; then
        usermod -aG wheel "$username"
        success "$username added to wheel group (sudo access)"
    fi
    
    # Configure docker access
    if [[ "$docker_access" == "true" ]]; then
        usermod -aG docker "$username"
        success "$username added to docker group"
    fi
    
    # Create SSH directory
    local ssh_dir="/home/$username/.ssh"
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chown "$username:$username" "$ssh_dir"
        chmod 700 "$ssh_dir"
        success "SSH directory created for $username"
    fi
}

# Setup SSH keys for a user
setup_ssh_keys() {
    local username="$1"
    local ssh_key="${2:-}"
    local generate_key="${3:-false}"
    
    info "Setting up SSH keys for: $username"
    
    local ssh_dir="/home/$username/.ssh"
    
    # Ensure SSH directory exists
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chown "$username:$username" "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi
    
    # Generate SSH key if requested
    if [[ "$generate_key" == "true" ]]; then
        local key_path="$ssh_dir/id_ed25519"
        if [[ ! -f "$key_path" ]]; then
            sudo -u "$username" ssh-keygen -t ed25519 -f "$key_path" -N "" -C "$username@$(hostname)"
            success "SSH key generated for $username"
            
            # Add to authorized_keys for self-authentication
            cp "$key_path.pub" "$ssh_dir/authorized_keys"
            chown "$username:$username" "$ssh_dir/authorized_keys"
            chmod 600 "$ssh_dir/authorized_keys"
            success "SSH key added to authorized_keys for $username"
            
            # Display public key
            echo
            info "Public key for $username:"
            cat "$key_path.pub"
            echo
        else
            warning "SSH key already exists for $username"
        fi
    fi
    
    # Add provided SSH key to authorized_keys
    if [[ -n "$ssh_key" ]]; then
        local auth_keys="$ssh_dir/authorized_keys"
        
        # Create or append to authorized_keys
        if [[ ! -f "$auth_keys" ]]; then
            echo "$ssh_key" > "$auth_keys"
        else
            # Check if key already exists
            if ! grep -q "$ssh_key" "$auth_keys"; then
                echo "$ssh_key" >> "$auth_keys"
            else
                warning "SSH key already exists in authorized_keys for $username"
                return 0
            fi
        fi
        
        chown "$username:$username" "$auth_keys"
        chmod 600 "$auth_keys"
        success "SSH key added to authorized_keys for $username"
    fi
}

# Create all standard users
create_all_users() {
    local service_name="$1"
    
    info "Creating all standard users for service: $service_name"
    echo
    
    # Jordan user (admin)
    local jordan_pass="${JORDAN_PASSWORD:-}"
    if [[ -z "$jordan_pass" ]]; then
        jordan_pass=$(generate_password)
        warning "Generated password for jordan: $jordan_pass"
    fi
    create_user "jordan" "$jordan_pass" "$DEFAULT_SHELL" "true" "true"
    setup_ssh_keys "jordan" "" "true"
    
    echo
    
    # Actions user (CI/CD)
    local actions_pass="${ACTIONS_USER_PASSWORD:-}"
    if [[ -z "$actions_pass" ]]; then
        actions_pass=$(generate_password)
        warning "Generated password for actions_user: $actions_pass"
    fi
    create_user "actions_user" "$actions_pass" "$DEFAULT_SHELL" "true" "true"
    setup_ssh_keys "actions_user" "" "true"
    
    echo
    
    # Service-specific user (non-sudo)
    local service_user="${service_name}_user"
    local service_pass=$(generate_password)
    warning "Generated password for $service_user: $service_pass"
    create_user "$service_user" "$service_pass" "$DEFAULT_SHELL" "false" "true"
    
    echo
    success "All standard users created successfully!"
    
    # Display summary
    echo
    info "User Summary:"
    echo "=============="
    echo "root - System administrator (existing)"
    echo "jordan - Personal admin (sudo, docker) - Password: $jordan_pass"
    echo "actions_user - CI/CD automation (sudo, docker) - Password: $actions_pass"
    echo "$service_user - Service account (docker only) - Password: $service_pass"
    echo
    warning "Save these passwords securely!"
}

# Configure sudo access for a user
configure_sudo() {
    local username="$1"
    local sudo_rules="${2:-ALL=(ALL) NOPASSWD:ALL}"
    
    info "Configuring sudo access for: $username"
    
    # Create sudoers file for user
    local sudoers_file="/etc/sudoers.d/$username"
    
    cat > "$sudoers_file" << EOF
# Sudo rules for $username
$username $sudo_rules
EOF
    
    chmod 440 "$sudoers_file"
    success "Sudo access configured for $username"
    
    # Test sudo configuration
    if visudo -c; then
        success "Sudo configuration is valid"
    else
        error "Sudo configuration is invalid"
        rm -f "$sudoers_file"
        return 1
    fi
}

# List all users on the system
list_users() {
    info "System users:"
    echo
    
    # Get users with home directories (real users)
    local users
    users=$(getent passwd | awk -F: '$3 >= 1000 { print $1, $3, $5, $6 }' | sort)
    
    if [[ -n "$users" ]]; then
        printf "%-15s %-5s %-20s %s\n" "Username" "UID" "Full Name" "Home Directory"
        printf "%-15s %-5s %-20s %s\n" "--------" "---" "---------" "--------------"
        echo "$users" | while read -r username uid fullname home; do
            printf "%-15s %-5s %-20s %s\n" "$username" "$uid" "$fullname" "$home"
        done
    else
        warning "No regular users found"
    fi
    
    echo
    
    # Show group memberships for key users
    local key_users=("root" "jordan" "actions_user")
    for user in "${key_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "$user groups: $(groups "$user" 2>/dev/null | cut -d: -f2)"
        fi
    done
    
    # Show service users
    echo
    info "Service users:"
    getent passwd | grep "_user:" | awk -F: '{ print $1, $3, $6 }' | while read -r username uid home; do
        printf "%-15s %-5s %s\n" "$username" "$uid" "$home"
    done
}

# Test user access and permissions
test_user_access() {
    local username="$1"
    
    info "Testing access for user: $username"
    echo
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        error "User $username does not exist"
        return 1
    fi
    
    # Basic user info
    echo "User ID: $(id "$username")"
    echo "Groups: $(groups "$username" 2>/dev/null | cut -d: -f2)"
    echo "Shell: $(getent passwd "$username" | cut -d: -f7)"
    echo "Home: $(getent passwd "$username" | cut -d: -f6)"
    echo
    
    # Check SSH directory
    local ssh_dir="/home/$username/.ssh"
    if [[ -d "$ssh_dir" ]]; then
        success "SSH directory exists"
        echo "SSH directory permissions: $(ls -ld "$ssh_dir" | awk '{print $1}')"
        
        if [[ -f "$ssh_dir/authorized_keys" ]]; then
            success "authorized_keys file exists"
            echo "Authorized keys count: $(wc -l < "$ssh_dir/authorized_keys")"
        else
            warning "No authorized_keys file found"
        fi
        
        if [[ -f "$ssh_dir/id_ed25519" ]]; then
            success "Private SSH key exists"
        else
            warning "No private SSH key found"
        fi
    else
        warning "SSH directory does not exist"
    fi
    
    # Check sudo access
    if groups "$username" | grep -q wheel; then
        success "User has sudo access (wheel group)"
    else
        info "User does not have sudo access"
    fi
    
    # Check docker access
    if groups "$username" | grep -q docker; then
        success "User has docker access"
    else
        info "User does not have docker access"
    fi
    
    echo
    
    # Test basic commands as user
    info "Testing basic access..."
    
    if sudo -u "$username" whoami &>/dev/null; then
        success "Can execute commands as $username"
    else
        error "Cannot execute commands as $username"
    fi
    
    if sudo -u "$username" test -w "/home/$username"; then
        success "Can write to home directory"
    else
        error "Cannot write to home directory"
    fi
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    local command="$1"
    shift
    
    # Parse arguments
    local service_name=""
    local username=""
    local password=""
    local ssh_key=""
    local shell="$DEFAULT_SHELL"
    local sudo_access="false"
    local docker_access="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --service)
                service_name="$2"
                shift 2
                ;;
            --user)
                username="$2"
                shift 2
                ;;
            --password)
                password="$2"
                shift 2
                ;;
            --ssh-key)
                ssh_key="$2"
                shift 2
                ;;
            --shell)
                shell="$2"
                shift 2
                ;;
            --sudo)
                sudo_access="true"
                shift
                ;;
            --docker)
                docker_access="true"
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
        create-all)
            if [[ -z "$service_name" ]]; then
                error "Service name is required for create-all command"
                exit 1
            fi
            create_all_users "$service_name"
            ;;
        create-user)
            if [[ -z "$username" ]]; then
                error "Username is required for create-user command"
                exit 1
            fi
            create_user "$username" "$password" "$shell" "$sudo_access" "$docker_access"
            ;;
        setup-ssh)
            if [[ -z "$username" ]]; then
                error "Username is required for setup-ssh command"
                exit 1
            fi
            setup_ssh_keys "$username" "$ssh_key" "true"
            ;;
        setup-sudo)
            if [[ -z "$username" ]]; then
                error "Username is required for setup-sudo command"
                exit 1
            fi
            configure_sudo "$username"
            ;;
        list-users)
            list_users
            ;;
        test-access)
            if [[ -z "$username" ]]; then
                error "Username is required for test-access command"
                exit 1
            fi
            test_user_access "$username"
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
