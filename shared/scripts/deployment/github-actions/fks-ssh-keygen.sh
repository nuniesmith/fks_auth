#!/bin/bash
# FKS SSH Key Generation Script
# Generates SSH key pairs for all FKS users and GitHub Actions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
KEY_DIR="./fks_ssh-keys"
KEY_TYPE="ed25519"  # More secure and shorter than RSA
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Users to generate keys for
USERS=(
    "jordan"
    "github_actions"
    "root"
    "fks_user"
)

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to generate SSH key pair
generate_key_pair() {
    local user=$1
    local key_path="$KEY_DIR/${user}"
    
    print_color $BLUE "Generating SSH key pair for ${user}@fks..."
    
    # Create directory for this user
    mkdir -p "$key_path"
    
    # Remove existing keys if they exist to avoid overwrite prompts
    rm -f "$key_path/id_${KEY_TYPE}" "$key_path/id_${KEY_TYPE}.pub"
    rm -f "$key_path/id_rsa" "$key_path/id_rsa.pub"
    
    # Generate key pair
    ssh-keygen -t $KEY_TYPE -f "$key_path/id_${KEY_TYPE}" -N "" -C "${user}@fks_${TIMESTAMP}" >/dev/null 2>&1
    
    # Also generate an RSA key for compatibility
    ssh-keygen -t rsa -b 4096 -f "$key_path/id_rsa" -N "" -C "${user}@fks_${TIMESTAMP}" >/dev/null 2>&1
    
    # Set proper permissions
    chmod 600 "$key_path/id_${KEY_TYPE}" "$key_path/id_rsa"
    chmod 644 "$key_path/id_${KEY_TYPE}.pub" "$key_path/id_rsa.pub"
    
    print_color $GREEN "✓ Generated keys for ${user}"
}

# Function to generate authorized_keys entries
generate_authorized_keys() {
    local auth_file="$KEY_DIR/authorized_keys_entries.txt"
    
    print_color $YELLOW "\nGenerating authorized_keys entries..."
    
    # Clear the file
    > "$auth_file"
    
    # Add header
    echo "# FKS Authorized Keys - Generated on $(date)" >> "$auth_file"
    echo "# Add these entries to ~/.ssh/authorized_keys for each user" >> "$auth_file"
    echo "" >> "$auth_file"
    
    # For each user, add their public keys and cross-authorization
    for user in "${USERS[@]}"; do
        echo "# Keys for $user" >> "$auth_file"
        echo "# Ed25519 key:" >> "$auth_file"
        cat "$KEY_DIR/${user}/id_${KEY_TYPE}.pub" >> "$auth_file"
        echo "# RSA key (compatibility):" >> "$auth_file"
        cat "$KEY_DIR/${user}/id_rsa.pub" >> "$auth_file"
        echo "" >> "$auth_file"
    done
    
    print_color $GREEN "✓ Generated authorized_keys entries"
}

# Function to generate GitHub secrets file
generate_github_secrets() {
    local secrets_file="$KEY_DIR/github_secrets.txt"
    
    print_color $YELLOW "\nGenerating GitHub secrets..."
    
    > "$secrets_file"
    
    echo "# GitHub Secrets - Generated on $(date)" >> "$secrets_file"
    echo "# Copy these values to your GitHub repository secrets" >> "$secrets_file"
    echo "" >> "$secrets_file"
    
    # ACTIONS_ROOT_PRIVATE_KEY for github_actions user
    echo "## ACTIONS_ROOT_PRIVATE_KEY (for github_actions user)" >> "$secrets_file"
    echo "## Add this to: Settings → Secrets and variables → Actions → New repository secret" >> "$secrets_file"
    echo "## Name: ACTIONS_ROOT_PRIVATE_KEY" >> "$secrets_file"
    echo "## Value:" >> "$secrets_file"
    echo "-----BEGIN OPENSSH PRIVATE KEY-----" >> "$secrets_file"
    tail -n +2 "$KEY_DIR/github_actions/id_${KEY_TYPE}" | head -n -1 >> "$secrets_file"
    echo "-----END OPENSSH PRIVATE KEY-----" >> "$secrets_file"
    echo "" >> "$secrets_file"
    
    # Also provide RSA key for compatibility
    echo "## SSH_PRIVATE_KEY_RSA (RSA version for compatibility)" >> "$secrets_file"
    echo "## Name: SSH_PRIVATE_KEY_RSA" >> "$secrets_file"
    echo "## Value:" >> "$secrets_file"
    cat "$KEY_DIR/github_actions/id_rsa" >> "$secrets_file"
    echo "" >> "$secrets_file"
    
    print_color $GREEN "✓ Generated GitHub secrets file"
}

# Function to generate StackScript variables
generate_stackscript_vars() {
    local stackscript_file="$KEY_DIR/stackscript_vars.sh"
    
    print_color $YELLOW "\nGenerating StackScript variables..."
    
    > "$stackscript_file"
    
    echo "#!/bin/bash" >> "$stackscript_file"
    echo "# StackScript SSH Key Variables - Generated on $(date)" >> "$stackscript_file"
    echo "# Include these in your StackScript or cloud-init" >> "$stackscript_file"
    echo "" >> "$stackscript_file"
    
    # Generate base64 encoded public keys for easy inclusion
    for user in "${USERS[@]}"; do
        echo "# Public keys for $user" >> "$stackscript_file"
        echo "${user^^}_SSH_PUB_ED25519=\"$(cat "$KEY_DIR/${user}/id_${KEY_TYPE}.pub")\"" >> "$stackscript_file"
        echo "${user^^}_SSH_PUB_RSA=\"$(cat "$KEY_DIR/${user}/id_rsa.pub")\"" >> "$stackscript_file"
        echo "" >> "$stackscript_file"
    done
    
    # Function to set up SSH keys in StackScript
    cat >> "$stackscript_file" << 'EOF'
# Function to setup SSH keys for a user
setup_user_ssh() {
    local username=$1
    local home_dir="/home/$username"
    local ssh_pub_ed25519_var="${username^^}_SSH_PUB_ED25519"
    local ssh_pub_rsa_var="${username^^}_SSH_PUB_RSA"
    
    # Handle root user home directory
    if [ "$username" = "root" ]; then
        home_dir="/root"
    fi
    
    # Create .ssh directory
    mkdir -p "$home_dir/.ssh"
    chmod 700 "$home_dir/.ssh"
    
    # Add public keys to authorized_keys
    echo "${!ssh_pub_ed25519_var}" >> "$home_dir/.ssh/authorized_keys"
    echo "${!ssh_pub_rsa_var}" >> "$home_dir/.ssh/authorized_keys"
    
    # Also add GitHub Actions key for all users (for deployment access)
    echo "$ACTIONS_USER_SSH_PUB_ED25519" >> "$home_dir/.ssh/authorized_keys"
    
    # Set proper permissions
    chmod 600 "$home_dir/.ssh/authorized_keys"
    
    # Set ownership (skip for root)
    if [ "$username" != "root" ]; then
        chown -R "$username:$username" "$home_dir/.ssh"
    fi
}

# Setup SSH for all users
setup_user_ssh "jordan"
setup_user_ssh "github_actions"
setup_user_ssh "root"
setup_user_ssh "fks_user"
EOF
    
    chmod +x "$stackscript_file"
    print_color $GREEN "✓ Generated StackScript variables"
}

# Function to generate deployment instructions
generate_instructions() {
    local instructions_file="$KEY_DIR/DEPLOYMENT_INSTRUCTIONS.md"
    
    print_color $YELLOW "\nGenerating deployment instructions..."
    
    cat > "$instructions_file" << 'EOF'
# FKS SSH Key Deployment Instructions

Generated on: DATE_PLACEHOLDER

## Overview

This directory contains SSH key pairs for all FKS users. Follow these instructions to properly deploy them.

## 1. GitHub Actions Setup

### Add SSH Private Key to GitHub Secrets:

1. Go to your repository on GitHub
2. Navigate to: Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `ACTIONS_ROOT_PRIVATE_KEY`
5. Value: Copy the entire content from `github_secrets.txt` (the first private key)
6. Click "Add secret"

## 2. StackScript/Cloud-Init Setup

### Option A: Using StackScript (Linode)

Include the content of `stackscript_vars.sh` in your StackScript. This will automatically set up SSH keys for all users when the server is created.

### Option B: Manual Server Setup

For each user, add their public keys to the authorized_keys file:

```bash
# For jordan user
sudo -u jordan bash -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
sudo -u jordan bash -c 'cat >> ~/.ssh/authorized_keys' < authorized_keys_entries.txt
sudo -u jordan bash -c 'chmod 600 ~/.ssh/authorized_keys'

# For github_actions user (create if doesn't exist)
sudo useradd -m -s /bin/bash github_actions
sudo -u github_actions bash -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
sudo -u github_actions bash -c 'cat >> ~/.ssh/authorized_keys' < authorized_keys_entries.txt
sudo -u github_actions bash -c 'chmod 600 ~/.ssh/authorized_keys'

# For fks_user
sudo -u fks_user bash -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
sudo -u fks_user bash -c 'cat >> ~/.ssh/authorized_keys' < authorized_keys_entries.txt
sudo -u fks_user bash -c 'chmod 600 ~/.ssh/authorized_keys'

# For root (if needed)
mkdir -p /root/.ssh && chmod 700 /root/.ssh
cat authorized_keys_entries.txt >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

## 3. Update GitHub Workflow

Update your `deploy-dev.yml` to use the `github_actions` user instead of `jordan`:

```yaml
Host target-server
    HostName $TARGET_HOST
    User github_actions  # Changed from jordan
    Port 22
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

## 4. Local SSH Config

To SSH into the server from your local machine, add this to `~/.ssh/config`:

```
Host fks_dev
    HostName fks.tailfef10.ts.net
    User jordan
    IdentityFile ~/path/to/fks_ssh-keys/jordan/id_ed25519
    
Host fks_dev-root
    HostName fks.tailfef10.ts.net
    User root
    IdentityFile ~/path/to/fks_ssh-keys/root/id_ed25519

Host fks_dev-github
    HostName fks.tailfef10.ts.net
    User github_actions
    IdentityFile ~/path/to/fks_ssh-keys/github_actions/id_ed25519
```

## 5. Testing

Test each connection:

```bash
ssh fks_dev "echo 'Jordan user works'"
ssh fks_dev-github "echo 'GitHub Actions user works'"
ssh fks_dev-root "echo 'Root user works'"
```

## Security Notes

1. **Keep private keys secure** - Never commit them to Git
2. **Use dedicated service account** - github_actions user should only have necessary permissions
3. **Rotate keys periodically** - Generate new keys every 6-12 months
4. **Limit root access** - Prefer sudo over direct root SSH
5. **Use Ed25519** - More secure than RSA for new deployments

## Key Files Generated

- `jordan/` - Keys for jordan user
- `github_actions/` - Keys for GitHub Actions (automated deployments)
- `root/` - Keys for root user (emergency access)
- `fks_user/` - Keys for fks_user
- `authorized_keys_entries.txt` - Public keys to add to each user's authorized_keys
- `github_secrets.txt` - Private key for GitHub Actions secret
- `stackscript_vars.sh` - Variables and setup function for StackScript
- `DEPLOYMENT_INSTRUCTIONS.md` - This file
EOF
    
    # Replace placeholder with actual date
    sed -i.bak "s/DATE_PLACEHOLDER/$(date)/" "$instructions_file" && rm "${instructions_file}.bak"
    
    print_color $GREEN "✓ Generated deployment instructions"
}

# Main execution
main() {
    print_color $MAGENTA "=== FKS SSH Key Generator ==="
    print_color $MAGENTA "============================="
    echo ""
    
    # Check if ssh-keygen is available
    if ! command -v ssh-keygen &> /dev/null; then
        print_color $RED "Error: ssh-keygen command not found. Please install OpenSSH."
        exit 1
    fi
    
    # Create main directory
    if [ -d "$KEY_DIR" ]; then
        print_color $YELLOW "Warning: $KEY_DIR already exists."
        read -p "Delete existing keys and regenerate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$KEY_DIR"
        else
            print_color $RED "Aborted."
            exit 1
        fi
    fi
    
    mkdir -p "$KEY_DIR"
    
    # Generate keys for each user
    for user in "${USERS[@]}"; do
        generate_key_pair "$user"
    done
    
    # Generate consolidated files
    generate_authorized_keys
    generate_github_secrets
    generate_stackscript_vars
    generate_instructions
    
    # Create a summary
    print_color $MAGENTA "\n=== Summary ==="
    print_color $GREEN "✓ Generated SSH keys for ${#USERS[@]} users"
    print_color $GREEN "✓ Created authorized_keys entries"
    print_color $GREEN "✓ Created GitHub secrets file"
    print_color $GREEN "✓ Created StackScript variables"
    print_color $GREEN "✓ Created deployment instructions"
    
    print_color $YELLOW "\n📁 All files saved to: $KEY_DIR/"
    print_color $YELLOW "📖 Read DEPLOYMENT_INSTRUCTIONS.md for next steps"
    
    # Display quick start
    print_color $MAGENTA "\n=== Quick Start ==="
    echo "1. Add GitHub secret:"
    echo "   cat $KEY_DIR/github_secrets.txt | head -20"
    echo ""
    echo "2. Include in StackScript:"
    echo "   cat $KEY_DIR/stackscript_vars.sh"
    echo ""
    echo "3. Test connection:"
    echo "   ssh -i $KEY_DIR/jordan/id_ed25519 jordan@your-server"
    
    print_color $GREEN "\n✓ Done!"
}

# Run main function
main "$@"
