#!/bin/bash

# FKS SSH Connection Emergency Troubleshooting
# Use this when GitHub Actions SSH connections fail

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    local status=$1
    local message=$2
    case $status in
        "success") echo -e "${GREEN}✅ $message${NC}" ;;
        "error") echo -e "${RED}❌ $message${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "info") echo -e "${BLUE}🔍 $message${NC}" ;;
    esac
}

echo "=================================================="
echo "  FKS SSH Emergency Troubleshooting"
echo "=================================================="
echo ""

# Default values from your error log
TARGET_HOST="${1:-fks.tailfef10.ts.net}"
PUBLIC_IP="${2:-172.105.97.209}"
TARGET_USER="${3:-jordan}"

print_status "info" "Troubleshooting SSH connection to:"
echo "  Tailscale Host: $TARGET_HOST"
echo "  Public IP: $PUBLIC_IP"
echo "  Target User: $TARGET_USER"
echo ""

# Step 1: Network connectivity
print_status "info" "Step 1: Testing network connectivity..."

if ping -c 2 -W 3 "$TARGET_HOST" >/dev/null 2>&1; then
    print_status "success" "Tailscale host reachable"
    TAILSCALE_OK=true
else
    print_status "error" "Tailscale host unreachable"
    TAILSCALE_OK=false
fi

if ping -c 2 -W 3 "$PUBLIC_IP" >/dev/null 2>&1; then
    print_status "success" "Public IP reachable"
    PUBLIC_OK=true
else
    print_status "error" "Public IP unreachable"
    PUBLIC_OK=false
fi

if [ "$TAILSCALE_OK" = "false" ] && [ "$PUBLIC_OK" = "false" ]; then
    print_status "error" "Server appears to be down or unreachable"
    echo ""
    echo "🆘 Server may be:"
    echo "   1. Powered off"
    echo "   2. Still initializing from StackScript"
    echo "   3. Network configuration issues"
    echo ""
    echo "💡 Check Linode console for server status"
    exit 1
fi

# Step 2: SSH port connectivity
print_status "info" "Step 2: Testing SSH port connectivity..."

if command -v nc >/dev/null 2>&1; then
    if [ "$TAILSCALE_OK" = "true" ]; then
        if timeout 10 nc -zv "$TARGET_HOST" 22 2>&1 | grep -q "succeeded\|connected"; then
            print_status "success" "SSH port open on Tailscale host"
            PREFERRED_HOST="$TARGET_HOST"
        else
            print_status "warning" "SSH port not accessible on Tailscale host"
            PREFERRED_HOST=""
        fi
    fi
    
    if [ "$PUBLIC_OK" = "true" ] && [ -z "$PREFERRED_HOST" ]; then
        if timeout 10 nc -zv "$PUBLIC_IP" 22 2>&1 | grep -q "succeeded\|connected"; then
            print_status "success" "SSH port open on public IP"
            PREFERRED_HOST="$PUBLIC_IP"
        else
            print_status "error" "SSH port not accessible on public IP either"
        fi
    fi
else
    print_status "warning" "nc command not available, skipping port test"
    PREFERRED_HOST="$TARGET_HOST"
fi

if [ -z "$PREFERRED_HOST" ]; then
    print_status "error" "SSH service not accessible on any interface"
    exit 1
fi

print_status "info" "Using host: $PREFERRED_HOST"

# Step 3: SSH key availability
print_status "info" "Step 3: Checking local SSH keys..."

SSH_KEY_FOUND=false
for key_file in "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_ecdsa"; do
    if [ -f "$key_file" ]; then
        if ssh-keygen -y -f "$key_file" >/dev/null 2>&1; then
            print_status "success" "Valid SSH key found: $key_file"
            FINGERPRINT=$(ssh-keygen -lf "$key_file" 2>/dev/null | awk '{print $2}')
            echo "         Fingerprint: $FINGERPRINT"
            SSH_KEY_FOUND=true
            WORKING_KEY="$key_file"
        fi
    fi
done

if [ "$SSH_KEY_FOUND" = "false" ]; then
    print_status "error" "No valid SSH keys found locally"
    echo ""
    echo "💡 Generate a key with: ssh-keygen -t ed25519 -C 'your_email@example.com'"
    exit 1
fi

# Step 4: SSH connection attempts
print_status "info" "Step 4: Testing SSH connections..."

USERS_TO_TRY=("$TARGET_USER" "jordan" "actions_user" "root")
SUCCESS_USER=""

for user in "${USERS_TO_TRY[@]}"; do
    echo ""
    print_status "info" "Trying user: $user"
    
    if timeout 15 ssh -v \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PasswordAuthentication=no \
        -o PubkeyAuthentication=yes \
        -i "$WORKING_KEY" \
        "$user@$PREFERRED_HOST" \
        "echo 'SSH Success: Connected as $user'" 2>/dev/null; then
        
        print_status "success" "SSH connection successful with user: $user"
        SUCCESS_USER="$user"
        break
    else
        print_status "error" "SSH failed for user: $user"
    fi
done

if [ -n "$SUCCESS_USER" ]; then
    echo ""
    print_status "success" "SSH access confirmed with user: $SUCCESS_USER"
    
    echo ""
    print_status "info" "Getting server information..."
    ssh -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$WORKING_KEY" \
        "$SUCCESS_USER@$PREFERRED_HOST" "
        echo '🖥️  Server: '\$(hostname)
        echo '👤 User: '\$(whoami)
        echo '⏰ Time: '\$(date)
        echo '⬆️  Uptime: '\$(uptime -p 2>/dev/null || uptime)
        echo ''
        echo '🔑 SSH Key Status:'
        echo '  ~/.ssh exists: '\$([ -d ~/.ssh ] && echo 'Yes' || echo 'No')
        echo '  authorized_keys exists: '\$([ -f ~/.ssh/authorized_keys ] && echo 'Yes' || echo 'No')
        echo '  Key count: '\$(grep -c '^ssh-' ~/.ssh/authorized_keys 2>/dev/null || echo '0')
        echo ''
        echo '📜 StackScript Status:'
        if [ -f /var/log/stackscript.log ]; then
          echo '  StackScript log exists: Yes'
          echo '  Last 5 lines:'
          tail -5 /var/log/stackscript.log | sed 's/^/    /'
        else
          echo '  StackScript log exists: No'
        fi
    "
    
    echo ""
    print_status "info" "Diagnosis complete!"
    
    if [ "$SUCCESS_USER" != "$TARGET_USER" ]; then
        echo ""
        print_status "warning" "Target user '$TARGET_USER' failed, but '$SUCCESS_USER' worked"
        echo ""
        echo "💡 This suggests:"
        echo "   1. The '$TARGET_USER' user may not exist"
        echo "   2. SSH keys not properly installed for '$TARGET_USER'"
        echo "   3. Use '$SUCCESS_USER' for deployments, or"
        echo "   4. Run SSH key recovery to fix '$TARGET_USER'"
    fi
    
else
    echo ""
    print_status "error" "No SSH access available with any user"
    
    echo ""
    echo "🔧 Possible causes:"
    echo "=================="
    echo "1. SSH keys not installed during server creation"
    echo "2. StackScript still running (check Linode console)"
    echo "3. SSH service configuration issues"
    echo "4. User accounts not created properly"
    
    echo ""
    echo "💡 Manual recovery steps:"
    echo "========================"
    echo "1. Access server via Linode Console (LISH)"
    echo "2. Login as root and run:"
    echo "   mkdir -p /home/$TARGET_USER/.ssh"
    echo "   echo 'YOUR_PUBLIC_KEY' >> /home/$TARGET_USER/.ssh/authorized_keys"
    echo "   chown -R $TARGET_USER:$TARGET_USER /home/$TARGET_USER/.ssh"
    echo "   chmod 700 /home/$TARGET_USER/.ssh"
    echo "   chmod 600 /home/$TARGET_USER/.ssh/authorized_keys"
    
    echo ""
    echo "🔑 Your public key to add:"
    ssh-keygen -y -f "$WORKING_KEY" 2>/dev/null || echo "Could not extract public key"
fi

echo ""
print_status "info" "Troubleshooting completed!"
