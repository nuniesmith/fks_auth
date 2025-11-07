#!/bin/bash
# =============================================================================
# FKS Trading System - SSH Connection Test Script
# =============================================================================
# This script tests SSH connectivity to the detected FKS server
#
# Usage: ./test-ssh-connection.sh [IP_ADDRESS]
#
# If no IP address is provided, it will use the detect-server-ip.sh script
# =============================================================================

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
SERVER_IP=""
ACTIONS_USER="actions_user"

# Parse command line arguments
if [ $# -eq 1 ]; then
  SERVER_IP="$1"
elif [ $# -eq 0 ]; then
  echo "🔍 Auto-detecting server IP..."
  SERVER_IP=$("$SCRIPT_DIR/detect-server-ip.sh" --verbose)
else
  echo "Usage: $0 [IP_ADDRESS]"
  echo "If no IP is provided, auto-detection will be used"
  exit 1
fi

# Validate IP
if [ -z "$SERVER_IP" ]; then
  echo "❌ No server IP provided or detected!"
  exit 1
fi

if ! [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ Invalid IP format: $SERVER_IP"
  exit 1
fi

echo "🎯 Testing SSH connection to: $SERVER_IP"

# Test basic connectivity
echo "🔍 Testing basic connectivity..."
if ping -c 3 -W 5 "$SERVER_IP" > /dev/null 2>&1; then
  echo "✅ Server is reachable via ping"
else
  echo "⚠️ Server is not responding to ping (may be normal if ICMP is blocked)"
fi

# Test SSH port
echo "🔍 Testing SSH port (22)..."
if timeout 10 bash -c "</dev/tcp/$SERVER_IP/22" 2>/dev/null; then
  echo "✅ SSH port (22) is open"
else
  echo "❌ SSH port (22) is not accessible"
  exit 1
fi

# Test SSH authentication (if ACTIONS_USER_PASSWORD is available)
if [ -n "$ACTIONS_USER_PASSWORD" ]; then
  echo "🔑 Testing SSH authentication with actions_user..."
  
  if command -v sshpass > /dev/null 2>&1; then
    if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
       "$ACTIONS_USER@$SERVER_IP" "echo 'SSH connection successful!'" 2>/dev/null; then
      echo "✅ SSH authentication successful!"
      
      # Test sudo access
      echo "🔑 Testing sudo access..."
      if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
         "$ACTIONS_USER@$SERVER_IP" "sudo -n echo 'Sudo access works!'" 2>/dev/null; then
        echo "✅ Sudo access works without password!"
      else
        echo "⚠️ Sudo access may require password (checking with password...)"
        if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           "$ACTIONS_USER@$SERVER_IP" "echo '$ACTIONS_USER_PASSWORD' | sudo -S echo 'Sudo access works with password!'" 2>/dev/null; then
          echo "✅ Sudo access works with password"
        else
          echo "❌ Sudo access failed"
        fi
      fi
      
      # Test deployment directory
      echo "📁 Testing deployment directory access..."
      if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
         "$ACTIONS_USER@$SERVER_IP" "sudo mkdir -p /home/fks_user/fks && sudo chown fks_user:fks_user /home/fks_user/fks && ls -la /home/fks_user/" 2>/dev/null; then
        echo "✅ Deployment directory accessible"
      else
        echo "⚠️ Could not access/create deployment directory"
      fi
      
    else
      echo "❌ SSH authentication failed"
      echo "Please check:"
      echo "  - ACTIONS_USER_PASSWORD secret is correct"
      echo "  - actions_user exists on the server"
      echo "  - Password authentication is enabled"
    fi
  else
    echo "⚠️ sshpass not available, skipping authentication test"
    echo "Install sshpass to test SSH authentication: sudo apt-get install sshpass"
  fi
else
  echo "ℹ️ ACTIONS_USER_PASSWORD not set, skipping authentication test"
fi

echo ""
echo "📋 Connection Summary:"
echo "  Server IP: $SERVER_IP"
echo "  SSH Port: Open"
echo "  User: $ACTIONS_USER"
echo ""
echo "🔧 Manual SSH command to test:"
echo "  ssh $ACTIONS_USER@$SERVER_IP"
echo ""

if [ -n "$ACTIONS_USER_PASSWORD" ]; then
  echo "💡 If authentication fails, you may need to:"
  echo "  1. Create the actions_user: sudo useradd -m -s /bin/bash actions_user"
  echo "  2. Set password: sudo passwd actions_user"
  echo "  3. Add to sudo group: sudo usermod -aG sudo actions_user"
  echo "  4. Enable password auth: sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && sudo systemctl restart ssh"
fi
