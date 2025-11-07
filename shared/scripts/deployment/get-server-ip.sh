#!/bin/bash
# =============================================================================
# FKS Trading System - Manual Server IP Retrieval
# =============================================================================
# This script helps you manually get the FKS server IP from Linode
# Useful for local testing and verification
# =============================================================================

set -e

echo "🏗️ FKS Server IP Retrieval Tool"
echo "================================"

# Check if Linode CLI is available
if ! command -v linode-cli > /dev/null 2>&1; then
  echo "📦 Linode CLI not found. Installing..."
  pip3 install --user linode-cli
  export PATH="$HOME/.local/bin:$PATH"
  
  if ! command -v linode-cli > /dev/null 2>&1; then
    echo "❌ Failed to install Linode CLI"
    echo "Please install manually: pip3 install linode-cli"
    exit 1
  fi
fi

# Check for Linode token
if [ -z "$LINODE_CLI_TOKEN" ]; then
  echo "⚠️ LINODE_CLI_TOKEN not set in environment"
  echo ""
  echo "To set up Linode CLI:"
  echo "1. Get your API token from: https://cloud.linode.com/profile/tokens"
  echo "2. Export it: export LINODE_CLI_TOKEN='your_token_here'"
  echo "3. Or configure Linode CLI: linode-cli configure"
  echo ""
  
  read -p "Do you want to configure Linode CLI now? (y/n): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    linode-cli configure
  else
    echo "❌ Cannot proceed without Linode CLI configuration"
    exit 1
  fi
fi

# List all servers
echo "🔍 Fetching your Linode servers..."
SERVERS=$(linode-cli linodes list --text --format "id,label,ipv4,status,region" 2>/dev/null || echo "")

if [ -z "$SERVERS" ]; then
  echo "❌ No servers found or API access failed"
  exit 1
fi

echo ""
echo "📋 Your Linode Servers:"
echo "======================="
echo "ID       Label                    IP Address      Status   Region"
echo "-------- ------------------------ --------------- -------- --------"
echo "$SERVERS"

echo ""
echo "🔍 Looking for FKS-related servers..."

# Find FKS servers
FKS_SERVERS=$(echo "$SERVERS" | grep -i -E "(fks|trading)" || echo "")

if [ -n "$FKS_SERVERS" ]; then
  echo ""
  echo "✅ Found FKS-related servers:"
  echo "ID       Label                    IP Address      Status   Region"
  echo "-------- ------------------------ --------------- -------- --------"
  echo "$FKS_SERVERS"
  
  # Extract IP addresses
  FKS_IPS=$(echo "$FKS_SERVERS" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  
  echo ""
  echo "🎯 FKS Server IP Addresses:"
  for ip in $FKS_IPS; do
    echo "  📍 $ip"
  done
  
  # If only one IP, suggest using it
  IP_COUNT=$(echo "$FKS_IPS" | wc -l)
  if [ "$IP_COUNT" -eq 1 ]; then
    SUGGESTED_IP=$(echo "$FKS_IPS" | head -1)
    echo ""
    echo "💡 Suggested IP for deployment: $SUGGESTED_IP"
    echo ""
    echo "🔧 To set as GitHub secret:"
    echo "  1. Go to your repository Settings → Secrets and variables → Actions"
    echo "  2. Add new secret: FKS_SERVER_IP = $SUGGESTED_IP"
    echo ""
    echo "🧪 To test SSH connection:"
    echo "  ./scripts/deployment/test-ssh-connection.sh $SUGGESTED_IP"
  fi
else
  echo ""
  echo "⚠️ No FKS-related servers found"
  echo "   Servers are identified by having 'fks' or 'trading' in their label"
  echo ""
  echo "💡 If you have a server that should be used for FKS:"
  echo "   1. Note its IP address from the list above"
  echo "   2. Consider renaming it to include 'fks' in the label"
  echo "   3. Or manually set the FKS_SERVER_IP secret"
fi

echo ""
echo "🔧 Manual Steps:"
echo "==============="
echo "1. Choose your FKS server IP from the list above"
echo "2. Test SSH connection:"
echo "   export ACTIONS_USER_PASSWORD='your_password'"
echo "   ./scripts/deployment/test-ssh-connection.sh YOUR_SERVER_IP"
echo "3. Set GitHub secret: FKS_SERVER_IP = YOUR_SERVER_IP"
echo "4. Run the deployment workflow"
