#!/bin/bash

# Script to set up SSH key for GitHub Actions deployment
# This script helps add the SSH key to GitHub repository settings

set -e

echo "🔑 SSH Key Setup Helper for GitHub Actions"
echo "==========================================="

# Check if SSH key is provided as argument
if [ -z "$1" ]; then
    echo "❌ Error: SSH key not provided"
    echo ""
    echo "Usage: $0 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample... actions_user@fks_dev'"
    echo ""
    echo "You should get this key from:"
    echo "1. Discord webhook notification when a new server is created"
    echo "2. Or by running: ssh root@your-server-ip 'cat /home/actions_user/.ssh/id_ed25519.pub'"
    exit 1
fi

SSH_KEY="$1"

# Validate SSH key format
if [[ ! "$SSH_KEY" =~ ^ssh-(rsa|ed25519|ecdsa).* ]]; then
    echo "❌ Error: Invalid SSH key format"
    echo "Expected format: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample... actions_user@fks_dev"
    exit 1
fi

echo "✅ SSH key format looks valid"
echo ""

# Instructions for adding to GitHub
echo "📋 Next Steps:"
echo ""
echo "1. 🌐 Go to GitHub repository settings:"
echo "   https://github.com/nuniesmith/fks/settings/secrets/actions"
echo ""
echo "2. 🔑 Add a new secret named: ACTIONS_USER_SSH_PUB"
echo ""
echo "3. 📝 Copy and paste this SSH key as the value:"
echo "   ┌─────────────────────────────────────────────────────────"
echo "   │ $SSH_KEY"
echo "   └─────────────────────────────────────────────────────────"
echo ""
echo "4. 🔐 Also add the SSH key as a Deploy Key:"
echo "   a. Go to: https://github.com/nuniesmith/fks/settings/keys"
echo "   b. Click 'Add deploy key'"
echo "   c. Title: 'actions_user@fks_dev'"
echo "   d. Key: (same key as above)"
echo "   e. ☑️ Check 'Allow write access'"
echo ""
echo "5. ✅ Save both settings"
echo ""

# Optional: Copy to clipboard if available
if command -v xclip &> /dev/null; then
    echo "$SSH_KEY" | xclip -selection clipboard
    echo "📋 SSH key copied to clipboard!"
    echo ""
elif command -v pbcopy &> /dev/null; then
    echo "$SSH_KEY" | pbcopy
    echo "📋 SSH key copied to clipboard!"
    echo ""
fi

echo "🚀 Once you've added the SSH key, you can re-run the deployment workflow."
echo "   The next deployment should be able to connect successfully!"
