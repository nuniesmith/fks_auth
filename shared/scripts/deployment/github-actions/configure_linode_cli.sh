#!/bin/bash

# Linode CLI Auto Configuration Script
# This script configures Linode CLI non-interactively for GitHub Actions

echo "🔧 Configuring Linode CLI for automated environment..."

# Set default region to avoid interactive prompts (aligned with workflow)
export LINODE_CLI_REGION="ca-central"

# Create Linode CLI config directory
mkdir -p ~/.config/linode-cli

# Create non-interactive configuration aligned with workflow settings
cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
default-user = DEFAULT
region = ca-central
type = g6-standard-2
image = linode/arch
authorized_users = 
authorized_keys = 
token = ${LINODE_CLI_TOKEN}
EOF

# Set proper permissions for security
chmod 600 ~/.config/linode-cli/config

# Verify configuration or install if needed
if command -v linode-cli >/dev/null 2>&1; then
    echo "✅ Linode CLI already available: $(linode-cli --version)"
else
    echo "📦 Linode CLI not found - installing..."
    
    # Try different pip commands
    if command -v pip >/dev/null 2>&1; then
        pip install --user linode-cli
    elif command -v pip3 >/dev/null 2>&1; then
        pip3 install --user linode-cli
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m pip install --user linode-cli
    else
        echo "❌ No Python/pip found"
        exit 1
    fi
    
    # Add user pip bin to PATH
    export PATH="$HOME/.local/bin:$PATH"
    echo "PATH=$HOME/.local/bin:$PATH" >> $GITHUB_ENV
fi

if command -v linode-cli >/dev/null 2>&1; then
    echo "✅ Linode CLI configured successfully"
    echo "🔍 Testing Linode CLI connection..."
    
    # Test with a simple command that doesn't require interactive input
    if timeout 30 linode-cli regions list --text --no-headers | head -5; then
        echo "✅ Linode CLI connection successful"
        echo "📍 Using region: ca-central"
        echo "🖥️  Default instance type: g6-standard-2"
        echo "💿 Default image: linode/arch"
    else
        echo "⚠️  Linode CLI connection test failed, but configuration is set"
        echo "💡 This may be due to network latency - will retry during actual deployment"
        echo "🔍 Debugging info:"
        echo "  Token present: $([[ -n \"$LINODE_CLI_TOKEN\" ]] && echo 'YES' || echo 'NO')"
        echo "  Token length: ${#LINODE_CLI_TOKEN}"
        echo "  Config file: $([ -f ~/.config/linode-cli/config ] && echo 'EXISTS' || echo 'MISSING')"
    fi
else
    echo "❌ Linode CLI still not found after installation attempt"
    echo "� Debugging installation:"
    echo "  pip location: $(which pip 2>/dev/null || echo 'NOT FOUND')"
    echo "  pip3 location: $(which pip3 2>/dev/null || echo 'NOT FOUND')"
    echo "  python3 location: $(which python3 2>/dev/null || echo 'NOT FOUND')"
    echo "  ~/.local/bin contents: $(ls -la ~/.local/bin/ 2>/dev/null || echo 'DIRECTORY NOT FOUND')"
    echo "  PATH: $PATH"
    exit 1
fi

# Export environment variables for use in workflow
echo "LINODE_CLI_REGION=ca-central" >> $GITHUB_ENV
echo "LINODE_DEFAULT_TYPE=g6-standard-2" >> $GITHUB_ENV
echo "LINODE_DEFAULT_IMAGE=linode/arch" >> $GITHUB_ENV

echo "🎉 Linode CLI configuration completed"
echo "🔧 Configuration exported to GitHub environment variables"
