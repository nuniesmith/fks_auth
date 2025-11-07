#!/bin/bash

# Quick cleanup script to run now
# Usage: LINODE_CLI_TOKEN=your_token ./cleanup-now.sh

if [ -z "$LINODE_CLI_TOKEN" ]; then
    echo "❌ Please set LINODE_CLI_TOKEN environment variable"
    echo "Usage: LINODE_CLI_TOKEN=your_token ./cleanup-now.sh"
    exit 1
fi

echo "🔍 Using Python environment to run cleanup..."
PYTHON_BIN="/home/jordan/oryx/code/repo/fks/.venv/bin/python"
LINODE_CLI="/home/jordan/oryx/code/repo/fks/.venv/bin/linode-cli"

# Configure CLI
echo "🔧 Configuring Linode CLI..."
mkdir -p ~/.config/linode-cli
cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
token = $LINODE_CLI_TOKEN
region = us-east
type = g6-nanode-1
image = linode/arch
EOF

# List all servers
echo "📋 All servers:"
$LINODE_CLI linodes list --json | jq -r '.[] | "\(.id) | \(.label) | \(.ipv4[0]) | \(.status) | \(.created)"'

echo ""
echo "🎯 FKS servers:"
FKS_SERVERS=$($LINODE_CLI linodes list --json | jq -r '.[] | select(.label | contains("fks")) | "\(.id)|\(.label)|\(.ipv4[0])|\(.status)"')

if [ -n "$FKS_SERVERS" ]; then
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status; do
        echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status"
    done
    
    echo ""
    echo "⚠️ Deleting all FKS servers..."
    
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status; do
        echo "🗑️ Deleting server $server_id ($server_label)..."
        
        # Power off if running
        if [ "$server_status" == "running" ]; then
            echo "🔌 Powering off server $server_id..."
            $LINODE_CLI linodes shutdown $server_id || echo "⚠️ Failed to power off, continuing..."
            sleep 3
        fi
        
        # Delete the server
        if $LINODE_CLI linodes delete $server_id --confirm; then
            echo "✅ Server $server_id deleted successfully"
        else
            echo "❌ Failed to delete server $server_id"
        fi
    done
else
    echo "ℹ️ No FKS servers found"
fi

echo ""
echo "🕒 Servers created today:"
TODAY=$(date +%Y-%m-%d)
TODAY_SERVERS=$($LINODE_CLI linodes list --json | jq -r ".[] | select(.created | startswith(\"$TODAY\")) | \"\(.id)|\(.label)|\(.ipv4[0])|\(.status)\"")

if [ -n "$TODAY_SERVERS" ]; then
    echo "$TODAY_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status; do
        echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status"
    done
    
    echo ""
    echo "⚠️ Deleting servers created today..."
    
    echo "$TODAY_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status; do
        echo "🗑️ Deleting server $server_id ($server_label)..."
        
        # Power off if running
        if [ "$server_status" == "running" ]; then
            echo "🔌 Powering off server $server_id..."
            $LINODE_CLI linodes shutdown $server_id || echo "⚠️ Failed to power off, continuing..."
            sleep 3
        fi
        
        # Delete the server
        if $LINODE_CLI linodes delete $server_id --confirm; then
            echo "✅ Server $server_id deleted successfully"
        else
            echo "❌ Failed to delete server $server_id"
        fi
    done
else
    echo "ℹ️ No servers created today"
fi

echo ""
echo "✅ Cleanup complete!"
