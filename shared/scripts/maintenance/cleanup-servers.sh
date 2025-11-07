#!/bin/bash

# Emergency cleanup script for failed FKS deployment servers
# This will find and delete orphaned FKS servers

set -e

# Check if LINODE_CLI_TOKEN is set
if [ -z "$LINODE_CLI_TOKEN" ]; then
    echo "❌ LINODE_CLI_TOKEN environment variable is not set"
    echo "Please set it with: export LINODE_CLI_TOKEN=your_token_here"
    exit 1
fi

echo "🔍 Setting up Linode CLI..."
# Use the Python environment
PYTHON_BIN="/home/jordan/oryx/code/repo/fks/.venv/bin/python"
LINODE_CLI="/home/jordan/oryx/code/repo/fks/.venv/bin/linode-cli"

# Configure Linode CLI
echo "$LINODE_CLI_TOKEN" | $LINODE_CLI configure --token

echo "🔍 Searching for FKS-related servers..."

# List all servers
echo "📋 All servers in account:"
$LINODE_CLI linodes list --json | jq -r '.[] | "\(.id) | \(.label) | \(.ipv4[0]) | \(.status) | \(.type)"' | while read -r server; do
    echo "  - $server"
done

echo ""
echo "🔍 Looking for servers with 'fks' in the name..."

# Find FKS servers
FKS_SERVERS=$($LINODE_CLI linodes list --json | jq -r '.[] | select(.label | contains("fks")) | "\(.id)|\(.label)|\(.ipv4[0])|\(.status)|\(.type)"')

if [ -n "$FKS_SERVERS" ]; then
    echo "🎯 Found FKS-related servers:"
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type; do
        echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status | Type: $server_type"
    done
    
    echo ""
    echo "⚠️ Do you want to delete these servers? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type; do
            echo "🗑️ Deleting server $server_id ($server_label)..."
            
            # Power off if running
            if [ "$server_status" == "running" ]; then
                echo "🔌 Powering off server $server_id..."
                $LINODE_CLI linodes shutdown $server_id || echo "⚠️ Failed to power off, continuing..."
                sleep 5
            fi
            
            # Delete the server
            if $LINODE_CLI linodes delete $server_id --confirm; then
                echo "✅ Server $server_id deleted successfully"
            else
                echo "❌ Failed to delete server $server_id"
            fi
        done
    else
        echo "❌ Server deletion cancelled"
    fi
else
    echo "ℹ️ No FKS-related servers found"
fi

echo ""
echo "🔍 Looking for servers created today (potential orphans)..."

# Find servers created today
TODAY=$(date +%Y-%m-%d)
RECENT_SERVERS=$($LINODE_CLI linodes list --json | jq -r ".[] | select(.created | startswith(\"$TODAY\")) | \"\(.id)|\(.label)|\(.ipv4[0])|\(.status)|\(.type)\"")

if [ -n "$RECENT_SERVERS" ]; then
    echo "🕒 Found servers created today:"
    echo "$RECENT_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type; do
        echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status | Type: $server_type"
    done
else
    echo "ℹ️ No servers created today"
fi

echo ""
echo "✅ Cleanup check complete"
