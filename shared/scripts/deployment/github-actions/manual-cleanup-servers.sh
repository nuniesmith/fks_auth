#!/bin/bash

# Manual cleanup script for FKS servers
# Run this to clean up any orphaned servers from failed deployments

echo "🧹 FKS Server Cleanup Script"
echo "=============================="
echo ""

# Check if we have the required environment variables
if [ -z "$LINODE_CLI_TOKEN" ]; then
    echo "❌ LINODE_CLI_TOKEN environment variable is not set"
    echo ""
    echo "To set it, run:"
    echo "  export LINODE_CLI_TOKEN=\"your_token_here\""
    echo ""
    echo "You can get your token from: https://cloud.linode.com/profile/tokens"
    exit 1
fi

# Check if linode-cli is installed
if ! command -v linode-cli >/dev/null 2>&1; then
    echo "📦 Installing Linode CLI..."
    pip install linode-cli
fi

# Configure Linode CLI
echo "🔧 Configuring Linode CLI..."
mkdir -p ~/.config/linode-cli
cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
token = $LINODE_CLI_TOKEN
region = us-east
type = g6-nanode-1
image = linode/arch
EOF

# Test connection
echo "🔍 Testing Linode API connection..."
if ! linode-cli linodes list >/dev/null 2>&1; then
    echo "❌ Failed to connect to Linode API"
    echo "Please check your LINODE_CLI_TOKEN"
    exit 1
fi

echo "✅ Connected to Linode API"
echo ""

# List all servers
echo "📋 All servers in your account:"
ALL_SERVERS=$(linode-cli linodes list --json)
echo "$ALL_SERVERS" | jq -r '.[] | "\(.id) | \(.label) | \(.ipv4[0]) | \(.status) | \(.type) | \(.created)"' | while read -r server; do
    echo "  - $server"
done

echo ""

# Find FKS-related servers
echo "🔍 Looking for FKS-related servers..."
FKS_SERVERS=$(echo "$ALL_SERVERS" | jq -r '.[] | select(.label | contains("fks")) | "\(.id)|\(.label)|\(.ipv4[0])|\(.status)|\(.type)|\(.created)"')

if [ -z "$FKS_SERVERS" ]; then
    echo "ℹ️ No servers with 'fks' in the name found"
    
    # Look for servers created today
    echo ""
    echo "🔍 Looking for servers created today (potential orphans)..."
    TODAY=$(date +%Y-%m-%d)
    TODAY_SERVERS=$(echo "$ALL_SERVERS" | jq -r ".[] | select(.created | startswith(\"$TODAY\")) | \"\(.id)|\(.label)|\(.ipv4[0])|\(.status)|\(.type)|\(.created)\"")
    
    if [ -n "$TODAY_SERVERS" ]; then
        echo "🕒 Found servers created today:"
        echo "$TODAY_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type server_created; do
            echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status | Type: $server_type | Created: $server_created"
        done
        
        echo ""
        echo "❓ Do you want to delete these servers created today? (y/N)"
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "$TODAY_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type server_created; do
                echo "🗑️ Deleting server $server_id ($server_label)..."
                
                # Power off if running
                if [ "$server_status" == "running" ]; then
                    echo "🔌 Powering off server $server_id..."
                    linode-cli linodes shutdown $server_id || echo "⚠️ Failed to power off, continuing..."
                    sleep 3
                fi
                
                # Delete the server
                if linode-cli linodes delete $server_id --confirm; then
                    echo "✅ Server $server_id deleted successfully"
                else
                    echo "❌ Failed to delete server $server_id"
                fi
            done
        else
            echo "❌ Cleanup cancelled"
        fi
    else
        echo "ℹ️ No servers created today"
    fi
else
    echo "🎯 Found FKS-related servers:"
    echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type server_created; do
        echo "  - ID: $server_id | Label: $server_label | IP: $server_ip | Status: $server_status | Type: $server_type | Created: $server_created"
    done
    
    echo ""
    echo "❓ Do you want to delete these FKS servers? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "$FKS_SERVERS" | while IFS='|' read -r server_id server_label server_ip server_status server_type server_created; do
            echo "🗑️ Deleting server $server_id ($server_label)..."
            
            # Power off if running
            if [ "$server_status" == "running" ]; then
                echo "🔌 Powering off server $server_id..."
                linode-cli linodes shutdown $server_id || echo "⚠️ Failed to power off, continuing..."
                sleep 3
            fi
            
            # Delete the server
            if linode-cli linodes delete $server_id --confirm; then
                echo "✅ Server $server_id deleted successfully"
            else
                echo "❌ Failed to delete server $server_id"
            fi
        done
    else
        echo "❌ Cleanup cancelled"
    fi
fi

echo ""
echo "✅ Cleanup script complete"
echo ""
echo "💡 Tips:"
echo "  - Run this script anytime you need to clean up orphaned servers"
echo "  - Check your Linode account regularly to avoid unexpected charges"
echo "  - Failed deployments should automatically clean up, but manual cleanup may be needed"
