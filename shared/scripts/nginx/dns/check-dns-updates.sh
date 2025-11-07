#!/bin/bash

echo "🔍 Checking DNS records for Tailscale IP updates..."
echo "=================================================="

# Expected Tailscale IP from deployment logs
EXPECTED_TAILSCALE_IP="100.67.16.63"

# List of DNS records that should be updated
DNS_RECORDS=(
    "7gram.xyz"
    "www.7gram.xyz"
    "admin.7gram.xyz"
    "nginx.7gram.xyz"
    "emby.7gram.xyz"
    "jellyfin.7gram.xyz"
    "plex.7gram.xyz"
    "nc.7gram.xyz"
    "ai.7gram.xyz"
    "chat.7gram.xyz"
    "sonarr.7gram.xyz"
    "radarr.7gram.xyz"
    "pihole.7gram.xyz"
    "grafana.7gram.xyz"
    "portainer.7gram.xyz"
)

echo "Expected Tailscale IP: $EXPECTED_TAILSCALE_IP"
echo ""

UPDATED_COUNT=0
TOTAL_COUNT=${#DNS_RECORDS[@]}

for record in "${DNS_RECORDS[@]}"; do
    echo -n "Checking $record... "
    
    # Get the current IP for this record
    CURRENT_IP=$(dig +short "$record" @1.1.1.1 | head -1)
    
    if [[ "$CURRENT_IP" == "$EXPECTED_TAILSCALE_IP" ]]; then
        echo "✅ UPDATED ($CURRENT_IP)"
        ((UPDATED_COUNT++))
    elif [[ -n "$CURRENT_IP" ]]; then
        echo "❌ NOT UPDATED ($CURRENT_IP)"
    else
        echo "⚠️ NO RECORD"
    fi
done

echo ""
echo "=================================================="
echo "Summary: $UPDATED_COUNT/$TOTAL_COUNT records updated to Tailscale IP"

if [[ $UPDATED_COUNT -eq $TOTAL_COUNT ]]; then
    echo "🎉 All DNS records successfully updated!"
elif [[ $UPDATED_COUNT -gt 0 ]]; then
    echo "⚠️ Partial DNS update - some records still need updating"
else
    echo "❌ No DNS records were updated - check deployment logs"
fi

echo ""
echo "🔍 Quick verification of key records:"
echo "  • 7gram.xyz: $(dig +short 7gram.xyz @1.1.1.1)"
echo "  • www.7gram.xyz: $(dig +short www.7gram.xyz @1.1.1.1)"
echo "  • nginx.7gram.xyz: $(dig +short nginx.7gram.xyz @1.1.1.1)"
