#!/bin/bash
set -euo pipefail

# DNS Update Script for 7gram.xyz - Route Services Through Nginx Reverse Proxy
# This script updates Cloudflare DNS records to point services to the nginx proxy

# Configuration (auto-detect when not provided)
# NGINX: Prefer provided env, else Tailscale IPv4 of this host
if [[ -z "${NGINX_IP:-}" ]]; then
    if command -v tailscale >/dev/null 2>&1; then
        NGINX_IP=$(tailscale ip -4 2>/dev/null | head -n1 || true)
    fi
fi
NGINX_IP="${NGINX_IP:-}"

# Sullivan/Freddy direct records: reuse existing DNS A record when env is unset
SULLIVAN_IP="${SULLIVAN_IP:-}"
FREDDY_IP="${FREDDY_IP:-}"
DOMAIN="7gram.xyz"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"

# Validate required environment variables
if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
    echo "❌ Error: CLOUDFLARE_API_TOKEN environment variable is required"
    exit 1
fi

if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then  
    echo "❌ Error: CLOUDFLARE_ZONE_ID environment variable is required"  
    exit 1
fi

# Resolve NGINX_IP if still empty
if [[ -z "$NGINX_IP" ]]; then
    echo "❌ Error: NGINX_IP not set and Tailscale IP could not be detected"
    echo "   Set NGINX_IP or ensure 'tailscale ip -4' works on this host."
    exit 1
fi

# Resolve Sullivan/Freddy direct IPs when missing
dig_a() { dig +short "$1" A @1.1.1.1 | head -n1; }
if [[ -z "$SULLIVAN_IP" ]]; then
    SULLIVAN_IP=$(dig_a "sullivan.7gram.xyz" || true)
fi
if [[ -z "$FREDDY_IP" ]]; then
    FREDDY_IP=$(dig_a "freddy.7gram.xyz" || true)
fi

echo "🌐 Updating DNS records for 7gram.xyz to use nginx reverse proxy"
echo "   Nginx IP: ${NGINX_IP}"
echo "   Sullivan IP: ${SULLIVAN_IP:-<unchanged>} (direct)"  
echo "   Freddy IP: ${FREDDY_IP:-<unchanged>} (direct)"
echo ""

# Function to update DNS record
update_dns_record() {
    local subdomain="$1"
    local target_ip="$2"
    local description="$3"
    
    local full_domain="${subdomain}.${DOMAIN}"
    if [[ "$subdomain" == "@" ]]; then
        full_domain="$DOMAIN"
    fi
    
    echo "🔄 Updating $full_domain → $target_ip ($description)"
    
    # Get existing record
    local record_response=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=$full_domain&type=A" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    local record_id=$(echo "$record_response" | jq -r '.result[0].id // empty')
    
    if [[ -n "$record_id" && "$record_id" != "null" ]]; then
        # Update existing record
        local update_response=$(curl -s -X PUT \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$full_domain\",\"content\":\"$target_ip\",\"ttl\":300,\"comment\":\"$description\"}")
        
        if echo "$update_response" | jq -e '.success' >/dev/null; then
            echo "✅ Updated $full_domain"
        else
            echo "❌ Failed to update $full_domain"
            echo "$update_response" | jq '.errors'
        fi
    else
        # Create new record
        local create_response=$(curl -s -X POST \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$full_domain\",\"content\":\"$target_ip\",\"ttl\":300,\"comment\":\"$description\"}")
        
        if echo "$create_response" | jq -e '.success' >/dev/null; then
            echo "✅ Created $full_domain"
        else
            echo "❌ Failed to create $full_domain"
            echo "$create_response" | jq '.errors'
        fi
    fi
}

echo "📋 Phase 1: Core Infrastructure Records"
echo "======================================="

# Core domain records that should go through nginx reverse proxy
update_dns_record "@" "$NGINX_IP" "Main domain - routed through nginx reverse proxy"
update_dns_record "www" "$NGINX_IP" "WWW subdomain - routed through nginx reverse proxy"
update_dns_record "nginx" "$NGINX_IP" "NGINX Reverse Proxy - Updated by script"
update_dns_record "proxy" "$NGINX_IP" "Proxy service - Updated by script"

echo ""
echo "📋 Phase 2: Media Services (via nginx → sullivan)"
echo "================================================="

# Media services that should be proxied through nginx to sullivan
update_dns_record "jellyfin" "$NGINX_IP" "Jellyfin Media Server - via nginx proxy"
update_dns_record "plex" "$NGINX_IP" "Plex Media Server - via nginx proxy"
update_dns_record "emby" "$NGINX_IP" "Emby Media Server - via nginx proxy"
update_dns_record "sonarr" "$NGINX_IP" "Sonarr TV Shows - via nginx proxy"
update_dns_record "radarr" "$NGINX_IP" "Radarr Movies - via nginx proxy"
update_dns_record "lidarr" "$NGINX_IP" "Lidarr Music - via nginx proxy"
update_dns_record "jackett" "$NGINX_IP" "Jackett Indexer - via nginx proxy"
update_dns_record "qbt" "$NGINX_IP" "qBittorrent - via nginx proxy"
update_dns_record "audiobooks" "$NGINX_IP" "Audiobook Shelf - via nginx proxy"
update_dns_record "calibre" "$NGINX_IP" "Calibre Library - via nginx proxy"
update_dns_record "calibreweb" "$NGINX_IP" "Calibre Web - via nginx proxy"
update_dns_record "ebooks" "$NGINX_IP" "E-books - via nginx proxy"

echo ""
echo "📋 Phase 3: Development & Management (via nginx → sullivan)"
echo "=========================================================="

# Development and management tools
update_dns_record "portainer" "$NGINX_IP" "Portainer Docker Management - via nginx proxy"
update_dns_record "code" "$NGINX_IP" "Code Server - via nginx proxy"
update_dns_record "grafana" "$NGINX_IP" "Grafana Monitoring - via nginx proxy"
update_dns_record "prometheus" "$NGINX_IP" "Prometheus Metrics - via nginx proxy"
update_dns_record "watchtower" "$NGINX_IP" "Watchtower Auto-updater - via nginx proxy"

echo ""
echo "📋 Phase 4: AI & Communication (via nginx → sullivan)" 
echo "===================================================="

# AI and communication services
update_dns_record "ai" "$NGINX_IP" "AI Services - via nginx proxy"
update_dns_record "ollama" "$NGINX_IP" "Ollama LLM - via nginx proxy"
update_dns_record "comfy" "$NGINX_IP" "ComfyUI - via nginx proxy"
update_dns_record "sd" "$NGINX_IP" "Stable Diffusion - via nginx proxy"
update_dns_record "whisper" "$NGINX_IP" "Whisper STT - via nginx proxy"
update_dns_record "chat" "$NGINX_IP" "Chat Services - via nginx proxy"

echo ""
echo "📋 Phase 5: Utilities (via nginx → sullivan)"
echo "============================================"

# Utility services
update_dns_record "nc" "$NGINX_IP" "Nextcloud - via nginx proxy"
update_dns_record "sync-sullivan" "$NGINX_IP" "Syncthing Sullivan - via nginx proxy"
update_dns_record "sync-desktop" "$NGINX_IP" "Syncthing Desktop - via nginx proxy"
update_dns_record "sync-oryx" "$NGINX_IP" "Syncthing Oryx - via nginx proxy"
update_dns_record "duplicati" "$NGINX_IP" "Duplicati Backup - via nginx proxy"
update_dns_record "filebot" "$NGINX_IP" "FileBot - via nginx proxy"
update_dns_record "grocy" "$NGINX_IP" "Grocy Inventory - via nginx proxy"
update_dns_record "mealie" "$NGINX_IP" "Mealie Recipes - via nginx proxy"
update_dns_record "youtube" "$NGINX_IP" "YouTube-DL - via nginx proxy"

echo ""
echo "📋 Phase 6: Home Automation (via nginx → freddy)"
echo "================================================"

# Home automation services (proxy to freddy)
update_dns_record "home" "$NGINX_IP" "Home Assistant - via nginx proxy"
update_dns_record "auth" "$NGINX_IP" "Authelia Authentication - via nginx proxy"
update_dns_record "dns" "$NGINX_IP" "Pi-hole DNS - via nginx proxy"
update_dns_record "pihole" "$NGINX_IP" "Pi-hole Admin - via nginx proxy"
update_dns_record "sync-freddy" "$NGINX_IP" "Syncthing Freddy - via nginx proxy"
update_dns_record "portainer-freddy" "$NGINX_IP" "Portainer Freddy - via nginx proxy"

echo ""
echo "📋 Phase 7: Direct Access Records (bypass proxy)"
echo "================================================"

# Records that should maintain direct access (not proxied)
update_dns_record "sullivan" "$SULLIVAN_IP" "Sullivan Media Server - direct access"
update_dns_record "freddy" "$FREDDY_IP" "Freddy Home Automation - direct access"

# Keep existing ATS service as-is (has its own server)
echo "ℹ️  Keeping ATS service records unchanged (dedicated server)"

# Email and network services that might need direct access
update_dns_record "mail" "$NGINX_IP" "Mail Server - via nginx proxy"
update_dns_record "smtp" "$NGINX_IP" "SMTP Server - via nginx proxy"
update_dns_record "imap" "$NGINX_IP" "IMAP Server - via nginx proxy"

# Status and monitoring
update_dns_record "status" "$NGINX_IP" "Status Page - via nginx proxy"
update_dns_record "uptime" "$NGINX_IP" "Uptime Monitor - via nginx proxy"
update_dns_record "monitor" "$NGINX_IP" "Monitoring Dashboard - via nginx proxy"

# VPN and remote access
update_dns_record "vpn" "$NGINX_IP" "VPN Server - via nginx proxy"
update_dns_record "remote" "$NGINX_IP" "Remote Access - via nginx proxy"

echo ""
echo "✅ DNS update completed!"
echo ""
echo "🔧 Next Steps:"
echo "1. Wait 2-5 minutes for DNS propagation"
echo "2. Test services via nginx proxy: https://jellyfin.7gram.xyz"
echo "3. Verify SSL certificates are working"
echo "4. Monitor nginx logs for any proxy issues"
echo ""
echo "📊 Summary:"
echo "- Main services now route through nginx reverse proxy ($NGINX_IP)"
echo "- Direct server access still available via sullivan.7gram.xyz and freddy.7gram.xyz"
echo "- SSL termination handled by nginx proxy"
echo "- Load balancing and failover capabilities enabled"

