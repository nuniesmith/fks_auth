#!/bin/bash
# =================================================================
# cloudflare-updater.sh - Automated DNS Management for Actions
# =================================================================
# 
# Integrates with GitHub Actions to automatically update Cloudflare
# DNS records when new servers are deployed
#
# Usage in GitHub Actions:
#   ./scripts/dns/cloudflare-updater.sh --service fks --ip $TAILSCALE_IP

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DOMAIN="7gram.xyz"
DEFAULT_TTL=120

# =================================================================
# LOGGING FUNCTIONS
# =================================================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} [$timestamp] $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} [$timestamp] $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} [$timestamp] $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} [$timestamp] $message"
            ;;
        "DNS")
            echo -e "${CYAN}[DNS]${NC} [$timestamp] $message"
            ;;
    esac
}

# =================================================================
# DEPENDENCY CHECK
# =================================================================
check_dependencies() {
    local missing=()
    
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing required dependencies: ${missing[*]}"
        log "INFO" "Install with: sudo apt-get install ${missing[*]} (Ubuntu) or pacman -S ${missing[*]} (Arch)"
        exit 1
    fi
}

# =================================================================
# CLOUDFLARE API FUNCTIONS
# =================================================================
test_cloudflare_api() {
    local api_token="$1"
    local zone_id="$2"
    
    log "INFO" "Testing Cloudflare API connectivity..."
    
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        local zone_name=$(echo "$response" | jq -r '.result.name')
        log "SUCCESS" "API connection successful - Zone: $zone_name"
        return 0
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        log "ERROR" "API connection failed: $errors"
        return 1
    fi
}

update_dns_record() {
    local api_token="$1"
    local zone_id="$2"
    local record_name="$3"
    local ip_address="$4"
    local record_type="${5:-A}"
    local ttl="${6:-$DEFAULT_TTL}"
    
    log "DNS" "Updating $record_name to $ip_address..."
    
    # Get existing record ID if it exists
    local existing_response=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?name=$record_name&type=$record_type" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    local record_id=$(echo "$existing_response" | jq -r '.result[0].id // empty')
    
    local response
    if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
        # Update existing record
        log "INFO" "Updating existing record: $record_name"
        response=$(curl -s -X PUT \
            "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
            -H "Authorization: Bearer $api_token" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"$record_type\",
                \"name\": \"$record_name\",
                \"content\": \"$ip_address\",
                \"ttl\": $ttl,
                \"proxied\": false
            }")
    else
        # Create new record
        log "INFO" "Creating new record: $record_name"
        response=$(curl -s -X POST \
            "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "Authorization: Bearer $api_token" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\": \"$record_type\",
                \"name\": \"$record_name\",
                \"content\": \"$ip_address\",
                \"ttl\": $ttl,
                \"proxied\": false
            }")
    fi
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        log "SUCCESS" "Updated $record_name → $ip_address"
        return 0
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        log "ERROR" "Failed to update $record_name: $errors"
        return 1
    fi
}

# =================================================================
# SERVICE-SPECIFIC DNS CONFIGURATIONS
# =================================================================
get_service_subdomains() {
    local service="$1"
    local domain="$2"
    
    case "$service" in
        "fks")
            echo "fks.$domain"
            echo "api.$domain"
            echo "data.$domain" 
            echo "auth.$domain"
            echo "trading.$domain"
            ;;
        "fks_auth")
            echo "auth.$domain"
            echo "sso.$domain"
            ;;
        "fks_api")
            echo "api.$domain"
            echo "data.$domain"
            echo "trading.$domain"
            echo "worker.$domain"
            ;;
        "fks_web")
            echo "fks.$domain"
            echo "app.$domain"
            echo "www.$domain"
            ;;
        "nginx")
            echo "nginx.$domain"
            echo "proxy.$domain"
            # Media Services
            echo "jellyfin.$domain"
            echo "plex.$domain"
            echo "emby.$domain"
            echo "music.$domain"
            # Download/Management
            echo "sonarr.$domain"
            echo "radarr.$domain"
            echo "lidarr.$domain"
            echo "qbt.$domain"
            echo "jackett.$domain"
            # System Monitoring
            echo "grafana.$domain"
            echo "prometheus.$domain"
            echo "portainer.$domain"
            echo "uptime.$domain"
            echo "status.$domain"
            echo "monitor.$domain"
            # Development/Tools
            echo "code.$domain"
            echo "wiki.$domain"
            echo "nc.$domain"
            # AI/ML Services
            echo "ollama.$domain"
            echo "sd.$domain"
            echo "comfy.$domain"
            echo "whisper.$domain"
            echo "ai.$domain"
            # Home Services
            echo "home.$domain"
            echo "grocy.$domain"
            echo "mealie.$domain"
            # Infrastructure
            echo "pihole.$domain"
            echo "dns.$domain"
            echo "vpn.$domain"
            echo "remote.$domain"
            # Sync Services
            echo "sync-desktop.$domain"
            echo "sync-freddy.$domain"
            echo "sync-oryx.$domain"
            echo "sync-sullivan.$domain"
            # Books/Media
            echo "calibre.$domain"
            echo "calibreweb.$domain"
            echo "ebooks.$domain"
            echo "audiobooks.$domain"
            # Backup/Utilities
            echo "duplicati.$domain"
            echo "watchtower.$domain"
            echo "filebot.$domain"
            # Communication
            echo "chat.$domain"
            echo "mail.$domain"
            echo "smtp.$domain"
            echo "imap.$domain"
            # Additional Services
            echo "youtube.$domain"
            echo "abs.$domain"
            ;;
        "ats")
            echo "ats.$domain"
            echo "game.$domain"
            echo "server.$domain"
            ;;
        *)
            echo "$service.$domain"
            ;;
    esac
}

# =================================================================
# MULTI-SERVER DNS CONFIGURATION
# =================================================================
update_multi_server_dns() {
    local api_token="$1"
    local zone_id="$2"
    local domain="$3"
    local auth_ip="$4"
    local api_ip="$5"
    local web_ip="$6"
    
    log "INFO" "Configuring multi-server DNS for FKS..."
    
    # Auth server subdomains
    if [ -n "$auth_ip" ]; then
        update_dns_record "$api_token" "$zone_id" "auth.$domain" "$auth_ip"
        update_dns_record "$api_token" "$zone_id" "sso.$domain" "$auth_ip"
    fi
    
    # API server subdomains
    if [ -n "$api_ip" ]; then
        update_dns_record "$api_token" "$zone_id" "api.$domain" "$api_ip"
        update_dns_record "$api_token" "$zone_id" "data.$domain" "$api_ip"
        update_dns_record "$api_token" "$zone_id" "trading.$domain" "$api_ip"
        update_dns_record "$api_token" "$zone_id" "worker.$domain" "$api_ip"
    fi
    
    # Web server subdomains
    if [ -n "$web_ip" ]; then
        update_dns_record "$api_token" "$zone_id" "fks.$domain" "$web_ip"
        update_dns_record "$api_token" "$zone_id" "app.$domain" "$web_ip"
        update_dns_record "$api_token" "$zone_id" "www.$domain" "$web_ip"
    fi
    
    log "SUCCESS" "Multi-server DNS configuration complete"
}

# =================================================================
# MAIN FUNCTIONS
# =================================================================
update_service_dns() {
    local service="$1"
    local ip_address="$2"
    local domain="${3:-$DEFAULT_DOMAIN}"
    local api_token="${4:-$CLOUDFLARE_API_TOKEN}"
    local zone_id="${5:-$CLOUDFLARE_ZONE_ID}"
    
    if [ -z "$api_token" ] || [ -z "$zone_id" ]; then
        log "ERROR" "Cloudflare API token and zone ID are required"
        return 1
    fi
    
    if ! test_cloudflare_api "$api_token" "$zone_id"; then
        return 1
    fi
    
    log "INFO" "Updating DNS for service: $service"
    log "INFO" "Target IP: $ip_address"
    log "INFO" "Domain: $domain"
    
    # Update service-specific subdomains
    local subdomains
    subdomains=$(get_service_subdomains "$service" "$domain")
    
    local success_count=0
    local total_count=0
    
    while IFS= read -r subdomain; do
        if [ -n "$subdomain" ]; then
            total_count=$((total_count + 1))
            if update_dns_record "$api_token" "$zone_id" "$subdomain" "$ip_address"; then
                success_count=$((success_count + 1))
            fi
            sleep 1  # Rate limiting
        fi
    done <<< "$subdomains"
    
    log "INFO" "DNS update complete: $success_count/$total_count records updated"
    
    if [ $success_count -eq $total_count ]; then
        log "SUCCESS" "All DNS records updated successfully"
        return 0
    else
        log "WARN" "Some DNS updates failed"
        return 1
    fi
}

# =================================================================
# COMMAND LINE INTERFACE
# =================================================================
show_help() {
    cat << EOF
Cloudflare DNS Updater for GitHub Actions

Usage: $0 [OPTIONS] COMMAND

Commands:
  update-service          Update DNS for a specific service
  update-multi-server     Update DNS for FKS multi-server setup
  test-api               Test Cloudflare API connectivity

Options:
  --service SERVICE      Service name (fks, nginx, ats, etc.)
  --ip IP_ADDRESS        IP address to update records to
  --domain DOMAIN        Domain name (default: $DEFAULT_DOMAIN)
  --auth-ip IP           Auth server IP (for multi-server)
  --api-ip IP            API server IP (for multi-server)  
  --web-ip IP            Web server IP (for multi-server)
  --token TOKEN          Cloudflare API token
  --zone-id ID           Cloudflare zone ID
  --ttl TTL              DNS TTL in seconds (default: $DEFAULT_TTL)
  --help                 Show this help

Environment Variables:
  CLOUDFLARE_API_TOKEN   Cloudflare API token
  CLOUDFLARE_ZONE_ID     Cloudflare zone ID

Examples:
  # Update single service
  $0 update-service --service fks --ip 100.64.0.1

  # Update multi-server FKS deployment
  $0 update-multi-server --auth-ip 100.64.0.1 --api-ip 100.64.0.2 --web-ip 100.64.0.3

  # Test API connection
  $0 test-api --token your_token --zone-id your_zone_id

EOF
}

# Parse command line arguments
main() {
    local command=""
    local service=""
    local ip_address=""
    local domain="$DEFAULT_DOMAIN"
    local auth_ip=""
    local api_ip=""
    local web_ip=""
    local api_token="${CLOUDFLARE_API_TOKEN:-}"
    local zone_id="${CLOUDFLARE_ZONE_ID:-}"
    local ttl="$DEFAULT_TTL"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            update-service)
                command="update-service"
                shift
                ;;
            update-multi-server)
                command="update-multi-server"
                shift
                ;;
            test-api)
                command="test-api"
                shift
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            --ip)
                ip_address="$2"
                shift 2
                ;;
            --domain)
                domain="$2"
                shift 2
                ;;
            --auth-ip)
                auth_ip="$2"
                shift 2
                ;;
            --api-ip)
                api_ip="$2"
                shift 2
                ;;
            --web-ip)
                web_ip="$2"
                shift 2
                ;;
            --token)
                api_token="$2"
                shift 2
                ;;
            --zone-id)
                zone_id="$2"
                shift 2
                ;;
            --ttl)
                ttl="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    check_dependencies
    
    case "$command" in
        "update-service")
            if [ -z "$service" ] || [ -z "$ip_address" ]; then
                log "ERROR" "Service name and IP address are required"
                exit 1
            fi
            update_service_dns "$service" "$ip_address" "$domain" "$api_token" "$zone_id"
            ;;
        "update-multi-server")
            if [ -z "$auth_ip" ] && [ -z "$api_ip" ] && [ -z "$web_ip" ]; then
                log "ERROR" "At least one server IP is required"
                exit 1
            fi
            update_multi_server_dns "$api_token" "$zone_id" "$domain" "$auth_ip" "$api_ip" "$web_ip"
            ;;
        "test-api")
            test_cloudflare_api "$api_token" "$zone_id"
            ;;
        "")
            log "ERROR" "Command is required"
            show_help
            exit 1
            ;;
        *)
            log "ERROR" "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
