#!/bin/bash
# cloudflare-dns-manager.sh
# Cloudflare DNS Manager for 7gram.xyz
# Standalone script to manage DNS records for your domain

# Configuration - Update these with your actual values
CLOUDFLARE_API_TOKEN=""  # Your Cloudflare API token
CLOUDFLARE_ZONE_ID=""    # Your zone ID for 7gram.xyz
DOMAIN="7gram.xyz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required dependencies: ${missing[*]}"
        error "Please install them with: pacman -S ${missing[*]}"
        exit 1
    fi
}

# Get Cloudflare credentials
get_credentials() {
    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        echo -n "Enter your Cloudflare API Token: "
        read -s CLOUDFLARE_API_TOKEN
        echo
    fi
    
    if [ -z "$CLOUDFLARE_ZONE_ID" ]; then
        echo -n "Enter your Cloudflare Zone ID: "
        read CLOUDFLARE_ZONE_ID
    fi
    
    if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
        error "API Token and Zone ID are required"
        exit 1
    fi
}

# Test Cloudflare API connectivity
test_api() {
    log "Testing Cloudflare API connectivity..."
    
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        local zone_name=$(echo "$response" | jq -r '.result.name')
        success "API connection successful - Zone: $zone_name"
        return 0
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        error "API connection failed: $errors"
        return 1
    fi
}

# Get current Tailscale IP
get_tailscale_ip() {
    if command -v tailscale &> /dev/null; then
        local ip=$(tailscale ip -4 2>/dev/null | head -n1)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    fi
    
    error "Cannot get Tailscale IP. Make sure Tailscale is installed and running."
    return 1
}

# Get current public IP
get_public_ip() {
    local ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    if [ -n "$ip" ]; then
        echo "$ip"
        return 0
    else
        error "Cannot get public IP"
        return 1
    fi
}

# List existing DNS records
list_dns_records() {
    log "Fetching current DNS records for $DOMAIN..."
    
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?per_page=100" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        echo
        echo "Current DNS Records:"
        echo "===================="
        echo "$response" | jq -r '.result[] | "\(.name) \(.type) \(.content) (TTL: \(.ttl))"' | sort
        echo
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        error "Failed to fetch DNS records: $errors"
        return 1
    fi
}

# Update DNS record
update_dns_record() {
    local record_name="$1"
    local ip_address="$2"
    local record_type="${3:-A}"
    
    log "Updating $record_name.$DOMAIN to $ip_address..."
    
    # Get existing record ID if it exists
    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=$record_name.$DOMAIN&type=$record_type" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    
    local response
    if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
        # Update existing record
        response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$ip_address\",\"ttl\":3600}")
    else
        # Create new record
        response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$record_type\",\"name\":\"$record_name\",\"content\":\"$ip_address\",\"ttl\":3600}")
    fi
    
    local success_status=$(echo "$response" | jq -r '.success')
    if [ "$success_status" = "true" ]; then
        success "Updated $record_name.$DOMAIN"
        return 0
    else
        local errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        error "Failed to update $record_name.$DOMAIN: $errors"
        return 1
    fi
}

# Update all subdomains from your zone file
update_all_subdomains() {
    local ip_address="$1"
    
    if [ -z "$ip_address" ]; then
        error "IP address is required"
        return 1
    fi
    
    log "Updating all subdomains to $ip_address..."
    
    # All subdomains from your zone file
    local subdomains=(
        "@"              # Root domain
        "www"
        "nginx"
        "sullivan"
        "freddy"
        "auth"
        "emby"
        "jellyfin"
        "plex"
        "music"
        "youtube"
        "nc"
        "abs"
        "calibre"
        "calibreweb"
        "mealie"
        "grocy"
        "wiki"
        "ai"
        "chat"
        "ollama"
        "sd"
        "comfy"
        "whisper"
        "code"
        "sonarr"
        "radarr"
        "lidarr"
        "audiobooks"
        "ebooks"
        "jackett"
        "qbt"
        "filebot"
        "duplicati"
        "home"
        "pihole"
        "dns"
        "grafana"
        "prometheus"
        "uptime"
        "watchtower"
        "portainer"
        "portainer-freddy"
        "portainer-sullivan"
        "sync-freddy"
        "sync-sullivan"
        "sync-desktop"
        "sync-oryx"
        "mail"
        "smtp"
        "imap"
        "api"
        "status"
        "vpn"
        "remote"
    )
    
    local updated=0
    local failed=0
    
    for subdomain in "${subdomains[@]}"; do
        if update_dns_record "$subdomain" "$ip_address"; then
            updated=$((updated + 1))
        else
            failed=$((failed + 1))
        fi
        sleep 1  # Rate limiting
    done
    
    echo
    log "Update completed: $updated updated, $failed failed"
    
    if [ $failed -eq 0 ]; then
        success "All DNS records updated successfully!"
    else
        warning "Some DNS updates failed. Check the logs above."
    fi
}

# Interactive menu
show_menu() {
    echo
    echo "=================================="
    echo "   Cloudflare DNS Manager"
    echo "   Domain: $DOMAIN"
    echo "=================================="
    echo "1. List current DNS records"
    echo "2. Update single record"
    echo "3. Update all records to Tailscale IP"
    echo "4. Update all records to public IP"
    echo "5. Update all records to custom IP"
    echo "6. Test API connection"
    echo "7. Exit"
    echo
    echo -n "Choose an option [1-7]: "
}

# Main interactive loop
main_interactive() {
    check_dependencies
    get_credentials
    
    if ! test_api; then
        error "Cannot continue without valid API access"
        exit 1
    fi
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                list_dns_records
                ;;
            2)
                echo -n "Enter subdomain (without .${DOMAIN}): "
                read subdomain
                echo -n "Enter IP address: "
                read ip_address
                update_dns_record "$subdomain" "$ip_address"
                ;;
            3)
                if tailscale_ip=$(get_tailscale_ip); then
                    info "Tailscale IP: $tailscale_ip"
                    echo -n "Update all records to this IP? (y/N): "
                    read confirm
                    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                        update_all_subdomains "$tailscale_ip"
                    fi
                fi
                ;;
            4)
                if public_ip=$(get_public_ip); then
                    info "Public IP: $public_ip"
                    echo -n "Update all records to this IP? (y/N): "
                    read confirm
                    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                        update_all_subdomains "$public_ip"
                    fi
                fi
                ;;
            5)
                echo -n "Enter IP address: "
                read custom_ip
                if [ -n "$custom_ip" ]; then
                    echo -n "Update all records to $custom_ip? (y/N): "
                    read confirm
                    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                        update_all_subdomains "$custom_ip"
                    fi
                fi
                ;;
            6)
                test_api
                ;;
            7)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid option. Please choose 1-7."
                ;;
        esac
        
        echo
        echo "Press Enter to continue..."
        read
    done
}

# Command line usage
usage() {
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo
    echo "Commands:"
    echo "  list                    List current DNS records"
    echo "  update-all-tailscale    Update all records to Tailscale IP"
    echo "  update-all-public       Update all records to public IP" 
    echo "  update-all IP           Update all records to specified IP"
    echo "  update SUBDOMAIN IP     Update specific subdomain"
    echo "  interactive             Run interactive mode (default)"
    echo
    echo "Options:"
    echo "  -t, --token TOKEN       Cloudflare API token"
    echo "  -z, --zone-id ID        Cloudflare zone ID"
    echo "  -d, --domain DOMAIN     Domain name (default: 7gram.xyz)"
    echo "  -h, --help              Show this help"
    echo
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 update-all-tailscale"
    echo "  $0 update nginx 192.168.1.100"
    echo "  $0 -t your_token -z your_zone_id update-all 10.0.0.1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--token)
            CLOUDFLARE_API_TOKEN="$2"
            shift 2
            ;;
        -z|--zone-id)
            CLOUDFLARE_ZONE_ID="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        list)
            check_dependencies
            get_credentials
            test_api && list_dns_records
            exit $?
            ;;
        update-all-tailscale)
            check_dependencies
            get_credentials
            if test_api && tailscale_ip=$(get_tailscale_ip); then
                update_all_subdomains "$tailscale_ip"
            fi
            exit $?
            ;;
        update-all-public)
            check_dependencies
            get_credentials
            if test_api && public_ip=$(get_public_ip); then
                update_all_subdomains "$public_ip"
            fi
            exit $?
            ;;
        update-all)
            if [ -z "$2" ]; then
                error "IP address required for update-all command"
                exit 1
            fi
            check_dependencies
            get_credentials
            test_api && update_all_subdomains "$2"
            exit $?
            ;;
        update)
            if [ -z "$2" ] || [ -z "$3" ]; then
                error "Subdomain and IP address required for update command"
                exit 1
            fi
            check_dependencies
            get_credentials
            test_api && update_dns_record "$2" "$3"
            exit $?
            ;;
        interactive)
            main_interactive
            exit $?
            ;;
        *)
            error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
done

# Default to interactive mode if no command specified
main_interactive