#!/bin/bash
# setup-dns.sh - DNS management setup (primarily Cloudflare)
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-dns"
readonly SCRIPT_VERSION="3.0.0"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# DNS CONFIGURATION VALIDATION
# ============================================================================
validate_dns_config() {
    log "Validating DNS configuration..."
    
    # Check if DNS management is enabled
    if [[ "${UPDATE_DNS:-true}" != "true" ]]; then
        log "DNS management is disabled"
        return 1
    fi
    
    # Validate required variables
    if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        warning "Cloudflare API token not provided, skipping DNS setup"
        return 1
    fi
    
    if [[ -z "${CLOUDFLARE_ZONE_ID:-}" ]]; then
        warning "Cloudflare Zone ID not provided, skipping DNS setup"
        return 1
    fi
    
    local domain="${DOMAIN_NAME:-7gram.xyz}"
    if ! validate_domain "$domain"; then
        error "Invalid domain name: $domain"
        return 1
    fi
    
    success "DNS configuration validated"
    return 0
}

test_cloudflare_api() {
    log "Testing Cloudflare API connectivity..."
    
    local api_token="${CLOUDFLARE_API_TOKEN}"
    local zone_id="${CLOUDFLARE_ZONE_ID}"
    
    # Test API token
    local response
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        success "Cloudflare API token is valid"
    else
        error "Cloudflare API token test failed"
        echo "Response: $response"
        return 1
    fi
    
    # Test zone access
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        local zone_name
        zone_name=$(echo "$response" | jq -r '.result.name')
        success "Cloudflare zone access confirmed: $zone_name"
    else
        error "Cloudflare zone access test failed"
        echo "Response: $response"
        return 1
    fi
}

# ============================================================================
# DNS MANAGEMENT SCRIPTS
# ============================================================================
create_cloudflare_dns_script() {
    log "Creating Cloudflare DNS management script..."
    
    cat > /usr/local/bin/update-cloudflare-dns << 'EOF'
#!/bin/bash
# Cloudflare DNS update script
# Usage: update-cloudflare-dns <ip_address> [subdomain|all]

set -euo pipefail

# Configuration
API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
DOMAIN="${DOMAIN_NAME:-7gram.xyz}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Validation
if [[ -z "$API_TOKEN" ]] || [[ -z "$ZONE_ID" ]]; then
    error "Cloudflare API token or Zone ID not configured"
    echo ""
    echo "Required environment variables:"
    echo "  CLOUDFLARE_API_TOKEN"
    echo "  CLOUDFLARE_ZONE_ID"
    exit 1
fi

if [[ -z "${1:-}" ]]; then
    error "IP address is required"
    echo ""
    echo "Usage: $0 <ip_address> [subdomain|all]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100          # Update @ record"
    echo "  $0 192.168.1.100 www      # Update www record"
    echo "  $0 192.168.1.100 all      # Update all common records"
    exit 1
fi

IP_ADDRESS="$1"
SUBDOMAIN="${2:-@}"

# Validate IP address
if ! [[ $IP_ADDRESS =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error "Invalid IP address format: $IP_ADDRESS"
    exit 1
fi

# Function to update a single DNS record
update_dns_record() {
    local subdomain="$1"
    local ip="$2"
    local record_name
    
    if [[ "$subdomain" == "@" ]]; then
        record_name="$DOMAIN"
    else
        record_name="$subdomain.$DOMAIN"
    fi
    
    log "Updating DNS record: $record_name -> $ip"
    
    # Get existing record ID
    local get_response
    get_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$record_name&type=A" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")
    
    if ! echo "$get_response" | jq -e '.success' >/dev/null 2>&1; then
        error "Failed to query existing records for $record_name"
        echo "Response: $get_response"
        return 1
    fi
    
    local record_id
    record_id=$(echo "$get_response" | jq -r '.result[0].id // empty')
    
    local response
    if [[ -n "$record_id" && "$record_id" != "null" ]]; then
        # Update existing record
        log "Updating existing record (ID: $record_id)"
        response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":300,\"proxied\":false}")
    else
        # Create new record
        log "Creating new record"
        response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":300,\"proxied\":false}")
    fi
    
    # Check response
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        success "Successfully updated $record_name"
        return 0
    else
        error "Failed to update $record_name"
        local errors
        errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"' 2>/dev/null)
        echo "Errors: $errors"
        return 1
    fi
}

# Function to update multiple records
update_all_records() {
    local ip="$1"
    local subdomains=("@" "www" "nginx" "api" "admin" "dashboard")
    local success_count=0
    local total_count=${#subdomains[@]}
    
    log "Updating all common DNS records for $DOMAIN"
    
    for subdomain in "${subdomains[@]}"; do
        if update_dns_record "$subdomain" "$ip"; then
            ((success_count++))
        fi
        
        # Rate limiting - wait between requests
        sleep 1
    done
    
    log "Updated $success_count/$total_count records successfully"
    
    if [[ $success_count -eq $total_count ]]; then
        return 0
    else
        return 1
    fi
}

# Main execution
main() {
    log "Starting DNS update for $DOMAIN"
    
    if [[ "$SUBDOMAIN" == "all" ]]; then
        update_all_records "$IP_ADDRESS"
    else
        update_dns_record "$SUBDOMAIN" "$IP_ADDRESS"
    fi
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        success "DNS update completed successfully"
        log "Changes may take a few minutes to propagate"
    else
        error "DNS update failed"
    fi
    
    exit $exit_code
}

main "$@"
EOF
    
    # Substitute environment variables
    sed -i "s/\${CLOUDFLARE_API_TOKEN:-}/${CLOUDFLARE_API_TOKEN}/g" /usr/local/bin/update-cloudflare-dns
    sed -i "s/\${CLOUDFLARE_ZONE_ID:-}/${CLOUDFLARE_ZONE_ID}/g" /usr/local/bin/update-cloudflare-dns
    sed -i "s/\${DOMAIN_NAME:-7gram.xyz}/${DOMAIN_NAME:-7gram.xyz}/g" /usr/local/bin/update-cloudflare-dns
    
    chmod +x /usr/local/bin/update-cloudflare-dns
    
    success "Cloudflare DNS script created"
}

create_dns_monitoring_script() {
    log "Creating DNS monitoring script..."
    
    cat > /usr/local/bin/dns-monitor << 'EOF'
#!/bin/bash
# DNS monitoring and verification script

set -euo pipefail

# Configuration
DOMAIN="${DOMAIN_NAME:-7gram.xyz}"
LOG_FILE="/var/log/dns-monitor.log"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }

# Function to resolve domain and check IP
check_dns_record() {
    local domain="$1"
    local expected_ip="${2:-}"
    
    log "Checking DNS record for $domain"
    
    # Resolve domain
    local resolved_ip
    resolved_ip=$(dig +short "$domain" A | head -n1)
    
    if [[ -z "$resolved_ip" ]]; then
        error "Failed to resolve $domain"
        return 1
    fi
    
    if [[ -n "$expected_ip" ]]; then
        if [[ "$resolved_ip" == "$expected_ip" ]]; then
            success "$domain resolves to correct IP: $resolved_ip"
            return 0
        else
            error "$domain resolves to incorrect IP: $resolved_ip (expected: $expected_ip)"
            return 1
        fi
    else
        success "$domain resolves to: $resolved_ip"
        return 0
    fi
}

# Function to check DNS propagation across multiple nameservers
check_dns_propagation() {
    local domain="$1"
    local nameservers=("8.8.8.8" "1.1.1.1" "208.67.222.222" "9.9.9.9")
    
    log "Checking DNS propagation for $domain"
    
    local results=()
    for ns in "${nameservers[@]}"; do
        local result
        result=$(dig +short "@$ns" "$domain" A | head -n1)
        if [[ -n "$result" ]]; then
            results+=("$ns:$result")
        else
            results+=("$ns:NXDOMAIN")
        fi
    done
    
    # Check if all results are consistent
    local first_ip
    first_ip=$(echo "${results[0]}" | cut -d: -f2)
    local consistent=true
    
    for result in "${results[@]}"; do
        local ip
        ip=$(echo "$result" | cut -d: -f2)
        if [[ "$ip" != "$first_ip" ]]; then
            consistent=false
            break
        fi
    done
    
    if [[ "$consistent" == "true" ]] && [[ "$first_ip" != "NXDOMAIN" ]]; then
        success "DNS propagation complete - all nameservers return: $first_ip"
        return 0
    else
        warning "DNS propagation inconsistent:"
        for result in "${results[@]}"; do
            echo "  $(echo "$result" | sed 's/:/ -> /')"
        done
        return 1
    fi
}

# Function to check reverse DNS
check_reverse_dns() {
    local ip="$1"
    
    log "Checking reverse DNS for $ip"
    
    local reverse_result
    reverse_result=$(dig +short -x "$ip" | head -n1)
    
    if [[ -n "$reverse_result" ]]; then
        success "Reverse DNS for $ip: $reverse_result"
        return 0
    else
        warning "No reverse DNS configured for $ip"
        return 1
    fi
}

# Function to test HTTP/HTTPS connectivity
test_connectivity() {
    local domain="$1"
    
    log "Testing connectivity to $domain"
    
    # Test HTTP
    local http_status
    http_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://$domain" 2>/dev/null)
    
    if [[ "$http_status" =~ ^[23] ]]; then
        success "HTTP connectivity to $domain: $http_status"
    else
        warning "HTTP connectivity to $domain failed: $http_status"
    fi
    
    # Test HTTPS
    local https_status
    https_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain" 2>/dev/null)
    
    if [[ "$https_status" =~ ^[23] ]]; then
        success "HTTPS connectivity to $domain: $https_status"
    else
        warning "HTTPS connectivity to $domain failed: $https_status"
    fi
}

# Main monitoring function
monitor_dns() {
    local domain="$1"
    local expected_ip="${2:-}"
    
    echo "=== DNS Monitoring Report for $domain ==="
    echo "Generated: $(date)"
    echo ""
    
    # Get current Tailscale IP if available
    if command -v tailscale &>/dev/null; then
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null | head -n1)
        if [[ -n "$ts_ip" ]]; then
            expected_ip="$ts_ip"
            log "Using Tailscale IP as expected: $ts_ip"
        fi
    fi
    
    # Check main domain and common subdomains
    local domains=("$domain" "www.$domain")
    local failed_checks=0
    
    for check_domain in "${domains[@]}"; do
        echo ""
        if ! check_dns_record "$check_domain" "$expected_ip"; then
            ((failed_checks++))
        fi
        
        if ! check_dns_propagation "$check_domain"; then
            ((failed_checks++))
        fi
    done
    
    # Check reverse DNS if we have an expected IP
    if [[ -n "$expected_ip" ]]; then
        echo ""
        check_reverse_dns "$expected_ip" || ((failed_checks++))
    fi
    
    # Test connectivity
    echo ""
    test_connectivity "$domain"
    
    echo ""
    if [[ $failed_checks -eq 0 ]]; then
        success "All DNS checks passed"
        return 0
    else
        error "$failed_checks DNS check(s) failed"
        return 1
    fi
}

# Usage information
show_usage() {
    echo "Usage: $0 [domain] [expected_ip]"
    echo ""
    echo "Monitor DNS resolution and propagation"
    echo ""
    echo "Arguments:"
    echo "  domain      - Domain to check (default: $DOMAIN)"
    echo "  expected_ip - Expected IP address (default: auto-detect)"
    echo ""
    echo "Examples:"
    echo "  $0                          # Check default domain"
    echo "  $0 example.com              # Check specific domain"
    echo "  $0 example.com 192.168.1.1  # Check with expected IP"
}

# Main execution
case "${1:-}" in
    -h|--help|help)
        show_usage
        exit 0
        ;;
    *)
        DOMAIN="${1:-$DOMAIN}"
        EXPECTED_IP="${2:-}"
        monitor_dns "$DOMAIN" "$EXPECTED_IP"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/dns-monitor
    
    success "DNS monitoring script created"
}

create_dns_backup_script() {
    log "Creating DNS backup and restore script..."
    
    cat > /usr/local/bin/dns-backup << 'EOF'
#!/bin/bash
# DNS backup and restore script for Cloudflare

set -euo pipefail

# Configuration
API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
BACKUP_DIR="/opt/backups/dns"
DOMAIN="${DOMAIN_NAME:-7gram.xyz}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Validation
validate_config() {
    if [[ -z "$API_TOKEN" ]] || [[ -z "$ZONE_ID" ]]; then
        error "Cloudflare API token or Zone ID not configured"
        return 1
    fi
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    return 0
}

# Backup DNS records
backup_dns() {
    log "Backing up DNS records for $DOMAIN"
    
    local backup_file="$BACKUP_DIR/dns-backup-$(date +%Y%m%d-%H%M%S).json"
    
    # Get all DNS records
    local response
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")
    
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        # Save the records
        echo "$response" | jq '.result' > "$backup_file"
        
        local record_count
        record_count=$(echo "$response" | jq '.result | length')
        
        success "Backed up $record_count DNS records to $backup_file"
        
        # Create human-readable summary
        create_backup_summary "$backup_file"
        
        return 0
    else
        error "Failed to backup DNS records"
        echo "Response: $response"
        return 1
    fi
}

# Create human-readable backup summary
create_backup_summary() {
    local backup_file="$1"
    local summary_file="${backup_file%.json}.txt"
    
    {
        echo "DNS Backup Summary"
        echo "=================="
        echo "Domain: $DOMAIN"
        echo "Backup Date: $(date)"
        echo "Zone ID: $ZONE_ID"
        echo ""
        echo "Records:"
        echo "--------"
        
        jq -r '.[] | "\(.type)\t\(.name)\t\(.content)\t\(.ttl)\t\(.proxied)"' "$backup_file" | \
        while IFS=$'\t' read -r type name content ttl proxied; do
            printf "%-6s %-30s %-20s %-6s %s\n" "$type" "$name" "$content" "$ttl" "$proxied"
        done
        
    } > "$summary_file"
    
    log "Summary created: $summary_file"
}

# List available backups
list_backups() {
    log "Available DNS backups:"
    
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR"/*.json 2>/dev/null)" ]]; then
        warning "No backups found"
        return 1
    fi
    
    echo ""
    echo "Backup files:"
    ls -la "$BACKUP_DIR"/*.json | while read -r line; do
        local file
        file=$(echo "$line" | awk '{print $NF}')
        local basename
        basename=$(basename "$file")
        local date_str
        date_str=$(echo "$basename" | sed 's/dns-backup-//' | sed 's/.json//' | sed 's/-/ /')
        
        echo "  $basename (created: $date_str)"
        
        # Show record count
        if [[ -f "$file" ]]; then
            local count
            count=$(jq '. | length' "$file" 2>/dev/null || echo "unknown")
            echo "    Records: $count"
        fi
        echo ""
    done
}

# Restore DNS records (dry run by default)
restore_dns() {
    local backup_file="$1"
    local dry_run="${2:-true}"
    
    if [[ ! -f "$backup_file" ]]; then
        error "Backup file not found: $backup_file"
        return 1
    fi
    
    log "Restoring DNS records from $backup_file"
    
    if [[ "$dry_run" == "true" ]]; then
        warning "DRY RUN MODE - no changes will be made"
    fi
    
    # Read records from backup
    local records
    records=$(cat "$backup_file")
    
    local count
    count=$(echo "$records" | jq '. | length')
    log "Found $count records to restore"
    
    # Process each record
    echo "$records" | jq -c '.[]' | while read -r record; do
        local name
        name=$(echo "$record" | jq -r '.name')
        local type
        type=$(echo "$record" | jq -r '.type')
        local content
        content=$(echo "$record" | jq -r '.content')
        local ttl
        ttl=$(echo "$record" | jq -r '.ttl')
        
        log "Processing: $type $name -> $content (TTL: $ttl)"
        
        if [[ "$dry_run" == "false" ]]; then
            # Check if record exists
            local existing_response
            existing_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$name&type=$type" \
                -H "Authorization: Bearer $API_TOKEN" \
                -H "Content-Type: application/json")
            
            local existing_id
            existing_id=$(echo "$existing_response" | jq -r '.result[0].id // empty')
            
            if [[ -n "$existing_id" && "$existing_id" != "null" ]]; then
                # Update existing record
                log "Updating existing record: $existing_id"
                curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$existing_id" \
                    -H "Authorization: Bearer $API_TOKEN" \
                    -H "Content-Type: application/json" \
                    --data "$record" >/dev/null
            else
                # Create new record
                log "Creating new record"
                local clean_record
                clean_record=$(echo "$record" | jq 'del(.id, .zone_id, .zone_name, .created_on, .modified_on)')
                curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
                    -H "Authorization: Bearer $API_TOKEN" \
                    -H "Content-Type: application/json" \
                    --data "$clean_record" >/dev/null
            fi
        fi
    done
    
    if [[ "$dry_run" == "true" ]]; then
        warning "DRY RUN completed - use 'restore-force' to actually restore"
    else
        success "DNS restore completed"
    fi
}

# Usage information
show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  backup              - Backup current DNS records"
    echo "  list               - List available backups"
    echo "  restore <file>     - Restore from backup (dry run)"
    echo "  restore-force <file> - Actually restore from backup"
    echo ""
    echo "Examples:"
    echo "  $0 backup"
    echo "  $0 list"
    echo "  $0 restore /opt/backups/dns/dns-backup-20231201-120000.json"
}

# Main execution
main() {
    if ! validate_config; then
        exit 1
    fi
    
    case "${1:-backup}" in
        backup)
            backup_dns
            ;;
        list)
            list_backups
            ;;
        restore)
            if [[ -z "${2:-}" ]]; then
                error "Backup file required for restore"
                show_usage
                exit 1
            fi
            restore_dns "$2" "true"
            ;;
        restore-force)
            if [[ -z "${2:-}" ]]; then
                error "Backup file required for restore"
                show_usage
                exit 1
            fi
            restore_dns "$2" "false"
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    # Set environment variables
    sed -i "s/\${CLOUDFLARE_API_TOKEN:-}/${CLOUDFLARE_API_TOKEN}/g" /usr/local/bin/dns-backup
    sed -i "s/\${CLOUDFLARE_ZONE_ID:-}/${CLOUDFLARE_ZONE_ID}/g" /usr/local/bin/dns-backup
    sed -i "s/\${DOMAIN_NAME:-7gram.xyz}/${DOMAIN_NAME:-7gram.xyz}/g" /usr/local/bin/dns-backup
    
    chmod +x /usr/local/bin/dns-backup
    
    success "DNS backup script created"
}

setup_dns_monitoring() {
    log "Setting up DNS monitoring..."
    
    # Create initial DNS backup
    if /usr/local/bin/dns-backup backup; then
        success "Initial DNS backup created"
    else
        warning "Failed to create initial DNS backup"
    fi
    
    # Add DNS monitoring to cron (every 6 hours)
    (crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/dns-monitor >/dev/null 2>&1") | crontab -
    
    # Add daily DNS backup to cron
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/dns-backup backup >/dev/null 2>&1") | crontab -
    
    success "DNS monitoring and backup scheduled"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting DNS setup..."
    
    # Validate configuration
    if ! validate_dns_config; then
        log "DNS management not configured or disabled, skipping DNS setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "DNS management disabled or not configured"
        return 0
    fi
    
    # Test Cloudflare API
    if ! test_cloudflare_api; then
        error "Cloudflare API test failed, skipping DNS setup"
        save_completion_status "$SCRIPT_NAME" "failed" "Cloudflare API test failed"
        return 1
    fi
    
    # Create DNS management scripts
    create_cloudflare_dns_script
    create_dns_monitoring_script
    create_dns_backup_script
    
    # Setup monitoring
    setup_dns_monitoring
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "DNS setup completed successfully"
    log "Use 'update-cloudflare-dns' to update DNS records"
    log "Use 'dns-monitor' to check DNS status"
    log "Use 'dns-backup' to manage DNS backups"
}

# Execute main function
main "$@"