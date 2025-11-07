#!/bin/bash

# Quick fix for GitHub Actions masking issue with SSL certificates
# This addresses the specific issue where SERVER_IP is being masked

set -e

# Configuration
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
SSL_STAGING="${SSL_STAGING:-false}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# SSH execution function
execute_ssh() {
    local command="$1"
    local description="$2"
    
    log "📡 $description"
    
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        if sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$TARGET_HOST" "$command"; then
            log "✅ Success: $description"
            return 0
        else
            error "❌ Failed: $description"
            return 1
        fi
    else
        error "❌ No password available for SSH"
        return 1
    fi
}

main() {
    log "🔧 Fixing SSL certificate setup with GitHub Actions masking workaround..."
    
    # Check if we have the required secrets
    if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
        error "❌ Missing required SSL secrets:"
        error "   CLOUDFLARE_API_TOKEN: $([ -n "$CLOUDFLARE_API_TOKEN" ] && echo "configured" || echo "missing")"
        error "   CLOUDFLARE_ZONE_ID: $([ -n "$CLOUDFLARE_ZONE_ID" ] && echo "configured" || echo "missing")"
        exit 1
    fi
    
    log "🔐 Setting up SSL certificates with masking workaround..."
    
    execute_ssh "
        echo '🔐 SSL Certificate Setup with GitHub Actions Masking Fix'
        echo '======================================================='
        
        # Get the IPv4 address from the server itself to avoid masking
        echo '🌐 Getting server IPv4 address from server...'
        SERVER_IP=''
        
        # Try multiple methods to get IPv4 address
        if command -v curl > /dev/null 2>&1; then
            SERVER_IP=\$(curl -4 -s --connect-timeout 10 ifconfig.me || curl -4 -s --connect-timeout 10 icanhazip.com || echo '')
        fi
        
        # Fallback to ip command
        if [ -z \"\$SERVER_IP\" ]; then
            SERVER_IP=\$(ip route get 8.8.8.8 | grep -oE 'src [0-9.]+' | cut -d' ' -f2 2>/dev/null || echo '')
        fi
        
        # Another fallback using hostname
        if [ -z \"\$SERVER_IP\" ]; then
            SERVER_IP=\$(hostname -I | awk '{print \$1}' | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$' || echo '')
        fi
        
        # Validate we got a proper IPv4 address
        if [[ ! \"\$SERVER_IP\" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$ ]]; then
            echo '❌ Could not determine valid IPv4 address'
            echo 'SERVER_IP value:' \"\$SERVER_IP\"
            exit 1
        fi
        
        echo \"✅ Server IPv4 address determined: \$SERVER_IP\"
        
        # Install packages if needed
        if ! command -v certbot > /dev/null 2>&1; then
            echo '📦 Installing certbot...'
            sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare
        fi
        
        if ! command -v jq > /dev/null 2>&1; then
            echo '📦 Installing jq...'
            sudo pacman -Sy --noconfirm jq
        fi
        
        # Function to update DNS record
        update_dns_record() {
            local record_name=\"\$1\"
            local record_type=\"\$2\"
            local record_content=\"\$3\"
            
            echo \"🔍 Updating DNS record: \$record_name (\$record_type) -> \$record_content\"
            
            # Validate IPv4 format
            if [[ ! \"\$record_content\" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$ ]]; then
                echo \"❌ Invalid IPv4 address format: \$record_content\"
                return 1
            fi
            
            # Get existing records
            EXISTING_RECORD=\$(curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=\$record_type&name=\$record_name\" \\
                -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                -H \"Content-Type: application/json\")
            
            if ! echo \"\$EXISTING_RECORD\" | jq -e .success > /dev/null; then
                echo \"❌ Failed to fetch DNS records for \$record_name\"
                return 1
            fi
            
            RECORD_COUNT=\$(echo \"\$EXISTING_RECORD\" | jq '.result | length')
            
            if [[ \"\$RECORD_COUNT\" -eq 0 ]]; then
                echo \"📝 Creating new \$record_type record...\"
                DNS_RESPONSE=\$(curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
            else
                RECORD_ID=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].id')
                echo \"🔄 Updating existing \$record_type record...\"
                DNS_RESPONSE=\$(curl -s -X PUT \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/\$RECORD_ID\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
            fi
            
            if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                echo \"✅ DNS record updated successfully\"
                return 0
            else
                echo \"❌ Failed to update DNS record\"
                echo \"Response: \$DNS_RESPONSE\"
                return 1
            fi
        }
        
        # Update DNS records
        echo '🌐 Updating DNS records...'
        update_dns_record \"$DOMAIN_NAME\" \"A\" \"\$SERVER_IP\"
        update_dns_record \"www.$DOMAIN_NAME\" \"A\" \"\$SERVER_IP\"
        
        # Create credentials file
        echo '🔐 Creating Cloudflare credentials file...'
        CLOUDFLARE_CREDS_FILE=\"/tmp/cloudflare-credentials-\$(date +%s)\"
        echo \"dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN\" > \"\$CLOUDFLARE_CREDS_FILE\"
        chmod 600 \"\$CLOUDFLARE_CREDS_FILE\"
        
        if [ ! -f \"\$CLOUDFLARE_CREDS_FILE\" ]; then
            echo \"❌ Failed to create credentials file\"
            exit 1
        fi
        echo \"✅ Credentials file created: \$CLOUDFLARE_CREDS_FILE\"
        
        # Wait for DNS propagation
        echo '⏳ Waiting 120 seconds for DNS propagation...'
        sleep 120
        
        # Verify DNS propagation
        echo '🔍 Verifying DNS propagation...'
        for i in {1..5}; do
            if nslookup \"$DOMAIN_NAME\" 8.8.8.8 | grep -q \"\$SERVER_IP\"; then
                echo \"✅ DNS propagation confirmed\"
                break
            fi
            
            if [[ \$i -eq 5 ]]; then
                echo \"⚠️ DNS propagation taking longer, but continuing...\"
                break
            fi
            
            echo \"⏳ Waiting for DNS propagation... (attempt \$i/5)\"
            sleep 30
        done
        
        # Generate SSL certificate
        echo '🔐 Generating SSL certificate...'
        
        STAGING_FLAG=\"\"
        if [ \"$SSL_STAGING\" = \"true\" ]; then
            STAGING_FLAG=\"--staging\"
            echo \"⚠️ Using Let's Encrypt staging environment\"
        fi
        
        if sudo certbot certonly \\
            --dns-cloudflare \\
            --dns-cloudflare-credentials \"\$CLOUDFLARE_CREDS_FILE\" \\
            --email \"$ADMIN_EMAIL\" \\
            --agree-tos \\
            --non-interactive \\
            --expand \\
            \$STAGING_FLAG \\
            -d \"$DOMAIN_NAME\" \\
            -d \"www.$DOMAIN_NAME\"; then
            
            echo '✅ SSL certificate generated successfully'
            
            # Set up auto-renewal
            echo '🔄 Setting up automatic renewal...'
            CRON_JOB=\"0 2 * * 0 /usr/bin/certbot renew --quiet && /usr/bin/systemctl reload nginx\"
            (sudo crontab -l 2>/dev/null; echo \"\$CRON_JOB\") | sudo crontab -
            echo '✅ Auto-renewal configured'
            
            # Show certificate info
            echo '📋 Certificate information:'
            sudo certbot certificates
            
        else
            echo '❌ SSL certificate generation failed'
            echo '📋 Checking certbot logs...'
            sudo tail -30 /var/log/letsencrypt/letsencrypt.log || echo 'No certbot logs found'
            
            # Clean up credentials file even on failure
            rm -f \"\$CLOUDFLARE_CREDS_FILE\"
            exit 1
        fi
        
        # Clean up credentials file
        rm -f \"\$CLOUDFLARE_CREDS_FILE\"
        echo '🧹 Cleaned up credentials file'
        
        echo '✅ SSL certificate setup completed successfully'
    " "SSL certificate setup with masking fix"
    
    log "✅ SSL certificate setup completed!"
    log "🔍 Your certificate is now ready:"
    log "   https://$DOMAIN_NAME"
    log "   https://www.$DOMAIN_NAME"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
