#!/bin/bash

# Quick fix for SSL issues in current deployment
# This script addresses the IPv6, DNS, and credentials file issues

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
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    log "🔧 Quick fix for SSL deployment issues..."
    
    # Check if we have the required secrets
    if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
        error "❌ Missing required SSL secrets:"
        error "   CLOUDFLARE_API_TOKEN: $([ -n "$CLOUDFLARE_API_TOKEN" ] && echo "configured" || echo "missing")"
        error "   CLOUDFLARE_ZONE_ID: $([ -n "$CLOUDFLARE_ZONE_ID" ] && echo "configured" || echo "missing")"
        echo ""
        echo "Please configure these GitHub secrets and re-run the deployment."
        exit 1
    fi
    
    log "🔍 Getting correct IPv4 address..."
    
    # Get the IPv4 address properly
    SERVER_IP=""
    if command -v dig > /dev/null 2>&1; then
        SERVER_IP=$(dig +short A "$TARGET_HOST" | head -n1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    fi
    
    if [ -z "$SERVER_IP" ]; then
        if command -v nslookup > /dev/null 2>&1; then
            SERVER_IP=$(nslookup "$TARGET_HOST" | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        fi
    fi
    
    if [ -z "$SERVER_IP" ]; then
        error "❌ Could not determine IPv4 address for $TARGET_HOST"
        exit 1
    fi
    
    log "🌐 Server IPv4: $SERVER_IP"
    
    # Fix the SSL setup
    execute_ssh "
        echo '🔧 Fixing SSL certificate setup...'
        
        # Stop any running certbot processes
        sudo pkill -f certbot || true
        
        # Function to update DNS record (fixed version)
        update_dns_record() {
            local record_name=\"\$1\"
            local record_type=\"\$2\"
            local record_content=\"\$3\"
            
            echo \"🔍 Updating DNS record: \$record_name (\$record_type) -> \$record_content\"
            
            # Validate IPv4 address format
            if [[ ! \"\$record_content\" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then
                echo \"❌ Invalid IPv4 address format: \$record_content\"
                return 1
            fi
            
            EXISTING_RECORD=\$(curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=\$record_type&name=\$record_name\" \\
                -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                -H \"Content-Type: application/json\")
            
            if ! echo \"\$EXISTING_RECORD\" | jq -e .success > /dev/null; then
                echo \"❌ Failed to fetch DNS records for \$record_name\"
                echo \"Response: \$EXISTING_RECORD\"
                return 1
            fi
            
            RECORD_COUNT=\$(echo \"\$EXISTING_RECORD\" | jq '.result | length')
            
            if [[ \"\$RECORD_COUNT\" -eq 0 ]]; then
                echo \"📝 Creating new \$record_type record for \$record_name...\"
                DNS_RESPONSE=\$(curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
            else
                RECORD_ID=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].id')
                echo \"🔄 Updating existing \$record_type record for \$record_name...\"
                DNS_RESPONSE=\$(curl -s -X PUT \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/\$RECORD_ID\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
            fi
            
            if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                echo \"✅ DNS record updated for \$record_name\"
                return 0
            else
                echo \"❌ Failed to update DNS record for \$record_name\"
                echo \"Response: \$DNS_RESPONSE\"
                return 1
            fi
        }
        
        # Update DNS records with correct IPv4 address
        echo '🌐 Updating DNS records with IPv4 address...'
        update_dns_record \"$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
        update_dns_record \"www.$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
        
        # Create Cloudflare credentials file properly
        echo '🔐 Creating Cloudflare credentials file...'
        CLOUDFLARE_CREDS_FILE=\"/root/.cloudflare-credentials\"
        echo \"dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN\" | sudo tee \"\$CLOUDFLARE_CREDS_FILE\" > /dev/null
        sudo chmod 600 \"\$CLOUDFLARE_CREDS_FILE\"
        
        if [ -f \"\$CLOUDFLARE_CREDS_FILE\" ]; then
            echo \"✅ Cloudflare credentials file created successfully\"
        else
            echo \"❌ Failed to create credentials file\"
            exit 1
        fi
        
        # Wait for DNS propagation
        echo '⏳ Waiting 120 seconds for DNS propagation...'
        sleep 120
        
        # Verify DNS propagation
        echo '🔍 Verifying DNS propagation...'
        for i in {1..5}; do
            if nslookup \"$DOMAIN_NAME\" 8.8.8.8 | grep -q \"$SERVER_IP\"; then
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
        
        # Try to generate the SSL certificate
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
            
        else
            echo '❌ SSL certificate generation failed'
            echo '📋 Checking certbot logs...'
            sudo tail -30 /var/log/letsencrypt/letsencrypt.log || echo 'No certbot logs found'
        fi
        
        # Clean up credentials file
        sudo rm -f \"\$CLOUDFLARE_CREDS_FILE\"
        echo '🧹 Cleaned up credentials file'
        
    " "Fix SSL certificate setup"
    
    log "✅ SSL fix completed!"
    log "🔍 You can now check your certificate status with:"
    log "   ssh actions_user@$TARGET_HOST 'sudo certbot certificates'"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
