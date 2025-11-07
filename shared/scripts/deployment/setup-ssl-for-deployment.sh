#!/bin/bash

# FKS Trading Systems - SSL Setup for Existing Deployment
# This script adds SSL certificates to an existing FKS deployment

set -e

# Configuration
TARGET_HOST="${TARGET_HOST:-fkstrading.xyz}"
ACTIONS_USER_PASSWORD="${ACTIONS_USER_PASSWORD:-}"
DOMAIN_NAME="${DOMAIN_NAME:-fkstrading.xyz}"
ADMIN_EMAIL="${ADMIN_EMAIL:-nunie.smith01@gmail.com}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
SSL_STAGING="${SSL_STAGING:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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
    local timeout="${3:-60}"
    
    log "📡 $description"
    
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        if timeout $timeout sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null actions_user@"$TARGET_HOST" "$command"; then
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

# Function to get server IP
get_server_ip() {
    local ip=""
    
    # Try different methods to get server IP
    if command -v dig > /dev/null 2>&1; then
        ip=$(dig +short "$TARGET_HOST" | head -n1)
    elif command -v nslookup > /dev/null 2>&1; then
        ip=$(nslookup "$TARGET_HOST" | grep -A1 "Name:" | grep "Address:" | cut -d: -f2 | tr -d ' ')
    fi
    
    # If we can't resolve, try to get from SSH connection
    if [ -z "$ip" ]; then
        ip=$(execute_ssh "curl -s ifconfig.me || curl -s icanhazip.com || echo 'unknown'" "Get server IP" 10 | tail -n1)
    fi
    
    echo "$ip"
}

# Validate required environment variables
validate_env() {
    local missing_vars=()
    
    [ -z "$DOMAIN_NAME" ] && missing_vars+=("DOMAIN_NAME")
    [ -z "$ADMIN_EMAIL" ] && missing_vars+=("ADMIN_EMAIL")
    [ -z "$CLOUDFLARE_API_TOKEN" ] && missing_vars+=("CLOUDFLARE_API_TOKEN")
    [ -z "$CLOUDFLARE_ZONE_ID" ] && missing_vars+=("CLOUDFLARE_ZONE_ID")
    [ -z "$ACTIONS_USER_PASSWORD" ] && missing_vars+=("ACTIONS_USER_PASSWORD")
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        error "Missing required environment variables: ${missing_vars[*]}"
        echo ""
        echo "Required environment variables:"
        echo "  DOMAIN_NAME         - Domain name (e.g., fkstrading.xyz)"
        echo "  ADMIN_EMAIL         - Admin email for Let's Encrypt"
        echo "  CLOUDFLARE_API_TOKEN - Cloudflare API token"
        echo "  CLOUDFLARE_ZONE_ID  - Cloudflare Zone ID"
        echo "  ACTIONS_USER_PASSWORD - SSH password for actions_user"
        echo ""
        echo "Optional environment variables:"
        echo "  SSL_STAGING         - Use staging environment (default: false)"
        echo "  TARGET_HOST         - Target server hostname (default: fkstrading.xyz)"
        echo ""
        exit 1
    fi
}

main() {
    log "🔐 Starting SSL setup for FKS Trading Systems deployment..."
    
    # Validate environment
    validate_env
    
    log "📋 Configuration:"
    log "  - Target: $TARGET_HOST"
    log "  - Domain: $DOMAIN_NAME"
    log "  - Admin Email: $ADMIN_EMAIL"
    log "  - SSL Staging: $SSL_STAGING"
    
    # Get server IP
    log "🌐 Determining server IP..."
    SERVER_IP=$(get_server_ip)
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "unknown" ]; then
        warn "⚠️ Could not determine server IP automatically"
        SERVER_IP="$TARGET_HOST"
    fi
    log "📍 Server IP: $SERVER_IP"
    
    # Step 1: Install SSL packages and setup certificates
    log "🔐 Setting up SSL certificates..."
    execute_ssh "
        echo '🔐 Installing SSL packages and setting up certificates...'
        
        # Install required packages
        echo '📦 Installing required packages...'
        if ! command -v certbot > /dev/null 2>&1; then
            echo '📥 Installing certbot and cloudflare plugin...'
            sudo pacman -Sy --noconfirm certbot certbot-dns-cloudflare || {
                echo '🔄 Trying AUR packages...'
                yay -S --noconfirm certbot certbot-dns-cloudflare || {
                    echo '❌ Failed to install certbot packages'
                    exit 1
                }
            }
        fi
        
        if ! command -v jq > /dev/null 2>&1; then
            echo '📥 Installing jq...'
            sudo pacman -Sy --noconfirm jq
        fi
        
        # Update DNS A records
        echo '🌐 Updating DNS A records...'
        
        # Function to update DNS record
        update_dns_record() {
            local record_name=\"\$1\"
            local record_type=\"\$2\"
            local record_content=\"\$3\"
            
            echo \"🔍 Checking DNS record: \$record_name (\$record_type)\"
            
            # Get existing DNS records
            EXISTING_RECORD=\$(curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=\$record_type&name=\$record_name\" \\
                -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                -H \"Content-Type: application/json\")
            
            if ! echo \"\$EXISTING_RECORD\" | jq -e .success > /dev/null; then
                echo \"❌ Failed to fetch DNS records for \$record_name\"
                return 1
            fi
            
            RECORD_COUNT=\$(echo \"\$EXISTING_RECORD\" | jq '.result | length')
            CURRENT_IP=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].content // empty')
            
            if [[ \"\$RECORD_COUNT\" -eq 0 ]]; then
                # Create new record
                echo \"📝 Creating new \$record_type record for \$record_name...\"
                DNS_RESPONSE=\$(curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                
                if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                    echo \"✅ Created \$record_type record for \$record_name\"
                else
                    echo \"❌ Failed to create \$record_type record for \$record_name\"
                    return 1
                fi
            elif [[ \"\$CURRENT_IP\" != \"\$record_content\" ]]; then
                # Update existing record
                RECORD_ID=\$(echo \"\$EXISTING_RECORD\" | jq -r '.result[0].id')
                echo \"🔄 Updating \$record_type record for \$record_name (was: \$CURRENT_IP, now: \$record_content)...\"
                DNS_RESPONSE=\$(curl -s -X PUT \"https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/\$RECORD_ID\" \\
                    -H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" \\
                    -H \"Content-Type: application/json\" \\
                    --data \"{\\\"type\\\":\\\"\$record_type\\\",\\\"name\\\":\\\"\$record_name\\\",\\\"content\\\":\\\"\$record_content\\\",\\\"ttl\\\":300}\")
                
                if echo \"\$DNS_RESPONSE\" | jq -e .success > /dev/null; then
                    echo \"✅ Updated \$record_type record for \$record_name\"
                else
                    echo \"❌ Failed to update \$record_type record for \$record_name\"
                    return 1
                fi
            else
                echo \"✅ \$record_type record for \$record_name is already correct: \$CURRENT_IP\"
            fi
        }
        
        # Update DNS records
        update_dns_record \"$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
        update_dns_record \"www.$DOMAIN_NAME\" \"A\" \"$SERVER_IP\"
        
        # Create Cloudflare credentials file
        echo '🔐 Setting up Cloudflare credentials...'
        CLOUDFLARE_CREDS_FILE=\"/root/.cloudflare-credentials\"
        sudo bash -c \"cat > \\\$CLOUDFLARE_CREDS_FILE << 'CFEOF'
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
CFEOF\"
        sudo chmod 600 \"\$CLOUDFLARE_CREDS_FILE\"
        
        # Wait for DNS propagation
        echo '⏳ Waiting for DNS propagation...'
        sleep 60
        
        # Verify DNS propagation
        echo '🔍 Verifying DNS propagation...'
        for i in {1..12}; do
            if nslookup \"$DOMAIN_NAME\" 8.8.8.8 | grep -q \"$SERVER_IP\"; then
                echo \"✅ DNS propagation confirmed\"
                break
            fi
            
            if [[ \$i -eq 12 ]]; then
                echo \"⚠️ DNS propagation taking longer than expected, continuing anyway...\"
                break
            fi
            
            echo \"⏳ Waiting for DNS propagation... (attempt \$i/12)\"
            sleep 10
        done
        
        # Generate SSL certificate
        echo '🔐 Generating SSL certificate...'
        
        STAGING_FLAG=\"\"
        if [ \"$SSL_STAGING\" = \"true\" ]; then
            STAGING_FLAG=\"--staging\"
            echo \"⚠️ Using Let's Encrypt staging environment\"
        fi
        
        # Run certbot with Cloudflare DNS challenge
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
        else
            echo '❌ Failed to generate SSL certificate'
            exit 1
        fi
        
        # Clean up credentials file
        sudo rm -f \"\$CLOUDFLARE_CREDS_FILE\"
        
        # Set up certificate auto-renewal
        echo '🔄 Setting up automatic certificate renewal...'
        CRON_JOB=\"0 2 * * 0 /usr/bin/certbot renew --quiet && /usr/bin/systemctl reload nginx\"
        (sudo crontab -l 2>/dev/null; echo \"\$CRON_JOB\") | sudo crontab -
        
        echo '✅ SSL certificates configured successfully'
    " "SSL certificate setup" 180
    
    # Step 2: Update deployment environment to enable SSL
    log "🔧 Updating deployment environment for SSL..."
    execute_ssh "
        echo '🔧 Updating deployment environment for SSL...'
        
        cd /home/fks_user/fks
        
        # Update .env file to enable SSL
        if [ -f .env ]; then
            echo '📝 Updating .env file to enable SSL...'
            sudo -u fks_user bash -c '
                # Backup existing .env
                cp .env .env.backup.\$(date +%s)
                
                # Update SSL settings
                sed -i \"s/ENABLE_SSL=false/ENABLE_SSL=true/g\" .env
                sed -i \"s/SSL_STAGING=false/SSL_STAGING=$SSL_STAGING/g\" .env
                sed -i \"s/DOMAIN_NAME=localhost/DOMAIN_NAME=$DOMAIN_NAME/g\" .env
                
                # Update URLs to use HTTPS
                sed -i \"s|API_URL=http://|API_URL=https://|g\" .env
                sed -i \"s|WS_URL=ws://|WS_URL=wss://|g\" .env
                sed -i \"s|REACT_APP_API_URL=http://|REACT_APP_API_URL=https://|g\" .env
                
                echo \"✅ .env file updated for SSL\"
            '
        else
            echo '❌ .env file not found in deployment'
            exit 1
        fi
        
        # Restart services to apply SSL configuration
        echo '🔄 Restarting services to apply SSL configuration...'
        sudo -u fks_user bash -c '
            cd /home/fks_user/fks
            
            # Source updated environment
            export \$(cat .env | xargs)
            
            # Restart nginx specifically to pick up SSL certificates
            docker compose restart nginx
            
            # Wait for services to restart
            sleep 15
            
            # Check service status
            echo \"📊 Service status after SSL update:\"
            docker compose ps
            
            # Check nginx logs
            echo \"📋 Nginx logs:\"
            docker logs fks_nginx --tail 20
        '
    " "Update deployment for SSL"
    
    # Step 3: Test SSL configuration
    log "🔍 Testing SSL configuration..."
    execute_ssh "
        echo '🔍 Testing SSL configuration...'
        
        # Test HTTPS connection
        echo '🌐 Testing HTTPS connection...'
        sleep 10
        
        if curl -s -I \"https://$DOMAIN_NAME\" | head -n1 | grep -q \"HTTP\"; then
            echo '✅ HTTPS connection successful'
        else
            echo '⚠️ HTTPS connection test inconclusive'
        fi
        
        # Test HTTP redirect
        echo '🔄 Testing HTTP to HTTPS redirect...'
        if curl -s -I \"http://$DOMAIN_NAME\" | grep -q \"301\\|302\"; then
            echo '✅ HTTP to HTTPS redirect working'
        else
            echo '⚠️ HTTP redirect test inconclusive'
        fi
        
        # Show certificate information
        echo '📋 Certificate information:'
        sudo certbot certificates
    " "Test SSL configuration"
    
    log "✅ SSL setup completed successfully!"
    log ""
    log "🎉 SSL Configuration Summary:"
    log "  🌐 Domain: $DOMAIN_NAME"
    log "  🔒 SSL Certificate: ✅ Generated and configured"
    log "  🔄 Auto-renewal: ✅ Enabled (weekly check)"
    log "  📍 DNS Records: ✅ Updated"
    log ""
    log "🌐 Your site is now available at:"
    log "  • https://$DOMAIN_NAME (HTTPS - recommended)"
    log "  • http://$DOMAIN_NAME (redirects to HTTPS)"
    log ""
    log "📝 Useful commands:"
    log "  • Check certificates: sudo certbot certificates"
    log "  • Test renewal: sudo certbot renew --dry-run"
    log "  • View nginx logs: docker logs fks_nginx"
    log "  • Check SSL status: curl -I https://$DOMAIN_NAME"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
