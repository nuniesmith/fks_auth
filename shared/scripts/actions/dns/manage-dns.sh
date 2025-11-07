#!/bin/bash
# DNS Management Script
# Manages DNS records using Cloudflare API
# Part of the GitHub Actions workflow refactoring

set -euo pipefail

# =============================================================================
# Configuration & Global Variables
# =============================================================================

SERVICE_NAME="${1:-}"
SERVER_IP="${2:-}"
DOMAIN_SUFFIX="${3:-7gram.xyz}"
CLOUDFLARE_EMAIL="${CLOUDFLARE_EMAIL:-}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"

DOMAIN="${SERVICE_NAME}.${DOMAIN_SUFFIX}"

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    echo "🌐 [DNS] $*"
}

error() {
    echo "❌ [DNS ERROR] $*" >&2
    exit 1
}

# =============================================================================
# Validation Functions
# =============================================================================

validate_inputs() {
    log "Validating DNS management inputs..."
    
    if [[ -z "$SERVICE_NAME" ]]; then
        error "SERVICE_NAME is required"
    fi
    
    if [[ -z "$SERVER_IP" ]]; then
        error "SERVER_IP is required"
    fi
    
    # DNS management is optional
    if [[ -z "$CLOUDFLARE_EMAIL" || -z "$CLOUDFLARE_API_TOKEN" ]]; then
        log "⚠️  Cloudflare credentials not provided - skipping DNS management"
        return 1
    fi
    
    log "✅ DNS management credentials provided"
    return 0
}

# =============================================================================
# Cloudflare API Functions
# =============================================================================

get_zone_id() {
    local zone_id
    zone_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_SUFFIX" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" | \
        jq -r '.result[0].id // empty')
    
    if [[ -z "$zone_id" ]]; then
        error "Failed to find zone ID for domain $DOMAIN_SUFFIX"
    fi
    
    echo "$zone_id"
}

get_dns_record() {
    local zone_id="$1"
    local record_name="$2"
    
    local record_id
    record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?name=$record_name&type=A" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" | \
        jq -r '.result[0].id // empty')
    
    echo "$record_id"
}

create_dns_record() {
    local zone_id="$1"
    local name="$2"
    local ip="$3"
    
    log "Creating DNS A record: $name -> $ip"
    
    local response
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{
            "type": "A",
            "name": "'"$name"'",
            "content": "'"$ip"'",
            "ttl": 300,
            "proxied": false
        }')
    
    local success
    success=$(echo "$response" | jq -r '.success')
    
    if [[ "$success" != "true" ]]; then
        local errors
        errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        error "Failed to create DNS record: $errors"
    fi
    
    log "✅ DNS record created successfully"
}

update_dns_record() {
    local zone_id="$1"
    local record_id="$2"
    local name="$3"
    local ip="$4"
    
    log "Updating DNS A record: $name -> $ip"
    
    local response
    response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{
            "type": "A",
            "name": "'"$name"'",
            "content": "'"$ip"'",
            "ttl": 300,
            "proxied": false
        }')
    
    local success
    success=$(echo "$response" | jq -r '.success')
    
    if [[ "$success" != "true" ]]; then
        local errors
        errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"')
        error "Failed to update DNS record: $errors"
    fi
    
    log "✅ DNS record updated successfully"
}

# =============================================================================
# DNS Management Functions
# =============================================================================

manage_dns_record() {
    log "Managing DNS record for $DOMAIN..."
    
    local zone_id
    zone_id=$(get_zone_id)
    log "Zone ID: $zone_id"
    
    local record_id
    record_id=$(get_dns_record "$zone_id" "$DOMAIN")
    
    if [[ -z "$record_id" ]]; then
        log "DNS record does not exist, creating new record..."
        create_dns_record "$zone_id" "$DOMAIN" "$SERVER_IP"
    else
        log "DNS record exists (ID: $record_id), updating..."
        update_dns_record "$zone_id" "$record_id" "$DOMAIN" "$SERVER_IP"
    fi
    
    log "🌐 DNS record for $DOMAIN points to $SERVER_IP"
}

verify_dns_propagation() {
    log "Verifying DNS propagation for $DOMAIN..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "Checking DNS resolution (attempt $attempt/$max_attempts)..."
        
        # Use multiple DNS resolvers for verification
        local resolved_ip
        resolved_ip=$(dig +short @8.8.8.8 "$DOMAIN" A | head -n1 || echo "")
        
        if [[ "$resolved_ip" == "$SERVER_IP" ]]; then
            log "✅ DNS propagation successful - $DOMAIN resolves to $SERVER_IP"
            return 0
        fi
        
        if [[ -n "$resolved_ip" ]]; then
            log "⏳ DNS resolves to $resolved_ip (expected: $SERVER_IP), waiting..."
        else
            log "⏳ DNS not yet resolved, waiting..."
        fi
        
        sleep 10
        ((attempt++))
    done
    
    log "⚠️  DNS verification timeout - propagation may still be in progress"
    log "Manual verification: dig $DOMAIN"
    return 0  # Don't fail deployment for DNS propagation delays
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "Starting DNS management for $SERVICE_NAME..."
    
    if ! validate_inputs; then
        log "Skipping DNS management"
        return 0
    fi
    
    manage_dns_record
    verify_dns_propagation
    
    log "🎉 DNS management completed successfully!"
}

# Execute main function
main "$@"
