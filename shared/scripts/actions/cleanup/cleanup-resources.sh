#!/bin/bash
set -euo pipefail

# Comprehensive resource cleanup script
# Usage: ./cleanup-resources.sh <service_name>

SERVICE_NAME="${1:-unknown}"

echo "🧹 Cleaning up old $SERVICE_NAME resources..."

# Install dependencies
sudo apt-get update && sudo apt-get install -y curl jq >/dev/null 2>&1

# Function to clean up Tailscale devices by hostname pattern
cleanup_tailscale_devices() {
  local hostname_pattern="$1"
  local cleanup_reason="${2:-old server cleanup}"
  
  echo "🔗 Tailscale cleanup for pattern: $hostname_pattern ($cleanup_reason)"
  
  # Get Tailscale access token using OAuth with better error handling
  echo "🔑 Getting Tailscale access token..."
  
  OAUTH_RESPONSE=$(curl -s -X POST https://api.tailscale.com/api/v2/oauth/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=${TS_OAUTH_CLIENT_ID}" \
    -d "client_secret=${TS_OAUTH_SECRET}" 2>/dev/null || echo "CURL_FAILED")
  
  echo "🔍 OAuth response preview: ${OAUTH_RESPONSE:0:100}..."
  
  if [[ "$OAUTH_RESPONSE" == "CURL_FAILED" ]]; then
    echo "❌ OAuth request failed completely"
    echo "🔍 Checking OAuth credentials..."
    echo "  Client ID length: ${#TS_OAUTH_CLIENT_ID}"
    echo "  Client secret length: ${#TS_OAUTH_SECRET}"
    return 1
  fi
  
  # Try to parse the token, with error handling
  TOKEN=$(echo "$OAUTH_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")
  
  if [[ -z "$TOKEN" || "$TOKEN" == "null" || "$TOKEN" == "empty" ]]; then
    echo "❌ Failed to get valid access token"
    echo "🔍 OAuth response: $OAUTH_RESPONSE"
    
    # Check if it's an error response
    ERROR_MSG=$(echo "$OAUTH_RESPONSE" | jq -r '.error_description // .error // empty' 2>/dev/null || echo "")
    if [[ -n "$ERROR_MSG" ]]; then
      echo "🔍 OAuth error: $ERROR_MSG"
    fi
    
    echo "⚠️ Skipping Tailscale cleanup due to OAuth issues"
    return 1
  else
    echo "✅ Successfully obtained access token"
    
    # Use OAuth token and correct tailnet reference
    TAILNET="${TAILSCALE_TAILNET:-"-"}"
    
    DEVICES_RESPONSE=$(curl -s "https://api.tailscale.com/api/v2/tailnet/$TAILNET/devices" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/json" 2>/dev/null || echo '{"devices":[]}')
    
    # Validate response before processing
    if ! echo "$DEVICES_RESPONSE" | jq empty 2>/dev/null; then
      echo "⚠️ Invalid JSON response from Tailscale API, skipping cleanup"
      return 0
    fi
    
    MATCHING_DEVICES=$(echo "$DEVICES_RESPONSE" | jq -r --arg pattern "$hostname_pattern" '
      .devices[]? | 
      select(
        (.name | test("^" + $pattern + "(-[0-9]+)?$")) or
        (.name == $pattern) or
        (.hostname | test("^" + $pattern + "(-[0-9]+)?$")) or
        (.hostname == $pattern)
      ) | 
      .id' 2>/dev/null || echo "")
    
    local removed_count=0
    if [[ -n "$MATCHING_DEVICES" ]]; then
      for device_id in $MATCHING_DEVICES; do
        if [[ -n "$device_id" && "$device_id" != "null" ]]; then
          echo "🗑️ Removing Tailscale device: $device_id"
          RESPONSE=$(curl -s -X DELETE "https://api.tailscale.com/api/v2/device/$device_id" \
            -H "Authorization: Bearer $TOKEN" \
            -w "HTTP_STATUS:%{http_code}" 2>/dev/null)
          
          HTTP_STATUS=$(echo "$RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
          if [[ "$HTTP_STATUS" == "200" || "$HTTP_STATUS" == "204" ]]; then
            echo "✅ Removed Tailscale device $device_id"
            removed_count=$((removed_count + 1))
          else
            echo "⚠️ Failed to remove device $device_id (HTTP $HTTP_STATUS)"
          fi
        fi
        sleep 1
      done
    fi
    
    if [[ $removed_count -gt 0 ]]; then
      echo "✅ $hostname_pattern cleanup completed - removed $removed_count devices"
    else
      echo "ℹ️ No $hostname_pattern devices found to remove"
    fi
    
    return 0
  fi
}

# Perform Tailscale cleanup
if [[ -n "${TS_OAUTH_CLIENT_ID:-}" && -n "${TS_OAUTH_SECRET:-}" ]]; then
  cleanup_tailscale_devices "$SERVICE_NAME" "pre-deployment cleanup" || {
    echo "⚠️ Cleanup function failed, but continuing deployment..."
  }
else
  echo "⚠️ Tailscale OAuth credentials not available"
fi

# Linode cleanup for old servers
if [[ -n "${LINODE_CLI_TOKEN:-}" ]]; then
  echo "🖥️ Cleaning up old Linode servers..."
  
  # Install linode-cli
  pip install linode-cli
  
  # Configure linode-cli
  echo "[DEFAULT]
token = $LINODE_CLI_TOKEN" > ~/.linode-cli
  
  # Remove old service servers
  echo "🔍 Looking for old $SERVICE_NAME servers..."
  OLD_SERVERS=$(linode-cli linodes list --json | jq -r --arg service "$SERVICE_NAME" '.[] | select(.label | startswith($service)) | "\(.id):\(.label)"')
  
  for server_entry in $OLD_SERVERS; do
    if [[ -n "$server_entry" && "$server_entry" != ":" ]]; then
      server_id="${server_entry%%:*}"
      server_label="${server_entry#*:}"
      
      echo "🗑️ Removing old server: $server_id ($server_label)"
      linode-cli linodes delete "$server_id" --json || echo "⚠️ Failed to remove server $server_id"
      sleep 10
    fi
  done
else
  echo "⚠️ Linode CLI token not available"
fi

echo "✅ Cleanup completed for $SERVICE_NAME"
