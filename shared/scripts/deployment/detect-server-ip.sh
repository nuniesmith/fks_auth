#!/bin/bash
# =============================================================================
# FKS Trading System - Server IP Detection Script
# =============================================================================
# This script detects the server IP for deployment using multiple methods
#
# Usage: ./detect-server-ip.sh [--method=METHOD] [--verbose]
#
# Methods:
#   - provisioned: Use IP from infrastructure provisioning
#   - linode: Auto-detect via Linode CLI (preferred)
#   - dns: Resolve domain name
#   - auto: Try all methods (default)
#
# Environment Variables:
#   - PROVISIONED_SERVER_IP: IP from infrastructure provisioning
#   - LINODE_CLI_TOKEN: Linode API token for auto-detection
#   - DOMAIN_NAME: Domain name for DNS resolution
# =============================================================================

set -e

# Configuration
METHOD="auto"
VERBOSE=false
DETECTED_IP=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --method=*)
      METHOD="${1#*=}"
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--method=METHOD] [--verbose]"
      echo ""
      echo "Methods: provisioned, linode, dns, auto"
      echo ""
      echo "Environment variables:"
      echo "  PROVISIONED_SERVER_IP - IP from infrastructure provisioning"
      echo "  LINODE_CLI_TOKEN     - Linode API token"
      echo "  DOMAIN_NAME          - Domain name for DNS resolution"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Logging function
log() {
  if [ "$VERBOSE" = true ]; then
    echo "🔍 [detect-server-ip] $*" >&2
  fi
}

# Method 1: Use server IP from infrastructure provisioning
detect_provisioned() {
  log "Checking provisioned server IP..."
  
  if [ -n "$PROVISIONED_SERVER_IP" ]; then
    if [[ "$PROVISIONED_SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      DETECTED_IP="$PROVISIONED_SERVER_IP"
      echo "✅ Using server IP from infrastructure provisioning: $DETECTED_IP" >&2
      return 0
    else
      log "Invalid provisioned IP format: $PROVISIONED_SERVER_IP"
    fi
  else
    log "No provisioned server IP available"
  fi
  
  return 1
}

# Method 2: Linode CLI detection (preferred method)
# Secret-based detection removed per user preference

# Method 2: Auto-detect via Linode CLI
detect_linode() {
  log "Checking Linode CLI auto-detection..."
  
  if [ -z "$LINODE_CLI_TOKEN" ]; then
    log "No LINODE_CLI_TOKEN available"
    return 1
  fi
  
  # Install Linode CLI if not available
  if ! command -v linode-cli > /dev/null 2>&1; then
    echo "📦 Installing Linode CLI..." >&2
    pip3 install --user linode-cli --quiet
    export PATH="$HOME/.local/bin:$PATH"
  fi
  
  # Configure Linode CLI
  export LINODE_CLI_TOKEN="$LINODE_CLI_TOKEN"
  
  log "Searching for FKS servers in Linode account..."
  
  # Get all servers
  LINODE_SERVERS=$(linode-cli linodes list --text --no-headers --format "id,label,ipv4" 2>/dev/null || echo "")
  
  if [ -z "$LINODE_SERVERS" ]; then
    log "No Linode servers found or CLI access failed"
    return 1
  fi
  
  if [ "$VERBOSE" = true ]; then
    echo "📋 Available Linode servers:" >&2
    echo "$LINODE_SERVERS" >&2
  fi
  
  # Try multiple patterns to find FKS server
  FKS_SERVER_IP=""
  
  # Pattern 1: Look for servers with 'fks' in label (case-insensitive)
  FKS_SERVER_IP=$(echo "$LINODE_SERVERS" | grep -i "fks" | head -1 | awk '{print $3}' || echo "")
  
  # Pattern 2: Look for servers with 'trading' in label
  if [ -z "$FKS_SERVER_IP" ]; then
    FKS_SERVER_IP=$(echo "$LINODE_SERVERS" | grep -i "trading" | head -1 | awk '{print $3}' || echo "")
  fi
  
  # Pattern 3: If only one server, use it
  if [ -z "$FKS_SERVER_IP" ]; then
    SERVER_COUNT=$(echo "$LINODE_SERVERS" | wc -l)
    if [ "$SERVER_COUNT" -eq 1 ]; then
      FKS_SERVER_IP=$(echo "$LINODE_SERVERS" | head -1 | awk '{print $3}' || echo "")
      log "Only one server found, using: $FKS_SERVER_IP"
    fi
  fi
  
  if [ -n "$FKS_SERVER_IP" ] && [[ "$FKS_SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    DETECTED_IP="$FKS_SERVER_IP"
    echo "✅ Auto-detected FKS server IP via Linode CLI: $DETECTED_IP" >&2
    return 0
  else
    log "Could not identify FKS server from available servers"
    return 1
  fi
}

# Method 3: Resolve domain name to IP
detect_dns() {
  log "Checking DNS resolution..."
  
  if [ -z "$DOMAIN_NAME" ]; then
    log "No DOMAIN_NAME available"
    return 1
  fi
  
  log "Resolving domain name to IP: $DOMAIN_NAME"
  DOMAIN_IP=$(dig +short "$DOMAIN_NAME" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "")
  
  if [ -n "$DOMAIN_IP" ]; then
    DETECTED_IP="$DOMAIN_IP"
    echo "✅ Resolved domain to IP: $DETECTED_IP" >&2
    return 0
  else
    log "Domain resolution failed or returned non-IP result"
    return 1
  fi
}

# Main detection logic
case "$METHOD" in
  provisioned)
    detect_provisioned || exit 1
    ;;
  secret)
    echo "❌ Secret-based detection has been disabled per user preference" >&2
    echo "Use Linode CLI detection instead: --method=linode" >&2
    exit 1
    ;;
  linode)
    detect_linode || exit 1
    ;;
  dns)
    detect_dns || exit 1
    ;;
  auto)
    log "Trying all detection methods..."
    
    if detect_provisioned; then
      :  # Success
    elif detect_linode; then
      :  # Success  
    elif detect_dns; then
      :  # Success
    else
      echo "❌ Failed to determine server IP using any method!" >&2
      echo "Please ensure one of the following:" >&2
      echo "  1. Infrastructure provisioning is enabled (run_infra=true)" >&2
      echo "  2. LINODE_CLI_TOKEN is set for auto-detection" >&2
      echo "  3. DOMAIN_NAME is set and resolves to your server" >&2
      exit 1
    fi
    ;;
  *)
    echo "❌ Unknown method: $METHOD" >&2
    echo "Valid methods: provisioned, linode, dns, auto" >&2
    exit 1
    ;;
esac

# Validate the detected IP
if [ -z "$DETECTED_IP" ]; then
  echo "❌ No server IP detected!" >&2
  exit 1
fi

if ! [[ "$DETECTED_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ Invalid IP format detected: $DETECTED_IP" >&2
  exit 1
fi

# Output the result
echo "$DETECTED_IP"
exit 0
