#!/bin/bash
set -euo pipefail

# Preflight script to validate all required secrets and environment variables
# Usage: ./validate-secrets.sh <service_name>

SERVICE_NAME="${1:-unknown}"

echo "🔐 Validating required secrets..."

MISSING_SECRETS=()

# Core Infrastructure Secrets
[[ -z "${LINODE_CLI_TOKEN:-}" ]] && MISSING_SECRETS+=("LINODE_CLI_TOKEN")
[[ -z "${SERVICE_ROOT_PASSWORD:-}" ]] && MISSING_SECRETS+=("SERVICE_ROOT_PASSWORD")
[[ -z "${JORDAN_PASSWORD:-}" ]] && MISSING_SECRETS+=("JORDAN_PASSWORD")
[[ -z "${ACTIONS_USER_PASSWORD:-}" ]] && MISSING_SECRETS+=("ACTIONS_USER_PASSWORD")
[[ -z "${TS_OAUTH_CLIENT_ID:-}" ]] && MISSING_SECRETS+=("TS_OAUTH_CLIENT_ID")
[[ -z "${TS_OAUTH_SECRET:-}" ]] && MISSING_SECRETS+=("TS_OAUTH_SECRET")

# Report missing secrets
if [[ ${#MISSING_SECRETS[@]} -gt 0 ]]; then
  echo "❌ Missing required secrets:"
  printf '  - %s\n' "${MISSING_SECRETS[@]}"
  exit 1
fi

echo "✅ All required secrets validated"

# Service-specific validations
case "$SERVICE_NAME" in
  "nginx")
    SSL_SECRETS=()
    [[ -z "${CLOUDFLARE_EMAIL:-}" ]] && SSL_SECRETS+=("CLOUDFLARE_EMAIL")
    [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]] && SSL_SECRETS+=("CLOUDFLARE_API_TOKEN")
    
    if [[ ${#SSL_SECRETS[@]} -gt 0 ]]; then
      echo "⚠️ SSL secrets missing (will use HTTP challenge or self-signed):"
      printf '  - %s\n' "${SSL_SECRETS[@]}"
      echo "💡 For wildcard certificates and better reliability, add:"
      echo "   - CLOUDFLARE_EMAIL (your Cloudflare account email)"
      echo "   - CLOUDFLARE_API_TOKEN (Cloudflare API token with DNS edit permissions)"
    else
      echo "✅ SSL secrets available for DNS-01 challenge"
    fi
    ;;
  *)
    echo "ℹ️ No service-specific secrets required for $SERVICE_NAME"
    ;;
esac

echo "🔐 Secret validation completed"
