#!/bin/bash
set -euo pipefail

echo "🔍 Testing Tailscale OAuth Connection"
echo "====================================="

# Check if required environment variables are set
if [[ -z "${TS_OAUTH_CLIENT_ID:-}" ]]; then
  echo "❌ TS_OAUTH_CLIENT_ID is not set"
  exit 1
fi

if [[ -z "${TS_OAUTH_SECRET:-}" ]]; then
  echo "❌ TS_OAUTH_SECRET is not set"
  exit 1
fi

echo "✅ OAuth credentials are set"
echo "Client ID length: ${#TS_OAUTH_CLIENT_ID}"
echo "Secret length: ${#TS_OAUTH_SECRET}"

# Test OAuth token request
echo ""
echo "🔑 Testing OAuth token request..."

OAUTH_RESPONSE=$(curl -s -X POST https://api.tailscale.com/api/v2/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$TS_OAUTH_CLIENT_ID" \
  -d "client_secret=$TS_OAUTH_SECRET" 2>/dev/null || echo "CURL_FAILED")

if [[ "$OAUTH_RESPONSE" == "CURL_FAILED" ]]; then
  echo "❌ OAuth request failed completely"
  exit 1
fi

echo "OAuth response received"

TOKEN=$(echo "$OAUTH_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

if [[ -z "$TOKEN" || "$TOKEN" == "null" || "$TOKEN" == "empty" ]]; then
  echo "❌ Failed to get OAuth access token"
  echo "Response: $OAUTH_RESPONSE"
  
  ERROR_MSG=$(echo "$OAUTH_RESPONSE" | jq -r '.error_description // .error // empty' 2>/dev/null || echo "")
  if [[ -n "$ERROR_MSG" ]]; then
    echo "Error: $ERROR_MSG"
  fi
  exit 1
fi

echo "✅ OAuth token obtained successfully"

# Test auth key creation
echo ""
echo "🔑 Testing ephemeral auth key creation..."

TAILNET="${TAILSCALE_TAILNET:-"-"}"
echo "Using tailnet: $TAILNET"

AUTH_KEY_RESPONSE=$(curl -s -X POST "https://api.tailscale.com/api/v2/tailnet/$TAILNET/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":true,"preauthorized":true,"tags":["tag:ci"]}}},"expirySeconds":3600}' 2>/dev/null || echo "CURL_FAILED")

if [[ "$AUTH_KEY_RESPONSE" == "CURL_FAILED" ]]; then
  echo "❌ Auth key creation request failed"
  exit 1
fi

AUTH_KEY=$(echo "$AUTH_KEY_RESPONSE" | jq -r '.key // empty' 2>/dev/null || echo "")

if [[ -z "$AUTH_KEY" || "$AUTH_KEY" == "empty" ]]; then
  echo "❌ Failed to create ephemeral auth key"
  echo "Response: $AUTH_KEY_RESPONSE"
  
  KEY_ERROR=$(echo "$AUTH_KEY_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "")
  if [[ -n "$KEY_ERROR" ]]; then
    echo "Error: $KEY_ERROR"
  fi
  exit 1
fi

echo "✅ Ephemeral auth key created successfully"
echo "Auth key prefix: ${AUTH_KEY:0:20}..."

echo ""
echo "🎉 All OAuth tests passed!"
echo "Your Tailscale OAuth configuration is working correctly."
