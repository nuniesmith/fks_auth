#!/bin/bash
set -euo pipefail

echo "🚀 Stage 0: Preflight checks and validation starting..."

# Configuration variables (to be replaced by workflow)
SERVICE_NAME="${1:-SERVICE_NAME_PLACEHOLDER}"
ACTION_TYPE="${2:-deploy}"
OVERWRITE_SERVER="${3:-false}"
BUILD_DOCKER_ON_CHANGES="${4:-true}"

echo "📋 Configuration loaded:"
echo "  • Service: $SERVICE_NAME"
echo "  • Action: $ACTION_TYPE"
echo "  • Overwrite Server: $OVERWRITE_SERVER"
echo "  • Build Docker on Changes: $BUILD_DOCKER_ON_CHANGES"

# Create outputs file for GitHub Actions
mkdir -p /tmp/stage0-outputs
GITHUB_OUTPUT="/tmp/stage0-outputs/github_output"
touch "$GITHUB_OUTPUT"

echo "🔐 Validating required secrets and environment variables..."

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
  echo "secrets_validated=false" >> "$GITHUB_OUTPUT"
  exit 1
fi

echo "✅ All required secrets validated"
echo "secrets_validated=true" >> "$GITHUB_OUTPUT"

# Service-specific validations
echo "🔧 Validating service-specific requirements..."
case "$SERVICE_NAME" in
  "nginx")
    SSL_SECRETS=()
    [[ -z "${CLOUDFLARE_EMAIL:-}" ]] && SSL_SECRETS+=("CLOUDFLARE_EMAIL")
    [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]] && SSL_SECRETS+=("CLOUDFLARE_API_TOKEN")
    
    if [[ ${#SSL_SECRETS[@]} -gt 0 ]]; then
      echo "⚠️ SSL secrets missing (will use HTTP challenge or self-signed):"
      printf '  - %s\n' "${SSL_SECRETS[@]}"
      echo "ssl_configured=false" >> "$GITHUB_OUTPUT"
    else
      echo "✅ SSL secrets available for DNS-01 challenge"
      echo "ssl_configured=true" >> "$GITHUB_OUTPUT"
    fi
    ;;
  "fks")
    echo "✅ FKS service requirements validated"
    echo "ssl_configured=false" >> "$GITHUB_OUTPUT"
    ;;
  "ats")
    echo "✅ ATS service requirements validated"
    echo "ssl_configured=false" >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "ℹ️ No specific service requirements for $SERVICE_NAME"
    echo "ssl_configured=false" >> "$GITHUB_OUTPUT"
    ;;
esac

echo "🎯 Validating action type and deployment settings..."

case "$ACTION_TYPE" in
  "deploy")
    echo "should_deploy=true" >> "$GITHUB_OUTPUT"
    echo "should_destroy=false" >> "$GITHUB_OUTPUT"
    echo "should_health_check=false" >> "$GITHUB_OUTPUT"
    ;;
  "destroy")
    echo "should_deploy=false" >> "$GITHUB_OUTPUT"
    echo "should_destroy=true" >> "$GITHUB_OUTPUT"
    echo "should_health_check=false" >> "$GITHUB_OUTPUT"
    ;;
  "health-check")
    echo "should_deploy=false" >> "$GITHUB_OUTPUT"
    echo "should_destroy=false" >> "$GITHUB_OUTPUT"
    echo "should_health_check=true" >> "$GITHUB_OUTPUT"
    ;;
  "restart")
    echo "should_deploy=true" >> "$GITHUB_OUTPUT"
    echo "should_destroy=false" >> "$GITHUB_OUTPUT"
    echo "should_health_check=false" >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "❌ Invalid action type: $ACTION_TYPE"
    echo "action_validated=false" >> "$GITHUB_OUTPUT"
    exit 1
    ;;
esac

echo "action_validated=true" >> "$GITHUB_OUTPUT"

# Check if server should be overwritten
echo "🔍 Checking overwrite server setting: $OVERWRITE_SERVER"
if [[ "$OVERWRITE_SERVER" == "true" && ("$ACTION_TYPE" == "deploy" || "$ACTION_TYPE" == "restart") ]]; then
  echo "should_overwrite_server=true" >> "$GITHUB_OUTPUT"
  echo "destroy_confirmed=true" >> "$GITHUB_OUTPUT"
  echo "⚠️ Server will be overwritten (destroyed and recreated)"
else
  echo "should_overwrite_server=false" >> "$GITHUB_OUTPUT"
  echo "destroy_confirmed=false" >> "$GITHUB_OUTPUT"
  echo "ℹ️ Server will be created if not exists, or reused if exists"
fi

echo "🔍 Checking for code and Docker changes..."

# TEMPORARY: Force Docker builds for all services since DockerHub images were cleared
echo "🔄 FORCING Docker builds - DockerHub images were cleared"
echo "code_changed=true" >> "$GITHUB_OUTPUT"
echo "docker_build_needed=true" >> "$GITHUB_OUTPUT"

# TODO: Re-enable change detection later by implementing proper git diff logic
# Currently forcing builds to ensure fresh deployments

echo "📊 Generating final outputs..."

# Set overall deployment readiness
echo "should_proceed=true" >> "$GITHUB_OUTPUT"
echo "stage0_complete=true" >> "$GITHUB_OUTPUT"

# Create summary for next stages
cat > /tmp/stage0-outputs/summary.txt << EOF
Stage 0 Preflight Check Summary
===============================
Service Name: $SERVICE_NAME
Action Type: $ACTION_TYPE
Overwrite Server: $OVERWRITE_SERVER
Secrets Validated: ✅
Action Validated: ✅
Docker Build Needed: ✅
SSL Configured: $(if [[ "${SSL_SECRETS:-0}" == "0" ]]; then echo "✅"; else echo "⚠️"; fi)

Ready to proceed to Stage 1: Infrastructure Setup
EOF

echo "✅ Stage 0 preflight checks completed successfully"
echo "📋 Summary:"
cat /tmp/stage0-outputs/summary.txt

# Display GitHub Action outputs for debugging
echo ""
echo "🔍 Generated GitHub Action outputs:"
cat "$GITHUB_OUTPUT"
