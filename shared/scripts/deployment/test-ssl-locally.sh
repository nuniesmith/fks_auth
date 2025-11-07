#!/bin/bash

# Test SSL deployment locally
set -e

echo "🔧 Testing SSL deployment locally..."

# Set up test environment
export TARGET_HOST="fkstrading.xyz"
export ACTIONS_USER_PASSWORD="N2sU72GqsJL31G"
export DOMAIN_NAME="fkstrading.xyz"
export ADMIN_EMAIL="nunie.smith01@gmail.com"
export CLOUDFLARE_API_TOKEN="iVZ37A81zwlhhrt8gjh6UKPjB0SdTWFA9cIDhiQQ"
export CLOUDFLARE_ZONE_ID="adf4aa60d4aad7799fc37e756174dfd8"
export ENABLE_SSL="true"
export SSL_STAGING="false"
export APP_ENV="development"
export DOCKER_USERNAME="nuniesmith"
export DOCKER_TOKEN="your_docker_token"
export GITHUB_TOKEN="your_github_token"

echo "🚀 Running SSL deployment script..."
./scripts/deployment/deploy-with-ssl-docker-fix.sh

echo "✅ SSL deployment test completed!"
