#!/bin/bash
set -euo pipefail

# Change detection script for Docker builds
# Usage: ./detect-changes.sh <build_docker_on_changes>

BUILD_DOCKER_ON_CHANGES="${1:-true}"

echo "🔍 Checking for code and Docker changes..."

# TEMPORARY: Force Docker builds for all services since DockerHub images were cleared
echo "🔄 FORCING Docker builds - DockerHub images were cleared"
echo "code_changed=true" >> $GITHUB_OUTPUT
echo "docker_build_needed=true" >> $GITHUB_OUTPUT

# TODO: Re-enable change detection later by uncommenting the logic below
# and removing the forced build logic above

# Disabled logic for future use:
# Check if this is the first commit or if we should build anyway
# if [[ $(git rev-list --count HEAD) -le 1 ]] || [[ "$BUILD_DOCKER_ON_CHANGES" == "false" ]]; then
#   echo "First commit or change detection disabled - assuming changes exist"
#   echo "code_changed=true" >> $GITHUB_OUTPUT
#   echo "docker_build_needed=true" >> $GITHUB_OUTPUT
# else
#   # Check for changes in the last commit
#   CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD)
#   echo "Changed files: $CHANGED_FILES"
#   
#   # Check if code files changed (exclude docs, configs, etc.)
#   CODE_CHANGED="false"
#   if echo "$CHANGED_FILES" | grep -E '\.(js|ts|py|go|java|cpp|c|rs|php)$' > /dev/null; then
#     CODE_CHANGED="true"
#     echo "✅ Code files changed"
#   fi
#   
#   # Check if Docker-related files changed
#   DOCKER_BUILD_NEEDED="false"
#   if echo "$CHANGED_FILES" | grep -E '(Dockerfile|docker-compose|requirements|package\.json|go\.mod|Cargo\.toml)' > /dev/null; then
#     DOCKER_BUILD_NEEDED="true"
#     echo "✅ Docker-related files changed"
#   fi
#   
#   # If build_docker_on_changes is true, only build if changes detected
#   if [[ "$BUILD_DOCKER_ON_CHANGES" == "true" ]]; then
#     if [[ "$CODE_CHANGED" == "true" || "$DOCKER_BUILD_NEEDED" == "true" ]]; then
#       DOCKER_BUILD_NEEDED="true"
#     else
#       DOCKER_BUILD_NEEDED="false"
#       echo "ℹ️ No relevant changes detected - skipping Docker build"
#     fi
#   fi
#   
#   echo "code_changed=$CODE_CHANGED" >> $GITHUB_OUTPUT
#   echo "docker_build_needed=$DOCKER_BUILD_NEEDED" >> $GITHUB_OUTPUT
# fi

echo "✅ Change detection completed"
