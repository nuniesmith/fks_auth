#!/bin/bash
set -euo pipefail

# Action validation script
# Usage: ./validate-action.sh <action_type> <overwrite_server>

ACTION_TYPE="${1:-deploy}"
OVERWRITE_SERVER="${2:-false}"

echo "🎯 Validating action: $ACTION_TYPE"

case "$ACTION_TYPE" in
  "deploy")
    echo "should_deploy=true" >> $GITHUB_OUTPUT
    echo "should_destroy=false" >> $GITHUB_OUTPUT
    echo "should_health_check=false" >> $GITHUB_OUTPUT
    ;;
  "destroy")
    echo "should_deploy=false" >> $GITHUB_OUTPUT
    echo "should_destroy=true" >> $GITHUB_OUTPUT
    echo "should_health_check=false" >> $GITHUB_OUTPUT
    ;;
  "health-check")
    echo "should_deploy=false" >> $GITHUB_OUTPUT
    echo "should_destroy=false" >> $GITHUB_OUTPUT
    echo "should_health_check=true" >> $GITHUB_OUTPUT
    ;;
  "restart")
    echo "should_deploy=true" >> $GITHUB_OUTPUT
    echo "should_destroy=false" >> $GITHUB_OUTPUT
    echo "should_health_check=false" >> $GITHUB_OUTPUT
    ;;
  *)
    echo "❌ Invalid action type: $ACTION_TYPE"
    exit 1
    ;;
esac

# Check if server should be overwritten
echo "🔍 Checking overwrite server setting: $OVERWRITE_SERVER"
if [[ "$OVERWRITE_SERVER" == "true" && ("$ACTION_TYPE" == "deploy" || "$ACTION_TYPE" == "restart") ]]; then
  echo "should_overwrite_server=true" >> $GITHUB_OUTPUT
  echo "⚠️ Server will be overwritten (destroyed and recreated)"
else
  echo "should_overwrite_server=false" >> $GITHUB_OUTPUT
  echo "ℹ️ Server will be created if not exists, or reused if exists"
fi

echo "validated=true" >> $GITHUB_OUTPUT
echo "✅ Action validation completed"
