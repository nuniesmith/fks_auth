#!/usr/bin/env bash
set -euo pipefail

# Inputs via env
WEBHOOK_URL=${DISCORD_WEBHOOK_URL:-}
SERVICE_NAME=${SERVICE_NAME:-service}
ACTION_TYPE=${ACTION_TYPE:-deploy}
SERVER_IP=${SERVER_IP:-}
TAILSCALE_IP=${TAILSCALE_IP:-}
SERVER_ID=${SERVER_ID:-}
INFRA_RESULT=${INFRA_RESULT:-}
RESTART_RESULT=${RESTART_RESULT:-}
DESTROY_RESULT=${DESTROY_RESULT:-}
HEALTH_RESULT=${HEALTH_RESULT:-}
POST_HEALTH_RESULT=${POST_HEALTH_RESULT:-}

if [[ -z "$WEBHOOK_URL" ]]; then
  echo "⚠️ Discord webhook URL is empty - skipping notification" >&2
  exit 0
fi

if [[ ! "$WEBHOOK_URL" =~ ^https://discord(app)?\.com/api/webhooks/ ]]; then
  echo "⚠️ Invalid Discord webhook URL format - skipping notification" >&2
  exit 0
fi

# Compute overall deployment status
DEPLOYMENT_STATUS=FAILED
if [[ "$INFRA_RESULT" == "success" || "$RESTART_RESULT" == "success" || "$DESTROY_RESULT" == "success" ]]; then
  DEPLOYMENT_STATUS=SUCCESS
fi

if [[ "$DEPLOYMENT_STATUS" == "SUCCESS" ]]; then
  COLOR=3066993
  EMOJI="✅"
else
  COLOR=15158332
  EMOJI="❌"
fi

# Build JSON payload safely
payload=$(jq -n \
  --arg title        "$EMOJI $SERVICE_NAME Deployment $DEPLOYMENT_STATUS" \
  --arg desc         "**Action:** $ACTION_TYPE\\n**Service:** $SERVICE_NAME\\n**Status:** $DEPLOYMENT_STATUS" \
  --arg serverDetails "**IP:** ${SERVER_IP:-N/A}\\n**Tailscale IP:** ${TAILSCALE_IP:-N/A}\\n**Server ID:** ${SERVER_ID:-N/A}" \
  --arg jobResults   "**Infrastructure:** ${INFRA_RESULT:-N/A}\\n**Restart:** ${RESTART_RESULT:-N/A}\\n**Destroy:** ${DESTROY_RESULT:-N/A}\\n**Health:** ${HEALTH_RESULT:-N/A}\\n**Post-Health:** ${POST_HEALTH_RESULT:-N/A}" \
  --argjson color    "$COLOR" \
  --arg timestamp    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    embeds: [
      {
        title: $title,
        description: $desc,
        color: $color,
        fields: [
          { name: "Server Details", value: $serverDetails, inline: true },
          { name: "Job Results", value: $jobResults, inline: true }
        ],
        timestamp: $timestamp
      }
    ]
  }')

# Send the notification
if curl -fsSL -H 'Content-Type: application/json' -d "$payload" "$WEBHOOK_URL" >/dev/null; then
  echo "✅ Discord notification sent"
else
  echo "❌ Failed to send Discord notification" >&2
  exit 0
fi
