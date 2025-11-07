#!/bin/bash

echo "🚨 URGENT: Tailscale Tag Permission Fix Required"
echo "=============================================="
echo ""
echo "❌ Current Error: 'requested tags [tag:ci] are invalid or not permitted'"
echo ""
echo "🔧 SOLUTION - Choose ONE of these options:"
echo ""
echo "OPTION 1: Update your Tailscale ACL (Recommended)"
echo "1. Go to: https://login.tailscale.com/admin/acls"
echo "2. Add this to your ACL policy:"
echo ""
echo '{
  "tagOwners": {
    "tag:ci": ["autogroup:admin"]
  },
  "acls": [
    {
      "action": "accept", 
      "src": ["tag:ci"],
      "dst": ["*:*"]
    }
  ]
}'
echo ""
echo "OPTION 2: Use existing tag (Quick fix)"
echo "1. Check your current ACL for existing tags"
echo "2. Update your OAuth client to use an existing tag instead of 'tag:ci'"
echo ""
echo "⏰ Your GitHub Actions deployment is waiting for this fix!"
echo ""
echo "📖 For detailed instructions, see: TAILSCALE_OAUTH_MIGRATION.md"
