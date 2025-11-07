# Tailscale OAuth Migration Guide

## Overview
Your GitHub Actions workflow has been updated to use Tailscale OAuth instead of auth keys. This is the recommended approach by Tailscale for better security and token management.

## Changes Made

### 1. Updated GitHub Actions Workflow
- ✅ Modified `.github/workflows/deploy.yml` to use OAuth credentials
- ✅ Replaced `TAILSCALE_AUTH_KEY` secret with `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`
- ✅ Updated cleanup processes to use OAuth access tokens
- ✅ Created new stage2 script that uses OAuth to generate ephemeral auth keys

### 2. Required GitHub Secrets Updates

You need to **remove** these secrets from your GitHub repository:
- `TAILSCALE_AUTH_KEY` (no longer needed)

You need to **add** these new secrets to your GitHub repository:
- `TS_OAUTH_CLIENT_ID` - Your Tailscale OAuth client ID
- `TS_OAUTH_SECRET` - Your Tailscale OAuth client secret
- `TAILSCALE_TAILNET` - Your tailnet identifier (optional, defaults to "-")

## Steps to Complete Migration

### Step 1: Create Tailscale OAuth Client
1. Go to your [Tailscale Admin Console](https://login.tailscale.com/admin/)
2. Navigate to "OAuth clients" page
3. Click "Generate OAuth client"
4. Select these scopes:
   - `auth_keys` (for creating ephemeral auth keys)
   - `devices:core` (for listing and deleting devices)
5. Add at least one tag, e.g., `tag:ci`
6. Save the client ID and secret

### Step 2: Update GitHub Repository Secrets
1. Go to your GitHub repository settings
2. Navigate to "Secrets and variables" → "Actions"
3. Add the new secrets:
   - `TS_OAUTH_CLIENT_ID`: Paste your OAuth client ID
   - `TS_OAUTH_SECRET`: Paste your OAuth client secret
   - `TAILSCALE_TAILNET`: Your tailnet name (or use "-" for default)

### Step 3: Remove Old Secret
1. Delete the old `TAILSCALE_AUTH_KEY` secret from GitHub

### Step 4: Update Your Tailscale ACLs (CRITICAL)
**This step is required** - the OAuth client needs proper tag permissions to connect.

Make sure your Access Control Lists (ACLs) allow the `tag:ci` (or whatever tag you chose) to:
- Connect to your tailnet
- Access the resources your deployment needs

**Option 1: Add tag to your ACL policy (Recommended)**
1. Go to [Tailscale Admin Console](https://login.tailscale.com/admin/acls)
2. Add this to your ACL policy:

```json
{
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
}
```

**Option 2: Use an existing tag (Quick fix)**
If you have existing tags in your ACL, you can update your OAuth client to use one of those instead of `tag:ci`.

**Current Error:** If you're seeing `"requested tags [tag:ci] are invalid or not permitted"`, this means your ACL doesn't include the `tag:ci` configuration above.
```

## Benefits of OAuth Approach

- **Better Security**: OAuth tokens are short-lived (1 hour) vs auth keys (up to 90 days)
- **Scoped Access**: Only allows specific operations (device management, key creation)
- **Ephemeral Nodes**: Automatically cleaned up after deployment
- **Non-expiring Credentials**: OAuth client credentials don't expire like auth keys
- **Better Audit Logging**: OAuth usage is logged in Tailscale admin console

## Testing Your Migration

1. After updating the secrets, run a deployment
2. Check that the new OAuth approach creates ephemeral devices
3. Verify that old devices are properly cleaned up
4. Confirm Tailscale connectivity works as expected

## Troubleshooting

### Common Issues:

**1. Tag Permission Error: `"requested tags [tag:ci] are invalid or not permitted"`**
- **Cause**: Your Tailscale ACL doesn't allow the OAuth client to use `tag:ci`
- **Solution**: Add the tag configuration to your ACL policy (see Step 4 above)
- **Quick fix**: Use an existing tag from your ACL instead of `tag:ci`

**2. 403 Forbidden errors**: Check tailnet identifier in `TAILSCALE_TAILNET` secret

**3. Missing scopes**: Ensure OAuth client has both `auth_keys` and `devices:core` scopes

**4. Token expiry**: OAuth access tokens expire after 1 hour (automatically refreshed)

### If you encounter issues:
1. Check the GitHub Actions logs for specific error messages
2. Verify OAuth client configuration in Tailscale admin console
3. Confirm all required secrets are set in GitHub
4. Test OAuth client manually using curl commands from the logs

## Next Deployment
Your next deployment will use the new OAuth approach and should resolve the current auth key issues.
