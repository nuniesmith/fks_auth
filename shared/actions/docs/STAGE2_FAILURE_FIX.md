# 🚨 Stage 2 Deployment Failure Fix

## Issue Detected
The Stage 2 script is failing because `TAILSCALE_AUTH_KEY_PLACEHOLDER` is not being replaced with the actual Tailscale auth key.

## Root Cause
The GitHub Actions workflow is not properly replacing placeholders in the stage2-post-reboot.sh script before uploading it to the server.

## Immediate Fixes Applied

### 1. **Enhanced Placeholder Replacement**
- Added debug logging to show secret availability
- Used environment variables with pipe delimiters to avoid sed escaping issues
- Added validation that replacements actually worked

### 2. **Backup Auth Key Mechanism**
- Stage 1 now creates `/root/tailscale_auth_key` as backup
- Stage 2 script checks for backup auth key if placeholder replacement fails
- Fallback to environment variables if available

### 3. **Better Error Handling**
- More descriptive error messages showing what went wrong
- Debug output to help identify the issue
- Early failure if required secrets are missing

## Quick Fixes You Can Try

### Option 1: Check GitHub Secrets
1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Verify these secrets are set:
   - `TAILSCALE_AUTH_KEY`
   - `ACTIONS_USER_PASSWORD`
   - `JORDAN_PASSWORD`
   - `SERVICE_ROOT_PASSWORD`
   - `LINODE_CLI_TOKEN`

### Option 2: Manual Stage 2 Trigger
If the deployment is still failing, you can manually trigger Stage 2:

```bash
# SSH into the server
ssh root@YOUR_SERVER_IP

# Check if auth key backup exists
cat /root/tailscale_auth_key

# If the auth key is there, manually run stage2
export TAILSCALE_AUTH_KEY="$(cat /root/tailscale_auth_key)"
export SERVICE_NAME_ENV="nginx"  # or whatever service you're deploying
/usr/local/bin/stage2-post-reboot.sh
```

### Option 3: Quick Tailscale Connection
If you just need to get Tailscale working quickly:

```bash
# SSH into the server
ssh root@YOUR_SERVER_IP

# Start tailscaled if not running
systemctl start tailscaled

# Connect with your auth key
tailscale up --authkey="tskey-auth-YOUR-KEY-HERE" --hostname="nginx" --accept-routes

# Check status
tailscale status
tailscale ip -4
```

## Verification Commands

### Check if Stage 2 completed:
```bash
# Check service status
systemctl status stage2-setup.service

# Check logs
journalctl -u stage2-setup.service --no-pager -l

# Check if Tailscale IP was saved
cat /tmp/tailscale_ip
```

### Check Tailscale status:
```bash
tailscale status
tailscale ip -4
docker network ls | grep -E "(fks|ats|nginx)-network"
```

## Updated Workflow Features

1. **Secret Validation**: Fails early if TAILSCALE_AUTH_KEY is empty
2. **Better Debugging**: Shows what secrets are available
3. **Safer Replacement**: Uses pipe delimiters to avoid sed issues
4. **Backup Mechanism**: Multiple fallback methods for auth key
5. **Enhanced Verification**: Checks both stage1 and stage2 replacements

## Next Steps

1. **Re-run the workflow** to test the improved placeholder replacement
2. **Check the debug output** in the GitHub Actions logs
3. **Verify secrets are properly set** in repository settings
4. **Use manual commands** as fallback if needed

The enhanced error handling should now clearly show what's going wrong and provide multiple ways to recover from the failure.
