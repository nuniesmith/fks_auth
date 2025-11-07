# Tailscale OAuth Connection Fixes

## Issues Identified and Fixed

### 1. OAuth Credential Replacement Failure
**Problem**: The OAuth credentials (`TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`) were not being properly replaced in the stage2 setup script, showing as `kRvWcvcyE821CNTRL` which appeared to be a placeholder.

**Root Cause**: 
- Complex shell variable expansion in sed commands
- Potential special characters in OAuth credentials causing sed parsing issues
- Inconsistent placeholder format

**Fix Applied**:
- Switched to `envsubst` for reliable environment variable substitution
- Updated stage2 script template to use `${VAR}` format instead of `VAR_PLACEHOLDER`
- Added robust validation of environment variables before replacement
- Improved error messaging to identify exact replacement failures

### 2. Server Destruction Logic Not Triggering
**Problem**: The `destroy-existing-server` job was being skipped even when server recreation was needed.

**Root Cause**: 
- The nginx deployment was setting `overwrite_server: false` by default
- The condition for server destruction required both `should_overwrite_server == 'true'` and proper action type

**Fix Applied**:
- Updated nginx deployment to set `overwrite_server: true` for consistent server recreation
- Enhanced preflight validation to properly handle restart and deploy actions
- Added better logging for overwrite server decisions

### 3. Missing Tailscale Subnet Sharing for Docker Networks
**Problem**: Docker networks on each service were isolated and not accessible through Tailscale.

**Root Cause**: 
- No subnet route advertising configured in Tailscale setup
- Missing IP forwarding configuration for subnet routing

**Fix Applied**:
- Added service-specific subnet route advertising:
  - nginx: `172.22.0.0/16`
  - fks: `172.20.0.0/16`
  - ats: `172.21.0.0/16`
  - default: `172.23.0.0/16`
- Enabled IP forwarding with sysctl configuration
- Added `--advertise-routes` and `--accept-routes` flags to Tailscale connection

## Technical Changes Made

### 1. OAuth Credential Handling (deploy.yml)
```yaml
# OLD: Sed-based replacement with potential parsing issues
sed -i "s|TS_OAUTH_CLIENT_ID_PLACEHOLDER|${TS_OAUTH_CLIENT_ID}|g" stage2-post-reboot.sh

# NEW: Environment variable substitution with envsubst
envsubst '${TS_OAUTH_CLIENT_ID} ${TS_OAUTH_SECRET} ${TAILSCALE_TAILNET}' < stage2-post-reboot.sh > stage2-post-reboot-temp.sh
```

### 2. Stage2 Script Template Updates
```bash
# OLD: Placeholder-based variables
TS_OAUTH_CLIENT_ID="TS_OAUTH_CLIENT_ID_PLACEHOLDER"

# NEW: Envsubst-compatible variables
TS_OAUTH_CLIENT_ID="${TS_OAUTH_CLIENT_ID}"
```

### 3. Server Overwrite Logic Enhancement
```yaml
# Enhanced validation for server recreation
if [[ "${{ env.OVERWRITE_SERVER }}" == "true" && ("${{ env.ACTION_TYPE }}" == "deploy" || "${{ env.ACTION_TYPE }}" == "restart") ]]; then
  echo "should_overwrite_server=true" >> $GITHUB_OUTPUT
  echo "⚠️ Server will be overwritten (destroyed and recreated)"
```

### 4. Tailscale Subnet Configuration
```bash
# Service-specific subnet advertising
case "$SERVICE_NAME" in
  "nginx")
    tailscale up --advertise-routes=172.22.0.0/16 --accept-routes
    ;;
  "fks")
    tailscale up --advertise-routes=172.20.0.0/16 --accept-routes
    ;;
  # ... other services
esac

# Enable IP forwarding for subnet routing
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p
```

### 5. nginx Deployment Configuration
```yaml
# Force server recreation for consistency
overwrite_server: true  # Force server recreation to ensure clean state
```

## Expected Outcomes

1. **OAuth Connection Success**: Tailscale should connect successfully using OAuth credentials
2. **Server Recreation**: Existing servers will be properly destroyed and recreated
3. **Docker Network Access**: Services on each server will be accessible through Tailscale subnet routes
4. **Reliable Deployment**: Consistent deployment behavior with proper error handling

## Verification Steps

1. **Check OAuth Replacement**: Look for "✅ OAuth credentials successfully replaced" in deployment logs
2. **Verify Server Destruction**: Confirm "💥 Destroy Existing Server" job runs when needed
3. **Validate Tailscale Connection**: Check for "✅ Tailscale connected successfully" in stage2 logs
4. **Test Subnet Routing**: Verify Docker containers are accessible via Tailscale IPs

## Debugging Information

If issues persist, check:
1. Environment variable lengths in deployment logs
2. OAuth token creation response details
3. Tailscale daemon status and logs via `journalctl -u tailscaled`
4. Subnet route advertising status with `tailscale status`

## Security Notes

- OAuth credentials are validated before use
- Temporary files for credential handling are cleaned up
- Environment variable substitution avoids shell injection risks
- Firewall rules properly configured for Tailscale interface
