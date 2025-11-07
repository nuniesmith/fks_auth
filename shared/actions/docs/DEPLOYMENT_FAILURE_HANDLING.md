# Deployment Failure Handling & Cleanup

## Overview

The enhanced FKS deployment workflow now includes comprehensive failure handling and automatic cleanup mechanisms to prevent resource leakage when deployments fail partway through.

## Problem Addressed

When the user reported a deployment failure during the Auth server configuration:

```
error: failed to commit transaction (conflicting files)
linux-firmware-nvidia: /usr/lib/firmware/nvidia/ad103 exists in filesystem
linux-firmware-nvidia: /usr/lib/firmware/nvidia/ad104 exists in filesystem
```

The deployment failed but left the server running, requiring manual cleanup.

## Solutions Implemented

### 1. NVIDIA Firmware Conflict Resolution

**Issue**: Arch Linux system updates can fail due to conflicting NVIDIA firmware files.

**Solution**: Added automatic conflict resolution to all server configurations:

```bash
# Handle potential NVIDIA firmware conflicts
if ! pacman -Syu --noconfirm 2>&1; then
  echo "⚠️ System update failed, trying to resolve conflicts..."
  # Remove conflicting NVIDIA firmware files
  rm -f /usr/lib/firmware/nvidia/ad103 /usr/lib/firmware/nvidia/ad104 /usr/lib/firmware/nvidia/ad106 /usr/lib/firmware/nvidia/ad107 2>/dev/null || true
  # Try update again
  pacman -Syu --noconfirm
fi
```

**Applied to**:
- Auth Server configuration
- API Server configuration
- Web Server configuration  
- Single Server configuration

### 2. Automatic Server Cleanup on Failure

**Issue**: When deployment fails after server creation, the server remains running and incurs costs.

**Solution**: Added cleanup steps that run on any failure using `if: failure()`:

#### Auth Server Cleanup
- Deletes the failed g6-nanode-1 server
- Removes auth.7gram.xyz DNS record if created
- Uses server ID for reliable cleanup

#### API Server Cleanup
- Deletes the failed g6-standard-1 server
- Removes api.7gram.xyz DNS record if created
- Uses server ID for reliable cleanup

#### Web Server Cleanup
- Deletes the failed g6-nanode-1 server
- Removes both fks.7gram.xyz and web.7gram.xyz DNS records if created
- Uses server ID for reliable cleanup

#### Single Server Cleanup
- Deletes the failed server (any type)
- Removes fks.7gram.xyz DNS record if created
- Uses server name lookup for cleanup

### 3. Comprehensive Error Handling

Each cleanup step includes:

✅ **Server Deletion**
- Configures Linode CLI with proper credentials
- Attempts graceful server deletion
- Provides fallback manual cleanup instructions

✅ **DNS Cleanup**  
- Only runs if DNS updates were enabled
- Checks for Cloudflare credentials
- Removes relevant DNS records automatically

✅ **Cost Protection**
- Prevents runaway server costs from failed deployments
- Ensures clean environment for retry attempts

## Deployment Modes and Cleanup Behavior

| Mode | Servers Created | Cleanup on Failure |
|------|----------------|-------------------|
| `single` | 1 server | Deletes single server + DNS |
| `multi-auth` | Auth only | Deletes auth server + DNS |
| `multi-api` | API only | Deletes API server + DNS |
| `multi-web` | Web only | Deletes web server + DNS |
| `multi-all` | Auth + API + Web | Deletes all failed servers + DNS |

## Failure Scenarios Handled

### 1. System Update Failures
- NVIDIA firmware conflicts
- Package manager corruption
- Network timeouts during updates

### 2. Configuration Failures
- SSH connection issues
- Service startup problems
- Docker configuration errors

### 3. Network Failures
- Tailscale connection problems
- DNS propagation issues
- Firewall blocking

## Manual Override

If automatic cleanup fails, the workflow provides:

- **Server ID** and **IP address** for manual deletion
- **Clear error messages** explaining the failure
- **Retry instructions** for common issues

## Cost Impact

With automatic cleanup:
- **Failed auth deployment**: $0 additional cost (server deleted)
- **Failed API deployment**: $0 additional cost (server deleted)  
- **Failed web deployment**: $0 additional cost (server deleted)
- **Failed multi-all deployment**: $0 additional cost (all servers deleted)

Without cleanup (old behavior):
- **Failed deployment**: Up to $22/month in orphaned servers

## Testing Recommendations

1. **Test failure scenarios** in development:
   ```bash
   # Trigger intentional failure to test cleanup
   ssh root@server "systemctl stop sshd"
   ```

2. **Verify DNS cleanup**:
   ```bash
   # Check DNS records after failed deployment
   dig auth.7gram.xyz +short
   ```

3. **Monitor server list**:
   ```bash
   # Ensure no orphaned servers remain
   linode-cli linodes list --text
   ```

## Future Improvements

- [ ] Add rollback for partial multi-server deployments
- [ ] Implement deployment state persistence
- [ ] Add notification alerts for cleanup events
- [ ] Create deployment health monitoring

## Files Modified

- `actions/.github/workflows/fks_enhanced-deploy.yml`
  - Added NVIDIA firmware conflict resolution
  - Added cleanup steps for all deployment modes
  - Enhanced error handling throughout

This comprehensive failure handling ensures robust, cost-effective deployments with automatic cleanup when things go wrong.
