# FKS Server Management Scripts

## Overview

This directory contains scripts for managing FKS Trading Systems servers, including creation, deployment, and comprehensive cleanup.

## Key Scripts

### 1. `cleanup-servers.sh` - Comprehensive Server Cleanup

**Purpose**: Safely remove FKS servers with automatic cleanup of associated services.

**Features**:
- ✅ Automatic Tailscale node removal
- ✅ Automatic Netdata node unclaiming  
- ✅ Linode server deletion
- ✅ Dry-run mode for safety
- ✅ Interactive and batch modes
- ✅ Specific server targeting

**Usage**:
```bash
# Interactive mode
./cleanup-servers.sh

# Cleanup all FKS servers (with confirmation)
./cleanup-servers.sh --all

# Cleanup specific server
./cleanup-servers.sh --server-id 12345678

# Dry run to see what would be cleaned
./cleanup-servers.sh --dry-run --all

# Force cleanup without prompts (dangerous!)
./cleanup-servers.sh --all --force
```

**Required Environment Variables**:
```bash
export LINODE_CLI_TOKEN="your_linode_token"
export FKS_DEV_ROOT_PASSWORD="your_server_root_password"
```

**Optional Environment Variables**:
```bash
export TAILSCALE_AUTH_KEY="your_tailscale_key"
export NETDATA_CLAIM_TOKEN="your_netdata_token"
```

### 2. GitHub Actions Workflow Options

#### Server Management Options

1. **Create New Server** (`create_new_server: true`)
   - Creates a new server alongside existing ones
   - Preserves existing servers
   - Safe option

2. **Overwrite Existing Server** (`overwrite_existing_server: true`)
   - ⚠️ **DESTRUCTIVE**: Permanently deletes current server
   - Automatically cleans up Tailscale and Netdata
   - Creates fresh server with same configuration
   - Use with caution!

#### Cleanup Process

When servers are deleted (either through overwrite or failure cleanup), the system automatically:

1. **Tailscale Cleanup**:
   - Attempts `tailscale logout` via SSH
   - Stops Tailscale daemon
   - Provides manual cleanup instructions for admin console

2. **Netdata Cleanup**:
   - Attempts to unclaim node via SSH
   - Stops Netdata service
   - Provides manual cleanup instructions for cloud console

3. **Linode Cleanup**:
   - Deletes server instance
   - Removes from Linode account
   - Cleans up local configuration files

## Safety Features

### Dry Run Mode
```bash
./cleanup-servers.sh --dry-run --all
```
Shows exactly what would be cleaned up without making any changes.

### Confirmation Prompts
Interactive mode requires explicit confirmation before destructive actions.

### Manual Cleanup Instructions
If SSH is unreachable, the script provides specific instructions for manual cleanup:

- **Tailscale**: https://login.tailscale.com/admin/machines
- **Netdata**: https://app.netdata.cloud/
- **Linode**: https://cloud.linode.com/linodes

## Troubleshooting

### Common Issues

1. **SSH Connection Fails**
   - Server may be unreachable
   - Manual cleanup required for external services
   - Linode server will still be deleted

2. **Permission Denied**
   - Check `FKS_DEV_ROOT_PASSWORD` is correct
   - Verify SSH is enabled on target server

3. **Linode CLI Not Found**
   - Script automatically installs Linode CLI
   - Ensure `LINODE_CLI_TOKEN` is valid

### Recovery

If cleanup fails partially:

1. Check Tailscale admin console for orphaned nodes
2. Check Netdata cloud console for unclaimed nodes  
3. Check Linode console for remaining servers
4. Use manual cleanup URLs provided in script output

## Best Practices

1. **Always use dry-run first** when cleaning multiple servers
2. **Backup important data** before using overwrite mode
3. **Verify external service cleanup** manually after automation
4. **Keep environment variables secure** and don't commit them
5. **Use specific server targeting** when possible to avoid accidents

## Security Considerations

- Script requires root SSH access to servers
- Environment variables contain sensitive tokens
- Use secure methods to provide credentials
- Consider using GitHub Secrets for automation
- Audit cleanup actions in production environments
