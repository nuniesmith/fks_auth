# SSH Key Management for FKS Trading Systems

This directory contains tools to help manage SSH keys for the FKS Trading Systems deployment.

## 🔑 GitHub Secrets and SSH Keys

The deployment system requires the `ACTIONS_ROOT_PRIVATE_KEY` GitHub secret to be properly configured. When a new server is created, you may need to update this secret with the server's SSH key.

## 🛠️ Available Tools

### 1. SSH Key Management Workflow

**File:** `.github/workflows/ssh-key-management.yml`

A GitHub Actions workflow for managing SSH keys on your servers.

**Usage:**

1. Go to your repository's **Actions** tab
2. Select **SSH Key Management** workflow
3. Click **Run workflow**
4. Choose your action:
   - `display_public_key` - Show server's public key and fingerprint
   - `generate_new_key` - Create new SSH key pair on server
   - `display_authorized_keys` - Show authorized SSH keys
   - `test_connection` - Test SSH connectivity

### 2. Local SSH Key Manager Script

**File:** `scripts/utils/ssh-key-manager.sh`

A local script for SSH key management that you can run from your development machine.

**Usage:**

```bash
# Display public key and update instructions
./scripts/utils/ssh-key-manager.sh --display

# Generate new SSH key on server
./scripts/utils/ssh-key-manager.sh --generate

# Test SSH connection
./scripts/utils/ssh-key-manager.sh --test

# Use with different server
./scripts/utils/ssh-key-manager.sh --server 192.168.1.100 --display
```

**Options:**

- `-s, --server HOST` - Server hostname or IP (default: fks.tailfef10.ts.net)
- `-u, --user USER` - SSH username (default: jordan)
- `-g, --generate` - Generate new SSH key on server
- `-d, --display` - Display public key and instructions
- `-t, --test` - Test SSH connection
- `-h, --help` - Show help message

## 📋 Manual SSH Key Update Process

### Step 1: Get the Private Key

```bash
# SSH into your server
ssh jordan@fks.tailfef10.ts.net

# Display the private key
cat ~/.ssh/id_rsa
```

### Step 2: Update GitHub Secret

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Find `ACTIONS_ROOT_PRIVATE_KEY` and click **Update**
4. Paste the entire private key content (including `-----BEGIN` and `-----END` lines)
5. Click **Update secret**

### Step 3: Verify the Update

Run a test deployment or use the SSH Key Management workflow to test connectivity.

## 🔍 Troubleshooting

### "Invalid SSH key format" Error

This usually means:

1. The SSH key in GitHub secrets is corrupted or incomplete
2. The key doesn't match the server's SSH configuration
3. The key has incorrect line endings or formatting

**Solutions:**

1. Use the SSH Key Management workflow to display the correct public key
2. Regenerate the SSH key using the tools above
3. Ensure you copy the entire private key including BEGIN/END lines

### SSH Connection Failures

1. **Server not accessible**: Check if the server is running and network accessible
2. **Wrong hostname**: Verify the Tailscale DNS name or use public IP as fallback
3. **User doesn't exist**: Ensure the `jordan` user exists on the server
4. **SSH key mismatch**: Update the GitHub secret with the correct private key

### Key Permission Issues

On the server, ensure proper permissions:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
chmod 644 ~/.ssh/authorized_keys
```

## 🚀 Integration with Deployment

The main deployment workflow (`deploy-dev.yml`) now includes:

1. **Automatic key validation** - Checks SSH key format before attempting connections
2. **New server detection** - Shows SSH key information when a new server is created
3. **Deployment summary** - Reminds you to update SSH keys for new servers
4. **Fallback support** - Uses public IP if Tailscale DNS fails

## 🔐 Security Best Practices

1. **Regular key rotation**: Generate new SSH keys periodically
2. **Unique keys per server**: Don't reuse SSH keys across multiple servers
3. **Secure storage**: Never commit private keys to version control
4. **Access monitoring**: Monitor SSH access logs for unauthorized attempts
5. **Backup keys**: Keep secure backups of SSH keys before regenerating

## 📞 Support

If you encounter issues with SSH key management:

1. Check the deployment workflow logs for detailed error messages
2. Use the SSH Key Management workflow to diagnose connectivity
3. Run the local script for manual key inspection
4. Verify server status in Linode console if using cloud servers
