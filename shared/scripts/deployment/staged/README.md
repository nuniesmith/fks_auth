# FKS Trading Systems - Staged Deployment Scripts

This directory contains the staged deployment system for the FKS Trading Systems, extracted from the working Linode StackScript and GitHub Actions workflow.

## Overview

The deployment is broken down into 3 stages:

- **Stage 0**: Server Creation - Creates or finds existing Linode servers
- **Stage 1**: Initial Setup - Installs packages, creates users, configures SSH
- **Stage 2**: Finalize Setup - Configures Tailscale, finalizes firewall, completes setup

## Scripts

### `stage-0-create-server.sh`
Creates or finds existing Linode servers using the Linode CLI.

**Requirements:**
- `LINODE_CLI_TOKEN` environment variable
- `FKS_DEV_ROOT_PASSWORD` environment variable

**Usage:**
```bash
./stage-0-create-server.sh --help
./stage-0-create-server.sh --target-server auto-detect
./stage-0-create-server.sh --target-server custom --custom-host 192.168.1.100
./stage-0-create-server.sh --force-new
```

**Outputs:**
- `server-details.env` - Contains server information for subsequent stages

### `stage-1-initial-setup.sh`
Performs initial server setup including package installation, user creation, and SSH configuration.

**Requirements:**
- Target server with SSH access
- Jordan and FKS user passwords
- Tailscale auth key (unless skipped)

**Usage:**
```bash
./stage-1-initial-setup.sh --help
./stage-1-initial-setup.sh \
  --target-host 192.168.1.100 \
  --jordan-password "mypassword" \
  --fks_user-password "mypassword2" \
  --tailscale-auth-key "tskey-xxxxx"
```

**Note:** Server will automatically reboot after Stage 1 completes.

### `stage-2-finalize.sh`
Finalizes server setup after reboot, configures Tailscale, and completes configuration.

**Usage:**
```bash
./stage-2-finalize.sh --help
./stage-2-finalize.sh --target-host 192.168.1.100
./stage-2-finalize.sh --target-host 192.168.1.100 --skip-tailscale
```

### `deploy-full.sh`
Orchestrates all stages in sequence with automatic reboot handling.

**Usage:**
```bash
./deploy-full.sh --help

# Full deployment with new server
./deploy-full.sh \
  --jordan-password "mypass" \
  --fks_user-password "mypass2" \
  --tailscale-auth-key "tskey-xxxxx"

# Use existing server
./deploy-full.sh \
  --target-server custom \
  --custom-host 192.168.1.100 \
  --jordan-password "mypass" \
  --fks_user-password "mypass2" \
  --tailscale-auth-key "tskey-xxxxx"

# Skip server creation
./deploy-full.sh \
  --skip-stage-0 \
  --custom-host 192.168.1.100 \
  --jordan-password "mypass" \
  --fks_user-password "mypass2"
```

## Environment File Support

All scripts support loading configuration from an environment file:

```bash
# Create deployment.env
cat > deployment.env << EOF
LINODE_CLI_TOKEN=your_token
FKS_DEV_ROOT_PASSWORD=your_password
JORDAN_PASSWORD=jordan_password
FKS_USER_PASSWORD=fks_password
TAILSCALE_AUTH_KEY=tskey-xxxxx
DOCKER_USERNAME=your_username
DOCKER_TOKEN=your_token
NETDATA_CLAIM_TOKEN=your_token
NETDATA_CLAIM_ROOM=your_room
TIMEZONE=America/Toronto
ACTIONS_JORDAN_SSH_PUB="ssh-ed25519 AAAA..."
ACTIONS_USER_SSH_PUB="ssh-ed25519 AAAA..."
EOF

# Use with any script
./deploy-full.sh --env-file deployment.env
```

### Environment File Troubleshooting

If you encounter issues with environment file loading:

```bash
# Fix common environment file issues automatically
./fix-env-file.sh deployment.env

# Common issues and fixes:
# 1. Unquoted SSH keys - the script will quote them
# 2. Values with spaces - the script will quote them
# 3. Syntax errors - the script will validate and report

# Manual fix example:
# Wrong: ACTIONS_JORDAN_SSH_PUB=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
# Right: ACTIONS_JORDAN_SSH_PUB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."
```

## GitHub Actions Integration

The simplified GitHub Actions workflow (`01-simplified-deployment.yml`) uses these scripts:

1. Validates required secrets
2. Creates environment file from secrets
3. Runs `deploy-full.sh` with appropriate parameters
4. Tests deployment
5. Sends notifications

**Required GitHub Secrets:**
- `LINODE_CLI_TOKEN` - Linode API token
- `FKS_DEV_ROOT_PASSWORD` - Root password for new servers
- `JORDAN_PASSWORD` - Password for jordan user
- `FKS_USER_PASSWORD` - Password for fks_user
- `TAILSCALE_AUTH_KEY` - Tailscale authentication key

**Optional GitHub Secrets:**
- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_TOKEN` - Docker Hub token
- `NETDATA_CLAIM_TOKEN` - Netdata Cloud claim token
- `NETDATA_CLAIM_ROOM` - Netdata Cloud room ID
- `ACTIONS_JORDAN_SSH_PUB` - Jordan's SSH public key
- `ACTIONS_USER_SSH_PUB` - GitHub Actions SSH public key
- `DISCORD_WEBHOOK_SERVERS` - Discord webhook for notifications

## Key Features

### Security
- Automatic firewall configuration
- Tailscale VPN integration with shields up
- SSH key authentication
- Fail2ban intrusion detection
- Application ports restricted to Tailscale (except SSH)

### Monitoring
- Netdata monitoring with cloud integration
- System health checks
- Docker container monitoring

### Development Environment
- Multi-language support (Python, Node.js, .NET, Rust, Go)
- Docker and Docker Compose
- Useful aliases and scripts
- Welcome screen with system information

### GitHub Actions Integration
- Automated deployment on push
- Manual deployment with parameters
- Docker image building (optional)
- Deployment testing
- Discord notifications

## Manual Usage Examples

### Deploy to new Linode server:
```bash
export LINODE_CLI_TOKEN="your_token"
export FKS_DEV_ROOT_PASSWORD="your_password"

./deploy-full.sh \
  --jordan-password "mypass" \
  --fks_user-password "mypass2" \
  --tailscale-auth-key "tskey-xxxxx"
```

### Deploy to existing server:
```bash
./deploy-full.sh \
  --skip-stage-0 \
  --custom-host 192.168.1.100 \
  --jordan-password "mypass" \
  --fks_user-password "mypass2" \
  --tailscale-auth-key "tskey-xxxxx"
```

### Run individual stages:
```bash
# Stage 0 only
./stage-0-create-server.sh --target-server auto-detect

# Stage 1 only (after Stage 0)
./stage-1-initial-setup.sh \
  --target-host $(grep TARGET_HOST server-details.env | cut -d= -f2) \
  --jordan-password "mypass" \
  --fks_user-password "mypass2" \
  --tailscale-auth-key "tskey-xxxxx"

# Wait for reboot, then Stage 2
./stage-2-finalize.sh --target-host $(grep TARGET_HOST server-details.env | cut -d= -f2)
```

## Post-Deployment Steps

After successful deployment:

1. SSH to the server:
   ```bash
   ssh jordan@<server-ip>
   # or via Tailscale:
   ssh jordan@<tailscale-ip>
   ```

2. Clone your repository:
   ```bash
   git clone <your-repo-url> ~/fks
   ```

3. Start services:
   ```bash
   cd ~/fks
   ./start.sh
   ```

## Troubleshooting

### Common Issues

1. **Environment file loading fails**
   ```
   AAAAC3NzaC1lZDI1NTE5AAAAI...: No such file or directory
   ```
   This means SSH keys in your `deployment.env` are not properly quoted.
   
   **Quick fix:**
   ```bash
   ./fix-env-file.sh deployment.env
   ```
   
   **Manual fix:** Ensure SSH keys are quoted:
   ```bash
   # Wrong:
   ACTIONS_JORDAN_SSH_PUB=ssh-ed25519 AAAAC3... user@host
   
   # Correct:
   ACTIONS_JORDAN_SSH_PUB="ssh-ed25519 AAAAC3... user@host"
   ```

2. **SSH connection fails after Stage 1**
   - Wait longer for reboot to complete
   - Check server console in Linode dashboard
   - Try SSH with root user if emergency access needed

3. **Tailscale connection fails**
   - Verify auth key is valid and not expired
   - Check Tailscale admin console
   - Use `--skip-tailscale` to bypass if needed

4. **Package installation fails**
   - Server may need more time for package databases
   - Check `/var/log/fks_setup.log` on server
   - Retry individual stages

### Logs

Check deployment logs on the server:
```bash
sudo tail -f /var/log/fks_setup.log
```

### Emergency Access

If normal SSH fails, use Linode's console access:
1. Log into Linode dashboard
2. Open server console (Lish)
3. Log in as root with your password
4. Check system status and logs

## Differences from Original StackScript

This staged approach offers several advantages over the monolithic StackScript:

1. **Modularity** - Each stage can be run independently
2. **Debugging** - Easier to identify and fix issues
3. **Flexibility** - Skip stages or run with different parameters
4. **CI/CD Integration** - Better integration with GitHub Actions
5. **Reusability** - Scripts can be used outside of Linode
6. **Testing** - Individual stages can be tested separately

The core functionality remains identical to the original working StackScript, just organized into logical stages.
