# 🚀 2-Stage Server Deployment Process

## Overview

The deployment uses a robust 2-stage process to ensure reliable server setup with proper networking, VPN connectivity, and DNS configuration.

## 🏗️ Stage 1: Pre-Reboot Foundation Setup

**Purpose**: Prepare the system and install essential packages before kernel refresh

### Key Actions:
1. **System Updates**
   - Update Arch Linux packages with conflict resolution
   - Install essential packages (Docker, Tailscale, tools)
   - Handle package conflicts gracefully

2. **User Management**
   - Create service users (actions_user, jordan, service-specific)
   - Configure SSH access and sudo permissions
   - Set secure passwords

3. **System Configuration**
   - Set hostname to service name
   - Configure timezone (EST/Toronto)
   - Enable services for post-reboot startup

4. **Docker Preparation**
   - Install Docker and Docker Compose
   - Create Docker daemon configuration
   - Enable Docker service for Stage 2

5. **Tailscale Preparation**
   - Install Tailscale package
   - Enable tailscaled service
   - Prepare TUN device and kernel modules

6. **Stage 2 Setup**
   - Create systemd service for post-reboot execution
   - Upload Stage 2 script with replaced placeholders
   - Schedule reboot for kernel refresh

### Files Modified:
- `/etc/hostname` - Set service hostname
- `/etc/sudoers` - Configure admin access
- `/etc/ssh/sshd_config` - Enable password auth
- `/etc/systemd/system/stage2-setup.service` - Post-reboot automation

## 🔄 Reboot Process

**Critical Step**: Server reboots to refresh kernel and networking stack

- Ensures clean networking state
- Activates new kernel modules
- Prepares for Tailscale connection

## 🌐 Stage 2: Post-Reboot Service Configuration

**Purpose**: Connect to VPN, configure networking, and update DNS

### Key Actions:

1. **Firewall Configuration**
   - Install iptables-nft and ufw (avoiding conflicts)
   - Configure Docker networking rules
   - Set up UFW basic rules

2. **Docker Network Setup**
   - Create service-specific networks with static IPs:
     - FKS: `172.20.0.0/16`
     - ATS: `172.21.0.0/16`
     - Nginx: `172.22.0.0/16`
   - Configure inter-service communication rules

3. **Tailscale Connection**
   - Start tailscaled daemon
   - Authenticate with provided auth key
   - Set hostname to service name
   - Accept routes from other nodes
   - **Advertise Docker subnets** for VPN access to containers

4. **DNS Updates (Optional)**
   - Get Tailscale IP address
   - Update Cloudflare DNS records
   - Point service domain to Tailscale IP
   - Enable secure access via VPN

### Enhanced Retry Logic:

```bash
CONNECTION_METHODS=(
  "full-with-reset"     # Complete config with reset
  "full-no-reset"       # Complete config without reset  
  "basic-with-reset"    # Basic + routes with reset
  "basic-no-reset"      # Basic + routes without reset
  "minimal"             # Minimal connection only
)
```

## 🔧 Key Improvements Made

### 1. **Corrupted Script Fix**
- Fixed corrupted content in stage2-post-reboot.sh
- Cleaned up malformed header

### 2. **Better Secret Handling**
- Graceful handling of optional Cloudflare credentials
- Validation that placeholders were properly replaced
- Clear messaging when DNS updates are skipped

### 3. **Enhanced Tailscale Reliability**
- Multiple connection strategies with fallbacks
- Better error logging and diagnostics
- Improved subnet advertisement handling

### 4. **Robust Error Handling**
- Comprehensive logging throughout both stages
- Graceful degradation for optional features
- Clear status reporting for troubleshooting

## 📊 Network Architecture

### Docker Networks:
```
FKS Services:    172.20.0.0/16 (containers: 172.20.1.0/24)
ATS Services:    172.21.0.0/16 (containers: 172.21.1.0/24)
Nginx Services:  172.22.0.0/16 (containers: 172.22.1.0/24)
```

### Tailscale Integration:
- Server gets Tailscale IP (100.x.x.x range)
- Docker subnets advertised via Tailscale
- All containers accessible through VPN
- DNS records point to Tailscale IP

## 🔍 Monitoring & Verification

### Stage 1 Completion:
- Check `/tmp/stage1_status` for completion marker
- Verify systemd service was created and enabled

### Stage 2 Completion:
- Monitor systemd service: `stage2-setup.service`
- Check Tailscale connection: `tailscale status`
- Verify Docker networks: `docker network ls`
- Confirm DNS updates in Cloudflare dashboard

### Troubleshooting:
```bash
# Check Stage 2 service logs
journalctl -u stage2-setup.service --no-pager -l

# Verify Tailscale status  
tailscale status
tailscale ip -4

# Check Docker networks
docker network ls
docker network inspect fks_network ats-network nginx-network

# Test DNS resolution
nslookup service.7gram.xyz
```

## 🚨 Common Issues & Solutions

### 1. **Tailscale Connection Fails**
- Check auth key validity
- Verify network connectivity
- Review tailscaled logs: `journalctl -u tailscaled`

### 2. **DNS Updates Fail**
- Verify Cloudflare credentials are set
- Check zone ID matches domain
- Confirm API token has DNS edit permissions

### 3. **Docker Networks Missing**
- Restart Docker service: `systemctl restart docker`
- Manually recreate networks using provided scripts
- Check iptables rules for conflicts

### 4. **Stage 2 Service Doesn't Run**
- Check service is enabled: `systemctl is-enabled stage2-setup.service`
- Manually trigger: `/usr/local/bin/stage2-post-reboot.sh`
- Review service logs for errors

## 🎯 Next Steps

1. **Deploy and Test**: Use the improved deployment process
2. **Monitor Results**: Check all services start correctly
3. **Verify Connectivity**: Test VPN access to all containers
4. **DNS Validation**: Confirm domains resolve to Tailscale IPs
5. **Security Review**: Ensure firewall rules are appropriate

The 2-stage process ensures reliable, repeatable deployments with proper VPN integration and secure container networking.
