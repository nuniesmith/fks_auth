# 🔧 2-Stage Deployment Troubleshooting Guide

## Quick Status Checks

### Stage 1 Verification
```bash
# Check if Stage 1 completed
cat /tmp/stage1_status  # Should show "NEEDS_REBOOT"

# Verify systemd service was created
ls -la /etc/systemd/system/stage2-setup.service
systemctl is-enabled stage2-setup.service

# Check that Stage 2 script was uploaded
ls -la /usr/local/bin/stage2-post-reboot.sh
```

### Stage 2 Verification
```bash
# Check Stage 2 service status
systemctl status stage2-setup.service
journalctl -u stage2-setup.service --no-pager -l

# Verify Tailscale connection
tailscale status
tailscale ip -4

# Check Docker networks
docker network ls | grep -E "(fks|ats|nginx)-network"

# Verify Tailscale IP was stored
cat /tmp/tailscale_ip
```

## Common Issues & Solutions

### 🚨 Stage 1 Issues

#### Package Installation Fails
```bash
# Clear package cache
rm -f /var/lib/pacman/db.lck
pacman -Scc --noconfirm

# Update keyring first
pacman-key --refresh-keys
pacman -Sy archlinux-keyring

# Retry installation
pacman -Syu --noconfirm --overwrite="*"
```

#### User Creation Fails
```bash
# Check if users exist
id jordan actions_user nginx_user

# Manually create missing users
useradd -m -s /bin/bash jordan
usermod -aG wheel,docker jordan
echo "jordan:PASSWORD" | chpasswd
```

### 🚨 Stage 2 Issues

#### Stage 2 Service Doesn't Start
```bash
# Check service file
cat /etc/systemd/system/stage2-setup.service

# Reload systemd and retry
systemctl daemon-reload
systemctl enable stage2-setup.service
systemctl start stage2-setup.service

# Manual execution
/usr/local/bin/stage2-post-reboot.sh
```

#### Tailscale Connection Fails
```bash
# Check tailscaled status
systemctl status tailscaled
journalctl -u tailscaled --no-pager -l

# Restart tailscaled
systemctl restart tailscaled
sleep 10

# Try manual connection
tailscale up --authkey="YOUR_KEY" --hostname="SERVICE_NAME" --accept-routes

# Check auth key validity
echo "Auth key starts with: $(echo $TAILSCALE_AUTH_KEY | cut -c1-20)..."
```

#### Docker Network Creation Fails
```bash
# Check Docker status
systemctl status docker
docker info

# Remove conflicting networks
docker network rm $(docker network ls -q) 2>/dev/null || true

# Recreate networks manually
docker network create --driver bridge --subnet=172.20.0.0/16 fks_network
docker network create --driver bridge --subnet=172.21.0.0/16 ats-network
docker network create --driver bridge --subnet=172.22.0.0/16 nginx-network
```

#### Firewall Issues
```bash
# Reset UFW
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow in on tailscale0
ufw --force enable

# Check iptables
iptables -L DOCKER 2>/dev/null || echo "Docker chains missing"

# Restart networking
systemctl restart systemd-networkd
systemctl restart docker
```

### 🚨 DNS Update Issues

#### Cloudflare API Fails
```bash
# Test API credentials
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json"

# Check zone access
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"

# Manual DNS update
ZONE_ID="your_zone_id"
DOMAIN="service.7gram.xyz"
TAILSCALE_IP="100.x.x.x"

curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"A\",\"name\":\"$DOMAIN\",\"content\":\"$TAILSCALE_IP\",\"ttl\":120}"
```

## Advanced Diagnostics

### Complete System Validation
```bash
# Download and run validation script
curl -o /tmp/stage2-validation.sh https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/stage2-validation.sh
chmod +x /tmp/stage2-validation.sh
/tmp/stage2-validation.sh
```

### Networking Debug
```bash
# Check all network interfaces
ip addr show

# Verify Tailscale interface
ip route show table all | grep tailscale

# Test connectivity through Tailscale
ping -c 3 100.64.0.1  # Tailscale coordination server

# Check Docker bridge networks
brctl show 2>/dev/null || docker network ls
```

### Log Analysis
```bash
# Stage 2 service logs
journalctl -u stage2-setup.service --no-pager -l --since="1 hour ago"

# Tailscale logs
journalctl -u tailscaled --no-pager -l --since="30 minutes ago"

# Docker logs
journalctl -u docker --no-pager -l --since="30 minutes ago"

# System boot logs
journalctl -b --no-pager -l | grep -E "(stage2|tailscale|docker)"
```

## Recovery Procedures

### Restart Stage 2 Process
```bash
# Stop any running services
systemctl stop stage2-setup.service tailscaled docker

# Clean up previous state
rm -f /tmp/tailscale_ip /tmp/stage2_status

# Restart in order
systemctl start docker
systemctl start tailscaled
systemctl start stage2-setup.service

# Monitor progress
journalctl -u stage2-setup.service -f
```

### Full Reset (Nuclear Option)
```bash
# Stop all services
systemctl stop stage2-setup.service tailscaled docker

# Remove all Docker networks
docker network prune -f

# Reset Tailscale
tailscale logout || true
rm -rf /var/lib/tailscale/*

# Restart everything
systemctl restart docker tailscaled
/usr/local/bin/stage2-post-reboot.sh
```

### Manual Service Deployment
If Stage 2 completes but services don't deploy:
```bash
# Switch to service user
su - nginx_user  # or fks_user, ats_user

# Clone repository
git clone https://github.com/nuniesmith/nginx.git
cd nginx

# Deploy manually
./deploy prod
```

## GitHub Actions Debugging

### Check Workflow Secrets
- Verify all required secrets are set in repository settings
- Test secret values don't contain extra whitespace or newlines
- Confirm TAILSCALE_AUTH_KEY is valid and not expired

### Manual Workflow Trigger
```yaml
# Add to workflow for debugging
- name: Debug Environment
  run: |
    echo "Service: ${{ env.SERVICE_NAME }}"
    echo "Domain: ${{ env.FULL_DOMAIN }}"
    echo "Tailscale Key: ${TAILSCALE_AUTH_KEY:0:20}..."
    echo "CF Email set: ${{ secrets.CLOUDFLARE_EMAIL != '' }}"
    echo "CF Token set: ${{ secrets.CLOUDFLARE_API_TOKEN != '' }}"
```

### SSH Into Server for Debug
```bash
# Use workflow output to get server IP
ssh -i ~/.ssh/deployment_key root@SERVER_IP

# Or use Tailscale IP
ssh root@TAILSCALE_IP
```

## Prevention Strategies

1. **Always test auth keys** before deployment
2. **Verify DNS credentials** in Cloudflare dashboard  
3. **Monitor resource usage** on Linode servers
4. **Keep backup auth keys** for Tailscale
5. **Test deployment** on staging servers first
6. **Document any manual changes** made to servers

## Getting Help

If issues persist:
1. Run the validation script for detailed diagnostics
2. Collect logs from all relevant services
3. Check GitHub Actions workflow logs
4. Verify all secrets are properly configured
5. Test individual components (Tailscale, Docker, DNS) separately
