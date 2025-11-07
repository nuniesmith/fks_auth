# 🚨 Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the standardized deployment system.

## 🔍 Quick Diagnosis

### System Health Check
Run this command to get an overview of your deployment:

```bash
# Using GitHub CLI
gh workflow run deploy-service.yml \
  -f service_name=your-service \
  -f deployment_mode=health-check

# Or use the server manager script
./scripts/linode/server-manager.sh info --service your-service
```

### Common Issue Categories

1. **🏗️ Infrastructure Issues** - Server creation, networking
2. **🔐 Authentication Issues** - SSH, API tokens, permissions
3. **🚢 Deployment Issues** - Service startup, configuration
4. **🌐 Networking Issues** - VPN, DNS, firewall
5. **📊 Monitoring Issues** - Netdata, health checks

## 🏗️ Infrastructure Issues

### Server Creation Failures

#### Issue: Linode server creation fails
```bash
# Check Linode API status
curl -H "Authorization: Bearer $LINODE_CLI_TOKEN" \
  https://api.linode.com/v4/account

# Verify token permissions
linode-cli profile view

# Check quota limits
linode-cli account view
```

**Solutions:**
- Verify `LINODE_CLI_TOKEN` is valid and has compute instance permissions
- Check account billing status and payment methods
- Ensure selected region has capacity for requested server type
- Try alternative regions: `us-east`, `us-central`, `ca-central`

#### Issue: Server is created but unreachable
```bash
# Check server status
linode-cli linodes list | grep your-service

# Get server details
linode-cli linodes view SERVER_ID

# Test connectivity
ping SERVER_IP
```

**Solutions:**
- Wait 2-3 minutes for server to fully boot
- Check Linode console for boot messages
- Verify firewall settings allow SSH (port 22)
- Try connecting via Linode LISH console

### Resource Limitations

#### Issue: Server type not available
**Solutions:**
- Choose alternative server types: `g6-standard-1`, `g6-standard-2`, `g6-standard-4`
- Try different regions with better availability
- Use smaller instance size temporarily

#### Issue: Out of memory errors
```bash
# Check memory usage
free -h
top

# Check swap space
swapon -s
```

**Solutions:**
- Upgrade to larger server type
- Add swap space: `sudo fallocate -l 2G /swapfile`
- Optimize Docker container memory limits
- Reduce number of running services

## 🔐 Authentication Issues

### SSH Connection Problems

#### Issue: SSH connection refused
```bash
# Test SSH connectivity
ssh -v root@SERVER_IP

# Check SSH service status
systemctl status sshd

# Verify firewall rules
ufw status
```

**Solutions:**
- Ensure SSH service is running: `systemctl start sshd`
- Check firewall: `ufw allow ssh`
- Verify correct IP address and username
- Try password authentication if key fails

#### Issue: SSH key authentication fails
```bash
# Check SSH key permissions
ls -la ~/.ssh/
cat ~/.ssh/id_ed25519.pub

# Test key on server
ssh-copy-id user@server-ip
```

**Solutions:**
- Verify SSH key is properly formatted
- Check file permissions: `chmod 600 ~/.ssh/id_ed25519`
- Ensure public key is in `~/.ssh/authorized_keys` on server
- Generate new SSH key if corrupted

### GitHub Actions Authentication

#### Issue: GitHub Actions cannot access secrets
**Solutions:**
- Verify secrets are set in repository settings
- Check secret names match exactly (case-sensitive)
- Ensure workflow has proper permissions
- Try refreshing secrets (delete and recreate)

#### Issue: API token permissions
```bash
# Test Linode token
curl -H "Authorization: Bearer $LINODE_CLI_TOKEN" \
  https://api.linode.com/v4/profile

# Test Tailscale OAuth
curl -H "Authorization: Bearer $TAILSCALE_OAUTH_SECRET" \
  https://api.tailscale.com/api/v2/device
```

**Solutions:**
- Regenerate API tokens with full permissions
- Check token expiration dates
- Verify OAuth scopes include required permissions

## 🚢 Deployment Issues

### Docker Problems

#### Issue: Docker containers fail to start
```bash
# Check Docker status
systemctl status docker

# View container logs
docker-compose logs

# Check container status
docker ps -a
```

**Solutions:**
- Restart Docker service: `systemctl restart docker`
- Check Docker Compose file syntax
- Verify environment variables are set
- Check port conflicts: `netstat -tlnp`

#### Issue: Docker Hub authentication fails
```bash
# Test Docker login
echo "$DOCKER_TOKEN" | docker login --username "$DOCKER_USERNAME" --password-stdin

# Check Docker credentials
cat ~/.docker/config.json
```

**Solutions:**
- Verify Docker Hub credentials in GitHub secrets
- Use Docker Hub access tokens instead of passwords
- Check Docker Hub account status and limits

### Service Configuration

#### Issue: Environment variables not set
```bash
# Check environment file
cat .env

# Verify variable substitution
docker-compose config
```

**Solutions:**
- Ensure `.env` file exists and is readable
- Check environment variable names match secrets
- Verify file permissions: `chmod 644 .env`

#### Issue: Port conflicts
```bash
# Check port usage
netstat -tlnp | grep PORT_NUMBER
ss -tlnp | grep PORT_NUMBER

# Check Docker port mapping
docker port CONTAINER_NAME
```

**Solutions:**
- Change service port configuration
- Stop conflicting services
- Use different ports for development/staging

## 🌐 Networking Issues

### Tailscale VPN Problems

#### Issue: Tailscale connection fails
```bash
# Check Tailscale status
tailscale status

# View Tailscale logs
journalctl -u tailscaled -f

# Test authentication
tailscale up --authkey="$TAILSCALE_AUTH_KEY"
```

**Solutions:**
- Verify `TAILSCALE_AUTH_KEY` is valid and not expired
- Check Tailscale admin console for device status
- Restart Tailscale: `systemctl restart tailscaled`
- Generate new auth key if expired

#### Issue: Cannot access services via Tailscale
```bash
# Check Tailscale IP
tailscale ip -4

# Test connectivity
ping TAILSCALE_IP

# Check firewall rules
ufw status | grep tailscale0
```

**Solutions:**
- Ensure firewall allows Tailscale: `ufw allow in on tailscale0`
- Check service binding to correct interface
- Verify DNS resolution: `nslookup service.7gram.xyz`

### DNS Issues

#### Issue: Domain not resolving
```bash
# Check DNS resolution
nslookup your-service.7gram.xyz
dig your-service.7gram.xyz

# Check Cloudflare DNS records
curl -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"
```

**Solutions:**
- Verify Cloudflare API credentials
- Check DNS record points to correct IP
- Wait for DNS propagation (up to 24 hours)
- Use Tailscale IP directly as workaround

### Firewall Configuration

#### Issue: Services not accessible externally
```bash
# Check firewall status
ufw status verbose

# Check specific port
ufw status | grep PORT_NUMBER

# Test port accessibility
telnet SERVER_IP PORT_NUMBER
```

**Solutions:**
- Open required ports: `ufw allow PORT_NUMBER`
- Check service binding: `netstat -tlnp | grep PORT_NUMBER`
- Verify no intermediate firewalls blocking traffic

## 📊 Monitoring Issues

### Netdata Problems

#### Issue: Netdata not starting
```bash
# Check Netdata status
systemctl status netdata

# View Netdata logs
journalctl -u netdata -f

# Check configuration
netdata -W buildinfo
```

**Solutions:**
- Restart Netdata: `systemctl restart netdata`
- Check configuration file: `/etc/netdata/netdata.conf`
- Verify permissions: `chown -R netdata:netdata /var/lib/netdata`

#### Issue: Netdata not claiming to cloud
```bash
# Check claim status
cat /var/lib/netdata/cloud.d/claimed_id

# Manual claim attempt
netdata-claim.sh -token="$CLAIM_TOKEN" -rooms="$ROOM_ID"
```

**Solutions:**
- Verify claim token is valid and not expired
- Check internet connectivity from server
- Try claiming with different room ID
- Restart Netdata after claiming

### Health Check Failures

#### Issue: Health checks timing out
```bash
# Test health endpoint manually
curl -f http://localhost:PORT/health

# Check service logs
docker-compose logs service-name

# Verify service is running
docker ps | grep service-name
```

**Solutions:**
- Increase health check timeout
- Fix application health endpoint
- Check service startup time
- Verify correct health check URL

## 🔧 Advanced Debugging

### Log Analysis

#### System Logs
```bash
# System journal
journalctl -f

# Service-specific logs
journalctl -u SERVICE_NAME -f

# Filter by time
journalctl --since "1 hour ago"
```

#### Application Logs
```bash
# Docker container logs
docker logs CONTAINER_NAME -f

# Docker Compose logs
docker-compose logs -f SERVICE_NAME

# Application-specific logs
tail -f /var/log/application.log
```

### Performance Debugging

#### Resource Usage
```bash
# CPU usage
top
htop

# Memory usage
free -h
cat /proc/meminfo

# Disk usage
df -h
du -sh /var/lib/docker
```

#### Network Debugging
```bash
# Network interfaces
ip addr show

# Routing table
ip route show

# Network connections
ss -tlnp
netstat -tlnp
```

### Database Issues

#### Connection Problems
```bash
# Test database connectivity
telnet DATABASE_HOST DATABASE_PORT

# Check database logs
docker logs DATABASE_CONTAINER

# Verify credentials
echo "SELECT 1;" | mysql -h HOST -u USER -p
```

## 📞 Getting Help

### Self-Service Resources

1. **Check GitHub Actions Logs**
   - Go to repository → Actions tab
   - Click on failed workflow run
   - Expand failed steps to see detailed logs

2. **Server Access**
   ```bash
   # SSH to server for debugging
   ssh root@server-ip
   
   # Or via Tailscale
   ssh jordan@service.7gram.xyz
   ```

3. **Use Diagnostic Scripts**
   ```bash
   # Server health check
   ./scripts/linode/server-manager.sh info --service your-service
   
   # User access test
   ./scripts/users/user-manager.sh test-access --user jordan
   ```

### Emergency Procedures

#### Service Recovery
```bash
# Stop all services
docker-compose down

# Clean up containers
docker system prune -af

# Restart deployment
./scripts/services/your-service/deploy.sh
```

#### Server Recovery
```bash
# Reboot server
sudo reboot

# Check boot messages
dmesg | tail -50

# Verify all services started
systemctl status docker tailscaled netdata
```

### Creating Support Requests

When creating a GitHub issue, include:

1. **Environment Information**
   - Service name and version
   - Server type and region
   - Deployment mode used

2. **Error Details**
   - Complete error messages
   - Relevant log excerpts
   - Steps to reproduce

3. **Diagnostic Output**
   ```bash
   # Include output from these commands
   docker ps -a
   docker-compose logs
   systemctl status --failed
   journalctl -p err --since "1 hour ago"
   ```

4. **Configuration Files**
   - Service configuration (with secrets redacted)
   - Docker Compose files
   - Environment templates

### Community Support

- **GitHub Discussions** - For questions and general help
- **GitHub Issues** - For bugs and feature requests
- **Documentation** - Check all guides in `/docs` directory

## 🔄 Prevention

### Best Practices

1. **Regular Monitoring**
   - Set up Netdata Cloud alerts
   - Monitor GitHub Actions for failures
   - Check server resources weekly

2. **Backup Strategy**
   - Enable Linode backups
   - Export important configurations
   - Test restoration procedures

3. **Update Schedule**
   - Keep secrets current and rotated
   - Update base images regularly
   - Monitor security advisories

4. **Testing**
   - Test deployments in staging first
   - Validate health checks before production
   - Practice failure recovery procedures
