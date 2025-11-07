# 🚀 Deployment Guide

This guide walks you through deploying services using the standardized GitHub Actions workflows.

## 📋 Prerequisites

### 1. Repository Setup
- Fork or use this actions repository
- Configure GitHub secrets (see [Secret Setup](#secret-setup))
- Ensure your service repository is accessible

### 2. Required Accounts
- **Linode Account** - For cloud servers
- **Tailscale Account** - For VPN networking
- **GitHub Account** - For CI/CD automation
- **Cloudflare Account** (Optional) - For DNS management
- **Netdata Cloud Account** (Optional) - For monitoring

### 3. Local Tools
- GitHub CLI (`gh`) - For workflow management
- SSH client - For server access
- Tailscale client - For VPN access

## 🔐 Secret Setup

### Quick Setup (Recommended)
Run the interactive setup script:

```bash
./scripts/setup-github-secrets.sh
```

### Manual Setup
Configure these secrets in your GitHub repository settings:

#### Core Infrastructure
| Secret | Description | Required |
|--------|-------------|----------|
| `LINODE_CLI_TOKEN` | Linode API access token | ✅ |
| `SERVICE_ROOT_PASSWORD` | Root password for servers | ✅ |

#### User Management
| Secret | Description | Required |
|--------|-------------|----------|
| `JORDAN_PASSWORD` | Admin user password | ✅ |
| `ACTIONS_USER_PASSWORD` | CI/CD user password | ✅ |

#### VPN & Networking
| Secret | Description | Required |
|--------|-------------|----------|
| `TAILSCALE_AUTH_KEY` | Tailscale authentication key | ✅ |
| `TAILSCALE_OAUTH_CLIENT_ID` | Tailscale OAuth client ID | ⚠️ |
| `TAILSCALE_OAUTH_SECRET` | Tailscale OAuth secret | ⚠️ |

#### Optional Services
| Secret | Description | Required |
|--------|-------------|----------|
| `NETDATA_CLAIM_TOKEN` | Netdata Cloud integration | ❌ |
| `NETDATA_CLAIM_ROOM` | Netdata room ID | ❌ |
| `CLOUDFLARE_API_TOKEN` | DNS management | ❌ |
| `CLOUDFLARE_ZONE_ID` | DNS zone ID | ❌ |
| `DOCKER_USERNAME` | Container registry | ❌ |
| `DOCKER_TOKEN` | Container registry token | ❌ |
| `DISCORD_WEBHOOK` | Notifications | ❌ |

## 🎯 Deployment Types

### 1. Full Deployment (Recommended)
Creates a new server and deploys your service:

```bash
gh workflow run deploy-service.yml \
  -f service_name=fks \
  -f deployment_mode=full-deploy \
  -f create_new_server=true \
  -f server_type=g6-standard-2 \
  -f target_region=ca-central
```

### 2. Update Deployment
Updates an existing service without recreating the server:

```bash
gh workflow run deploy-service.yml \
  -f service_name=fks \
  -f deployment_mode=update-only \
  -f create_new_server=false
```

### 3. Health Check
Performs health checks without deployment:

```bash
gh workflow run deploy-service.yml \
  -f service_name=fks \
  -f deployment_mode=health-check
```

## 📁 Service Configuration

### Supported Services

#### 1. FKS Trading Systems
- **Type**: Container-based application
- **Requirements**: 4GB+ RAM, Docker support
- **Features**: Multi-container trading platform
- **Access**: `https://fks.7gram.xyz` (via Tailscale)

#### 2. NGINX Reverse Proxy
- **Type**: Web server/load balancer
- **Requirements**: 2GB RAM, SSL certificates
- **Features**: SSL termination, request routing
- **Access**: Public + Tailscale

#### 3. ATS Game Server
- **Type**: Gaming server
- **Requirements**: 4GB+ RAM, Steam integration
- **Features**: Dedicated game server with web interface
- **Access**: `https://ats.7gram.xyz` (via Tailscale)

### Custom Service Configuration

Create a configuration file for your service:

```yaml
# services/my-service/config.yml
service:
  name: my-service
  type: container
  domain: my-service.7gram.xyz
  user: my_service_user
  ports:
    - "3000:3000"

infrastructure:
  server_type: g6-standard-2
  region: ca-central
  backup_enabled: true

deployment:
  compose_file: docker-compose.yml
  health_check: /health
```

## 🌐 Networking Architecture

### Tailscale VPN Setup
All services are accessible through Tailscale VPN for security:

1. **Server Network**: `100.x.x.x/32` (Tailscale IPs)
2. **User Access**: Via Tailscale client
3. **DNS Resolution**: `service.7gram.xyz` → Tailscale IP

### Firewall Configuration
- **SSH**: Port 22 (public access)
- **HTTP/HTTPS**: Ports 80/443 (NGINX only)
- **Services**: Custom ports (Tailscale only)
- **Monitoring**: Port 19999 (Tailscale only)

## 👥 User Management

### Standard User Accounts
Each server includes these standardized accounts:

1. **`root`** - System administrator
   - Purpose: Emergency access and system management
   - Access: SSH with password

2. **`jordan`** - Personal admin account
   - Purpose: Personal server administration
   - Privileges: sudo, docker group
   - Access: SSH with key + password

3. **`actions_user`** - CI/CD automation
   - Purpose: GitHub Actions deployment
   - Privileges: sudo, docker group
   - Access: SSH with generated key

4. **`{service}_user`** - Service account
   - Purpose: Run service applications
   - Privileges: docker group only (no sudo)
   - Access: Local only

### SSH Key Management
- **Automatic Generation**: SSH keys generated during deployment
- **Key Distribution**: Public keys shared via GitHub Actions
- **Security**: Ed25519 keys with unique identifiers

## 🔍 Monitoring & Health Checks

### Netdata Integration
- **System Monitoring**: CPU, memory, disk, network
- **Container Monitoring**: Docker container metrics
- **Service Monitoring**: Application-specific health checks
- **Cloud Integration**: Optional Netdata Cloud sync

### Access Monitoring
- **Local Dashboard**: `http://service.7gram.xyz:19999`
- **Cloud Dashboard**: `https://app.netdata.cloud`
- **Alerts**: Discord notifications (if configured)

## 🚨 Troubleshooting

### Common Issues

#### 1. Deployment Failures
```bash
# Check workflow logs
gh run view --log

# SSH to server for debugging
gh workflow run deploy-service.yml -f deployment_mode=health-check
```

#### 2. SSH Access Issues
```bash
# Test SSH connectivity
ssh root@server-ip

# Check Tailscale status
tailscale status

# Verify user accounts
ssh jordan@tailscale-ip
```

#### 3. Service Not Responding
```bash
# Check Docker containers
docker ps

# View service logs
docker-compose logs

# Restart services
docker-compose restart
```

#### 4. Monitoring Issues
```bash
# Check Netdata status
systemctl status netdata

# Test API access
curl http://localhost:19999/api/v1/info

# View Netdata logs
journalctl -u netdata -f
```

### Debug Commands

#### Server Status
```bash
# System health
top
df -h
free -h

# Network connectivity
ping google.com
tailscale status

# Service status
systemctl status docker
docker ps
```

#### Log Analysis
```bash
# System logs
journalctl -f

# Service logs
docker-compose logs -f

# Deployment logs
tail -f /var/log/deployment.log
```

## 🔄 Updating Services

### Automatic Updates
Services update automatically when you push to the main branch:

1. **Code Changes** → **GitHub Push**
2. **GitHub Actions** → **Deployment Trigger**
3. **Server Update** → **Service Restart**

### Manual Updates
Force an update without code changes:

```bash
gh workflow run deploy-service.yml \
  -f service_name=your-service \
  -f deployment_mode=update-only
```

### Rollback Procedures
If an update fails:

1. **Check Logs**: Review GitHub Actions logs
2. **SSH Access**: Connect to server for debugging
3. **Manual Rollback**: Revert to previous version
4. **Redeploy**: Trigger new deployment with fixes

## 📈 Scaling & Performance

### Vertical Scaling
Upgrade server resources:

1. **Resize Server**: Use Linode console
2. **Update Config**: Modify `server_type` in config
3. **Redeploy**: Run deployment to apply changes

### Horizontal Scaling
Deploy multiple instances:

1. **Multiple Regions**: Deploy in different regions
2. **Load Balancing**: Use NGINX for distribution
3. **Database Replication**: Configure data sync

### Performance Optimization
- **Monitor Resources**: Use Netdata dashboards
- **Optimize Containers**: Review Docker configurations
- **Database Tuning**: Optimize query performance
- **Cache Implementation**: Add Redis/Memcached

## 🔒 Security Best Practices

### Access Control
- **VPN Required**: All services behind Tailscale
- **SSH Keys**: No password authentication
- **User Separation**: Service isolation with dedicated accounts
- **Sudo Limitation**: Minimal sudo privileges

### Monitoring & Alerting
- **Real-time Monitoring**: Netdata integration
- **Log Aggregation**: Centralized logging
- **Intrusion Detection**: Fail2ban configuration
- **Regular Updates**: Automated security patches

### Backup Strategy
- **Server Backups**: Linode automatic backups
- **Data Backups**: Application-specific backup scripts
- **Configuration Backup**: Git-based configuration management
- **Recovery Testing**: Regular restore procedures

## 🎯 Next Steps

1. **Deploy Your First Service**: Start with a simple service deployment
2. **Setup Monitoring**: Configure Netdata Cloud integration
3. **Custom Configuration**: Create service-specific configurations
4. **Team Access**: Add team members to Tailscale network
5. **Production Hardening**: Implement additional security measures

## 📞 Support

### Documentation
- **API Reference**: [API_REFERENCE.md](API_REFERENCE.md)
- **Security Guide**: [SECURITY.md](SECURITY.md)
- **Troubleshooting**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

### Community
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub discussions for questions
- **Contributions**: Submit pull requests for improvements

### Emergency Contacts
- **Server Issues**: Check Linode status page
- **VPN Issues**: Check Tailscale status page
- **DNS Issues**: Check Cloudflare status page
