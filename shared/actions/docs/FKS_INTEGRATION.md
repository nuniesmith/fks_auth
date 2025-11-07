# 🚀 FKS Multi-Server Deployment Integration

This document describes the enhanced integration between your shared actions repository and FKS project for seamless multi-server deployment with Tailscale VPN and Cloudflare DNS automation.

## 🎯 Updated Multi-Server Implementation

**FIXED**: The enhanced deployment workflow now properly creates and deploys to three separate servers:
- `fks_auth` - Authentication and user management services
- `fks_api` - Trading API, workers, and data services  
- `fks_web` - React frontend and web services

Each server uses the appropriate Docker Compose file:
- `docker-compose.auth.yml` for auth server
- `docker-compose.api.yml` for API server
- `docker-compose.web.yml` for web server

## 🏗️ Architecture OverviewFKS Multi-Server Deployment Integration

This document describes the enhanced integration between your shared actions repository and FKS project for seamless multi-server deployment with Tailscale VPN and Cloudflare DNS automation.

## 🏗️ Architecture Overview

### Multi-Server Setup
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Server   │    │   API Server    │    │   Web Server    │
│   (g6-nanode-1) │    │ (g6-standard-1) │    │   (g6-nanode-1) │
│     $5/month    │    │    $12/month    │    │     $5/month    │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Authentik SSO │    │ • Trading API   │    │ • React Frontend│
│ • User Auth     │    │ • Workers       │    │ • Nginx Proxy   │
│ • SSL Proxy     │    │ • PostgreSQL    │    │ • Static Assets │
│ • Redis Cache   │    │ • Redis Queue   │    │ • SSL Termination│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Tailscale     │
                    │   VPN Network   │
                    │  100.64.0.0/10  │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Cloudflare    │
                    │   DNS & CDN     │
                    │   7gram.xyz     │
                    └─────────────────┘
```

**💰 Cost-Optimized Architecture**: Total monthly cost of $22 for complete multi-server setup
- Auth/Web servers use lightweight 1GB instances for $5/month each
- API server uses enhanced 2GB instance for better performance at $12/month

## ✨ New Features Added

### 1. Enhanced DNS Management
- **Automated Cloudflare Updates**: `scripts/dns/cloudflare-updater.sh`
- **Service-Specific Subdomains**: Automatically configures DNS for each service
- **Multi-Server DNS Coordination**: Updates all server IPs simultaneously
- **Tailscale IP Detection**: Automatically discovers and uses VPN IPs

### 2. FKS Service Manager
- **Multi-Server Orchestration**: `services/fks/fks_service-manager.sh`
- **Deployment Coordination**: Handles auth → api → web deployment order
- **Health Checks**: Comprehensive service health validation
- **Server Connectivity Testing**: Pre-deployment validation

### 3. Enhanced GitHub Actions
- **Flexible Deployment Modes**: Single, multi-auth, multi-api, multi-web, multi-all
- **Automatic Server Creation**: Creates Linode servers when needed
- **Tailscale Integration**: Automatic VPN setup and IP detection
- **DNS Automation**: Updates Cloudflare records after deployment

## 🚀 Quick Start Guide

### 1. Setup GitHub Secrets

Required secrets for your repository:

```bash
# Infrastructure
LINODE_CLI_TOKEN=your_linode_api_token
SERVICE_ROOT_PASSWORD=your_secure_root_password

# User Management  
JORDAN_PASSWORD=your_admin_password
ACTIONS_USER_PASSWORD=your_cicd_password

# VPN & Networking
TAILSCALE_AUTH_KEY=your_tailscale_auth_key
TAILSCALE_OAUTH_CLIENT_ID=your_tailscale_oauth_client_id  # Optional
TAILSCALE_OAUTH_SECRET=your_tailscale_oauth_secret        # Optional

# DNS Management
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ZONE_ID=your_cloudflare_zone_id

# Container Registry (Optional)
DOCKER_USERNAME=your_docker_username
DOCKER_TOKEN=your_docker_token

# Notifications (Optional)
DISCORD_WEBHOOK=your_discord_webhook_url
```

### 2. Single Server Deployment

Deploy all FKS services on one server:

```yaml
# .github/workflows/deploy-fks.yml
name: Deploy FKS
on:
  workflow_dispatch:

jobs:
  deploy:
    uses: ./.github/workflows/fks_enhanced-deploy.yml
    with:
      deployment_mode: 'single'
      server_type: 'g6-standard-2'
      create_new_servers: true
      update_dns: true
    secrets: inherit
```

### 3. Multi-Server Deployment

Deploy FKS across three optimized servers:

```yaml
# .github/workflows/deploy-fks_multi.yml
name: Deploy FKS Multi-Server
on:
  workflow_dispatch:

jobs:
  deploy:
    uses: ./.github/workflows/fks_enhanced-deploy.yml
    with:
      deployment_mode: 'multi-all'
      server_type: 'g6-standard-2'  # API server gets this
      create_new_servers: true
      update_dns: true
    secrets: inherit
```

### 4. Manual Server Management

Use the enhanced tools directly:

```bash
# Deploy using service manager
./services/fks/fks_service-manager.sh deploy --mode multi \
  --auth-server auth.7gram.xyz \
  --api-server api.7gram.xyz \
  --web-server web.7gram.xyz

# Update DNS records
./scripts/dns/cloudflare-updater.sh update-multi-server \
  --auth-ip 100.64.0.1 \
  --api-ip 100.64.0.2 \
  --web-ip 100.64.0.3

# Health check
./services/fks/fks_service-manager.sh health-check --mode multi \
  --auth-server auth.7gram.xyz \
  --api-server api.7gram.xyz \
  --web-server web.7gram.xyz
```

## 🔧 Configuration

### Environment Template

Copy and customize the configuration template:

```bash
cp templates/fks_multi-server.env.template fks/.env
# Edit the file with your specific configuration
```

Key configurations to update:
- Domain names and SSL settings
- Database passwords and authentication keys
- Trading API credentials (if using live trading)
- Monitoring and notification settings

### Server Specifications

Optimized server sizing for cost-effectiveness:

| Server Type | RAM | CPU | Cost/Month | Use Case |
|-------------|-----|-----|------------|----------|
| **Auth Server** | 1GB | 1 vCPU | $5 | Authentik SSO, Nginx |
| **API Server** | 4GB | 2 vCPU | $20 | Trading API, Workers, DB |
| **Web Server** | 1GB | 1 vCPU | $5 | React Frontend, Nginx |
| **Single Server** | 4GB | 2 vCPU | $20 | All services combined |

### DNS Configuration

The system automatically configures these subdomains:

| Subdomain | Points To | Purpose |
|-----------|-----------|---------|
| `fks.7gram.xyz` | Web Server | Main application |
| `api.7gram.xyz` | API Server | Trading API |
| `auth.7gram.xyz` | Auth Server | SSO authentication |
| `data.7gram.xyz` | API Server | Data services |
| `trading.7gram.xyz` | API Server | Trading endpoints |

## 🔄 Deployment Workflows

### Workflow Options

The enhanced GitHub Actions workflow supports multiple deployment modes:

1. **Single Server** (`single`): All services on one server
2. **Multi-Auth** (`multi-auth`): Deploy only auth server
3. **Multi-API** (`multi-api`): Deploy only API server  
4. **Multi-Web** (`multi-web`): Deploy only web server
5. **Multi-All** (`multi-all`): Deploy all three servers

### Deployment Process

1. **Pre-flight Checks**: Validates secrets and determines strategy
2. **Server Creation**: Creates or finds existing Linode servers
3. **Initial Setup**: Installs packages, creates users, configures Tailscale
4. **Service Deployment**: Deploys FKS services using Docker Compose
5. **DNS Updates**: Updates Cloudflare records with Tailscale IPs
6. **Health Checks**: Validates service availability
7. **Notifications**: Sends deployment status to Discord

### Automatic Features

- **Server Auto-Discovery**: Finds existing servers by name pattern
- **Tailscale Auto-Config**: Automatically joins VPN and gets IP
- **DNS Auto-Update**: Updates all relevant subdomains
- **Health Monitoring**: Checks service endpoints
- **Error Recovery**: Handles common deployment issues

## 🔐 Security & Best Practices

### Network Security
- All server communication via Tailscale VPN
- SSH access only via Tailscale network
- Firewall configured to deny public access to services
- SSL/TLS encryption for all web traffic

### Authentication & Authorization
- Centralized SSO via Authentik
- Service-specific user accounts with minimal privileges
- API authentication via JWT tokens
- Regular password rotation recommended

### Secrets Management
- All sensitive data in GitHub secrets
- No secrets in code or configuration files
- Environment-specific configuration templates
- Automatic secret injection during deployment

## 🧪 Testing & Validation

### Health Check Endpoints

The system provides comprehensive health checks:

```bash
# API Server
curl https://api.7gram.xyz/health

# Web Server  
curl https://fks.7gram.xyz/

# Auth Server
curl https://auth.7gram.xyz/api/v3/ping/
```

### Service Validation

```bash
# Check all services in multi-server setup
./services/fks/fks_service-manager.sh health-check --mode multi \
  --auth-server auth.7gram.xyz \
  --api-server api.7gram.xyz \
  --web-server web.7gram.xyz

# Test DNS resolution
dig fks.7gram.xyz
dig api.7gram.xyz
dig auth.7gram.xyz
```

## 🚨 Troubleshooting

### Common Issues

1. **Tailscale Connection Failed**
   - Check auth key validity
   - Verify network connectivity
   - Restart tailscaled service

2. **DNS Updates Not Working**
   - Verify Cloudflare API token permissions
   - Check zone ID is correct
   - Confirm domain ownership

3. **Service Health Check Failed**
   - Check container logs: `docker compose logs`
   - Verify environment variables
   - Check service dependencies

4. **SSH Connection Issues**
   - Verify Tailscale connectivity
   - Check user account exists
   - Confirm SSH key authentication

### Debug Commands

```bash
# Check Tailscale status
ssh user@server "tailscale status"

# View service logs
ssh user@server "cd fks && docker compose logs -f"

# Test connectivity
./scripts/dns/cloudflare-updater.sh test-api

# Manual deployment
./services/fks/fks_service-manager.sh deploy --mode single --server fks.7gram.xyz
```

## 📊 Monitoring & Maintenance

### Automated Monitoring
- Docker-based monitoring with cloud dashboard
- Service health endpoint monitoring
- Resource usage tracking
- Automated alert notifications

### Regular Maintenance
- Update server packages monthly
- Rotate authentication keys quarterly
- Review security logs weekly
- Test backup procedures monthly

### Cost Optimization
- Monitor resource usage
- Scale servers based on demand
- Use reserved instances for long-term deployments
- Implement auto-shutdown for dev environments

## 🎯 Next Steps

1. **Setup Secrets**: Configure all required GitHub secrets
2. **Test Deployment**: Start with single-server mode
3. **Verify DNS**: Confirm Cloudflare integration works
4. **Scale to Multi-Server**: Deploy across three servers
5. **Monitor & Optimize**: Set up monitoring and alerts
6. **Production Readiness**: Review security and backup procedures

## 📚 Additional Resources

- [FKS Project Documentation](../fks/README.md)
- [Tailscale Setup Guide](docs/TAILSCALE_SETUP.md)
- [Cloudflare DNS API Guide](docs/CLOUDFLARE_SETUP.md)
- [Linode Server Management](docs/LINODE_SETUP.md)
- [Security Best Practices](docs/SECURITY.md)

---

**💡 Pro Tip**: Start with single-server deployment to test everything works, then scale to multi-server for production workloads.
