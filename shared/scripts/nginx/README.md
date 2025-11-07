# Scripts Directory

This directory contains all deployment and management scripts for the NGINX reverse proxy.

## Directory Structure

```text
scripts/
├── deployment/          # Main deployment scripts
│   ├── deploy.sh       # Full deployment pipeline
│   ├── setup.sh        # Initial server setup
│   └── tailscale.sh    # Tailscale configuration
├── ssl/                # SSL/TLS certificate management
│   └── lets_encrypt.sh # Let's Encrypt certificate setup
├── dns/                # DNS management
│   └── cloudflare-dns-manager.sh # Cloudflare DNS updates
├── templates/          # Script templates
├── utils/              # Utility functions
│   ├── common.sh       # Common functions
│   ├── logging.sh      # Logging utilities
│   └── validation.sh   # Validation functions
├── setup-*.sh          # Individual setup components
├── health-monitor.sh   # Health monitoring
├── 7gram-status.sh     # System status checker
└── rollback.sh         # Deployment rollback
```

## Usage

### Quick Start

Use the main deployment script from the project root:

```bash
# Run full deployment
./deploy deploy

# Setup SSL only
./deploy ssl

# Check system status
./deploy status

# Show help
./deploy help
```

### Direct Script Usage

You can also run scripts directly:

```bash
# Full deployment
./scripts/deployment/deploy.sh

# SSL setup
./scripts/ssl/lets_encrypt.sh

# DNS updates
./scripts/dns/cloudflare-dns-manager.sh
```

## Script Categories

### Deployment Scripts (`deployment/`)

- **deploy.sh**: Complete deployment pipeline
- **setup.sh**: Initial server configuration
- **tailscale.sh**: VPN network setup

### SSL Scripts (`ssl/`)

- **lets_encrypt.sh**: Automated SSL certificate management

### DNS Scripts (`dns/`)

- **cloudflare-dns-manager.sh**: DNS record management

### Component Setup Scripts

- **setup-base.sh**: Base system configuration
- **setup-docker.sh**: Docker installation and setup
- **setup-nginx.sh**: NGINX configuration
- **setup-monitoring.sh**: Monitoring stack setup
- **setup-backup.sh**: Backup system configuration

### Monitoring & Maintenance

- **health-monitor.sh**: System health checks
- **7gram-status.sh**: Comprehensive status reporting
- **performance-baseline.sh**: Performance monitoring
- **rollback.sh**: Deployment rollback procedures

### Utilities (`utils/`)

- **common.sh**: Shared functions and variables
- **logging.sh**: Centralized logging functions
- **validation.sh**: Input validation and checks

## Environment Variables

Many scripts use environment variables for configuration. See `.env.example` in the project root for required variables.

## GitHub Actions Integration

The scripts are designed to work with GitHub Actions workflows located in `.github/workflows/`.

## Security Notes

- Scripts handle sensitive data like API tokens and passwords
- Always review scripts before execution
- Use environment variables for secrets, never hardcode them
- Scripts are designed to be idempotent where possible
