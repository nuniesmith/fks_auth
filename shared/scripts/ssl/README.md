# FKS SSL Certificate Management

This directory contains the SSL certificate management system for the FKS trading platform. It provides automated SSL certificate generation and renewal for `fkstrading.xyz` and all subdomains.

## Components

### Scripts

- **`manage-ssl-certs.sh`** - Main SSL certificate management script
- **`install-ssl-service.sh`** - Installation script for the SSL service

### Systemd Units

- **`fks_ssl-manager.service`** - Systemd service for SSL certificate management
- **`fks_ssl-renewal.timer`** - Systemd timer for automatic certificate renewal

## Features

- ✅ **Automatic SSL certificates** for fkstrading.xyz and subdomains
- ✅ **Let's Encrypt integration** with ACME protocol
- ✅ **Automatic renewal** twice daily with randomized timing
- ✅ **Nginx integration** with automatic configuration
- ✅ **VPN-only setup** compatible with Tailscale
- ✅ **Staging support** for testing
- ✅ **Comprehensive logging**

## Supported Domains

The SSL service automatically manages certificates for:

- `fkstrading.xyz` (root domain)
- `www.fkstrading.xyz`
- `api.fkstrading.xyz`
- `data.fkstrading.xyz`
- `worker.fkstrading.xyz`
- `nodes.fkstrading.xyz`
- `auth.fkstrading.xyz`
- `monitor.fkstrading.xyz`
- `admin.fkstrading.xyz`

## Manual Usage

### Install SSL Service

```bash
# Install and configure SSL service
sudo ./scripts/ssl/install-ssl-service.sh install

# Test installation (uses staging certificates)
sudo ./scripts/ssl/install-ssl-service.sh test
```

### Manage Certificates

```bash
# Install certificates manually
sudo fks_ssl-manager.sh install

# Check certificate status
sudo fks_ssl-manager.sh status

# Renew certificates manually
sudo fks_ssl-manager.sh renew

# Test with staging certificates
sudo STAGING=true fks_ssl-manager.sh install

# Remove certificates and configuration
sudo fks_ssl-manager.sh cleanup
```

### Check Service Status

```bash
# Check SSL renewal timer
systemctl status fks_ssl-renewal.timer

# Check recent renewal attempts
journalctl -u fks_ssl-manager.service

# View SSL manager logs
tail -f /var/log/fks_ssl-manager.log
```

## GitHub Actions Integration

The SSL service is automatically installed during GitHub Actions deployment in Stage 1:

1. **Upload scripts** - SSL management scripts are uploaded to the server
2. **Install service** - Systemd service and timer are configured
3. **Generate certificates** - Initial SSL certificates are created
4. **Enable auto-renewal** - Timer is started for automatic renewals

### Required GitHub Secrets

- `ADMIN_EMAIL` - Email address for Let's Encrypt (optional, defaults to `nunie.smith01@gmail.com`)

### Environment Variables

- `DOMAIN` - Main domain (default: fkstrading.xyz)
- `LETSENCRYPT_EMAIL` - Email for Let's Encrypt notifications (uses ADMIN_EMAIL from GitHub secrets)
- `WEBROOT_PATH` - Webroot for ACME challenges (default: /var/www/html)
- `STAGING` - Use staging environment for testing (default: false)

## Security Considerations

### VPN-Only Access

This SSL setup is designed to work with Tailscale VPN-only configuration:

- DNS records point to Tailscale IP addresses
- Services are only accessible when connected to Tailscale VPN
- SSL certificates are still valid for external validation

### Rate Limits

Let's Encrypt has rate limits:

- **20 certificates per week** per domain
- **5 duplicate certificates per week**
- **300 new orders per account per 3 hours**

Use staging environment for testing to avoid hitting rate limits.

## Nginx Configuration

The SSL service automatically configures nginx with:

- **HTTP to HTTPS redirect** for all domains
- **SSL/TLS best practices** (TLS 1.2+, secure ciphers)
- **Security headers** (HSTS, X-Frame-Options, etc.)
- **Proxy configuration** for Docker services

## Troubleshooting

### Certificate Generation Failed

```bash
# Check DNS resolution
dig fkstrading.xyz
dig api.fkstrading.xyz

# Check nginx configuration
nginx -t

# Check ACME challenge accessibility
curl -v http://fkstrading.xyz/.well-known/acme-challenge/test

# Check Let's Encrypt logs
tail -f /var/log/letsencrypt/letsencrypt.log
```

### Auto-renewal Issues

```bash
# Test renewal manually
sudo certbot renew --dry-run

# Check timer status
systemctl status fks_ssl-renewal.timer
systemctl list-timers | grep fks

# Check service logs
journalctl -u fks_ssl-manager.service -f
```

### Rate Limit Errors

```bash
# Use staging environment
sudo STAGING=true fks_ssl-manager.sh install

# Wait for rate limit reset (usually 1 hour to 1 week)
# Check Let's Encrypt status page
```

## File Locations

- **Scripts**: `/usr/local/bin/fks_ssl-manager.sh`
- **Systemd units**: `/etc/systemd/system/fks_ssl-*`
- **Certificates**: `/etc/letsencrypt/live/fkstrading.xyz/`
- **Nginx config**: `/etc/nginx/conf.d/fks_ssl*.conf`
- **Logs**: `/var/log/fks_ssl-manager.log`
- **Webroot**: `/var/www/html`

## Cleanup

The SSL service is automatically cleaned up when servers are destroyed:

1. **Stop services** - Timer and renewal are stopped
2. **Remove certificates** - Let's Encrypt certificates are revoked
3. **Clean configuration** - Nginx and systemd configs are removed
4. **Remove scripts** - SSL management scripts are deleted

Manual cleanup:

```bash
# Uninstall SSL service
sudo ./scripts/ssl/install-ssl-service.sh uninstall

# Or use the SSL manager directly
sudo fks_ssl-manager.sh cleanup
```

## Logs and Monitoring

### Log Files

- `/var/log/fks_ssl-manager.log` - SSL manager operations
- `/var/log/letsencrypt/letsencrypt.log` - Let's Encrypt operations
- `journalctl -u fks_ssl-manager.service` - Systemd service logs

### Monitoring

The SSL service provides status checking:

```bash
# Quick status
fks_ssl-manager.sh status

# Detailed certificate info
openssl x509 -in /etc/letsencrypt/live/fkstrading.xyz/cert.pem -text -noout

# Check expiry dates
openssl x509 -in /etc/letsencrypt/live/fkstrading.xyz/cert.pem -noout -dates
```

## Support

For issues or questions about the SSL management system:

1. Check the troubleshooting section above
2. Review the logs for error messages
3. Ensure DNS records are correctly configured
4. Verify Tailscale VPN connectivity if using VPN-only setup
