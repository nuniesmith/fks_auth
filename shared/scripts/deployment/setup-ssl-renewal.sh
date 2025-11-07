#!/bin/bash
# =================================================================
# FKS Trading Systems - SSL Certificate Auto-Renewal Setup
# =================================================================
# This script sets up automatic SSL certificate renewal using certbot

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Configuration
DOMAIN_NAME="${1:-fkstrading.xyz}"
FKS_HOME="${2:-/home/fks_user/fks}"

log_info "Setting up SSL certificate auto-renewal for $DOMAIN_NAME"

# Create renewal hook script
cat > /etc/letsencrypt/renewal-hooks/deploy/fks_nginx-reload.sh << 'EOF'
#!/bin/bash
# Reload nginx in the FKS container after certificate renewal

FKS_HOME="${FKS_HOME:-/home/fks_user/fks}"

if [ -d "$FKS_HOME" ]; then
    cd "$FKS_HOME"
    # Check if nginx container is running
    if docker-compose ps nginx | grep -q "Up"; then
        echo "Reloading nginx configuration..."
        docker-compose exec -T nginx nginx -s reload
        echo "Nginx reloaded successfully"
    else
        echo "Nginx container is not running, skipping reload"
    fi
else
    echo "FKS directory not found at $FKS_HOME"
fi
EOF

# Make the hook script executable
chmod +x /etc/letsencrypt/renewal-hooks/deploy/fks_nginx-reload.sh

# Update the hook script with the correct FKS_HOME
sed -i "s|FKS_HOME=\"\${FKS_HOME:-/home/fks_user/fks}\"|FKS_HOME=\"$FKS_HOME\"|" /etc/letsencrypt/renewal-hooks/deploy/fks_nginx-reload.sh

# Test certificate renewal (dry run)
log_info "Testing certificate renewal (dry run)..."
if certbot renew --dry-run; then
    log_info "Certificate renewal test successful"
else
    log_error "Certificate renewal test failed"
    exit 1
fi

# Check if systemd timer exists
if systemctl list-timers | grep -q certbot; then
    log_info "Certbot renewal timer is already active"
    systemctl status certbot.timer --no-pager || true
else
    # Create systemd timer for renewal if it doesn't exist
    log_info "Creating systemd timer for automatic renewal..."
    
    cat > /etc/systemd/system/certbot-renew.service << EOF
[Unit]
Description=Certbot Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet
ExecStartPost=/bin/systemctl reload nginx
EOF

    cat > /etc/systemd/system/certbot-renew.timer << EOF
[Unit]
Description=Run certbot twice daily
Persistent=true

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF

    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable certbot-renew.timer
    systemctl start certbot-renew.timer
    
    log_info "Systemd timer created and started"
fi

# Create a cron job as backup
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    log_info "Adding cron job for certificate renewal (backup)..."
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet && cd $FKS_HOME && docker-compose exec -T nginx nginx -s reload") | crontab -
    log_info "Cron job added"
else
    log_info "Cron job for renewal already exists"
fi

log_info "SSL certificate auto-renewal setup complete!"
log_info ""
log_info "Certificate will be automatically renewed:"
log_info "  - Via systemd timer (twice daily)"
log_info "  - Via cron job at 3 AM (backup)"
log_info "  - Nginx will be automatically reloaded after renewal"
log_info ""
log_info "To manually renew certificates, run: certbot renew"
log_info "To check renewal status, run: certbot certificates"
