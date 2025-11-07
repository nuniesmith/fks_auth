#!/bin/bash
# install-ssl-systemd.sh
# Install SSL certificate management systemd services for FKS

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="fks_ssl-manager"
INSTALL_PATH="/opt/fks"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
#!/usr/bin/env bash
# Shim: install-ssl-systemd moved to domains/ssl/systemd-install.sh
set -euo pipefail
NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/domains/ssl/systemd-install.sh"
if [[ -f "$NEW_PATH" ]]; then
    exec "$NEW_PATH" "$@"
else
    echo "[WARN] Expected relocated script not found: $NEW_PATH" >&2
    echo "TODO: restore full systemd SSL installer under domains/ssl/systemd-install.sh" >&2
    exit 2
fi
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$INSTALL_PATH
Environment=DOMAIN_NAME=fkstrading.xyz
Environment=API_DOMAIN=api.fkstrading.xyz
Environment=AUTH_DOMAIN=auth.fkstrading.xyz
Environment=LETSENCRYPT_EMAIL=admin@fkstrading.xyz
EnvironmentFile=-$INSTALL_PATH/.env
ExecStart=$INSTALL_PATH/scripts/ssl-manager.sh renew
StandardOutput=journal
StandardError=journal
TimeoutStartSec=300

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_PATH /var/log /tmp
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

    # Create timer file
    cat > "/etc/systemd/system/${SERVICE_NAME}.timer" << EOF
[Unit]
Description=FKS SSL Certificate Renewal Timer
Documentation=https://github.com/nuniesmith/fks
Requires=${SERVICE_NAME}.service

[Timer]
# Run twice daily at 2:30 AM and 2:30 PM (offset from nginx)
OnCalendar=*-*-* 02,14:30:00
# Add randomization to prevent all servers renewing at same time
RandomizedDelaySec=3600
# Run immediately if the system was powered off during scheduled time
Persistent=true
# Prevent accumulation of missed runs
AccuracySec=1h

[Install]
WantedBy=timers.target
EOF

    # Set proper permissions
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.timer"
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd service files created"
}

# Enable and start services
enable_services() {
    log_info "Enabling and starting FKS SSL management services..."
    
    # Enable the timer (this will automatically handle the service)
    systemctl enable "${SERVICE_NAME}.timer"
    systemctl start "${SERVICE_NAME}.timer"
    
    # Show status
    systemctl status "${SERVICE_NAME}.timer" --no-pager
    
    log_success "FKS SSL management services enabled and started"
}

# Create environment file template
create_env_template() {
    log_info "Creating environment configuration..."
    
    cat > "$INSTALL_PATH/.env.template" << 'EOF'
# FKS SSL Certificate Configuration
DOMAIN_NAME=fkstrading.xyz
API_DOMAIN=api.fkstrading.xyz
AUTH_DOMAIN=auth.fkstrading.xyz
LETSENCRYPT_EMAIL=admin@fkstrading.xyz

# Cloudflare DNS Challenge (recommended for multi-domain certificates)
CLOUDFLARE_EMAIL=your-email@cloudflare.com
CLOUDFLARE_API_TOKEN=your-api-token

# Docker Configuration
HTTP_PORT=80
HTTPS_PORT=443
TZ=America/Toronto

# FKS-specific Configuration
WEB_DOMAIN_NAME=fkstrading.xyz
API_DOMAIN_NAME=api.fkstrading.xyz
AUTH_DOMAIN_NAME=auth.fkstrading.xyz
APP_NAME="FKS Trading Platform"
APP_VERSION=1.0.0
ENVIRONMENT=production

# Netdata Configuration (optional)
NETDATA_CLAIM_TOKEN=
NETDATA_CLAIM_URL=https://app.netdata.cloud
NETDATA_CLAIM_ROOMS=
NETDATA_DISABLE_TELEMETRY=1
EOF

    # Create actual .env file if it doesn't exist
    if [ ! -f "$INSTALL_PATH/.env" ]; then
        cp "$INSTALL_PATH/.env.template" "$INSTALL_PATH/.env"
        log_warn "Created $INSTALL_PATH/.env - please configure your settings"
    fi
    
    chmod 600 "$INSTALL_PATH/.env"
    
    log_success "Environment configuration created"
}

# Run initial SSL setup
run_initial_setup() {
    log_info "Running initial SSL certificate setup for FKS..."
    
    # Source environment variables
    if [ -f "$INSTALL_PATH/.env" ]; then
        set -a
        source "$INSTALL_PATH/.env"
        set +a
    fi
    
    # Run SSL manager setup
    if "$INSTALL_PATH/scripts/ssl-manager.sh" setup; then
        log_success "Initial FKS SSL setup completed successfully"
    else
        log_warn "Initial FKS SSL setup completed with warnings (check logs)"
    fi
}

# Create management scripts
create_management_scripts() {
    log_info "Creating FKS SSL management scripts..."
    
    # SSL management wrapper
    cat > "/usr/local/bin/fks_ssl" << EOF
#!/bin/bash
# FKS SSL Certificate Management Wrapper
cd "$INSTALL_PATH"
exec "$INSTALL_PATH/scripts/ssl-manager.sh" "\$@"
EOF
    chmod +x "/usr/local/bin/fks_ssl"
    
    # Service management wrapper
    cat > "/usr/local/bin/fks_ssl-service" << EOF
#!/bin/bash
# FKS SSL Service Management Wrapper

case "\$1" in
    status)
        systemctl status ${SERVICE_NAME}.timer --no-pager
        echo
        systemctl status ${SERVICE_NAME}.service --no-pager
        ;;
    logs)
        journalctl -u ${SERVICE_NAME}.service -f
        ;;
    enable)
        systemctl enable ${SERVICE_NAME}.timer
        systemctl start ${SERVICE_NAME}.timer
        ;;
    disable)
        systemctl stop ${SERVICE_NAME}.timer
        systemctl disable ${SERVICE_NAME}.timer
        ;;
    restart)
        systemctl restart ${SERVICE_NAME}.timer
        ;;
    run-now)
        systemctl start ${SERVICE_NAME}.service
        ;;
    *)
        echo "Usage: \$0 {status|logs|enable|disable|restart|run-now}"
        echo
        echo "Commands:"
        echo "  status   - Show service status"
        echo "  logs     - Follow service logs"
        echo "  enable   - Enable automatic renewal"
        echo "  disable  - Disable automatic renewal"
        echo "  restart  - Restart the timer"
        echo "  run-now  - Run certificate renewal immediately"
        exit 1
        ;;
esac
EOF
    chmod +x "/usr/local/bin/fks_ssl-service"
    
    log_success "Management scripts created"
    echo "  - fks_ssl: Direct SSL certificate management"
    echo "  - fks_ssl-service: Systemd service management"
}

# Show completion message
show_completion() {
    cat << EOF

${GREEN}🎉 FKS SSL Certificate Management Installation Complete!${NC}

${BLUE}Configuration:${NC}
  • Project installed at: $INSTALL_PATH
  • Environment file: $INSTALL_PATH/.env
  • Logs: /var/log/fks_ssl/manager.log

${BLUE}Management Commands:${NC}
  • fks_ssl setup                   - Initial SSL certificate setup
  • fks_ssl renew                   - Renew certificates manually
  • fks_ssl status                  - Show certificate status
  • fks_ssl-service status          - Show systemd service status
  • fks_ssl-service logs            - View renewal logs
  • fks_ssl-service run-now         - Run renewal immediately

${BLUE}Systemd Services:${NC}
  • ${SERVICE_NAME}.service         - Certificate renewal service
  • ${SERVICE_NAME}.timer           - Automatic renewal timer (twice daily, offset 30min from nginx)

${BLUE}FKS Domains Managed:${NC}
  • fkstrading.xyz (main web)
  • api.fkstrading.xyz (API server)
  • auth.fkstrading.xyz (auth server)
  • *.fkstrading.xyz (wildcard)

${BLUE}Next Steps:${NC}
  1. Configure your settings in: $INSTALL_PATH/.env
  2. Add Cloudflare credentials for multi-domain certificates
  3. Run: fks_ssl setup
  4. Check status: fks_ssl-service status

${YELLOW}Timer Schedule:${NC}
  • Automatic renewal checks: 2:30 AM and 2:30 PM daily
  • Randomized delay: up to 1 hour to prevent server overload
  • Persistent: will run missed schedules on boot

EOF
}

# Uninstall function
uninstall() {
    log_info "Uninstalling FKS SSL certificate management..."
    
    # Stop and disable services
    systemctl stop "${SERVICE_NAME}.timer" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}.timer" 2>/dev/null || true
    
    # Remove systemd files
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/systemd/system/${SERVICE_NAME}.timer"
    systemctl daemon-reload
    
    # Remove management scripts
    rm -f "/usr/local/bin/fks_ssl"
    rm -f "/usr/local/bin/fks_ssl-service"
    
    # Ask about project directory
    read -p "Remove project directory $INSTALL_PATH? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_PATH"
        log_success "Project directory removed"
    fi
    
    log_success "FKS SSL certificate management uninstalled"
}

# Help function
show_help() {
    cat << EOF
FKS SSL Certificate Management Installer

Usage: $0 [COMMAND]

Commands:
    install     Install SSL certificate management (default)
    uninstall   Remove SSL certificate management
    help        Show this help message

This installer will:
  • Copy the FKS project to $INSTALL_PATH
  • Install systemd services for automatic certificate renewal
  • Create management scripts for easy certificate handling
  • Set up twice-daily automatic renewal checks (offset from nginx)
  • Support multi-domain certificates (fkstrading.xyz, api.fkstrading.xyz, auth.fkstrading.xyz)

Requirements:
  • Root privileges (use sudo)
  • Docker and docker-compose installed
  • Systemd-based Linux distribution

EOF
}

# Main function
main() {
    local command="${1:-install}"
    
    case "$command" in
        install)
            check_root
            log_info "Starting FKS SSL certificate management installation..."
            install_project
            create_env_template
            create_systemd_files
            enable_services
            create_management_scripts
            run_initial_setup
            show_completion
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
