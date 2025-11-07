#!/bin/bash
# install-ssl-systemd.sh
# Install SSL certificate management systemd services

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="nginx-ssl-manager"
INSTALL_PATH="/opt/nginx"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $*${NC}"; }
log_success() { echo -e "${GREEN}✅ $*${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
log_error() { echo -e "${RED}❌ $*${NC}"; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Install project to system location
install_project() {
    log_info "Installing nginx project to $INSTALL_PATH..."
    
    # Create installation directory
    mkdir -p "$INSTALL_PATH"
    
    # Copy project files (preserving structure)
    rsync -av --exclude='.git' --exclude='*.log' --exclude='ssl/letsencrypt' "$PROJECT_ROOT/" "$INSTALL_PATH/"
    
    # Ensure scripts are executable
    chmod +x "$INSTALL_PATH/scripts/"*.sh
    
    # Create log directory
    mkdir -p /var/log/nginx-ssl
    touch /var/log/nginx-ssl-manager.log
    chmod 644 /var/log/nginx-ssl-manager.log
    
    # Set proper ownership
    chown -R root:root "$INSTALL_PATH"
    chmod 755 "$INSTALL_PATH"
    
    log_success "Project installed to $INSTALL_PATH"
}

# Install systemd services
install_systemd_services() {
    log_info "Installing systemd services..."
    
    # Copy service files
    cp "$INSTALL_PATH/config/systemd/${SERVICE_NAME}.service" "/etc/systemd/system/"
    cp "$INSTALL_PATH/config/systemd/${SERVICE_NAME}.timer" "/etc/systemd/system/"
    
    # Update service file with correct paths
    sed -i "s|/opt/nginx|$INSTALL_PATH|g" "/etc/systemd/system/${SERVICE_NAME}.service"
    sed -i "s|/var/log/nginx-ssl-manager.log|/var/log/nginx-ssl/manager.log|g" "/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Set proper permissions
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.timer"
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd services installed"
}

# Enable and start services
enable_services() {
    log_info "Enabling and starting SSL management services..."
    
    # Enable the timer (this will automatically handle the service)
    systemctl enable "${SERVICE_NAME}.timer"
    systemctl start "${SERVICE_NAME}.timer"
    
    # Show status
    systemctl status "${SERVICE_NAME}.timer" --no-pager
    
    log_success "SSL management services enabled and started"
}

# Create environment file template
create_env_template() {
    log_info "Creating environment configuration..."
    
    cat > "$INSTALL_PATH/.env.template" << 'EOF'
# SSL Certificate Configuration
DOMAIN_NAME=nginx.7gram.xyz
LETSENCRYPT_EMAIL=admin@7gram.xyz

# Cloudflare DNS Challenge (optional)
# Required for wildcard certificates or when HTTP challenge fails
CLOUDFLARE_EMAIL=your-email@cloudflare.com
CLOUDFLARE_API_TOKEN=your-api-token

# Docker Configuration
NGINX_IMAGE=nginx:alpine
HTTP_PORT=80
HTTPS_PORT=443
TZ=America/Toronto

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
    log_info "Running initial SSL certificate setup..."
    
    # Source environment variables
    if [ -f "$INSTALL_PATH/.env" ]; then
        set -a
        source "$INSTALL_PATH/.env"
        set +a
    fi
    
    # Run SSL manager setup
    if "$INSTALL_PATH/scripts/ssl-manager.sh" setup; then
        log_success "Initial SSL setup completed successfully"
    else
        log_warn "Initial SSL setup completed with warnings (check logs)"
    fi
}

# Create management scripts
create_management_scripts() {
    log_info "Creating management scripts..."
    
    # SSL management wrapper
    cat > "/usr/local/bin/nginx-ssl" << EOF
#!/bin/bash
# Nginx SSL Certificate Management Wrapper
cd "$INSTALL_PATH"
exec "$INSTALL_PATH/scripts/ssl-manager.sh" "\$@"
EOF
    chmod +x "/usr/local/bin/nginx-ssl"
    
    # Service management wrapper
    cat > "/usr/local/bin/nginx-ssl-service" << EOF
#!/bin/bash
# Nginx SSL Service Management Wrapper

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
    chmod +x "/usr/local/bin/nginx-ssl-service"
    
    log_success "Management scripts created"
    echo "  - nginx-ssl: Direct SSL certificate management"
    echo "  - nginx-ssl-service: Systemd service management"
}

# Show completion message
show_completion() {
    cat << EOF

${GREEN}🎉 SSL Certificate Management Installation Complete!${NC}

${BLUE}Configuration:${NC}
  • Project installed at: $INSTALL_PATH
  • Environment file: $INSTALL_PATH/.env
  • Logs: /var/log/nginx-ssl/manager.log

${BLUE}Management Commands:${NC}
  • nginx-ssl setup                 - Initial SSL certificate setup
  • nginx-ssl renew                 - Renew certificates manually
  • nginx-ssl status                - Show certificate status
  • nginx-ssl-service status        - Show systemd service status
  • nginx-ssl-service logs          - View renewal logs
  • nginx-ssl-service run-now       - Run renewal immediately

${BLUE}Systemd Services:${NC}
  • ${SERVICE_NAME}.service         - Certificate renewal service
  • ${SERVICE_NAME}.timer           - Automatic renewal timer (twice daily)

${BLUE}Next Steps:${NC}
  1. Configure your settings in: $INSTALL_PATH/.env
  2. Run: nginx-ssl setup
  3. Check status: nginx-ssl-service status

${YELLOW}Timer Schedule:${NC}
  • Automatic renewal checks: 2:00 AM and 2:00 PM daily
  • Randomized delay: up to 1 hour to prevent server overload
  • Persistent: will run missed schedules on boot

EOF
}

# Uninstall function
uninstall() {
    log_info "Uninstalling SSL certificate management..."
    
    # Stop and disable services
    systemctl stop "${SERVICE_NAME}.timer" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}.timer" 2>/dev/null || true
    
    # Remove systemd files
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/systemd/system/${SERVICE_NAME}.timer"
    systemctl daemon-reload
    
    # Remove management scripts
    rm -f "/usr/local/bin/nginx-ssl"
    rm -f "/usr/local/bin/nginx-ssl-service"
    
    # Ask about project directory
    read -p "Remove project directory $INSTALL_PATH? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_PATH"
        log_success "Project directory removed"
    fi
    
    log_success "SSL certificate management uninstalled"
}

# Help function
show_help() {
    cat << EOF
Nginx SSL Certificate Management Installer

Usage: $0 [COMMAND]

Commands:
    install     Install SSL certificate management (default)
    uninstall   Remove SSL certificate management
    help        Show this help message

This installer will:
  • Copy the nginx project to $INSTALL_PATH
  • Install systemd services for automatic certificate renewal
  • Create management scripts for easy certificate handling
  • Set up twice-daily automatic renewal checks

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
            log_info "Starting SSL certificate management installation..."
            install_project
            create_env_template
            install_systemd_services
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
