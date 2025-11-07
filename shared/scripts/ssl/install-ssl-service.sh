#!/bin/bash

# FKS SSL Service Installation Script
# Installs SSL certificate management service and timer

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="${DOMAIN:-fkstrading.xyz}"
EMAIL="${ADMIN_EMAIL:-${LETSENCRYPT_EMAIL:-nunie.smith01@gmail.com}}"
STAGING="${STAGING:-false}"

log() {
    echo -e "${1}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "${RED}❌ This script must be run as root${NC}"
        exit 1
    fi
}

# Install SSL management script
install_ssl_script() {
    log "${BLUE}📦 Installing SSL management script...${NC}"
    
    # Copy the SSL manager script
    cp "$(dirname "$0")/../ssl/manage-ssl-certs.sh" "/usr/local/bin/fks_ssl-manager.sh"
    chmod +x "/usr/local/bin/fks_ssl-manager.sh"
    
    log "${GREEN}✅ SSL management script installed to /usr/local/bin/fks_ssl-manager.sh${NC}"
}

# Install systemd service and timer
install_systemd_units() {
    log "${BLUE}⚙️ Installing systemd service and timer...${NC}"
    
    # Copy systemd units
    cp "$(dirname "$0")/../config/systemd/fks_ssl-manager.service" "/etc/systemd/system/"
    cp "$(dirname "$0")/../config/systemd/fks_ssl-renewal.timer" "/etc/systemd/system/"
    
    # Update environment variables in service file
    sed -i "s/Environment=DOMAIN=.*/Environment=DOMAIN=$DOMAIN/" "/etc/systemd/system/fks_ssl-manager.service"
    sed -i "s/Environment=LETSENCRYPT_EMAIL=.*/Environment=LETSENCRYPT_EMAIL=$EMAIL/" "/etc/systemd/system/fks_ssl-manager.service"
    sed -i "s/Environment=STAGING=.*/Environment=STAGING=$STAGING/" "/etc/systemd/system/fks_ssl-manager.service"
    
    # Reload systemd
    systemctl daemon-reload
    
    log "${GREEN}✅ Systemd units installed${NC}"
}

# Start and enable services
enable_services() {
    log "${BLUE}🚀 Enabling and starting SSL services...${NC}"
    
    # Enable and start the timer (this will handle automatic renewals)
    systemctl enable fks_ssl-renewal.timer
    systemctl start fks_ssl-renewal.timer
    
    log "${GREEN}✅ SSL renewal timer enabled and started${NC}"
    
    # Show timer status
    systemctl status fks_ssl-renewal.timer --no-pager -l || true
}

# Run the initial SSL setup
run_initial_setup() {
    log "${BLUE}🔐 Running initial SSL certificate setup...${NC}"
    
    if [ "$STAGING" = "true" ]; then
        log "${YELLOW}⚠️ Using staging environment for testing${NC}"
    fi
    
    # Run the SSL manager to install certificates
    if /usr/local/bin/fks_ssl-manager.sh install; then
        log "${GREEN}✅ Initial SSL setup completed successfully!${NC}"
        return 0
    else
        log "${RED}❌ Initial SSL setup failed${NC}"
        return 1
    fi
}

# Cleanup function for removal
cleanup_ssl_service() {
    log "${BLUE}🧹 Removing SSL service and certificates...${NC}"
    
    # Stop and disable timer
    systemctl stop fks_ssl-renewal.timer 2>/dev/null || true
    systemctl disable fks_ssl-renewal.timer 2>/dev/null || true
    
    # Remove systemd units
    rm -f "/etc/systemd/system/fks_ssl-manager.service"
    rm -f "/etc/systemd/system/fks_ssl-renewal.timer"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Clean up SSL certificates
    /usr/local/bin/fks_ssl-manager.sh cleanup 2>/dev/null || true
    
    # Remove SSL manager script
    rm -f "/usr/local/bin/fks_ssl-manager.sh"
    
    log "${GREEN}✅ SSL service cleanup completed${NC}"
}

# Status check
check_status() {
    log "${BLUE}📊 SSL Service Status:${NC}"
    
    # Check timer status
    if systemctl is-active fks_ssl-renewal.timer >/dev/null 2>&1; then
        log "${GREEN}✅ SSL renewal timer is active${NC}"
        systemctl status fks_ssl-renewal.timer --no-pager -l || true
    else
        log "${RED}❌ SSL renewal timer is not active${NC}"
    fi
    
    # Check certificate status
    if [ -f "/usr/local/bin/fks_ssl-manager.sh" ]; then
        /usr/local/bin/fks_ssl-manager.sh status || true
    else
        log "${RED}❌ SSL manager script not found${NC}"
    fi
}

# Main function
main() {
    case "${1:-}" in
        "install")
            log "${BLUE}🚀 Installing FKS SSL service...${NC}"
            check_root
            install_ssl_script
            install_systemd_units
            enable_services
            run_initial_setup
            log "${GREEN}🎉 FKS SSL service installation completed!${NC}"
            log "${BLUE}ℹ️ Certificates will be automatically renewed twice daily${NC}"
            ;;
        "uninstall"|"cleanup")
            check_root
            cleanup_ssl_service
            ;;
        "status")
            check_status
            ;;
        "test")
            log "${BLUE}🧪 Installing SSL service in test mode...${NC}"
            STAGING=true
            check_root
            install_ssl_script
            install_systemd_units
            enable_services
            run_initial_setup
            log "${GREEN}✅ SSL service test installation completed${NC}"
            ;;
        *)
            echo "FKS SSL Service Installer"
            echo ""
            echo "Usage: $0 {install|uninstall|status|test}"
            echo ""
            echo "Commands:"
            echo "  install    - Install SSL service and generate certificates"
            echo "  uninstall  - Remove SSL service and certificates"
            echo "  status     - Check service and certificate status"
            echo "  test       - Install in test mode (staging certificates)"
            echo ""
            echo "Environment variables:"
            echo "  DOMAIN            - Main domain (default: fkstrading.xyz)"
            echo "  ADMIN_EMAIL       - Email for Let's Encrypt (default: nunie.smith01@gmail.com)"
            echo "  STAGING           - Use staging environment (default: false)"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
