#!/bin/bash
# 7gram-status.sh - Comprehensive system status and management script
# Version: 3.0.0

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly SCRIPT_VERSION="3.0.0"
readonly CONFIG_DIR="/etc/nginx-automation"
readonly LOG_DIR="/var/log/linode-setup"

# ============================================================================
# COLORS AND FORMATTING
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly NC='\033[0m'

# Unicode characters for better display
readonly CHECK="✅"
readonly CROSS="❌"
readonly WARNING="⚠️"
readonly INFO="ℹ️"
readonly ARROW="➤"
readonly BULLET="•"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
print_header() {
    local title="$1"
    local width=80
    local padding=$(( (width - ${#title} - 2) / 2 ))
    
    echo ""
    echo -e "${BLUE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    printf "${BLUE}║${NC}%*s${WHITE}%s${NC}%*s${BLUE}║${NC}\n" $padding "" "$title" $padding ""
    echo -e "${BLUE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    echo ""
}

print_section() {
    local title="$1"
    echo -e "\n${CYAN}${title}${NC}"
    echo -e "${CYAN}$(printf '─%.0s' $(seq 1 ${#title}))${NC}"
}

status_indicator() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "ok"|"running"|"active"|"healthy"|"connected"|"enabled")
            echo -e "  ${CHECK} ${GREEN}${message}${NC}"
            ;;
        "warning"|"stopped"|"inactive"|"disconnected")
            echo -e "  ${WARNING} ${YELLOW}${message}${NC}"
            ;;
        "error"|"failed"|"critical"|"down")
            echo -e "  ${CROSS} ${RED}${message}${NC}"
            ;;
        "info"|"unknown")
            echo -e "  ${INFO} ${GRAY}${message}${NC}"
            ;;
        *)
            echo -e "  ${BULLET} ${message}"
            ;;
    esac
}

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================
load_system_config() {
    # Set defaults
    DOMAIN_NAME="7gram.xyz"
    GITHUB_REPO="nuniesmith/nginx"
    HOSTNAME=$(hostname)
    
    # Load from configuration file if available
    if [[ -f "$CONFIG_DIR/deployment-config.json" ]]; then
        DOMAIN_NAME=$(jq -r '.domain // "7gram.xyz"' "$CONFIG_DIR/deployment-config.json" 2>/dev/null || echo "7gram.xyz")
        GITHUB_REPO=$(jq -r '.github.repository // "nuniesmith/nginx"' "$CONFIG_DIR/deployment-config.json" 2>/dev/null || echo "nuniesmith/nginx")
        SETUP_VERSION=$(jq -r '.version // "unknown"' "$CONFIG_DIR/deployment-config.json" 2>/dev/null || echo "unknown")
    fi
    
    # Export for use by other functions
    export DOMAIN_NAME GITHUB_REPO HOSTNAME SETUP_VERSION
}

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================
show_system_overview() {
    print_header "7gram Dashboard - System Overview"
    
    echo -e "${WHITE}Server Information:${NC}"
    echo -e "  ${BULLET} Hostname: ${CYAN}$HOSTNAME${NC}"
    echo -e "  ${BULLET} Domain: ${CYAN}$DOMAIN_NAME${NC}"
    echo -e "  ${BULLET} Setup Version: ${CYAN}${SETUP_VERSION:-unknown}${NC}"
    echo -e "  ${BULLET} Script Version: ${CYAN}$SCRIPT_VERSION${NC}"
    echo -e "  ${BULLET} OS: ${CYAN}$(lsb_release -ds 2>/dev/null || echo 'Unknown')${NC}"
    echo -e "  ${BULLET} Kernel: ${CYAN}$(uname -r)${NC}"
    echo -e "  ${BULLET} Uptime: ${CYAN}$(uptime -p)${NC}"
    echo -e "  ${BULLET} Current Time: ${CYAN}$(date)${NC}"
}

show_resource_usage() {
    print_section "Resource Usage"
    
    # CPU Usage
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' 2>/dev/null || echo "0")
    if (( $(echo "$cpu_usage > 80" | bc -l) 2>/dev/null )); then
        status_indicator "warning" "CPU Usage: ${cpu_usage}% (High)"
    elif (( $(echo "$cpu_usage > 60" | bc -l) 2>/dev/null )); then
        status_indicator "info" "CPU Usage: ${cpu_usage}% (Medium)"
    else
        status_indicator "ok" "CPU Usage: ${cpu_usage}% (Normal)"
    fi
    
    # Memory Usage
    local mem_info
    mem_info=$(free | awk '/^Mem:/ {printf "%.1f %.1f %.1f", ($3/$2)*100, $3/1024/1024, $2/1024/1024}' 2>/dev/null || echo "0 0 0")
    local mem_percent=$(echo "$mem_info" | awk '{print $1}')
    local mem_used=$(echo "$mem_info" | awk '{print $2}')
    local mem_total=$(echo "$mem_info" | awk '{print $3}')
    
    if (( $(echo "$mem_percent > 85" | bc -l) 2>/dev/null )); then
        status_indicator "warning" "Memory: ${mem_percent}% (${mem_used}GB/${mem_total}GB) - High Usage"
    elif (( $(echo "$mem_percent > 70" | bc -l) 2>/dev/null )); then
        status_indicator "info" "Memory: ${mem_percent}% (${mem_used}GB/${mem_total}GB) - Medium Usage"
    else
        status_indicator "ok" "Memory: ${mem_percent}% (${mem_used}GB/${mem_total}GB) - Normal"
    fi
    
    # Disk Usage
    local disk_info
    disk_info=$(df / | awk 'NR==2 {print $5 " " $3/1024/1024 " " $2/1024/1024}' 2>/dev/null || echo "0% 0 0")
    local disk_percent=$(echo "$disk_info" | awk '{print $1}' | sed 's/%//')
    local disk_used=$(echo "$disk_info" | awk '{print $2}')
    local disk_total=$(echo "$disk_info" | awk '{print $3}')
    
    if [[ $disk_percent -gt 85 ]]; then
        status_indicator "warning" "Disk: ${disk_percent}% (${disk_used}GB/${disk_total}GB) - High Usage"
    elif [[ $disk_percent -gt 70 ]]; then
        status_indicator "info" "Disk: ${disk_percent}% (${disk_used}GB/${disk_total}GB) - Medium Usage"
    else
        status_indicator "ok" "Disk: ${disk_percent}% (${disk_used}GB/${disk_total}GB) - Normal"
    fi
    
    # Load Average
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ' 2>/dev/null || echo "0")
    if (( $(echo "$load_avg > 2.0" | bc -l) 2>/dev/null )); then
        status_indicator "warning" "Load Average: $load_avg (High)"
    elif (( $(echo "$load_avg > 1.0" | bc -l) 2>/dev/null )); then
        status_indicator "info" "Load Average: $load_avg (Medium)"
    else
        status_indicator "ok" "Load Average: $load_avg (Normal)"
    fi
}

# ============================================================================
# SERVICE STATUS
# ============================================================================
show_service_status() {
    print_section "Service Status"
    
    # Core services
    local services=(
        "nginx:NGINX Web Server"
        "tailscaled:Tailscale VPN"
    )
    
    # Add optional services if they exist
    systemctl is-enabled prometheus &>/dev/null && services+=("prometheus:Prometheus Monitoring")
    systemctl is-enabled prometheus-node-exporter &>/dev/null && services+=("prometheus-node-exporter:Node Exporter")
    systemctl is-enabled webhook-receiver &>/dev/null && services+=("webhook-receiver:GitHub Webhook Receiver")
    
    for service_info in "${services[@]}"; do
        local service_name="${service_info%%:*}"
        local service_desc="${service_info#*:}"
        
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            status_indicator "ok" "$service_desc: Running"
        elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
            status_indicator "warning" "$service_desc: Stopped (but enabled)"
        else
            status_indicator "error" "$service_desc: Disabled"
        fi
    done
}

# ============================================================================
# NETWORK STATUS
# ============================================================================
show_network_status() {
    print_section "Network Status"
    
    # Public IP
    local public_ip
    public_ip=$(curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || echo "Unable to determine")
    status_indicator "info" "Public IP: $public_ip"
    
    # Tailscale Status
    if command -v tailscale &>/dev/null; then
        if tailscale status >/dev/null 2>&1; then
            local ts_ip
            ts_ip=$(tailscale ip -4 2>/dev/null | head -n1)
            status_indicator "ok" "Tailscale: Connected ($ts_ip)"
        else
            status_indicator "warning" "Tailscale: Disconnected"
        fi
    else
        status_indicator "info" "Tailscale: Not installed"
    fi
    
    # DNS Resolution
    if nslookup "$DOMAIN_NAME" >/dev/null 2>&1; then
        local resolved_ip
        resolved_ip=$(nslookup "$DOMAIN_NAME" | awk '/^Address: / { print $2 }' | head -n1 2>/dev/null || echo "unknown")
        status_indicator "ok" "DNS Resolution: $DOMAIN_NAME → $resolved_ip"
    else
        status_indicator "warning" "DNS Resolution: Failed for $DOMAIN_NAME"
    fi
    
    # Internet Connectivity
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        status_indicator "ok" "Internet Connectivity: Online"
    else
        status_indicator "error" "Internet Connectivity: Offline"
    fi
}

# ============================================================================
# APPLICATION HEALTH
# ============================================================================
show_application_health() {
    print_section "Application Health"
    
    # HTTP Health Check
    local http_status
    http_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://localhost/health" 2>/dev/null || echo "000")
    if [[ "$http_status" =~ ^[23] ]]; then
        status_indicator "ok" "HTTP Health Check: Healthy (Status: $http_status)"
    else
        status_indicator "error" "HTTP Health Check: Unhealthy (Status: $http_status)"
    fi
    
    # HTTPS Health Check
    if [[ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]]; then
        local https_status
        https_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://localhost/health" 2>/dev/null || echo "000")
        if [[ "$https_status" =~ ^[23] ]]; then
            status_indicator "ok" "HTTPS Health Check: Healthy (Status: $https_status)"
        else
            status_indicator "warning" "HTTPS Health Check: Issues (Status: $https_status)"
        fi
    else
        status_indicator "info" "HTTPS: SSL certificate not found"
    fi
    
    # NGINX Configuration Test
    if nginx -t >/dev/null 2>&1; then
        status_indicator "ok" "NGINX Configuration: Valid"
    else
        status_indicator "error" "NGINX Configuration: Invalid"
    fi
    
    # Recent Error Logs
    if [[ -f "/var/log/nginx/error.log" ]]; then
        local recent_errors
        recent_errors=$(tail -50 /var/log/nginx/error.log 2>/dev/null | grep -c "$(date '+%Y/%m/%d')" || echo "0")
        if [[ $recent_errors -eq 0 ]]; then
            status_indicator "ok" "NGINX Errors (today): None"
        elif [[ $recent_errors -lt 10 ]]; then
            status_indicator "info" "NGINX Errors (today): $recent_errors (Low)"
        else
            status_indicator "warning" "NGINX Errors (today): $recent_errors (High)"
        fi
    fi
}

# ============================================================================
# SSL CERTIFICATE STATUS
# ============================================================================
show_ssl_status() {
    print_section "SSL Certificate Status"
    
    if [[ -d "/etc/letsencrypt/live" ]]; then
        local cert_found=false
        
        for cert_dir in /etc/letsencrypt/live/*/; do
            if [[ -d "$cert_dir" ]]; then
                cert_found=true
                local domain
                domain=$(basename "$cert_dir")
                
                if [[ -f "$cert_dir/fullchain.pem" ]]; then
                    # Get certificate expiration
                    local expire_date
                    expire_date=$(openssl x509 -enddate -noout -in "$cert_dir/fullchain.pem" 2>/dev/null | cut -d= -f2)
                    
                    if [[ -n "$expire_date" ]]; then
                        local expire_epoch
                        expire_epoch=$(date -d "$expire_date" +%s 2>/dev/null || echo "0")
                        local current_epoch
                        current_epoch=$(date +%s)
                        local days_left
                        days_left=$(( (expire_epoch - current_epoch) / 86400 ))
                        
                        if [[ $days_left -gt 30 ]]; then
                            status_indicator "ok" "$domain: Valid for $days_left days"
                        elif [[ $days_left -gt 7 ]]; then
                            status_indicator "warning" "$domain: Expires in $days_left days"
                        elif [[ $days_left -gt 0 ]]; then
                            status_indicator "error" "$domain: Expires in $days_left days (Critical)"
                        else
                            status_indicator "error" "$domain: Expired"
                        fi
                    else
                        status_indicator "error" "$domain: Unable to read expiration date"
                    fi
                else
                    status_indicator "error" "$domain: Certificate file missing"
                fi
            fi
        done
        
        if [[ "$cert_found" == "false" ]]; then
            status_indicator "info" "SSL Certificates: None found"
        fi
    else
        status_indicator "info" "SSL Certificates: Let's Encrypt not configured"
    fi
}

# ============================================================================
# DEPLOYMENT STATUS
# ============================================================================
show_deployment_status() {
    print_section "Deployment Status"
    
    # GitHub Repository Status
    if [[ -d "/opt/nginx-deployment/.git" ]]; then
        cd /opt/nginx-deployment
        
        local current_commit
        current_commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        local branch
        branch=$(git branch --show-current 2>/dev/null || echo "unknown")
        local last_commit_msg
        last_commit_msg=$(git log -1 --pretty=format:"%s" 2>/dev/null || echo "unknown")
        
        status_indicator "ok" "Repository: $GITHUB_REPO"
        status_indicator "info" "Branch: $branch"
        status_indicator "info" "Current Commit: $current_commit"
        status_indicator "info" "Last Commit: $last_commit_msg"
        
        # Check if working directory is clean
        if git diff --quiet 2>/dev/null; then
            status_indicator "ok" "Working Directory: Clean"
        else
            status_indicator "warning" "Working Directory: Has uncommitted changes"
        fi
        
        # Check for updates
        git fetch origin >/dev/null 2>&1 || true
        local commits_behind
        commits_behind=$(git rev-list --count HEAD..origin/$branch 2>/dev/null || echo "0")
        if [[ $commits_behind -eq 0 ]]; then
            status_indicator "ok" "Repository: Up to date"
        else
            status_indicator "info" "Repository: $commits_behind commit(s) behind origin"
        fi
    else
        status_indicator "warning" "Repository: Not configured or missing"
    fi
    
    # Last Deployment Status
    if [[ -f "$CONFIG_DIR/deployment-status.json" ]]; then
        local deploy_data
        deploy_data=$(cat "$CONFIG_DIR/deployment-status.json" 2>/dev/null)
        
        local last_status
        last_status=$(echo "$deploy_data" | jq -r '.status // "unknown"' 2>/dev/null)
        local last_timestamp
        last_timestamp=$(echo "$deploy_data" | jq -r '.timestamp // "unknown"' 2>/dev/null)
        local last_version
        last_version=$(echo "$deploy_data" | jq -r '.version // "unknown"' 2>/dev/null)
        
        case "$last_status" in
            "success")
                status_indicator "ok" "Last Deployment: Successful ($last_timestamp)"
                ;;
            "failed")
                status_indicator "error" "Last Deployment: Failed ($last_timestamp)"
                ;;
            *)
                status_indicator "info" "Last Deployment: $last_status ($last_timestamp)"
                ;;
        esac
        
        status_indicator "info" "Deployed Version: $last_version"
    else
        status_indicator "info" "Deployment History: No records found"
    fi
    
    # Recent Backups
    local recent_backups
    recent_backups=$(find /opt/backups -name "*.tar.gz" -mtime -1 2>/dev/null | wc -l)
    if [[ $recent_backups -gt 0 ]]; then
        status_indicator "ok" "Recent Backups: $recent_backups (last 24h)"
    else
        status_indicator "warning" "Recent Backups: None found (last 24h)"
    fi
}

# ============================================================================
# SECURITY STATUS
# ============================================================================
show_security_status() {
    print_section "Security Status"
    
    # Firewall Status
    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
            status_indicator "ok" "Firewall (UFW): Active"
        else
            status_indicator "warning" "Firewall (UFW): Inactive"
        fi
    else
        status_indicator "info" "Firewall: UFW not installed"
    fi
    
    # Fail2ban Status
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        local banned_ips
        banned_ips=$(fail2ban-client status 2>/dev/null | grep -c "Jail list:" || echo "0")
        status_indicator "ok" "Fail2ban: Active"
    elif systemctl is-enabled --quiet fail2ban 2>/dev/null; then
        status_indicator "warning" "Fail2ban: Installed but not running"
    else
        status_indicator "info" "Fail2ban: Not installed"
    fi
    
    # SSH Key Authentication
    if [[ -f "/home/github-deploy/.ssh/github_deploy.pub" ]]; then
        status_indicator "ok" "SSH Keys: GitHub deployment key configured"
    else
        status_indicator "info" "SSH Keys: GitHub deployment key not found"
    fi
    
    # Recent Authentication Failures
    local auth_failures
    auth_failures=$(journalctl --since="24 hours ago" | grep -c "authentication failure" 2>/dev/null || echo "0")
    if [[ $auth_failures -eq 0 ]]; then
        status_indicator "ok" "Authentication: No recent failures"
    elif [[ $auth_failures -lt 10 ]]; then
        status_indicator "info" "Authentication: $auth_failures failure(s) in last 24h"
    else
        status_indicator "warning" "Authentication: $auth_failures failure(s) in last 24h (High)"
    fi
}

# ============================================================================
# MONITORING STATUS
# ============================================================================
show_monitoring_status() {
    print_section "Monitoring Status"
    
    # Prometheus
    if command -v prometheus &>/dev/null && systemctl is-active --quiet prometheus 2>/dev/null; then
        status_indicator "ok" "Prometheus: Running (http://localhost:9090)"
    elif command -v prometheus &>/dev/null; then
        status_indicator "warning" "Prometheus: Installed but not running"
    else
        status_indicator "info" "Prometheus: Not installed"
    fi
    
    # Node Exporter
    if systemctl is-active --quiet prometheus-node-exporter 2>/dev/null; then
        status_indicator "ok" "Node Exporter: Running"
    elif systemctl is-enabled --quiet prometheus-node-exporter 2>/dev/null; then
        status_indicator "warning" "Node Exporter: Installed but not running"
    else
        status_indicator "info" "Node Exporter: Not installed"
    fi
    
    # Health Check Script
    if [[ -x "/opt/monitoring/health-check.sh" ]]; then
        if /opt/monitoring/health-check.sh >/dev/null 2>&1; then
            status_indicator "ok" "Health Checks: Passing"
        else
            status_indicator "warning" "Health Checks: Some issues detected"
        fi
    else
        status_indicator "info" "Health Checks: Script not found"
    fi
    
    # Log Files
    local log_size
    log_size=$(du -sh /var/log 2>/dev/null | cut -f1 || echo "unknown")
    status_indicator "info" "Log Directory Size: $log_size"
}

# ============================================================================
# MANAGEMENT COMMANDS
# ============================================================================
show_management_commands() {
    print_section "Management Commands"
    
    echo -e "${WHITE}System Management:${NC}"
    echo -e "  ${ARROW} ${CYAN}7gram-status${NC}                    - Show this status (you are here)"
    echo -e "  ${ARROW} ${CYAN}systemctl status nginx${NC}         - Check NGINX service status"
    echo -e "  ${ARROW} ${CYAN}systemctl reload nginx${NC}         - Reload NGINX configuration"
    echo -e "  ${ARROW} ${CYAN}nginx -t${NC}                       - Test NGINX configuration"
    
    echo -e "\n${WHITE}Deployment Commands:${NC}"
    echo -e "  ${ARROW} ${CYAN}sudo -u github-deploy /opt/nginx-deployment/deploy.sh${NC}"
    echo -e "      ${GRAY}Deploy latest changes from repository${NC}"
    echo -e "  ${ARROW} ${CYAN}sudo -u github-deploy /opt/nginx-deployment/deploy.sh rollback${NC}"
    echo -e "      ${GRAY}Rollback to previous deployment${NC}"
    echo -e "  ${ARROW} ${CYAN}sudo -u github-deploy /opt/nginx-deployment/deploy.sh status${NC}"
    echo -e "      ${GRAY}Show deployment status and history${NC}"
    
    echo -e "\n${WHITE}Backup Commands:${NC}"
    echo -e "  ${ARROW} ${CYAN}/opt/backups/backup-system.sh full${NC}"
    echo -e "      ${GRAY}Create full system backup${NC}"
    echo -e "  ${ARROW} ${CYAN}/opt/backups/backup-system.sh quick${NC}"
    echo -e "      ${GRAY}Create quick configuration backup${NC}"
    echo -e "  ${ARROW} ${CYAN}/opt/backups/restore-backup.sh${NC}"
    echo -e "      ${GRAY}Interactive backup restore${NC}"
    
    echo -e "\n${WHITE}Monitoring Commands:${NC}"
    echo -e "  ${ARROW} ${CYAN}/opt/monitoring/health-check.sh${NC}"
    echo -e "      ${GRAY}Run comprehensive health check${NC}"
    echo -e "  ${ARROW} ${CYAN}/opt/monitoring/dashboard.sh${NC}"
    echo -e "      ${GRAY}Show monitoring dashboard${NC}"
    echo -e "  ${ARROW} ${CYAN}tailscale-status${NC}"
    echo -e "      ${GRAY}Check Tailscale connection status${NC}"
    
    echo -e "\n${WHITE}SSL Management:${NC}"
    echo -e "  ${ARROW} ${CYAN}ssl-check${NC}                      - Check SSL certificate status"
    echo -e "  ${ARROW} ${CYAN}ssl-renew${NC}                      - Manually renew SSL certificates"
    echo -e "  ${ARROW} ${CYAN}certbot certificates${NC}           - List all certificates"
    
    echo -e "\n${WHITE}Log Files:${NC}"
    echo -e "  ${ARROW} ${CYAN}tail -f /var/log/nginx/access.log${NC}  - NGINX access logs"
    echo -e "  ${ARROW} ${CYAN}tail -f /var/log/nginx/error.log${NC}   - NGINX error logs"
    echo -e "  ${ARROW} ${CYAN}journalctl -u nginx -f${NC}             - NGINX service logs"
    echo -e "  ${ARROW} ${CYAN}journalctl -u webhook-receiver -f${NC}  - Webhook logs"
}

# ============================================================================
# QUICK ACTIONS
# ============================================================================
perform_quick_health_check() {
    echo -e "${YELLOW}Performing quick health check...${NC}\n"
    
    local issues=0
    
    # Check critical services
    if ! systemctl is-active --quiet nginx; then
        echo -e "${CROSS} NGINX is not running"
        ((issues++))
    fi
    
    if ! curl -sf http://localhost/health >/dev/null 2>&1; then
        echo -e "${CROSS} HTTP health check failed"
        ((issues++))
    fi
    
    if command -v tailscale &>/dev/null && ! tailscale status >/dev/null 2>&1; then
        echo -e "${WARNING} Tailscale is not connected"
        ((issues++))
    fi
    
    # Check disk space
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        echo -e "${CROSS} Disk usage critical: ${disk_usage}%"
        ((issues++))
    fi
    
    if [[ $issues -eq 0 ]]; then
        echo -e "${CHECK} ${GREEN}All critical systems are healthy${NC}"
        return 0
    else
        echo -e "${CROSS} ${RED}Found $issues issue(s)${NC}"
        echo -e "${INFO} Run '7gram-status' for detailed information"
        return 1
    fi
}

restart_services() {
    echo -e "${YELLOW}Restarting services...${NC}\n"
    
    local services=("nginx")
    
    # Add optional services if they exist and are enabled
    systemctl is-enabled tailscaled &>/dev/null && services+=("tailscaled")
    systemctl is-enabled webhook-receiver &>/dev/null && services+=("webhook-receiver")
    
    for service in "${services[@]}"; do
        echo -e "Restarting $service..."
        if systemctl restart "$service"; then
            echo -e "${CHECK} $service restarted successfully"
        else
            echo -e "${CROSS} Failed to restart $service"
        fi
    done
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================
show_full_status() {
    clear
    load_system_config
    
    show_system_overview
    show_resource_usage
    show_service_status
    show_network_status
    show_application_health
    show_ssl_status
    show_deployment_status
    show_security_status
    show_monitoring_status
    show_management_commands
    
    echo ""
    echo -e "${GRAY}Last updated: $(date)${NC}"
    echo -e "${GRAY}For more information, visit: https://github.com/$GITHUB_REPO${NC}"
    echo ""
}

show_usage() {
    echo "7gram Dashboard Status & Management Tool v$SCRIPT_VERSION"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  status, show     - Show full system status (default)"
    echo "  quick           - Quick health check"
    echo "  services        - Show service status only"
    echo "  network         - Show network status only"
    echo "  ssl             - Show SSL certificate status only"
    echo "  deployment      - Show deployment status only"
    echo "  restart         - Restart core services"
    echo "  help            - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0              # Show full status"
    echo "  $0 quick        # Quick health check"
    echo "  $0 services     # Service status only"
    echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    local command="${1:-status}"
    
    case "$command" in
        "status"|"show"|"")
            show_full_status
            ;;
        "quick")
            perform_quick_health_check
            ;;
        "services")
            load_system_config
            print_header "Service Status"
            show_service_status
            ;;
        "network")
            load_system_config
            print_header "Network Status"
            show_network_status
            ;;
        "ssl")
            load_system_config
            print_header "SSL Certificate Status"
            show_ssl_status
            ;;
        "deployment")
            load_system_config
            print_header "Deployment Status"
            show_deployment_status
            ;;
        "restart")
            restart_services
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            echo "Unknown command: $command"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Status check interrupted${NC}"; exit 0' INT

# Execute main function
main "$@"