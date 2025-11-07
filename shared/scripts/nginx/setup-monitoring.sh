#!/bin/bash
# setup-monitoring.sh - Monitoring stack setup (Prometheus, Node Exporter, etc.)
# Part of the modular StackScript system

set -euo pipefail

# ============================================================================
# SCRIPT METADATA
# ============================================================================
readonly SCRIPT_NAME="setup-monitoring"
readonly SCRIPT_VERSION="3.0.0"

# ============================================================================
# LOAD COMMON UTILITIES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_URL="${SCRIPT_BASE_URL:-}/utils/common.sh"

# Download and source common utilities
if [[ -f "$SCRIPT_DIR/utils/common.sh" ]]; then
    source "$SCRIPT_DIR/utils/common.sh"
else
    curl -fsSL "$UTILS_URL" -o /tmp/common.sh
    source /tmp/common.sh
fi

# ============================================================================
# MONITORING CONFIGURATION
# ============================================================================
setup_monitoring_directories() {
    log "Setting up monitoring directories..."
    
    local dirs=(
        "/etc/prometheus"
        "/var/lib/prometheus"
        "/var/lib/grafana"
        "/opt/monitoring"
        "/var/log/monitoring"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done
    
    # Create prometheus user if it doesn't exist
    if ! id prometheus &>/dev/null; then
        useradd -r -s /bin/false prometheus || true
    fi
    
    # Set ownership
    chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
    
    success "Monitoring directories created"
}

# ============================================================================
# PROMETHEUS SETUP
# ============================================================================
install_prometheus() {
    log "Installing Prometheus and Node Exporter..."
    
    # Try to install from official repositories first
    local packages=("prometheus" "prometheus-node-exporter")
    local installed_packages=()
    
    for pkg in "${packages[@]}"; do
        if pacman -S --needed --noconfirm "$pkg" 2>/dev/null; then
            installed_packages+=("$pkg")
            success "Installed $pkg from official repository"
        else
            warning "Failed to install $pkg from official repository"
            
            # Try AUR if yay is available
            if command -v yay &>/dev/null; then
                if sudo -u builder yay -S --noconfirm "$pkg" 2>/dev/null; then
                    installed_packages+=("$pkg")
                    success "Installed $pkg from AUR"
                else
                    warning "Failed to install $pkg from AUR"
                fi
            fi
        fi
    done
    
    if [[ ${#installed_packages[@]} -eq 0 ]]; then
        warning "No monitoring packages installed, will create manual setup"
        create_manual_monitoring_setup
        return 1
    fi
    
    success "Monitoring packages installation completed"
}

create_manual_monitoring_setup() {
    log "Creating manual monitoring setup..."
    
    # Create basic monitoring script since packages failed
    cat > /opt/monitoring/basic-monitor.sh << 'EOF'
#!/bin/bash
# Basic monitoring script when prometheus is not available

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/monitoring/basic-monitor.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

# System metrics collection
collect_metrics() {
    local timestamp=$(date +%s)
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    # Memory usage
    local mem_total=$(free -b | awk '/^Mem:/{print $2}')
    local mem_used=$(free -b | awk '/^Mem:/{print $3}')
    local mem_percent=$(awk "BEGIN {printf \"%.1f\", ($mem_used/$mem_total)*100}")
    
    # Disk usage
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # Load average
    local load_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    
    # Network connections
    local connections=$(ss -tun | wc -l)
    
    # NGINX status
    local nginx_status=0
    if systemctl is-active --quiet nginx; then
        nginx_status=1
    fi
    
    # Create metrics output
    cat > /var/log/monitoring/metrics.txt << EOL
# Basic system metrics - $(date)
cpu_usage_percent $cpu_usage
memory_usage_percent $mem_percent
disk_usage_percent $disk_usage
load_average_1m $load_1
network_connections $connections
nginx_running $nginx_status
EOL
    
    log "Metrics collected: CPU=${cpu_usage}%, MEM=${mem_percent}%, DISK=${disk_usage}%, LOAD=${load_1}"
}

# Main execution
collect_metrics
EOF
    
    chmod +x /opt/monitoring/basic-monitor.sh
    
    # Add to cron every minute
    (crontab -l 2>/dev/null; echo "* * * * * /opt/monitoring/basic-monitor.sh >/dev/null 2>&1") | crontab -
    
    success "Basic monitoring setup created"
}

configure_prometheus() {
    if ! command -v prometheus &>/dev/null; then
        log "Prometheus not available, skipping configuration"
        return 0
    fi
    
    log "Configuring Prometheus..."
    
    # Download template or create inline
    if ! download_template "monitoring/prometheus.yml" "/tmp/prometheus.yml.template"; then
        create_inline_prometheus_config
    else
        substitute_template "/tmp/prometheus.yml.template" "/etc/prometheus/prometheus.yml"
    fi
    
    # Set ownership
    chown prometheus:prometheus /etc/prometheus/prometheus.yml
    
    success "Prometheus configuration created"
}

create_inline_prometheus_config() {
    log "Creating inline Prometheus configuration..."
    
    cat > /etc/prometheus/prometheus.yml << 'EOF'
# Prometheus configuration for 7gram Dashboard
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: '7gram-dashboard'

# Rule files
rule_files:
  - "/etc/prometheus/rules/*.yml"

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    metrics_path: /metrics

  # Node Exporter
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s
    metrics_path: /metrics

  # NGINX metrics
  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 15s
    metrics_path: /nginx_status
    params:
      format: ['prometheus']

  # Application health
  - job_name: 'app-health'
    static_configs:
      - targets: ['localhost:80']
    scrape_interval: 30s
    metrics_path: /health
    scheme: http

  # SSL certificate monitoring
  - job_name: 'ssl-certs'
    static_configs:
      - targets: ['localhost:443']
    scrape_interval: 3600s  # Check hourly
    metrics_path: /
    scheme: https
    tls_config:
      insecure_skip_verify: true

# Alerting configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: []

# Storage configuration
storage:
  tsdb:
    path: /var/lib/prometheus
    retention.time: 30d
    retention.size: 1GB
EOF
    
    success "Inline Prometheus configuration created"
}

create_prometheus_rules() {
    if ! command -v prometheus &>/dev/null; then
        return 0
    fi
    
    log "Creating Prometheus alerting rules..."
    
    mkdir -p /etc/prometheus/rules
    
    cat > /etc/prometheus/rules/basic-alerts.yml << 'EOF'
groups:
  - name: basic-alerts
    rules:
      # High CPU usage
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"

      # High memory usage
      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% for more than 5 minutes"

      # Low disk space
      - alert: LowDiskSpace
        expr: (1 - (node_filesystem_avail_bytes{fstype!="tmpfs"} / node_filesystem_size_bytes{fstype!="tmpfs"})) * 100 > 85
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Disk usage is above 85%"

      # NGINX down
      - alert: NginxDown
        expr: up{job="nginx"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NGINX is down"
          description: "NGINX service is not responding"

      # SSL certificate expiring
      - alert: SSLCertificateExpiring
        expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 7
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSL certificate expiring soon"
          description: "SSL certificate expires in less than 7 days"
EOF
    
    chown -R prometheus:prometheus /etc/prometheus/rules
    
    success "Prometheus alerting rules created"
}

# ============================================================================
# NGINX MONITORING INTEGRATION
# ============================================================================
configure_nginx_monitoring() {
    log "Configuring NGINX monitoring integration..."
    
    # Create NGINX prometheus exporter configuration
    cat > /etc/nginx/conf.d/metrics.conf << 'EOF'
# Metrics and monitoring endpoints
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    
    access_log off;
    
    # NGINX status for Prometheus
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        deny all;
    }
    
    # Basic Prometheus metrics endpoint
    location /metrics {
        access_log off;
        return 200 "# NGINX Metrics\nnginx_up 1\nnginx_connections_active $(curl -s http://127.0.0.1:8080/nginx_status | awk 'NR==1 {print $3}')\n";
        add_header Content-Type text/plain;
        allow 127.0.0.1;
        deny all;
    }
    
    # Health check endpoint for monitoring
    location /health-detailed {
        access_log off;
        return 200 '{"status":"healthy","timestamp":"$time_iso8601","version":"nginx/$nginx_version","connections_active":"$connections_active","connections_reading":"$connections_reading","connections_writing":"$connections_writing","connections_waiting":"$connections_waiting"}';
        add_header Content-Type application/json;
        allow 127.0.0.1;
        deny all;
    }
}
EOF
    
    success "NGINX monitoring configuration created"
}

# ============================================================================
# HEALTH CHECK SYSTEM
# ============================================================================
create_comprehensive_health_check() {
    log "Creating comprehensive health check system..."
    
    cat > /opt/monitoring/health-check.sh << 'EOF'
#!/bin/bash
# Comprehensive health check script for 7gram Dashboard

set -euo pipefail

# Configuration
SERVICES=("nginx" "tailscaled")
ENDPOINTS=("http://localhost/health" "http://localhost/status")
WEBHOOK_URL="${DISCORD_WEBHOOK:-}"
LOG_FILE="/var/log/monitoring/health-check.log"
STATUS_FILE="/tmp/health-status.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
mkdir -p "$(dirname "$LOG_FILE")"
log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }

# Add monitoring services if they exist
command -v prometheus &>/dev/null && systemctl is-enabled prometheus &>/dev/null && SERVICES+=("prometheus")
command -v prometheus &>/dev/null && systemctl is-enabled prometheus-node-exporter &>/dev/null && SERVICES+=("prometheus-node-exporter")
systemctl is-enabled webhook-receiver &>/dev/null && SERVICES+=("webhook-receiver")

# Health check functions
check_service() {
    local service="$1"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        success "Service $service is running"
        return 0
    else
        error "Service $service is not running"
        return 1
    fi
}

check_endpoint() {
    local url="$1"
    local timeout="${2:-5}"
    
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null)
    
    if [[ "$response" =~ ^[23] ]]; then
        success "Endpoint $url responded with $response"
        return 0
    else
        error "Endpoint $url returned $response"
        return 1
    fi
}

check_ssl_certificate() {
    local domain="${DOMAIN_NAME:-7gram.xyz}"
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    
    if [[ ! -f "$cert_path" ]]; then
        warning "SSL certificate not found for $domain"
        return 1
    fi
    
    # Check expiration
    local expire_date
    expire_date=$(openssl x509 -in "$cert_path" -enddate -noout | cut -d= -f2)
    local expire_epoch
    expire_epoch=$(date -d "$expire_date" +%s)
    local current_epoch
    current_epoch=$(date +%s)
    local days_left
    days_left=$(( (expire_epoch - current_epoch) / 86400 ))
    
    if [[ $days_left -gt 7 ]]; then
        success "SSL certificate valid for $days_left days"
        return 0
    elif [[ $days_left -gt 0 ]]; then
        warning "SSL certificate expires in $days_left days"
        return 1
    else
        error "SSL certificate has expired"
        return 2
    fi
}

check_disk_space() {
    local threshold=85
    local usage
    usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ $usage -lt $threshold ]]; then
        success "Disk usage is $usage% (threshold: $threshold%)"
        return 0
    else
        error "Disk usage is $usage% (exceeds threshold: $threshold%)"
        return 1
    fi
}

check_memory_usage() {
    local threshold=85
    local usage
    usage=$(free | awk '/^Mem:/ {printf "%.0f", ($3/$2)*100}')
    
    if [[ $usage -lt $threshold ]]; then
        success "Memory usage is $usage% (threshold: $threshold%)"
        return 0
    else
        warning "Memory usage is $usage% (exceeds threshold: $threshold%)"
        return 1
    fi
}

check_load_average() {
    local threshold=2.0
    local load
    load=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    
    if (( $(echo "$load < $threshold" | bc -l) )); then
        success "Load average is $load (threshold: $threshold)"
        return 0
    else
        warning "Load average is $load (exceeds threshold: $threshold)"
        return 1
    fi
}

check_network_connectivity() {
    local targets=("8.8.8.8" "1.1.1.1")
    local failures=0
    
    for target in "${targets[@]}"; do
        if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
            success "Network connectivity to $target: OK"
        else
            error "Network connectivity to $target: Failed"
            ((failures++))
        fi
    done
    
    return $failures
}

check_tailscale_connectivity() {
    if ! command -v tailscale &>/dev/null; then
        warning "Tailscale not installed"
        return 1
    fi
    
    if tailscale status >/dev/null 2>&1; then
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null | head -n1)
        success "Tailscale connected: $ts_ip"
        return 0
    else
        error "Tailscale not connected"
        return 1
    fi
}

# Monitoring metrics collection
collect_system_metrics() {
    local metrics=()
    
    # CPU usage
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    metrics+=("cpu_usage_percent:$cpu_usage")
    
    # Memory usage
    local mem_usage
    mem_usage=$(free | awk '/^Mem:/ {printf "%.1f", ($3/$2)*100}')
    metrics+=("memory_usage_percent:$mem_usage")
    
    # Disk usage
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    metrics+=("disk_usage_percent:$disk_usage")
    
    # Load average
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    metrics+=("load_average_1m:$load_avg")
    
    # Network connections
    local connections
    connections=$(ss -tun | wc -l)
    metrics+=("network_connections:$connections")
    
    # Export metrics
    for metric in "${metrics[@]}"; do
        echo "$metric"
    done
}

# Generate health report
generate_health_report() {
    local total_checks=0
    local failed_checks=0
    local warnings=0
    
    echo "=== 7gram Dashboard Health Check Report ==="
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo ""
    
    echo "Service Status:"
    for service in "${SERVICES[@]}"; do
        ((total_checks++))
        if ! check_service "$service"; then
            ((failed_checks++))
        fi
    done
    
    echo ""
    echo "Endpoint Health:"
    for endpoint in "${ENDPOINTS[@]}"; do
        ((total_checks++))
        if ! check_endpoint "$endpoint"; then
            ((failed_checks++))
        fi
    done
    
    echo ""
    echo "System Health:"
    
    ((total_checks++))
    if ! check_disk_space; then
        ((failed_checks++))
    fi
    
    ((total_checks++))
    if ! check_memory_usage; then
        ((warnings++))
    fi
    
    ((total_checks++))
    if ! check_load_average; then
        ((warnings++))
    fi
    
    echo ""
    echo "Network Connectivity:"
    
    ((total_checks++))
    if ! check_network_connectivity; then
        ((failed_checks++))
    fi
    
    ((total_checks++))
    if ! check_tailscale_connectivity; then
        ((warnings++))
    fi
    
    echo ""
    echo "SSL Certificate:"
    
    ((total_checks++))
    ssl_result=$(check_ssl_certificate; echo $?)
    case $ssl_result in
        1) ((warnings++)) ;;
        2) ((failed_checks++)) ;;
    esac
    
    echo ""
    echo "System Metrics:"
    collect_system_metrics | while IFS=: read -r key value; do
        echo "  $key: $value"
    done
    
    echo ""
    echo "Summary:"
    echo "  Total checks: $total_checks"
    echo "  Failed: $failed_checks"
    echo "  Warnings: $warnings"
    echo "  Passed: $((total_checks - failed_checks - warnings))"
    
    # Save status to file
    cat > "$STATUS_FILE" << EOL
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "total_checks": $total_checks,
    "failed_checks": $failed_checks,
    "warnings": $warnings,
    "passed_checks": $((total_checks - failed_checks - warnings)),
    "status": "$([ $failed_checks -eq 0 ] && echo "healthy" || echo "unhealthy")"
}
EOL
    
    # Send notification if there are failures
    if [[ $failed_checks -gt 0 ]] && [[ -n "$WEBHOOK_URL" ]]; then
        send_health_notification "$failed_checks" "$warnings" "$total_checks"
    fi
    
    return "$failed_checks"
}

send_health_notification() {
    local failed="$1"
    local warnings="$2" 
    local total="$3"
    
    local color="15158332"  # Red
    local emoji="🚨"
    
    if [[ $failed -eq 0 ]] && [[ $warnings -gt 0 ]]; then
        color="16776960"  # Yellow
        emoji="⚠️"
    fi
    
    local message="$emoji Health Check Alert

**Failed Checks:** $failed
**Warnings:** $warnings
**Total Checks:** $total
**Hostname:** $(hostname)
**Timestamp:** $(date)

Please check the system status and logs."
    
    curl -s -H "Content-Type: application/json" \
        -d "{\"embeds\":[{\"title\":\"Health Check Alert\",\"description\":\"$message\",\"color\":$color}]}" \
        "$WEBHOOK_URL" >/dev/null 2>&1 || true
}

# Main execution
main() {
    log "Starting comprehensive health check..."
    
    if generate_health_report; then
        success "Health check completed - system is healthy"
        exit 0
    else
        error "Health check completed - issues detected"
        exit 1
    fi
}

# Command line options
case "${1:-check}" in
    check)
        main
        ;;
    metrics)
        collect_system_metrics
        ;;
    status)
        if [[ -f "$STATUS_FILE" ]]; then
            cat "$STATUS_FILE"
        else
            echo '{"status": "unknown", "message": "No status file found"}'
        fi
        ;;
    *)
        echo "Usage: $0 [check|metrics|status]"
        echo ""
        echo "Commands:"
        echo "  check   - Run full health check (default)"
        echo "  metrics - Collect system metrics only"
        echo "  status  - Show last health check status"
        exit 1
        ;;
esac
EOF
    
    chmod +x /opt/monitoring/health-check.sh
    
    # Add to cron every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/monitoring/health-check.sh >/dev/null 2>&1") | crontab -
    
    success "Comprehensive health check system created"
}

# ============================================================================
# MONITORING DASHBOARD
# ============================================================================
create_monitoring_dashboard() {
    log "Creating monitoring dashboard..."
    
    cat > /opt/monitoring/dashboard.sh << 'EOF'
#!/bin/bash
# Simple monitoring dashboard

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_system_overview() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}                          ${CYAN}7gram Dashboard Monitoring${NC}                          ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} Generated: $(date)                                          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} Hostname: $(hostname -f)                                             ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # System Information
    echo -e "${CYAN}System Information:${NC}"
    echo "  OS: $(lsb_release -ds 2>/dev/null || echo 'Unknown')"
    echo "  Kernel: $(uname -r)"
    echo "  Uptime: $(uptime -p)"
    echo ""
    
    # Resource Usage
    echo -e "${CYAN}Resource Usage:${NC}"
    
    # CPU
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    printf "  CPU: %6.1f%% " "$cpu_usage"
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        echo -e "${RED}[HIGH]${NC}"
    elif (( $(echo "$cpu_usage > 60" | bc -l) )); then
        echo -e "${YELLOW}[MEDIUM]${NC}"
    else
        echo -e "${GREEN}[NORMAL]${NC}"
    fi
    
    # Memory
    local mem_info=$(free | awk '/^Mem:/ {printf "%.1f %.1f", ($3/$2)*100, $2/1024/1024}')
    local mem_usage=$(echo "$mem_info" | awk '{print $1}')
    local mem_total=$(echo "$mem_info" | awk '{print $2}')
    printf "  RAM: %6.1f%% of %.1fGB " "$mem_usage" "$mem_total"
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        echo -e "${RED}[HIGH]${NC}"
    elif (( $(echo "$mem_usage > 70" | bc -l) )); then
        echo -e "${YELLOW}[MEDIUM]${NC}"
    else
        echo -e "${GREEN}[NORMAL]${NC}"
    fi
    
    # Disk
    local disk_info=$(df / | awk 'NR==2 {print $5 " " $2/1024/1024}')
    local disk_usage=$(echo "$disk_info" | awk '{print $1}' | sed 's/%//')
    local disk_total=$(echo "$disk_info" | awk '{print $2}')
    printf "  Disk: %5s%% of %.1fGB " "$disk_usage" "$disk_total"
    if [[ $disk_usage -gt 85 ]]; then
        echo -e "${RED}[HIGH]${NC}"
    elif [[ $disk_usage -gt 70 ]]; then
        echo -e "${YELLOW}[MEDIUM]${NC}"
    else
        echo -e "${GREEN}[NORMAL]${NC}"
    fi
    
    # Load Average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    printf "  Load: %6s " "$load_avg"
    if (( $(echo "$load_avg > 2.0" | bc -l) )); then
        echo -e "${RED}[HIGH]${NC}"
    elif (( $(echo "$load_avg > 1.0" | bc -l) )); then
        echo -e "${YELLOW}[MEDIUM]${NC}"
    else
        echo -e "${GREEN}[NORMAL]${NC}"
    fi
    
    echo ""
    
    # Service Status
    echo -e "${CYAN}Service Status:${NC}"
    local services=("nginx" "tailscaled" "prometheus" "prometheus-node-exporter" "webhook-receiver")
    
    for service in "${services[@]}"; do
        printf "  %-20s " "$service:"
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "${GREEN}[RUNNING]${NC}"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo -e "${YELLOW}[STOPPED]${NC}"
        else
            echo -e "${RED}[DISABLED]${NC}"
        fi
    done
    
    echo ""
    
    # Network Status
    echo -e "${CYAN}Network Status:${NC}"
    
    # Tailscale
    if command -v tailscale &>/dev/null; then
        local ts_status="DISCONNECTED"
        local ts_ip="N/A"
        if tailscale status >/dev/null 2>&1; then
            ts_status="CONNECTED"
            ts_ip=$(tailscale ip -4 2>/dev/null | head -n1)
        fi
        printf "  %-15s %s" "Tailscale:" "$ts_status"
        if [[ "$ts_status" == "CONNECTED" ]]; then
            echo -e " ${GREEN}($ts_ip)${NC}"
        else
            echo -e " ${RED}${NC}"
        fi
    fi
    
    # Public IP
    local public_ip=$(curl -s --max-time 5 ipinfo.io/ip 2>/dev/null || echo "Unknown")
    echo "  Public IP:      $public_ip"
    
    echo ""
    
    # Application Health
    echo -e "${CYAN}Application Health:${NC}"
    
    # HTTP Health Check
    printf "  %-15s " "HTTP:"
    if curl -sf http://localhost/health >/dev/null 2>&1; then
        echo -e "${GREEN}[HEALTHY]${NC}"
    else
        echo -e "${RED}[UNHEALTHY]${NC}"
    fi
    
    # HTTPS Health Check
    if [[ -f "/etc/letsencrypt/live/$(hostname)/fullchain.pem" ]]; then
        printf "  %-15s " "HTTPS:"
        if curl -sf https://localhost/health >/dev/null 2>&1; then
            echo -e "${GREEN}[HEALTHY]${NC}"
        else
            echo -e "${RED}[UNHEALTHY]${NC}"
        fi
    fi
    
    echo ""
    
    # Recent Activity
    echo -e "${CYAN}Recent Activity:${NC}"
    echo "  Last 5 log entries:"
    tail -5 /var/log/monitoring/health-check.log 2>/dev/null | sed 's/^/    /' || echo "    No logs available"
    
    echo ""
    echo -e "${BLUE}Press Ctrl+C to exit, or wait for auto-refresh...${NC}"
}

# Main loop
main() {
    local refresh_interval=30
    
    while true; do
        show_system_overview
        sleep "$refresh_interval"
    done
}

# Handle command line arguments
case "${1:-dashboard}" in
    dashboard)
        main
        ;;
    once)
        show_system_overview
        ;;
    *)
        echo "Usage: $0 [dashboard|once]"
        echo ""
        echo "Commands:"
        echo "  dashboard - Show real-time dashboard (default)"
        echo "  once      - Show dashboard once and exit"
        exit 1
        ;;
esac
EOF
    
    chmod +x /opt/monitoring/dashboard.sh
    
    success "Monitoring dashboard created"
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================
enable_monitoring_services() {
    log "Enabling monitoring services..."
    
    local services=()
    
    # Add services that were successfully installed
    if command -v prometheus &>/dev/null; then
        services+=("prometheus")
    fi
    
    if systemctl list-unit-files prometheus-node-exporter.service &>/dev/null; then
        services+=("prometheus-node-exporter")
    fi
    
    # Enable services
    for service in "${services[@]}"; do
        if systemctl enable "$service" 2>/dev/null; then
            success "Enabled service: $service"
        else
            warning "Failed to enable service: $service"
        fi
    done
    
    success "Monitoring services configuration completed"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log "Starting monitoring setup..."
    
    # Check if monitoring is enabled
    if [[ "${ENABLE_MONITORING:-true}" != "true" ]]; then
        log "Monitoring is disabled, skipping monitoring setup"
        save_completion_status "$SCRIPT_NAME" "skipped" "Monitoring disabled"
        return 0
    fi
    
    # Setup monitoring infrastructure
    setup_monitoring_directories
    
    # Install monitoring tools
    install_prometheus
    configure_prometheus
    create_prometheus_rules
    
    # Configure NGINX integration
    configure_nginx_monitoring
    
    # Create health check system
    create_comprehensive_health_check
    
    # Create monitoring dashboard
    create_monitoring_dashboard
    
    # Enable services
    enable_monitoring_services
    
    # Save completion status
    save_completion_status "$SCRIPT_NAME" "success"
    
    success "Monitoring setup completed successfully"
    log "Use '/opt/monitoring/health-check.sh' for health checks"
    log "Use '/opt/monitoring/dashboard.sh' for monitoring dashboard"
    log "Prometheus available at: http://localhost:9090 (if installed)"
}

# Execute main function
main "$@"