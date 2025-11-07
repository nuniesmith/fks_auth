#!/bin/bash
# filepath: fks/health.sh
# FKS Trading Systems - Health Check System (Refactored)
# Comprehensive system health monitoring and diagnostics

# Prevent multiple sourcing
[[ -n "${FKS_HEALTH_LOADED:-}" ]] && return 0
readonly FKS_HEALTH_LOADED=1

# Module metadata
readonly HEALTH_MODULE_VERSION="3.0.0"
readonly HEALTH_MODULE_NAME="FKS Health System"

# Health check configuration
readonly HEALTH_CONFIG_FILE="config/health.yaml"
readonly HEALTH_REPORTS_DIR="reports/health"
readonly HEALTH_LOGS_DIR="logs/health"
readonly HEALTH_ARCHIVE_DIR="archive/health"

# Default thresholds
declare -A HEALTH_THRESHOLDS=(
    ["memory_warning"]=80
    ["memory_critical"]=90
    ["disk_warning"]=80
    ["disk_critical"]=90
    ["cpu_warning"]=80
    ["cpu_critical"]=90
    ["overall_warning"]=70
    ["overall_critical"]=50
)

# Health check categories with weights
declare -A HEALTH_CATEGORIES=(
    ["system"]=20
    ["configuration"]=15
    ["docker"]=20
    ["python"]=15
    ["services"]=15
    ["security"]=10
    ["performance"]=5
)

# Health check results
declare -A HEALTH_RESULTS=()
declare -A HEALTH_SCORES=()

# Initialize health system
init_health_system() {
    # Create required directories
    mkdir -p "$HEALTH_REPORTS_DIR" "$HEALTH_LOGS_DIR" "$HEALTH_ARCHIVE_DIR"
    
    # Load configuration if exists
    [[ -f "$HEALTH_CONFIG_FILE" ]] && load_health_config
    
    # Initialize logging
    local log_file="$HEALTH_LOGS_DIR/health_$(date +%Y%m%d_%H%M%S).log"
    exec 3>&1 4>&2
    exec 1> >(tee -a "$log_file")
    exec 2> >(tee -a "$log_file" >&2)
    
    log_debug "Health system initialized"
}

# Load health configuration
load_health_config() {
    if command -v yq >/dev/null 2>&1 && [[ -f "$HEALTH_CONFIG_FILE" ]]; then
        # Load thresholds from config
        while IFS= read -r line; do
            if [[ $line =~ ^([^:]+):[[:space:]]*([0-9]+)$ ]]; then
                HEALTH_THRESHOLDS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            fi
        done < <(yq eval '.thresholds | to_entries | .[] | .key + ":" + (.value | tostring)' "$HEALTH_CONFIG_FILE" 2>/dev/null)
    fi
}

# Main health check orchestrator
comprehensive_health_check() {
    log_info "🏥 ${HEALTH_MODULE_NAME} - Comprehensive Health Check"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    init_health_system
    
    local start_time=$(date +%s)
    local report_file="$HEALTH_REPORTS_DIR/health_report_$(date +%Y%m%d_%H%M%S).txt"
    
    # Initialize report
    init_health_report "$report_file"
    
    # Run health checks
    local total_score=0
    local max_score=0
    
    for category in "${!HEALTH_CATEGORIES[@]}"; do
        local weight=${HEALTH_CATEGORIES[$category]}
        log_section "$(capitalize_string "$category") Health"
        
        local score
        score=$(run_health_check "$category" "$report_file")
        
        HEALTH_SCORES[$category]=$score
        total_score=$((total_score + score * weight / 100))
        max_score=$((max_score + weight))
    done
    
    # Generate final report
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    generate_health_summary "$total_score" "$max_score" "$duration" "$report_file"
    save_health_data "$total_score" "$max_score"
    
    log_success "✅ Health check completed! Report: $report_file"
    
    # Return based on overall health
    local health_percentage=$((total_score * 100 / max_score))
    [[ $health_percentage -ge ${HEALTH_THRESHOLDS[overall_warning]} ]]
}

# Run specific health check
run_health_check() {
    local category=$1
    local report_file=$2
    
    case $category in
        "system") check_system_health "$report_file" ;;
        "configuration") check_configuration_health "$report_file" ;;
        "docker") check_docker_health "$report_file" ;;
        "python") check_python_health "$report_file" ;;
        "services") check_service_health "$report_file" ;;
        "security") check_security_health "$report_file" ;;
        "performance") check_performance_health "$report_file" ;;
        *) 
            log_error "Unknown health check category: $category"
            echo 0
            return
            ;;
    esac
}

# System health check
check_system_health() {
    local report_file=$1
    local score=0
    
    log_to_report "System Health Check" "$report_file"
    log_to_report "===================" "$report_file"
    
    # OS Information
    local os_info="$(uname -s -r)"
    local arch="$(uname -m)"
    log_to_report "OS: $os_info ($arch)" "$report_file"
    score=$((score + 10))
    
    # Memory check
    local mem_result
    mem_result=$(check_memory_usage)
    log_to_report "$mem_result" "$report_file"
    
    case $mem_result in
        *"✅"*) score=$((score + 30)) ;;
        *"⚠️"*) score=$((score + 20)) ;;
        *"❌"*) score=$((score + 10)) ;;
    esac
    
    # Disk space check
    local disk_result
    disk_result=$(check_disk_usage)
    log_to_report "$disk_result" "$report_file"
    
    case $disk_result in
        *"✅"*) score=$((score + 30)) ;;
        *"⚠️"*) score=$((score + 20)) ;;
        *"❌"*) score=$((score + 10)) ;;
    esac
    
    # CPU load check
    local cpu_result
    cpu_result=$(check_cpu_load)
    log_to_report "$cpu_result" "$report_file"
    
    case $cpu_result in
        *"✅"*) score=$((score + 30)) ;;
        *"⚠️"*) score=$((score + 20)) ;;
        *"❌"*) score=$((score + 10)) ;;
    esac
    
    log_to_report "" "$report_file"
    log_to_report "System Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Configuration health check
check_configuration_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Configuration Health Check" "$report_file"
    log_to_report "==========================" "$report_file"
    
    # Check critical configuration files
    local config_files=(
        "docker-compose.yml:Docker Compose:25"
        ".env:Environment Variables:20"
        "config/app.yaml:Application Config:20"
        "requirements.txt:Python Requirements:15"
        "Dockerfile:Docker Image:10"
    )
    
    for config_spec in "${config_files[@]}"; do
        IFS=':' read -r file desc points <<< "$config_spec"
        
        if [[ -f "$file" ]]; then
            log_to_report "✅ $desc: Found" "$report_file"
            score=$((score + points))
            
            # Syntax validation for YAML files
            if [[ "$file" =~ \.ya?ml$ ]] && command -v yq >/dev/null 2>&1; then
                if yq eval 'true' "$file" >/dev/null 2>&1; then
                    log_to_report "  ✅ Valid YAML syntax" "$report_file"
                else
                    log_to_report "  ❌ Invalid YAML syntax" "$report_file"
                    score=$((score - 5))
                fi
            fi
        else
            log_to_report "❌ $desc: Missing ($file)" "$report_file"
            score=$((score + 5))
        fi
    done
    
    # Additional configuration checks
    score=$((score + $(check_configuration_security "$report_file")))
    
    log_to_report "" "$report_file"
    log_to_report "Configuration Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Docker health check
check_docker_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Docker Health Check" "$report_file"
    log_to_report "===================" "$report_file"
    
    # Docker installation check
    if command -v docker >/dev/null 2>&1; then
        log_to_report "✅ Docker installed" "$report_file"
        score=$((score + 20))
        
        # Docker daemon check
        if docker info >/dev/null 2>&1; then
            log_to_report "✅ Docker daemon running" "$report_file"
            score=$((score + 20))
            
            # Docker version
            local docker_version
            docker_version=$(docker --version | awk '{print $3}' | tr -d ',')
            log_to_report "Docker Version: $docker_version" "$report_file"
            score=$((score + 10))
            
            # Docker Compose check
            score=$((score + $(check_docker_compose "$report_file")))
            
            # Container status
            score=$((score + $(check_docker_containers "$report_file")))
            
            # Resource usage
            score=$((score + $(check_docker_resources "$report_file")))
            
        else
            log_to_report "❌ Docker daemon not running" "$report_file"
            score=$((score + 10))
        fi
    else
        log_to_report "❌ Docker not installed" "$report_file"
        score=$((score + 5))
    fi
    
    log_to_report "" "$report_file"
    log_to_report "Docker Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Python health check
check_python_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Python Health Check" "$report_file"
    log_to_report "===================" "$report_file"
    
    # Python installation
    if command -v python3 >/dev/null 2>&1; then
        local python_version
        python_version=$(python3 --version | awk '{print $2}')
        log_to_report "✅ Python3 installed: $python_version" "$report_file"
        score=$((score + 20))
        
        # Version compatibility
        score=$((score + $(check_python_version "$python_version" "$report_file")))
        
        # Package manager
        score=$((score + $(check_python_pip "$report_file")))
        
        # Virtual environment
        score=$((score + $(check_python_environment "$report_file")))
        
        # Critical packages
        score=$((score + $(check_python_packages "$report_file")))
        
    else
        log_to_report "❌ Python3 not found" "$report_file"
        score=$((score + 5))
    fi
    
    log_to_report "" "$report_file"
    log_to_report "Python Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Service health check
check_service_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Service Health Check" "$report_file"
    log_to_report "====================" "$report_file"
    
    # Docker Compose services
    if [[ -f "docker-compose.yml" ]]; then
        log_to_report "✅ Docker Compose file found" "$report_file"
        score=$((score + 20))
        
        # Service definitions
        score=$((score + $(check_service_definitions "$report_file")))
        
        # Running services
        score=$((score + $(check_running_services "$report_file")))
        
        # Service endpoints
        score=$((score + $(check_service_endpoints "$report_file")))
        
    else
        log_to_report "❌ Docker Compose file not found" "$report_file"
        score=$((score + 10))
    fi
    
    log_to_report "" "$report_file"
    log_to_report "Service Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Security health check
check_security_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Security Health Check" "$report_file"
    log_to_report "=====================" "$report_file"
    
    # File permissions
    score=$((score + $(check_file_permissions "$report_file")))
    
    # Sensitive data exposure
    score=$((score + $(check_sensitive_data "$report_file")))
    
    # Network security
    score=$((score + $(check_network_security "$report_file")))
    
    # Container security
    score=$((score + $(check_container_security "$report_file")))
    
    log_to_report "" "$report_file"
    log_to_report "Security Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Performance health check
check_performance_health() {
    local report_file=$1
    local score=0
    
    log_to_report "Performance Health Check" "$report_file"
    log_to_report "========================" "$report_file"
    
    # System performance
    score=$((score + $(check_system_performance "$report_file")))
    
    # Application performance
    score=$((score + $(check_application_performance "$report_file")))
    
    # Network performance
    score=$((score + $(check_network_performance "$report_file")))
    
    log_to_report "" "$report_file"
    log_to_report "Performance Health Score: $score/100" "$report_file"
    log_to_report "" "$report_file"
    
    echo $score
}

# Utility functions
check_memory_usage() {
    if command -v free >/dev/null 2>&1; then
        local mem_usage
        mem_usage=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
        local mem_total_gb
        mem_total_gb=$(free -g | awk '/^Mem:/ {print $2}')
        
        if [[ $mem_usage -gt ${HEALTH_THRESHOLDS[memory_critical]} ]]; then
            echo "❌ Memory usage critical: ${mem_usage}% (${mem_total_gb}GB total)"
        elif [[ $mem_usage -gt ${HEALTH_THRESHOLDS[memory_warning]} ]]; then
            echo "⚠️  Memory usage high: ${mem_usage}% (${mem_total_gb}GB total)"
        else
            echo "✅ Memory usage normal: ${mem_usage}% (${mem_total_gb}GB total)"
        fi
    else
        echo "⚠️  Cannot determine memory usage"
    fi
}

check_disk_usage() {
    local disk_usage
    disk_usage=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
    local available_gb
    available_gb=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if [[ $disk_usage -gt ${HEALTH_THRESHOLDS[disk_critical]} ]]; then
        echo "❌ Disk usage critical: ${disk_usage}% (${available_gb}GB available)"
    elif [[ $disk_usage -gt ${HEALTH_THRESHOLDS[disk_warning]} ]]; then
        echo "⚠️  Disk usage high: ${disk_usage}% (${available_gb}GB available)"
    else
        echo "✅ Disk usage normal: ${disk_usage}% (${available_gb}GB available)"
    fi
}

check_cpu_load() {
    if [[ -f /proc/loadavg ]]; then
        local load_1min
        load_1min=$(cut -d' ' -f1 /proc/loadavg)
        local cpu_count
        cpu_count=$(nproc 2>/dev/null || echo 1)
        local load_percentage
        load_percentage=$(echo "scale=0; $load_1min * 100 / $cpu_count" | bc -l 2>/dev/null || echo 0)
        
        if [[ $load_percentage -gt ${HEALTH_THRESHOLDS[cpu_critical]} ]]; then
            echo "❌ CPU load critical: ${load_1min} (${load_percentage}%)"
        elif [[ $load_percentage -gt ${HEALTH_THRESHOLDS[cpu_warning]} ]]; then
            echo "⚠️  CPU load high: ${load_1min} (${load_percentage}%)"
        else
            echo "✅ CPU load normal: ${load_1min} (${load_percentage}%)"
        fi
    else
        echo "⚠️  Cannot determine CPU load"
    fi
}

# Helper functions
log_to_report() {
    local message=$1
    local report_file=$2
    echo "$message" | tee -a "$report_file"
}

capitalize_string() {
    echo "$1" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}'
}

init_health_report() {
    local report_file=$1
    cat > "$report_file" << EOF
FKS Trading Systems - Health Check Report
Generated: $(date)
Version: $HEALTH_MODULE_VERSION
========================================

EOF
}

generate_health_summary() {
    local total_score=$1
    local max_score=$2
    local duration=$3
    local report_file=$4
    
    local percentage=$((total_score * 100 / max_score))
    
    log_to_report "OVERALL HEALTH SUMMARY" "$report_file"
    log_to_report "======================" "$report_file"
    log_to_report "" "$report_file"
    log_to_report "Total Score: $total_score / $max_score" "$report_file"
    log_to_report "Health Percentage: $percentage%" "$report_file"
    log_to_report "Check Duration: ${duration}s" "$report_file"
    log_to_report "" "$report_file"
    
    # Health grade
    local grade
    if [[ $percentage -ge 90 ]]; then
        grade="A+ (Excellent)"
        log_to_report "🎉 System Health: $grade" "$report_file"
    elif [[ $percentage -ge 80 ]]; then
        grade="A (Very Good)"
        log_to_report "✅ System Health: $grade" "$report_file"
    elif [[ $percentage -ge 70 ]]; then
        grade="B (Good)"
        log_to_report "👍 System Health: $grade" "$report_file"
    elif [[ $percentage -ge 60 ]]; then
        grade="C (Fair)"
        log_to_report "⚠️  System Health: $grade" "$report_file"
    else
        grade="D (Poor)"
        log_to_report "❌ System Health: $grade" "$report_file"
    fi
    
    # Category breakdown
    log_to_report "" "$report_file"
    log_to_report "CATEGORY BREAKDOWN" "$report_file"
    log_to_report "==================" "$report_file"
    
    for category in "${!HEALTH_SCORES[@]}"; do
        local score=${HEALTH_SCORES[$category]}
        local weight=${HEALTH_CATEGORIES[$category]}
        log_to_report "$(capitalize_string "$category"): $score/100 (weight: $weight%)" "$report_file"
    done
    
    # Recommendations
    generate_recommendations "$percentage" "$report_file"
}

generate_recommendations() {
    local percentage=$1
    local report_file=$2
    
    log_to_report "" "$report_file"
    log_to_report "RECOMMENDATIONS" "$report_file"
    log_to_report "===============" "$report_file"
    log_to_report "" "$report_file"
    
    if [[ $percentage -ge 90 ]]; then
        log_to_report "• System is in excellent health" "$report_file"
        log_to_report "• Continue regular maintenance and monitoring" "$report_file"
    elif [[ $percentage -ge 80 ]]; then
        log_to_report "• System is in very good health" "$report_file"
        log_to_report "• Address any warning items for optimal performance" "$report_file"
    elif [[ $percentage -ge 70 ]]; then
        log_to_report "• System health is good with room for improvement" "$report_file"
        log_to_report "• Review and address warning items" "$report_file"
        log_to_report "• Consider performance optimizations" "$report_file"
    elif [[ $percentage -ge 60 ]]; then
        log_to_report "• System health is fair - attention needed" "$report_file"
        log_to_report "• Address failing components promptly" "$report_file"
        log_to_report "• Review system resources and configuration" "$report_file"
    else
        log_to_report "• System health is poor - immediate attention required" "$report_file"
        log_to_report "• Address all failing components" "$report_file"
        log_to_report "• Consider system upgrade or reconfiguration" "$report_file"
    fi
    
    log_to_report "" "$report_file"
    log_to_report "For detailed troubleshooting, run: $0 --health-troubleshoot" "$report_file"
    log_to_report "Report generated: $(date)" "$report_file"
}

save_health_data() {
    local total_score=$1
    local max_score=$2
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local percentage=$((total_score * 100 / max_score))
    
    # Save to JSON
    local json_file="$HEALTH_REPORTS_DIR/health_data_$(date +%Y%m%d_%H%M%S).json"
    cat > "$json_file" << EOF
{
  "timestamp": "$timestamp",
  "version": "$HEALTH_MODULE_VERSION",
  "scores": {
$(for category in "${!HEALTH_SCORES[@]}"; do
    echo "    \"$category\": ${HEALTH_SCORES[$category]},"
done | sed '$s/,$//')
  },
  "summary": {
    "total_score": $total_score,
    "max_score": $max_score,
    "percentage": $percentage,
    "grade": "$(get_health_grade $percentage)"
  }
}
EOF
    
    log_debug "Health data saved to $json_file"
}

get_health_grade() {
    local percentage=$1
    
    if [[ $percentage -ge 90 ]]; then
        echo "A+"
    elif [[ $percentage -ge 80 ]]; then
        echo "A"
    elif [[ $percentage -ge 70 ]]; then
        echo "B"
    elif [[ $percentage -ge 60 ]]; then
        echo "C"
    else
        echo "D"
    fi
}

# Quick health check
quick_health_check() {
    log_info "⚡ Quick Health Check"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local issues=0
    
    # System basics
    echo "System:"
    echo "  $(check_memory_usage)"
    echo "  $(check_disk_usage)"
    echo "  $(check_cpu_load)"
    
    # Docker
    echo "Docker:"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local containers
        containers=$(docker ps -q | wc -l)
        echo "  ✅ Running ($containers containers)"
    else
        echo "  ❌ Not available"
        ((issues++))
    fi
    
    # Python
    echo "Python:"
    if command -v python3 >/dev/null 2>&1; then
        echo "  ✅ $(python3 --version)"
    else
        echo "  ❌ Not available"
        ((issues++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ $issues -eq 0 ]]; then
        echo "✅ Quick check passed - run comprehensive check for details"
        return 0
    else
        echo "⚠️  $issues issue(s) found - run comprehensive check for analysis"
        return 1
    fi
}

# Export main functions
export -f comprehensive_health_check quick_health_check
export -f init_health_system load_health_config

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        --comprehensive|--full) comprehensive_health_check ;;
        --quick) quick_health_check ;;
        *) 
            echo "FKS Health System v$HEALTH_MODULE_VERSION"
            echo "Usage: $0 [--comprehensive|--quick]"
            ;;
    esac
fi