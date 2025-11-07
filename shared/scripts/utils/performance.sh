#!/bin/bash
# filepath: scripts/utils/performance.sh
# FKS Trading Systems - Performance Timing Module
# Handles performance monitoring and timing functions

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly PERFORMANCE_MODULE_VERSION="2.5.0"
readonly PERFORMANCE_MODULE_LOADED="$(date +%s)"

# Performance timing storage
declare -A TIMERS
declare -A TIMER_DESCRIPTIONS
declare -A PERFORMANCE_STATS

# Performance timing functions
start_timer() {
    local timer_name="$1"
    local description="${2:-$timer_name}"
    
    TIMERS["$timer_name"]=$(date +%s.%N)
    TIMER_DESCRIPTIONS["$timer_name"]="$description"
    
    log_debug "⏱️  Started timer: $timer_name ($description)"
}

stop_timer() {
    local timer_name="$1"
    local start_time=${TIMERS["$timer_name"]:-}
    
    if [[ -n "$start_time" ]]; then
        local end_time=$(date +%s.%N)
        local duration
        
        # Calculate duration with fallback for systems without bc
        if command -v bc >/dev/null 2>&1; then
            duration=$(echo "scale=3; $end_time - $start_time" | bc)
        else
            # Fallback calculation (less precise)
            local start_int=${start_time%.*}
            local start_dec=${start_time#*.}
            local end_int=${end_time%.*}
            local end_dec=${end_time#*.}
            
            local diff_int=$((end_int - start_int))
            local diff_dec=$((end_dec - start_dec))
            
            if [[ $diff_dec -lt 0 ]]; then
                diff_int=$((diff_int - 1))
                diff_dec=$((diff_dec + 1000000000))
            fi
            
            duration=$(printf "%d.%03d" $diff_int $((diff_dec / 1000000)))
        fi
        
        # Store performance stats
        PERFORMANCE_STATS["$timer_name"]="$duration"
        
        log_debug "⏱️  Stopped timer: $timer_name (${TIMER_DESCRIPTIONS[$timer_name]:-$timer_name}) - Duration: ${duration}s"
        
        echo "$duration"
        unset TIMERS["$timer_name"]
        unset TIMER_DESCRIPTIONS["$timer_name"]
    else
        log_warn "Timer '$timer_name' was not started or already stopped"
        echo "0.000"
    fi
}

# Get elapsed time without stopping timer
get_timer_elapsed() {
    local timer_name="$1"
    local start_time=${TIMERS["$timer_name"]:-}
    
    if [[ -n "$start_time" ]]; then
        local current_time=$(date +%s.%N)
        local duration
        
        if command -v bc >/dev/null 2>&1; then
            duration=$(echo "scale=3; $current_time - $start_time" | bc)
        else
            # Fallback calculation
            local start_int=${start_time%.*}
            local current_int=${current_time%.*}
            local diff_int=$((current_int - start_int))
            duration=$(printf "%d.000" $diff_int)
        fi
        
        echo "$duration"
    else
        echo "0.000"
    fi
}

# Check if timer is running
is_timer_running() {
    local timer_name="$1"
    [[ -n "${TIMERS[$timer_name]:-}" ]]
}

# List all active timers
list_active_timers() {
    if [[ ${#TIMERS[@]} -eq 0 ]]; then
        echo "No active timers"
        return 0
    fi
    
    echo "Active timers:"
    for timer_name in "${!TIMERS[@]}"; do
        local elapsed
        elapsed=$(get_timer_elapsed "$timer_name")
        echo "  • $timer_name: ${elapsed}s (${TIMER_DESCRIPTIONS[$timer_name]:-$timer_name})"
    done
}

# Stop all active timers
stop_all_timers() {
    local stopped_count=0
    
    for timer_name in "${!TIMERS[@]}"; do
        stop_timer "$timer_name" >/dev/null
        ((stopped_count++))
    done
    
    if [[ $stopped_count -gt 0 ]]; then
        log_debug "⏱️  Stopped $stopped_count active timer(s)"
    fi
    
    return $stopped_count
}

# Performance benchmarking
benchmark_operation() {
    local operation_name="$1"
    shift
    local command_to_run="$@"
    
    log_info "🏃 Benchmarking: $operation_name"
    start_timer "benchmark_$operation_name" "$operation_name benchmark"
    
    # Execute the command
    local exit_code=0
    if eval "$command_to_run"; then
        log_debug "✅ Benchmark operation completed successfully"
    else
        exit_code=$?
        log_warn "⚠️  Benchmark operation failed with exit code $exit_code"
    fi
    
    local duration
    duration=$(stop_timer "benchmark_$operation_name")
    
    log_info "📊 Benchmark result: $operation_name completed in ${duration}s"
    
    # Store benchmark result
    PERFORMANCE_STATS["benchmark_$operation_name"]="$duration"
    
    return $exit_code
}

# Time a function execution
time_function() {
    local function_name="$1"
    shift
    local args="$@"
    
    if ! command -v "$function_name" >/dev/null 2>&1; then
        log_error "Function '$function_name' not found"
        return 1
    fi
    
    start_timer "function_$function_name" "Function: $function_name"
    
    local exit_code=0
    if "$function_name" $args; then
        log_debug "✅ Function execution completed successfully"
    else
        exit_code=$?
        log_debug "Function execution failed with exit code $exit_code"
    fi
    
    local duration
    duration=$(stop_timer "function_$function_name")
    
    log_debug "📊 Function timing: $function_name executed in ${duration}s"
    
    return $exit_code
}

# Performance monitoring
monitor_performance() {
    local monitor_name="${1:-system}"
    local duration="${2:-60}"
    
    log_info "📊 Starting performance monitoring: $monitor_name (${duration}s)"
    
    start_timer "monitor_$monitor_name" "Performance monitoring: $monitor_name"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local sample_count=0
    
    # Create monitoring log file
    local monitor_log="${FKS_LOGS_DIR:-./logs}/performance_${monitor_name}_$(date +%Y%m%d_%H%M%S).log"
    mkdir -p "$(dirname "$monitor_log")" 2>/dev/null
    
    echo "# Performance Monitoring: $monitor_name" > "$monitor_log"
    echo "# Started: $(date)" >> "$monitor_log"
    echo "# Duration: ${duration}s" >> "$monitor_log"
    echo "# Timestamp,CPU_Load,Memory_Usage,Disk_Usage" >> "$monitor_log"
    
    while [[ $(date +%s) -lt $end_time ]]; do
        local timestamp=$(date +%s)
        local cpu_load="N/A"
        local memory_usage="N/A"
        local disk_usage="N/A"
        
        # Collect CPU load if available
        if command -v uptime >/dev/null 2>&1; then
            cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
        fi
        
        # Collect memory usage if available
        if command -v free >/dev/null 2>&1; then
            memory_usage=$(free | awk 'NR==2{printf "%.1f", $3/$2*100}')
        fi
        
        # Collect disk usage
        disk_usage=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
        
        # Log data point
        echo "$timestamp,$cpu_load,$memory_usage,$disk_usage" >> "$monitor_log"
        
        ((sample_count++))
        sleep 5
    done
    
    local monitoring_duration
    monitoring_duration=$(stop_timer "monitor_$monitor_name")
    
    echo "# Completed: $(date)" >> "$monitor_log"
    echo "# Actual duration: ${monitoring_duration}s" >> "$monitor_log"
    echo "# Samples collected: $sample_count" >> "$monitor_log"
    
    log_success "✅ Performance monitoring completed: $sample_count samples in ${monitoring_duration}s"
    log_info "📄 Monitor log: $monitor_log"
    
    return 0
}

# System resource usage snapshot
get_resource_snapshot() {
    local snapshot_name="${1:-snapshot}"
    
    log_debug "📸 Taking resource snapshot: $snapshot_name"
    
    local snapshot=()
    
    # Timestamp
    snapshot+=("timestamp:$(date +%s)")
    snapshot+=("datetime:$(date)")
    
    # CPU information
    if command -v uptime >/dev/null 2>&1; then
        local load_avg
        load_avg=$(uptime | awk -F'load average:' '{print $2}' | tr -d ' ')
        snapshot+=("load_average:$load_avg")
    fi
    
    # Memory information
    if command -v free >/dev/null 2>&1; then
        local memory_total memory_used memory_free memory_usage
        memory_total=$(free -m | awk 'NR==2{print $2}')
        memory_used=$(free -m | awk 'NR==2{print $3}')
        memory_free=$(free -m | awk 'NR==2{print $4}')
        memory_usage=$(free | awk 'NR==2{printf "%.1f", $3/$2*100}')
        
        snapshot+=("memory_total_mb:$memory_total")
        snapshot+=("memory_used_mb:$memory_used")
        snapshot+=("memory_free_mb:$memory_free")
        snapshot+=("memory_usage_percent:$memory_usage")
    fi
    
    # Disk information
    local disk_total disk_used disk_free disk_usage
    disk_total=$(df -h . | awk 'NR==2 {print $2}')
    disk_used=$(df -h . | awk 'NR==2 {print $3}')
    disk_free=$(df -h . | awk 'NR==2 {print $4}')
    disk_usage=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
    
    snapshot+=("disk_total:$disk_total")
    snapshot+=("disk_used:$disk_used")
    snapshot+=("disk_free:$disk_free")
    snapshot+=("disk_usage_percent:$disk_usage")
    
    # Process information
    if command -v ps >/dev/null 2>&1; then
        local process_count
        process_count=$(ps aux | wc -l)
        snapshot+=("process_count:$process_count")
    fi
    
    # Docker information (if in server mode)
    if [[ "${FKS_MODE:-}" == "server" ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local container_count image_count
        container_count=$(docker ps -q | wc -l)
        image_count=$(docker images -q | wc -l)
        
        snapshot+=("docker_containers:$container_count")
        snapshot+=("docker_images:$image_count")
    fi
    
    # Store snapshot
    PERFORMANCE_STATS["snapshot_$snapshot_name"]="${snapshot[*]}"
    
    # Return snapshot data
    printf '%s\n' "${snapshot[@]}"
}

# Performance statistics summary
show_performance_stats() {
    if [[ ${#PERFORMANCE_STATS[@]} -eq 0 ]]; then
        log_info "No performance statistics available"
        return 0
    fi
    
    echo "${WHITE}📊 Performance Statistics${NC}"
    echo "${CYAN}=========================${NC}"
    echo ""
    
    # Show timing statistics
    local timing_stats=()
    local snapshot_stats=()
    local benchmark_stats=()
    
    for stat_name in "${!PERFORMANCE_STATS[@]}"; do
        if [[ $stat_name =~ ^snapshot_ ]]; then
            snapshot_stats+=("$stat_name")
        elif [[ $stat_name =~ ^benchmark_ ]]; then
            benchmark_stats+=("$stat_name")
        else
            timing_stats+=("$stat_name")
        fi
    done
    
    # Display timing statistics
    if [[ ${#timing_stats[@]} -gt 0 ]]; then
        echo "${YELLOW}Timing Statistics:${NC}"
        for stat in "${timing_stats[@]}"; do
            echo "  • $stat: ${PERFORMANCE_STATS[$stat]}s"
        done
        echo ""
    fi
    
    # Display benchmark statistics
    if [[ ${#benchmark_stats[@]} -gt 0 ]]; then
        echo "${YELLOW}Benchmark Results:${NC}"
        for stat in "${benchmark_stats[@]}"; do
            local clean_name=${stat#benchmark_}
            echo "  • $clean_name: ${PERFORMANCE_STATS[$stat]}s"
        done
        echo ""
    fi
    
    # Display resource snapshots
    if [[ ${#snapshot_stats[@]} -gt 0 ]]; then
        echo "${YELLOW}Resource Snapshots:${NC}"
        for stat in "${snapshot_stats[@]}"; do
            local clean_name=${stat#snapshot_}
            echo "  📸 $clean_name:"
            
            # Parse and display snapshot data
            local snapshot_data="${PERFORMANCE_STATS[$stat]}"
            IFS=' ' read -ra snapshot_items <<< "$snapshot_data"
            
            for item in "${snapshot_items[@]}"; do
                if [[ $item =~ ^([^:]+):(.+)$ ]]; then
                    local key="${BASH_REMATCH[1]}"
                    local value="${BASH_REMATCH[2]}"
                    echo "    $key: $value"
                fi
            done
            echo ""
        done
    fi
}

# Clear performance statistics
clear_performance_stats() {
    local cleared_count=${#PERFORMANCE_STATS[@]}
    PERFORMANCE_STATS=()
    
    log_info "🧹 Cleared $cleared_count performance statistic(s)"
}

# Cleanup function for module
cleanup_performance_module() {
    # Stop any running timers
    stop_all_timers >/dev/null
    
    # Clear performance stats if requested
    if [[ "${FKS_CLEAR_STATS_ON_EXIT:-false}" == "true" ]]; then
        clear_performance_stats >/dev/null
    fi
    
    log_debug "🧹 Performance module cleanup completed"
}

# Performance optimization suggestions
suggest_performance_optimizations() {
    log_info "💡 Performance Optimization Suggestions"
    
    echo "${YELLOW}General Optimizations:${NC}"
    echo "  • Use SSD storage for better I/O performance"
    echo "  • Ensure adequate RAM (8GB+ recommended)"
    echo "  • Close unnecessary applications"
    echo "  • Regular system maintenance and updates"
    echo ""
    
    case "${FKS_MODE:-}" in
        "development")
            echo "${YELLOW}Development Mode Optimizations:${NC}"
            echo "  • Use conda environments for dependency isolation"
            echo "  • Enable Python bytecode caching"
            echo "  • Use local package caches"
            echo "  • Consider using faster package managers (mamba)"
            echo ""
            ;;
        "server")
            echo "${YELLOW}Server Mode Optimizations:${NC}"
            echo "  • Optimize Docker image layers"
            echo "  • Use multi-stage builds"
            echo "  • Implement proper resource limits"
            echo "  • Enable container health checks"
            echo "  • Use Docker BuildKit for faster builds"
            echo ""
            ;;
    esac
    
    # Resource-specific suggestions based on current usage
    local current_snapshot
    current_snapshot=$(get_resource_snapshot "current" | grep -E "(memory_usage|disk_usage|load_average)")
    
    if echo "$current_snapshot" | grep -q "memory_usage.*:[89][0-9]\|memory_usage.*:100"; then
        echo "${RED}⚠️  High Memory Usage Detected:${NC}"
        echo "  • Consider increasing system RAM"
        echo "  • Optimize application memory usage"
        echo "  • Close memory-intensive applications"
        echo ""
    fi
    
    if echo "$current_snapshot" | grep -q "disk_usage.*:[89][0-9]\|disk_usage.*:100"; then
        echo "${RED}⚠️  High Disk Usage Detected:${NC}"
        echo "  • Clean up temporary files"
        echo "  • Remove unused Docker images/containers"
        echo "  • Archive old log files"
        echo ""
    fi
}

echo "📦 Loaded performance timing module (v$PERFORMANCE_MODULE_VERSION)"