#!/bin/bash
# filepath: scripts/utils/menu.sh
# FKS Trading Systems - Interactive Menu System
# Modular, maintainable menu system with comprehensive functionality

# Prevent multiple sourcing
[[ -n "${FKS_MENU_SYSTEM_LOADED:-}" ]] && return 0
readonly FKS_MENU_SYSTEM_LOADED=1

# Module metadata
readonly MENU_MODULE_VERSION="3.0.0"
readonly MENU_MODULE_LOADED="$(date +%s)"

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"

# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

# Menu configuration
readonly MENU_TIMEOUT="${FKS_MENU_TIMEOUT:-300}"
readonly MENU_CLEAR_SCREEN="${FKS_MENU_CLEAR_SCREEN:-true}"
readonly MENU_SHOW_HEADER="${FKS_MENU_SHOW_HEADER:-true}"
readonly MENU_WIDTH=80

# Menu structure definitions
declare -A MENU_SECTIONS
declare -A MENU_ACTIONS
declare -A MENU_HANDLERS

# =============================================================================
# CORE MENU SYSTEM
# =============================================================================

# Main entry point for the interactive menu system
show_full_menu() {
    initialize_menu_system
    
    while true; do
        clear_screen_if_enabled
        show_menu_header
        show_current_menu
        
        local choice
        if ! read_menu_choice choice; then
            log_info "Menu timeout or exit signal received"
            break
        fi
        
        if ! process_menu_choice "$choice"; then
            break
        fi
    done
    
    log_info "👋 Goodbye!"
}

# Initialize menu system based on mode
initialize_menu_system() {
    local mode="${FKS_MODE:-development}"
    
    case "$mode" in
        "development")
            setup_development_menu
            ;;
        "server")
            setup_server_menu
            ;;
        "production")
            setup_production_menu
            ;;
        *)
            setup_generic_menu
            ;;
    esac
    
    log_debug "Menu system initialized for $mode mode"
}

# =============================================================================
# MENU DEFINITIONS
# =============================================================================

# Development mode menu setup
setup_development_menu() {
    MENU_SECTIONS=(
        ["python"]="🐍 Python Development"
        ["data"]="📊 Data & Analysis"
        ["tools"]="🔧 Development Tools"
        ["system"]="⚙️ System Management"
        ["advanced"]="🎛️ Advanced Options"
    )
    
    MENU_ACTIONS=(
        # Python section
        ["python_1"]="Setup Python Environment"
        ["python_2"]="Install Requirements"
        ["python_3"]="Run Python Script"
        ["python_4"]="Interactive Python Shell"
        ["python_5"]="Run Tests"
        ["python_6"]="Code Quality Check"
        
        # Data section
        ["data_1"]="Process Data Files"
        ["data_2"]="Generate Reports"
        ["data_3"]="Visualize Data"
        ["data_4"]="Data Validation"
        
        # Tools section
        ["tools_1"]="Git Operations"
        ["tools_2"]="Database Management"
        ["tools_3"]="API Testing"
        ["tools_4"]="Performance Profiling"
        
        # System section
        ["system_1"]="System Health Check"
        ["system_2"]="View Logs"
        ["system_3"]="Configuration Management"
        ["system_4"]="Backup & Restore"
        
        # Advanced section
        ["advanced_1"]="Switch to Server Mode"
        ["advanced_2"]="Performance Monitoring"
        ["advanced_3"]="Troubleshooting Tools"
        ["advanced_4"]="System Information"
    )
    
    setup_development_handlers
}

# Server mode menu setup
setup_server_menu() {
    MENU_SECTIONS=(
        ["services"]="🚀 Service Management"
        ["docker"]="🐳 Container Operations"
        ["monitoring"]="📊 Monitoring & Logs"
        ["maintenance"]="🛠️ System Maintenance"
        ["advanced"]="🎛️ Advanced Operations"
    )
    
    MENU_ACTIONS=(
        # Services section
        ["services_1"]="Start Services"
        ["services_2"]="Stop Services"
        ["services_3"]="Restart Services"
        ["services_4"]="View Service Status"
        ["services_5"]="Deploy Application"
        ["services_6"]="Rollback Deployment"
        
        # Docker section
        ["docker_1"]="Build Images"
        ["docker_2"]="Pull Images"
        ["docker_3"]="Container Logs"
        ["docker_4"]="Container Shell"
        ["docker_5"]="Clean Docker System"
        ["docker_6"]="Docker Metrics"
        
        # Monitoring section
        ["monitoring_1"]="System Metrics"
        ["monitoring_2"]="Application Logs"
        ["monitoring_3"]="Error Analysis"
        ["monitoring_4"]="Performance Dashboard"
        
        # Maintenance section
        ["maintenance_1"]="Health Check"
        ["maintenance_2"]="Backup Data"
        ["maintenance_3"]="Update System"
        ["maintenance_4"]="Security Scan"
        
        # Advanced section
        ["advanced_1"]="Switch to Development Mode"
        ["advanced_2"]="Database Operations"
        ["advanced_3"]="Network Diagnostics"
        ["advanced_4"]="System Configuration"
    )
    
    setup_server_handlers
}

# Generic menu setup (fallback)
setup_generic_menu() {
    MENU_SECTIONS=(
        ["basic"]="🎛️ Basic Operations"
        ["setup"]="🔧 Setup & Installation"
        ["info"]="📊 Information"
    )
    
    MENU_ACTIONS=(
        ["basic_1"]="System Health Check"
        ["basic_2"]="View System Information"
        ["basic_3"]="Show Configuration"
        ["basic_4"]="View Logs"
        ["basic_5"]="Performance Check"
        
        ["setup_1"]="Install Dependencies"
        ["setup_2"]="Setup Environment"
        ["setup_3"]="Validate Configuration"
        ["setup_4"]="Reset System"
        
        ["info_1"]="Show Help"
        ["info_2"]="About FKS"
        ["info_3"]="Documentation"
    )
    
    setup_generic_handlers
}

# =============================================================================
# MENU DISPLAY FUNCTIONS
# =============================================================================

# Show menu header with status
show_menu_header() {
    if [[ "$MENU_SHOW_HEADER" != "true" ]]; then
        return 0
    fi
    
    local title="FKS Trading Systems - ${FKS_MODE^} Mode"
    local separator=$(printf "%*s" $MENU_WIDTH "" | tr ' ' '=')
    
    echo "${CYAN}$separator${NC}"
    echo "${WHITE}🚀 $title${NC}"
    echo "${CYAN}$separator${NC}"
    echo ""
    
    show_menu_status
    echo ""
}

# Show current menu based on configuration
show_current_menu() {
    local section_count=1
    local action_count=1
    
    for section_key in $(printf '%s\n' "${!MENU_SECTIONS[@]}" | sort); do
        echo "${YELLOW}${MENU_SECTIONS[$section_key]}:${NC}"
        
        # Show actions for this section
        for action_key in $(printf '%s\n' "${!MENU_ACTIONS[@]}" | grep "^${section_key}_" | sort -V); do
            echo "  ${GREEN}${action_count}.${NC} ${MENU_ACTIONS[$action_key]}"
            ((action_count++))
        done
        echo ""
    done
    
    echo "${DIM}Enter your choice (or 'q' to quit, 'h' for help):${NC}"
}

# Show system status in menu
show_menu_status() {
    echo "${YELLOW}Current Status:${NC}"
    echo "  Mode: ${WHITE}${FKS_MODE:-unknown}${NC}"
    echo "  Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  User: ${USER:-unknown}"
    echo "  Directory: $(basename "$(pwd)")"
    
    # Show system resources
    show_system_resources_summary
    
    # Show mode-specific status
    case "${FKS_MODE:-}" in
        "development")
            show_development_status
            ;;
        "server")
            show_server_status
            ;;
    esac
}

# Show condensed system resources
show_system_resources_summary() {
    local load_avg memory_usage
    
    if [[ -f /proc/loadavg ]]; then
        load_avg=$(cut -d' ' -f1 /proc/loadavg)
        echo "  Load: $load_avg"
    fi
    
    if command -v free >/dev/null 2>&1; then
        memory_usage=$(free | awk '/^Mem:/ {printf "%.1f%%", $3/$2*100}')
        echo "  Memory: $memory_usage"
    fi
}

# Development mode status
show_development_status() {
    echo ""
    echo "${YELLOW}Development Environment:${NC}"
    
    # Python environment
    if [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
        echo "  Python: Conda (${CONDA_DEFAULT_ENV})"
    elif [[ -n "${VIRTUAL_ENV:-}" ]]; then
        echo "  Python: venv ($(basename "$VIRTUAL_ENV"))"
    elif command -v python3 >/dev/null 2>&1; then
        echo "  Python: System ($(python3 --version 2>&1 | awk '{print $2}'))"
    else
        echo "  Python: ${RED}Not available${NC}"
    fi
    
    # Git status
    if [[ -d ".git" ]] && command -v git >/dev/null 2>&1; then
        local git_branch git_status
        git_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
        git_status=$(git status --porcelain 2>/dev/null | wc -l)
        echo "  Git: $git_branch (${git_status} changes)"
    fi
}

# Server mode status
show_server_status() {
    echo ""
    echo "${YELLOW}Server Environment:${NC}"
    
    # Docker status
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local container_count
        container_count=$(docker ps -q | wc -l)
        echo "  Docker: ${GREEN}Running${NC} ($container_count containers)"
    else
        echo "  Docker: ${RED}Not available${NC}"
    fi
    
    # Services status
    if [[ -f "docker-compose.yml" ]]; then
        echo "  Compose: Available"
    fi
}

# =============================================================================
# INPUT HANDLING
# =============================================================================

# Read menu choice with timeout and validation
read_menu_choice() {
    local -n choice_ref=$1
    
    if [[ -t 0 ]]; then
        if read -r -t "$MENU_TIMEOUT" choice_ref; then
            choice_ref=$(echo "$choice_ref" | xargs)  # Trim whitespace
            return 0
        else
            log_debug "Menu read timeout after ${MENU_TIMEOUT}s"
            return 1
        fi
    else
        log_warn "Non-interactive mode detected"
        choice_ref="q"
        return 0
    fi
}

# Process menu choice
process_menu_choice() {
    local choice="$1"
    
    # Handle special commands
    case "$choice" in
        "q"|"Q"|"quit"|"exit")
            return 1
            ;;
        "h"|"H"|"help")
            show_menu_help
            press_enter_to_continue
            return 0
            ;;
        "r"|"R"|"refresh")
            return 0
            ;;
        "")
            log_warn "No choice entered"
            return 0
            ;;
    esac
    
    # Validate numeric choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        log_error "Invalid choice: $choice"
        press_enter_to_continue
        return 0
    fi
    
    # Convert choice to action key
    local action_key
    if ! action_key=$(get_action_key_by_number "$choice"); then
        log_error "Invalid choice number: $choice"
        press_enter_to_continue
        return 0
    fi
    
    # Execute action
    execute_menu_action "$action_key"
    return 0
}

# Convert choice number to action key
get_action_key_by_number() {
    local choice_num="$1"
    local current_num=1
    
    for section_key in $(printf '%s\n' "${!MENU_SECTIONS[@]}" | sort); do
        for action_key in $(printf '%s\n' "${!MENU_ACTIONS[@]}" | grep "^${section_key}_" | sort -V); do
            if [[ "$current_num" -eq "$choice_num" ]]; then
                echo "$action_key"
                return 0
            fi
            ((current_num++))
        done
    done
    
    return 1
}

# Execute menu action
execute_menu_action() {
    local action_key="$1"
    
    if [[ -n "${MENU_HANDLERS[$action_key]:-}" ]]; then
        local handler="${MENU_HANDLERS[$action_key]}"
        log_debug "Executing handler: $handler"
        
        if command -v "$handler" >/dev/null 2>&1; then
            "$handler"
        else
            log_error "Handler function not found: $handler"
            press_enter_to_continue
        fi
    else
        log_error "No handler defined for action: $action_key"
        press_enter_to_continue
    fi
}

# =============================================================================
# HANDLER SETUP FUNCTIONS
# =============================================================================

# Setup development mode handlers
setup_development_handlers() {
    MENU_HANDLERS=(
        # Python handlers
        ["python_1"]="handle_setup_python_environment"
        ["python_2"]="handle_install_requirements"
        ["python_3"]="handle_run_python_script"
        ["python_4"]="handle_interactive_python"
        ["python_5"]="handle_run_tests"
        ["python_6"]="handle_code_quality_check"
        
        # Data handlers
        ["data_1"]="handle_process_data_files"
        ["data_2"]="handle_generate_reports"
        ["data_3"]="handle_visualize_data"
        ["data_4"]="handle_data_validation"
        
        # Tools handlers
        ["tools_1"]="handle_git_operations"
        ["tools_2"]="handle_database_management"
        ["tools_3"]="handle_api_testing"
        ["tools_4"]="handle_performance_profiling"
        
        # System handlers
        ["system_1"]="handle_system_health_check"
        ["system_2"]="handle_view_logs"
        ["system_3"]="handle_configuration_management"
        ["system_4"]="handle_backup_restore"
        
        # Advanced handlers
        ["advanced_1"]="handle_switch_to_server_mode"
        ["advanced_2"]="handle_performance_monitoring"
        ["advanced_3"]="handle_troubleshooting_tools"
        ["advanced_4"]="handle_system_information"
    )
}

# Setup server mode handlers
setup_server_handlers() {
    MENU_HANDLERS=(
        # Service handlers
        ["services_1"]="handle_start_services"
        ["services_2"]="handle_stop_services"
        ["services_3"]="handle_restart_services"
        ["services_4"]="handle_view_service_status"
        ["services_5"]="handle_deploy_application"
        ["services_6"]="handle_rollback_deployment"
        
        # Docker handlers
        ["docker_1"]="handle_build_images"
        ["docker_2"]="handle_pull_images"
        ["docker_3"]="handle_container_logs"
        ["docker_4"]="handle_container_shell"
        ["docker_5"]="handle_clean_docker_system"
        ["docker_6"]="handle_docker_metrics"
        
        # Monitoring handlers
        ["monitoring_1"]="handle_system_metrics"
        ["monitoring_2"]="handle_application_logs"
        ["monitoring_3"]="handle_error_analysis"
        ["monitoring_4"]="handle_performance_dashboard"
        
        # Maintenance handlers
        ["maintenance_1"]="handle_health_check"
        ["maintenance_2"]="handle_backup_data"
        ["maintenance_3"]="handle_update_system"
        ["maintenance_4"]="handle_security_scan"
        
        # Advanced handlers
        ["advanced_1"]="handle_switch_to_development_mode"
        ["advanced_2"]="handle_database_operations"
        ["advanced_3"]="handle_network_diagnostics"
        ["advanced_4"]="handle_system_configuration"
    )
}

# Setup generic handlers
setup_generic_handlers() {
    MENU_HANDLERS=(
        ["basic_1"]="handle_system_health_check"
        ["basic_2"]="handle_system_information"
        ["basic_3"]="handle_show_configuration"
        ["basic_4"]="handle_view_logs"
        ["basic_5"]="handle_performance_check"
        
        ["setup_1"]="handle_install_dependencies"
        ["setup_2"]="handle_setup_environment"
        ["setup_3"]="handle_validate_configuration"
        ["setup_4"]="handle_reset_system"
        
        ["info_1"]="handle_show_help"
        ["info_2"]="handle_about_fks"
        ["info_3"]="handle_documentation"
    )
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Clear screen if enabled
clear_screen_if_enabled() {
    if [[ "$MENU_CLEAR_SCREEN" == "true" ]]; then
        clear
    fi
}

# Wait for user input
press_enter_to_continue() {
    echo ""
    echo "${DIM}Press Enter to continue...${NC}"
    read -r
}

# Show menu help
show_menu_help() {
    echo "${WHITE}📖 FKS Menu Help${NC}"
    echo "${CYAN}===============${NC}"
    echo ""
    echo "Navigation:"
    echo "  • Enter a number to select an option"
    echo "  • Type 'q' or 'quit' to exit"
    echo "  • Type 'h' or 'help' for this help"
    echo "  • Type 'r' or 'refresh' to refresh the menu"
    echo ""
    echo "Features:"
    echo "  • Menu timeout: ${MENU_TIMEOUT} seconds"
    echo "  • Mode switching available in advanced options"
    echo "  • Status information shown at top"
    echo ""
    echo "Keyboard Shortcuts:"
    echo "  • Ctrl+C: Cancel current operation"
    echo "  • Ctrl+Z: Suspend (use 'fg' to resume)"
}

# =============================================================================
# DEFAULT HANDLER IMPLEMENTATIONS
# =============================================================================

# Mode switching handlers
handle_switch_to_server_mode() {
    log_info "🔄 Switching to server mode..."
    export FKS_MODE="server"
    export FKS_MODE_REASON="User selected via menu"
    log_success "Switched to server mode"
    initialize_menu_system
    press_enter_to_continue
}

handle_switch_to_development_mode() {
    log_info "🔄 Switching to development mode..."
    export FKS_MODE="development"
    export FKS_MODE_REASON="User selected via menu"
    log_success "Switched to development mode"
    initialize_menu_system
    press_enter_to_continue
}

# Common system handlers
handle_system_health_check() {
    log_info "🏥 Running system health check..."
    
    if command -v comprehensive_health_check >/dev/null 2>&1; then
        comprehensive_health_check
    else
        log_error "Health check handler not available"
    fi
    
    press_enter_to_continue
}

handle_system_information() {
    log_info "ℹ️ System Information"
    
    if command -v show_system_information >/dev/null 2>&1; then
        show_system_information
    else
        echo "FKS Trading Systems"
        echo "Version: ${SCRIPT_VERSION:-unknown}"
        echo "Mode: ${FKS_MODE:-unknown}"
        echo ""
        echo "System: $(uname -s -m)"
        echo "User: ${USER:-unknown}"
        echo "Directory: $(pwd)"
    fi
    
    press_enter_to_continue
}

# Placeholder handlers for unimplemented features
handle_setup_python_environment() { log_info "🐍 Python environment setup not implemented"; press_enter_to_continue; }
handle_install_requirements() { log_info "📦 Requirements installation not implemented"; press_enter_to_continue; }
handle_run_python_script() { log_info "🏃 Python script execution not implemented"; press_enter_to_continue; }
handle_interactive_python() { log_info "🐍 Interactive Python not implemented"; press_enter_to_continue; }
handle_run_tests() { log_info "🧪 Test runner not implemented"; press_enter_to_continue; }
handle_code_quality_check() { log_info "🔍 Code quality check not implemented"; press_enter_to_continue; }
handle_process_data_files() { log_info "📊 Data processing not implemented"; press_enter_to_continue; }
handle_generate_reports() { log_info "📈 Report generation not implemented"; press_enter_to_continue; }
handle_visualize_data() { log_info "📊 Data visualization not implemented"; press_enter_to_continue; }
handle_data_validation() { log_info "✅ Data validation not implemented"; press_enter_to_continue; }
handle_git_operations() { log_info "🔄 Git operations not implemented"; press_enter_to_continue; }
handle_database_management() { log_info "🗃️ Database management not implemented"; press_enter_to_continue; }
handle_api_testing() { log_info "🔗 API testing not implemented"; press_enter_to_continue; }
handle_performance_profiling() { log_info "⚡ Performance profiling not implemented"; press_enter_to_continue; }
handle_view_logs() { log_info "📄 Log viewing not implemented"; press_enter_to_continue; }
handle_configuration_management() { log_info "⚙️ Configuration management not implemented"; press_enter_to_continue; }
handle_backup_restore() { log_info "💾 Backup & restore not implemented"; press_enter_to_continue; }
handle_performance_monitoring() { log_info "📊 Performance monitoring not implemented"; press_enter_to_continue; }
handle_troubleshooting_tools() { log_info "🔧 Troubleshooting tools not implemented"; press_enter_to_continue; }

# Server mode handlers
handle_start_services() { log_info "🚀 Starting services not implemented"; press_enter_to_continue; }
handle_stop_services() { log_info "🛑 Stopping services not implemented"; press_enter_to_continue; }
handle_restart_services() { log_info "🔄 Restarting services not implemented"; press_enter_to_continue; }
handle_view_service_status() { log_info "📊 Service status not implemented"; press_enter_to_continue; }
handle_deploy_application() { log_info "🚀 Application deployment not implemented"; press_enter_to_continue; }
handle_rollback_deployment() { log_info "🔙 Deployment rollback not implemented"; press_enter_to_continue; }
handle_build_images() { log_info "🏗️ Image building not implemented"; press_enter_to_continue; }
handle_pull_images() { log_info "⬇️ Image pulling not implemented"; press_enter_to_continue; }
handle_container_logs() { log_info "📄 Container logs not implemented"; press_enter_to_continue; }
handle_container_shell() { log_info "🐚 Container shell not implemented"; press_enter_to_continue; }
handle_clean_docker_system() { log_info "🧹 Docker cleanup not implemented"; press_enter_to_continue; }
handle_docker_metrics() { log_info "📊 Docker metrics not implemented"; press_enter_to_continue; }
handle_system_metrics() { log_info "📊 System metrics not implemented"; press_enter_to_continue; }
handle_application_logs() { log_info "📄 Application logs not implemented"; press_enter_to_continue; }
handle_error_analysis() { log_info "🔥 Error analysis not implemented"; press_enter_to_continue; }
handle_performance_dashboard() { log_info "📊 Performance dashboard not implemented"; press_enter_to_continue; }
handle_health_check() { handle_system_health_check; }
handle_backup_data() { log_info "💾 Data backup not implemented"; press_enter_to_continue; }
handle_update_system() { log_info "⬆️ System update not implemented"; press_enter_to_continue; }
handle_security_scan() { log_info "🔒 Security scan not implemented"; press_enter_to_continue; }
handle_database_operations() { log_info "🗃️ Database operations not implemented"; press_enter_to_continue; }
handle_network_diagnostics() { log_info "🌐 Network diagnostics not implemented"; press_enter_to_continue; }
handle_system_configuration() { log_info "⚙️ System configuration not implemented"; press_enter_to_continue; }

# Generic handlers
handle_show_configuration() { log_info "⚙️ Configuration display not implemented"; press_enter_to_continue; }
handle_performance_check() { log_info "⚡ Performance check not implemented"; press_enter_to_continue; }
handle_install_dependencies() { log_info "📦 Dependency installation not implemented"; press_enter_to_continue; }
handle_setup_environment() { log_info "🔧 Environment setup not implemented"; press_enter_to_continue; }
handle_validate_configuration() { log_info "✅ Configuration validation not implemented"; press_enter_to_continue; }
handle_reset_system() { log_info "🔄 System reset not implemented"; press_enter_to_continue; }
handle_show_help() { show_menu_help; }
handle_about_fks() { log_info "ℹ️ About FKS: Advanced Trading Systems Framework"; press_enter_to_continue; }
handle_documentation() { log_info "📖 Documentation: https://github.com/nuniesmith/fks"; press_enter_to_continue; }

# =============================================================================
# EXPORTS
# =============================================================================

# Export main functions
export -f show_full_menu initialize_menu_system
export -f show_menu_header show_current_menu show_menu_status
export -f read_menu_choice process_menu_choice execute_menu_action
export -f press_enter_to_continue show_menu_help
export -f clear_screen_if_enabled

log_debug "📦 Loaded enhanced menu module (v$MENU_MODULE_VERSION)"