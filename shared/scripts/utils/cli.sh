#!/bin/bash
# filepath: scripts/utils/cli.sh
# FKS Trading Systems - CLI Handling Module
# Handles command-line argument processing and special modes

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Module metadata
readonly CLI_MODULE_VERSION="2.5.0"
readonly CLI_MODULE_LOADED="$(date +%s)"

# help with mode information
show_help() {
    cat << EOF
${WHITE}FKS Trading Systems Runner v${SCRIPT_VERSION:-2.5.0}${NC}
${CYAN}Modular orchestrator with development and server mode support${NC}

${YELLOW}USAGE:${NC}
  $0 [MODE] [OPTIONS] [ARGUMENTS]

${YELLOW}MODES:${NC}
  ${GREEN}Development Mode (--dev):${NC}
    • Local development with conda/venv Python environments
    • Interactive debugging and development tools
    • Local package installation and management
    • Git integration and development workflow
    
  ${GREEN}Server Mode (--server):${NC}
    • Production deployment with Docker containers
    • Optimized for server environments
    • Container orchestration and management
    • Headless operation support

${YELLOW}MODE SELECTION:${NC}
  --dev, --development       Force development mode
  --server, --production     Force server mode
  --auto                     Auto-detect mode (default)

${YELLOW}OPTIONS:${NC}
  ${GREEN}General:${NC}
    -h, --help                 Show this help message
    -v, --version              Show version information
    --debug                    Enable debug mode
    --mode-info                Show current mode detection
    
  ${GREEN}Execution Modes:${NC}
    -d, --docker               Force Docker mode (server-oriented)
    -p, --python               Force Python mode (dev-oriented)
    --interactive              Force interactive mode (default)
    
  ${GREEN}Configuration:${NC}
    -c, --config PATH          Specify app config file path
    --docker-config PATH       Specify docker config file path
    --service-configs PATH     Specify service configs directory path
    --data PATH                Specify data file path
    
  ${GREEN}Operations:${NC}
    --clean                    Clean mode (remove containers/cache)
    --regenerate-env           Force regeneration of .env file
    --regenerate-compose       Force regeneration of docker-compose.yml
    --regenerate-all           Regenerate both .env and docker-compose.yml
    --validate-yaml            Validate YAML files only
    --show-config              Show configuration summary only
    --generate-requirements    Generate service-specific requirements files
    
  ${GREEN}Environment Management:${NC}
    --setup-conda              Setup conda environment (dev mode)
    --setup-venv               Setup virtual environment (dev mode)
    --setup-docker             Setup Docker environment (server mode)
    --install-requirements     Install Python requirements (mode-aware)
    
  ${GREEN}System Management:${NC}
    --install                  Run installation wizard
    --reset                    Run reset operations
    --update                   Run update operations
    --monitor                  Run monitoring dashboard
    --health-check             Run comprehensive health check

${YELLOW}EXAMPLES:${NC}
  ${GREEN}Development Mode:${NC}
    $0 --dev                   # Development mode with conda environment
    $0 --dev --setup-conda     # Setup conda environment
    $0 --dev --python          # Run Python directly with local env
    
  ${GREEN}Server Mode:${NC}
    $0 --server                # Server mode with Docker
    $0 --server --docker       # Force Docker execution
    $0 --server --setup-docker # Setup Docker environment
    
  ${GREEN}Auto Mode:${NC}
    $0                         # Auto-detect mode and run interactively
    $0 --auto --status         # Auto-detect and show status
    
  ${GREEN}Configuration Management:${NC}
    $0 --regenerate-all        # Rebuild all configuration files
    $0 --generate-requirements # Generate service-specific requirements
    
  ${GREEN}Environment Variables:${NC}
    FKS_MODE=development $0    # Force development mode
    FKS_MODE=server $0         # Force server mode
    DEBUG=true $0 --dev        # Enable debug in development

${YELLOW}MODE DETECTION:${NC}
  Auto-detection considers:
  ${GREEN}Development Indicators:${NC}
    • Conda/Anaconda installation
    • macOS or desktop environment
    • Git repository presence
    • Python development files
    
  ${GREEN}Server Indicators:${NC}
    • Docker daemon availability
    • SSH connection
    • Running as root
    • Linux server environment
    • Inside Docker container

${YELLOW}ENVIRONMENT SETUP:${NC}
  ${GREEN}Development Mode:${NC}
    • Creates/activates conda environment: fks
    • Installs requirements locally
    • Sets up development tools
    • Enables interactive debugging
    
  ${GREEN}Server Mode:${NC}
    • Uses Docker containers for all services
    • No local Python environment needed
    • Optimized for production deployment
    • Container orchestration and monitoring

${YELLOW}DOCUMENTATION:${NC}
  📖 Repository: https://github.com/nuniesmith/fks
  📚 Docs: https://docs.fks.com
  🐛 Issues: https://github.com/nuniesmith/fks/issues

EOF
}

# version information with mode details
show_version() {
    # Set mode if not already set
    [[ -z "${FKS_MODE:-}" ]] && set_operating_mode "auto"
    
    cat << EOF
${WHITE}FKS Trading Systems Runner v${SCRIPT_VERSION:-2.5.0}${NC}
${CYAN}Modular orchestrator with development/server mode support${NC}

${YELLOW}Current Configuration:${NC}
  Operating Mode: ${WHITE}$FKS_MODE${NC}
  Mode Reason: $FKS_MODE_REASON
  Main Runner: $MAIN_SCRIPT
  Scripts Dir: $SCRIPTS_RUN_DIR
  
${YELLOW}System Information:${NC}
  Bash Version: ${BASH_VERSION}
  Platform: $(uname -s -m)
  Working Dir: $(pwd)
  User: ${USER:-unknown}

${YELLOW}Mode Capabilities:${NC}
EOF
    
    case "$FKS_MODE" in
        "development")
            cat << EOF
  ${GREEN}Development Mode Features:${NC}
  ✅ Conda environment management
  ✅ Local Python package installation
  ✅ Interactive development tools
  ✅ Git integration
  ✅ Debug mode support
  ✅ Live reloading and testing
EOF
            ;;
        "server")
            cat << EOF
  ${GREEN}Server Mode Features:${NC}
  ✅ Docker container orchestration
  ✅ Production-optimized deployment
  ✅ Container health monitoring
  ✅ Scalable service management
  ✅ Headless operation
  ✅ Resource optimization
EOF
            ;;
    esac
    
    cat << EOF

${YELLOW}Available Tools:${NC}
EOF
    
    # Check available tools
    local tools=(
        "python3:Python 3"
        "conda:Conda"
        "docker:Docker"
        "docker-compose:Docker Compose"
        "git:Git"
    )
    
    for tool_spec in "${tools[@]}"; do
        local tool=$(echo "$tool_spec" | cut -d: -f1)
        local name=$(echo "$tool_spec" | cut -d: -f2)
        
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  ✅ $name"
        else
            echo "  ❌ $name"
        fi
    done
    
    echo ""
}

# special CLI mode handling with mode support
handle_special_cli_modes() {
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            show_version
            exit 0
            ;;
        --mode-info)
            show_mode_info
            exit 0
            ;;
        --dev|--development|--local)
            set_operating_mode "development"
            return 1  # Continue processing
            ;;
        --server|--production|--prod)
            set_operating_mode "server"
            return 1  # Continue processing
            ;;
        --auto)
            set_operating_mode "auto"
            return 1  # Continue processing
            ;;
        --debug)
            export DEBUG=true
            export LOG_LEVEL=DEBUG
            log_debug "Debug mode enabled"
            return 1  # Continue processing other arguments
            ;;
        --setup-conda)
            set_operating_mode "development"
            handle_setup_conda
            exit $?
            ;;
        --setup-venv)
            set_operating_mode "development"
            handle_setup_venv
            exit $?
            ;;
        --setup-docker)
            set_operating_mode "server"
            handle_setup_docker
            exit $?
            ;;
        --install-requirements)
            handle_install_requirements
            exit $?
            ;;
        --install)
            handle_install_mode "$@"
            exit $?
            ;;
        --generate-requirements)
            handle_requirements_mode "$@"
            exit $?
            ;;
        --health-check)
            handle_health_check_mode
            exit $?
            ;;
        --show-config)
            handle_show_config_mode
            exit $?
            ;;
        --validate-yaml)
            handle_validate_yaml_mode
            exit $?
            ;;
        --clean)
            handle_clean_mode
            exit $?
            ;;
    esac
    return 1  # Not a special mode, continue normal processing
}

# Process command line arguments
process_cli_arguments() {
    local processed_args=()
    
    # Process arguments and handle special modes
    while [[ $# -gt 0 ]]; do
        if handle_special_cli_modes "$1"; then
            # Special mode handled, continue with remaining args
            shift
        else
            # Regular argument, add to processed args
            processed_args+=("$1")
            shift
        fi
    done
    
    # Return processed arguments
    printf '%s\n' "${processed_args[@]}"
}

# Handle configuration display
handle_show_config_mode() {
    log_info "📋 Configuration Summary Mode ($FKS_MODE)"
    
    # Show environment summary
    if command -v show_environment_summary >/dev/null 2>&1; then
        show_environment_summary
    else
        log_warn "Environment summary not available"
    fi
    
    # Show file locations
    echo "${YELLOW}Configuration Files:${NC}"
    local config_files=(
        "app_config.yaml:App Configuration"
        "docker-compose.yml:Docker Compose"
        "requirements.txt:Python Requirements"
        ".env:Environment Variables"
    )
    
    for config_spec in "${config_files[@]}"; do
        local config_file=$(echo "$config_spec" | cut -d: -f1)
        local config_desc=$(echo "$config_spec" | cut -d: -f2)
        
        if [[ -f "$config_file" ]]; then
            echo "  ✅ $config_desc: $config_file"
        else
            echo "  ❌ $config_desc: $config_file (missing)"
        fi
    done
    
    echo ""
}

# Handle YAML validation
handle_validate_yaml_mode() {
    log_info "🔍 YAML Validation Mode"
    
    local yaml_files=()
    local validation_errors=0
    
    # Find YAML files
    if [[ -f "app_config.yaml" ]]; then
        yaml_files+=("app_config.yaml")
    fi
    
    if [[ -f "docker-compose.yml" ]]; then
        yaml_files+=("docker-compose.yml")
    fi
    
    # Add other YAML files if they exist
    local other_yamls=("environment.yml" "config.yaml" ".github/workflows/*.yml")
    for pattern in "${other_yamls[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                yaml_files+=("$file")
            fi
        done
    done
    
    if [[ ${#yaml_files[@]} -eq 0 ]]; then
        log_warn "No YAML files found to validate"
        return 0
    fi
    
    # Validate each YAML file
    for yaml_file in "${yaml_files[@]}"; do
        log_info "Validating: $yaml_file"
        
        if command -v python3 >/dev/null 2>&1; then
            if python3 -c "import yaml; yaml.safe_load(open('$yaml_file'))" 2>/dev/null; then
                log_success "✅ $yaml_file is valid"
            else
                log_error "❌ $yaml_file has syntax errors"
                ((validation_errors++))
            fi
        else
            log_warn "⚠️  Python not available for YAML validation"
        fi
    done
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "✅ All YAML files are valid"
        return 0
    else
        log_error "❌ $validation_errors YAML file(s) have errors"
        return 1
    fi
}

# Handle clean mode
handle_clean_mode() {
    log_info "🧹 Clean Mode ($FKS_MODE)"
    
    case "$FKS_MODE" in
        "development")
            clean_development_environment
            ;;
        "server")
            clean_server_environment
            ;;
        *)
            log_warn "Unknown mode: $FKS_MODE"
            return 1
            ;;
    esac
}

# Clean development environment
clean_development_environment() {
    log_info "🧹 Cleaning development environment..."
    
    local cleaned=0
    
    # Clean Python cache
    if [[ -d "__pycache__" ]]; then
        rm -rf __pycache__
        log_info "Removed Python cache"
        ((cleaned++))
    fi
    
    # Clean .pyc files
    local pyc_files
    pyc_files=$(find . -name "*.pyc" -type f 2>/dev/null)
    if [[ -n "$pyc_files" ]]; then
        find . -name "*.pyc" -type f -delete
        log_info "Removed .pyc files"
        ((cleaned++))
    fi
    
    # Clean temporary files
    if [[ -d "temp" ]]; then
        rm -rf temp/*
        log_info "Cleaned temp directory"
        ((cleaned++))
    fi
    
    if [[ $cleaned -eq 0 ]]; then
        log_info "Development environment is already clean"
    else
        log_success "✅ Cleaned $cleaned development artifacts"
    fi
}

# Clean server environment
clean_server_environment() {
    log_info "🧹 Cleaning server environment..."
    
    local cleaned=0
    
    # Clean Docker containers
    if command -v docker >/dev/null 2>&1; then
        local containers
        containers=$(docker ps -aq --filter "label=com.docker.compose.project=fks" 2>/dev/null)
        
        if [[ -n "$containers" ]]; then
            docker rm -f $containers
            log_info "Removed Docker containers"
            ((cleaned++))
        fi
        
        # Clean Docker images
        local images
        images=$(docker images -q --filter "label=com.docker.compose.project=fks" 2>/dev/null)
        
        if [[ -n "$images" ]]; then
            docker rmi $images
            log_info "Removed Docker images"
            ((cleaned++))
        fi
    fi
    
    # Clean volumes
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose down --volumes 2>/dev/null || true
        log_info "Cleaned Docker volumes"
        ((cleaned++))
    fi
    
    if [[ $cleaned -eq 0 ]]; then
        log_info "Server environment is already clean"
    else
        log_success "✅ Cleaned $cleaned server artifacts"
    fi
}

echo "📦 Loaded CLI handling module (v$CLI_MODULE_VERSION)"