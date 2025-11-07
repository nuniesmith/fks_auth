#!/bin/bash
# filepath: scripts/run/yaml/validator.sh
# FKS Trading Systems - YAML Validation Functions
# Version: 1.0.0 - Aligned with configuration standards

# Prevent multiple sourcing
[[ -n "${FKS_YAML_VALIDATOR_LOADED:-}" ]] && return 0
readonly FKS_YAML_VALIDATOR_LOADED=1

# =============================================================================
# CONFIGURATION AND DEPENDENCIES
# =============================================================================

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source dependencies with fallback
source "$SCRIPT_DIR/../core/logging.sh" 2>/dev/null || {
    # Fallback logging if core logging not available
    log_info() { echo "[INFO] $1"; }
    log_warn() { echo "[WARN] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_success() { echo "[SUCCESS] $1"; }
    log_debug() { echo "[DEBUG] $1"; }
}

source "$SCRIPT_DIR/processor.sh" 2>/dev/null || {
    log_error "processor.sh not found - validation functions may not work properly"
    exit 1
}

# Configuration paths (hardcoded for reliability)
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly MAIN_CONFIG_PATH="${CONFIG_DIR}/main.yaml"
readonly DOCKER_CONFIG_PATH="${CONFIG_DIR}/docker.yaml"
readonly SERVICES_CONFIG_PATH="${CONFIG_DIR}/services.yaml"
readonly SERVICE_CONFIGS_DIR="${CONFIG_DIR}/services"

# Version information
readonly VALIDATOR_VERSION="1.0.0"

# =============================================================================
# MAIN VALIDATION FUNCTIONS
# =============================================================================

# Validate all YAML configuration files
validate_all_yaml_files() {
    log_info "🔍 Validating YAML configuration files..."
    echo ""
    
    local validation_errors=0
    local total_files=0
    local warnings=0
    
    # Ensure yq is available
    if ! ensure_yq_available; then
        log_error "yq is required for YAML validation"
        return 1
    fi
    
    # Validate main config
    log_info "Validating main configuration..."
    if validate_main_config; then
        log_success "✅ main.yaml is valid"
    else
        ((validation_errors++))
    fi
    ((total_files++))
    
    # Validate docker config
    log_info "Validating Docker configuration..."
    if validate_docker_config; then
        log_success "✅ docker.yaml is valid"
    else
        ((validation_errors++))
    fi
    ((total_files++))
    
    # Validate services config
    log_info "Validating services configuration..."
    local service_result
    service_result=$(validate_services_configuration)
    case $service_result in
        0)
            log_success "✅ services configuration is valid"
            ;;
        1)
            log_warn "⚠️  services configuration has warnings"
            ((warnings++))
            ;;
        *)
            log_error "❌ services configuration has errors"
            ((validation_errors++))
            ;;
    esac
    ((total_files++))
    
    # Validate individual service configs (if they exist)
    if [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
        log_info "Validating individual service configurations..."
        local individual_errors
        individual_errors=$(validate_individual_service_configs)
        validation_errors=$((validation_errors + individual_errors))
        
        local service_count
        service_count=$(find "$SERVICE_CONFIGS_DIR" -name "*.yaml" -type f | wc -l)
        total_files=$((total_files + service_count))
    fi
    
    # Cross-validation between configs
    log_info "Performing cross-validation..."
    if validate_cross_references; then
        log_success "✅ Cross-validation passed"
    else
        log_warn "⚠️  Cross-validation found inconsistencies"
        ((warnings++))
    fi
    
    # Report results
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [[ $validation_errors -eq 0 && $warnings -eq 0 ]]; then
        log_success "🎉 All $total_files YAML files are valid!"
        return 0
    elif [[ $validation_errors -eq 0 ]]; then
        log_warn "⚠️  Validation completed with $warnings warning(s) across $total_files files"
        return 0
    else
        log_error "❌ Validation failed: $validation_errors error(s) and $warnings warning(s) across $total_files files"
        return 1
    fi
}

# =============================================================================
# MAIN CONFIG VALIDATION
# =============================================================================

# Validate main configuration file
validate_main_config() {
    if [[ ! -f "$MAIN_CONFIG_PATH" ]]; then
        log_error "Main config file not found: $MAIN_CONFIG_PATH"
        return 1
    fi
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$MAIN_CONFIG_PATH"; then
        return 1
    fi
    
    # Structure validation
    validate_main_config_structure "$MAIN_CONFIG_PATH"
}

# Validate main config structure
validate_main_config_structure() {
    local config_file="$1"
    local errors=0
    
    # Required top-level sections
    local required_sections=("system" "environment" "logging")
    
    for section in "${required_sections[@]}"; do
        if ! yaml_path_exists "$config_file" "$section"; then
            log_error "Missing required section in main config: $section"
            ((errors++))
        fi
    done
    
    # Validate system section
    if yaml_path_exists "$config_file" "system"; then
        validate_system_section "$config_file" || ((errors++))
    fi
    
    # Validate environment section
    if yaml_path_exists "$config_file" "environment"; then
        validate_environment_section "$config_file" || ((errors++))
    fi
    
    # Validate logging section
    if yaml_path_exists "$config_file" "logging"; then
        validate_logging_section "$config_file" || ((errors++))
    fi
    
    # Validate optional sections
    if yaml_path_exists "$config_file" "trading"; then
        validate_trading_section "$config_file" || ((errors++))
    fi
    
    if yaml_path_exists "$config_file" "models"; then
        validate_models_section "$config_file" || ((errors++))
    fi
    
    return $errors
}

# Validate system section
validate_system_section() {
    local config_file="$1"
    local errors=0
    
    # Check required system fields
    local required_fields=("name" "version")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "system.$field"; then
            log_error "Missing required system field: $field"
            ((errors++))
        fi
    done
    
    # Validate version format
    local version
    version=$(get_yaml_value "$config_file" "system.version" "")
    if [[ -n "$version" ]]; then
        if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_warn "Version format should be semantic (x.y.z): $version"
        fi
    fi
    
    return $errors
}

# Validate environment section
validate_environment_section() {
    local config_file="$1"
    local errors=0
    
    # Validate mode
    local mode
    mode=$(get_yaml_value "$config_file" "environment.mode" "")
    if [[ -n "$mode" ]]; then
        case "$mode" in
            "development"|"staging"|"production")
                log_debug "Valid environment mode: $mode"
                ;;
            *)
                log_warn "⚠️  Non-standard environment mode: $mode"
                ;;
        esac
    fi
    
    # Validate paths if they exist
    if yaml_path_exists "$config_file" "environment.paths"; then
        validate_environment_paths "$config_file" || ((errors++))
    fi
    
    return $errors
}

# Validate environment paths
validate_environment_paths() {
    local config_file="$1"
    local errors=0
    
    # Get all path entries
    local paths
    mapfile -t paths < <(get_yaml_keys "$config_file" "environment.paths")
    
    for path_key in "${paths[@]}"; do
        local path_value
        path_value=$(get_yaml_value "$config_file" "environment.paths.$path_key" "")
        
        if [[ -n "$path_value" ]]; then
            # Check if path is absolute
            if [[ "$path_value" != /* ]]; then
                log_warn "Path '$path_key' should be absolute: $path_value"
            fi
            
            # Check if critical directories exist (for some paths)
            case "$path_key" in
                "project_root"|"config_dir")
                    if [[ ! -d "$path_value" ]]; then
                        log_error "Critical directory does not exist: $path_key -> $path_value"
                        ((errors++))
                    fi
                    ;;
            esac
        fi
    done
    
    return $errors
}

# Validate logging section
validate_logging_section() {
    local config_file="$1"
    local errors=0
    
    # Validate log level
    local log_level
    log_level=$(get_yaml_value "$config_file" "logging.level" "")
    if [[ -n "$log_level" ]]; then
        case "$log_level" in
            "DEBUG"|"INFO"|"WARN"|"WARNING"|"ERROR"|"CRITICAL")
                log_debug "Valid log level: $log_level"
                ;;
            *)
                log_error "Invalid log level: $log_level"
                ((errors++))
                ;;
        esac
    fi
    
    # Validate log file path
    local log_file
    log_file=$(get_yaml_value "$config_file" "logging.file" "")
    if [[ -n "$log_file" ]]; then
        local log_dir
        log_dir=$(dirname "$log_file")
        if [[ ! -d "$log_dir" ]]; then
            log_warn "Log directory does not exist: $log_dir"
        fi
    fi
    
    return $errors
}

# Validate trading section
validate_trading_section() {
    local config_file="$1"
    local errors=0
    
    # Validate trading mode
    local trading_mode
    trading_mode=$(get_yaml_value "$config_file" "trading.mode" "")
    if [[ -n "$trading_mode" ]]; then
        case "$trading_mode" in
            "paper"|"live"|"backtest"|"simulation")
                log_debug "Valid trading mode: $trading_mode"
                ;;
            *)
                log_warn "⚠️  Non-standard trading mode: $trading_mode"
                ;;
        esac
    fi
    
    # Validate initial balance
    local initial_balance
    initial_balance=$(get_yaml_value "$config_file" "trading.initial_balance" "")
    if [[ -n "$initial_balance" ]]; then
        if ! [[ "$initial_balance" =~ ^[0-9]+(\.[0-9]+)?$ ]] || (( $(echo "$initial_balance <= 0" | bc -l 2>/dev/null || echo 1) )); then
            log_error "Invalid initial balance: $initial_balance"
            ((errors++))
        fi
    fi
    
    return $errors
}

# Validate models section
validate_models_section() {
    local config_file="$1"
    local errors=0
    
    # Validate default model
    local default_model
    default_model=$(get_yaml_value "$config_file" "models.default_model" "")
    if [[ -n "$default_model" ]]; then
        case "$default_model" in
            "transformer"|"lstm"|"gru"|"cnn"|"mlp"|"xgboost"|"random_forest")
                log_debug "Valid default model: $default_model"
                ;;
            *)
                log_warn "⚠️  Non-standard model type: $default_model"
                ;;
        esac
    fi
    
    return $errors
}

# =============================================================================
# DOCKER CONFIG VALIDATION
# =============================================================================

# Validate docker configuration file
validate_docker_config() {
    if [[ ! -f "$DOCKER_CONFIG_PATH" ]]; then
        log_error "Docker config file not found: $DOCKER_CONFIG_PATH"
        return 1
    fi
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$DOCKER_CONFIG_PATH"; then
        return 1
    fi
    
    # Structure validation
    validate_docker_config_structure "$DOCKER_CONFIG_PATH"
}

# Validate docker config structure
validate_docker_config_structure() {
    local config_file="$1"
    local errors=0
    
    # Required top-level sections
    local required_sections=("system" "build" "databases")
    
    for section in "${required_sections[@]}"; do
        if ! yaml_path_exists "$config_file" "$section"; then
            log_error "Missing required section in docker config: $section"
            ((errors++))
        fi
    done
    
    # Validate system section
    if yaml_path_exists "$config_file" "system"; then
        validate_docker_system_section "$config_file" || ((errors++))
    fi
    
    # Validate build section
    if yaml_path_exists "$config_file" "build"; then
        validate_docker_build_section "$config_file" || ((errors++))
    fi
    
    # Validate databases section
    if yaml_path_exists "$config_file" "databases"; then
        validate_docker_databases_section "$config_file" || ((errors++))
    fi
    
    # Validate optional sections
    if yaml_path_exists "$config_file" "networks"; then
        validate_docker_networks_section "$config_file" || ((errors++))
    fi
    
    if yaml_path_exists "$config_file" "volumes"; then
        validate_docker_volumes_section "$config_file" || ((errors++))
    fi
    
    if yaml_path_exists "$config_file" "resources"; then
        validate_docker_resources_section "$config_file" || ((errors++))
    fi
    
    return $errors
}

# Validate docker system section
validate_docker_system_section() {
    local config_file="$1"
    local errors=0
    
    # Validate registry configuration
    if yaml_path_exists "$config_file" "system.registry"; then
        local username
        username=$(get_yaml_value "$config_file" "system.registry.username" "")
        if [[ -z "$username" ]]; then
            log_error "Docker registry username is required"
            ((errors++))
        fi
        
        local repository
        repository=$(get_yaml_value "$config_file" "system.registry.repository" "")
        if [[ -z "$repository" ]]; then
            log_error "Docker registry repository is required"
            ((errors++))
        fi
    fi
    
    # Validate user configuration
    if yaml_path_exists "$config_file" "system.user"; then
        local user_id
        user_id=$(get_yaml_value "$config_file" "system.user.id" "")
        if [[ -n "$user_id" ]]; then
            if ! [[ "$user_id" =~ ^[0-9]+$ ]] || [[ $user_id -lt 1000 ]]; then
                log_warn "User ID should be >= 1000 for security: $user_id"
            fi
        fi
    fi
    
    return $errors
}

# Validate docker build section
validate_docker_build_section() {
    local config_file="$1"
    local errors=0
    
    # Validate version specifications
    if yaml_path_exists "$config_file" "build.versions"; then
        local python_version
        python_version=$(get_yaml_value "$config_file" "build.versions.python" "")
        if [[ -n "$python_version" ]]; then
            if ! [[ "$python_version" =~ ^[0-9]+\.[0-9]+ ]]; then
                log_warn "Python version format should be x.y or x.y-variant: $python_version"
            fi
        fi
        
        local cuda_version
        cuda_version=$(get_yaml_value "$config_file" "build.versions.cuda" "")
        if [[ -n "$cuda_version" ]]; then
            if ! [[ "$cuda_version" =~ ^[0-9]+\.[0-9]+ ]]; then
                log_warn "CUDA version format should be x.y: $cuda_version"
            fi
        fi
    fi
    
    # Validate healthcheck configuration
    if yaml_path_exists "$config_file" "build.healthcheck"; then
        validate_healthcheck_config "$config_file" "build.healthcheck" || ((errors++))
    fi
    
    return $errors
}

# Validate healthcheck configuration
validate_healthcheck_config() {
    local config_file="$1"
    local section="$2"
    local errors=0
    
    # Validate interval
    local interval
    interval=$(get_yaml_value "$config_file" "$section.interval" "")
    if [[ -n "$interval" ]]; then
        if ! [[ "$interval" =~ ^[0-9]+[smh]$ ]]; then
            log_error "Invalid healthcheck interval format: $interval (should be like 30s, 5m, 1h)"
            ((errors++))
        fi
    fi
    
    # Validate timeout
    local timeout
    timeout=$(get_yaml_value "$config_file" "$section.timeout" "")
    if [[ -n "$timeout" ]]; then
        if ! [[ "$timeout" =~ ^[0-9]+[smh]$ ]]; then
            log_error "Invalid healthcheck timeout format: $timeout (should be like 10s, 1m)"
            ((errors++))
        fi
    fi
    
    # Validate retries
    local retries
    retries=$(get_yaml_value "$config_file" "$section.retries" "")
    if [[ -n "$retries" ]]; then
        if ! [[ "$retries" =~ ^[0-9]+$ ]] || [[ $retries -lt 1 ]] || [[ $retries -gt 10 ]]; then
            log_error "Invalid healthcheck retries (should be 1-10): $retries"
            ((errors++))
        fi
    fi
    
    return $errors
}

# Validate docker databases section
validate_docker_databases_section() {
    local config_file="$1"
    local errors=0
    
    # Get all databases
    local databases
    mapfile -t databases < <(get_yaml_keys "$config_file" "databases")
    
    for db in "${databases[@]}"; do
        if ! validate_database_definition "$config_file" "databases.$db" "$db"; then
            ((errors++))
        fi
    done
    
    return $errors
}

# Validate database definition
validate_database_definition() {
    local config_file="$1"
    local db_path="$2"
    local db_name="$3"
    local errors=0
    
    # Required database fields
    local required_fields=("image" "port")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "$db_path.$field"; then
            log_error "Database $db_name missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate port number
    local port
    port=$(get_yaml_value "$config_file" "$db_path.port" "")
    if [[ -n "$port" ]]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
            log_error "Database $db_name has invalid port: $port"
            ((errors++))
        fi
    fi
    
    # Database-specific validation
    case "$db_name" in
        "postgres")
            validate_postgres_config "$config_file" "$db_path" || ((errors++))
            ;;
        "redis")
            validate_redis_config "$config_file" "$db_path" || ((errors++))
            ;;
    esac
    
    return $errors
}

# Validate PostgreSQL configuration
validate_postgres_config() {
    local config_file="$1"
    local db_path="$2"
    local errors=0
    
    # PostgreSQL specific fields
    local postgres_fields=("database" "user" "password")
    
    for field in "${postgres_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "$db_path.$field"; then
            log_error "PostgreSQL missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate password strength
    local password
    password=$(get_yaml_value "$config_file" "$db_path.password" "")
    if [[ -n "$password" ]]; then
        if [[ ${#password} -lt 12 ]]; then
            log_warn "PostgreSQL password should be at least 12 characters long"
        fi
        if [[ "$password" == "123456" ]] || [[ "$password" == "password" ]] || [[ "$password" == "postgres" ]]; then
            log_error "PostgreSQL password is too weak: $password"
            ((errors++))
        fi
    fi
    
    return $errors
}

# Validate Redis configuration
validate_redis_config() {
    local config_file="$1"
    local db_path="$2"
    local errors=0
    
    # Validate password
    local password
    password=$(get_yaml_value "$config_file" "$db_path.password" "")
    if [[ -z "$password" ]]; then
        log_warn "⚠️  Redis has no password configured"
    elif [[ ${#password} -lt 12 ]]; then
        log_warn "Redis password should be at least 12 characters long"
    elif [[ "$password" == "123456" ]] || [[ "$password" == "password" ]] || [[ "$password" == "redis" ]]; then
        log_error "Redis password is too weak: $password"
        ((errors++))
    fi
    
    # Validate memory settings
    local maxmemory
    maxmemory=$(get_yaml_value "$config_file" "$db_path.maxmemory" "")
    if [[ -n "$maxmemory" ]]; then
        if ! [[ "$maxmemory" =~ ^[0-9]+[kmgtKMGT]?[bB]?$ ]]; then
            log_warn "Redis maxmemory format should be like 512mb, 1gb: $maxmemory"
        fi
    fi
    
    return $errors
}

# Validate docker networks section
validate_docker_networks_section() {
    local config_file="$1"
    local errors=0
    
    # Get all networks
    local networks
    mapfile -t networks < <(get_yaml_keys "$config_file" "networks")
    
    for network in "${networks[@]}"; do
        # Validate network driver
        local driver
        driver=$(get_yaml_value "$config_file" "networks.$network.driver" "")
        if [[ -n "$driver" ]]; then
            case "$driver" in
                "bridge"|"host"|"overlay"|"macvlan"|"none")
                    log_debug "Valid network driver for $network: $driver"
                    ;;
                *)
                    log_warn "Non-standard network driver for $network: $driver"
                    ;;
            esac
        fi
    done
    
    return $errors
}

# Validate docker volumes section
validate_docker_volumes_section() {
    local config_file="$1"
    local errors=0
    
    # Get all volumes
    local volumes
    mapfile -t volumes < <(get_yaml_keys "$config_file" "volumes")
    
    for volume in "${volumes[@]}"; do
        # Validate volume driver
        local driver
        driver=$(get_yaml_value "$config_file" "volumes.$volume.driver" "")
        if [[ -n "$driver" ]]; then
            case "$driver" in
                "local"|"nfs"|"rexray"|"flocker")
                    log_debug "Valid volume driver for $volume: $driver"
                    ;;
                *)
                    log_warn "Non-standard volume driver for $volume: $driver"
                    ;;
            esac
        fi
    done
    
    return $errors
}

# Validate docker resources section
validate_docker_resources_section() {
    local config_file="$1"
    local errors=0
    
    # Get all resource definitions
    local services
    mapfile -t services < <(get_yaml_keys "$config_file" "resources")
    
    for service in "${services[@]}"; do
        # Validate CPU limits
        local cpu_limit
        cpu_limit=$(get_yaml_value "$config_file" "resources.$service.cpu_limit" "")
        if [[ -n "$cpu_limit" ]]; then
            if ! [[ "$cpu_limit" =~ ^[0-9]+(\.[0-9]+)?$ ]] || (( $(echo "$cpu_limit <= 0" | bc -l 2>/dev/null || echo 1) )); then
                log_error "Invalid CPU limit for $service: $cpu_limit"
                ((errors++))
            fi
        fi
        
        # Validate memory limits
        local memory_limit
        memory_limit=$(get_yaml_value "$config_file" "resources.$service.memory_limit" "")
        if [[ -n "$memory_limit" ]]; then
            if ! [[ "$memory_limit" =~ ^[0-9]+[KMGT]?$ ]]; then
                log_error "Invalid memory limit format for $service: $memory_limit (should be like 1024M, 2G)"
                ((errors++))
            fi
        fi
    done
    
    return $errors
}

# =============================================================================
# SERVICES CONFIG VALIDATION
# =============================================================================

# Validate services configuration (consolidated or individual)
validate_services_configuration() {
    # Try consolidated services.yaml first
    if [[ -f "$SERVICES_CONFIG_PATH" ]]; then
        validate_consolidated_services_config
    elif [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
        validate_individual_service_configs
    else
        log_error "No services configuration found"
        return 2
    fi
}

# Validate consolidated services configuration
validate_consolidated_services_config() {
    if [[ ! -f "$SERVICES_CONFIG_PATH" ]]; then
        log_error "Services config file not found: $SERVICES_CONFIG_PATH"
        return 2
    fi
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$SERVICES_CONFIG_PATH"; then
        return 2
    fi
    
    # Structure validation
    validate_services_config_structure "$SERVICES_CONFIG_PATH"
}

# Validate services config structure
validate_services_config_structure() {
    local config_file="$1"
    local errors=0
    local warnings=0
    
    # Get all service definitions
    local services
    mapfile -t services < <(get_yaml_keys "$config_file" "")
    
    # Validate each service
    for service in "${services[@]}"; do
        # Skip special sections
        if [[ "$service" =~ ^(global|service_groups|dependencies|health_checks)$ ]]; then
            continue
        fi
        
        local service_result
        service_result=$(validate_service_definition "$config_file" "$service")
        case $service_result in
            0)
                log_debug "Service $service: valid"
                ;;
            1)
                log_debug "Service $service: warnings"
                ((warnings++))
                ;;
            *)
                log_debug "Service $service: errors"
                ((errors++))
                ;;
        esac
    done
    
    # Validate global section if it exists
    if yaml_path_exists "$config_file" "global"; then
        validate_global_service_config "$config_file" || ((warnings++))
    fi
    
    # Validate service groups if they exist
    if yaml_path_exists "$config_file" "service_groups"; then
        validate_service_groups_config "$config_file" || ((warnings++))
    fi
    
    # Return result based on errors and warnings
    if [[ $errors -gt 0 ]]; then
        return 2
    elif [[ $warnings -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Validate individual service definition
validate_service_definition() {
    local config_file="$1"
    local service_name="$2"
    local errors=0
    local warnings=0
    
    # Required service fields
    local required_fields=("service.port" "container_name" "image_tag")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "$service_name.$field"; then
            log_error "Service $service_name missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate port number
    local port
    port=$(get_yaml_value "$config_file" "$service_name.service.port" "")
    if [[ -n "$port" ]]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
            log_error "Service $service_name has invalid port: $port"
            ((errors++))
        elif [[ $port -lt 1024 ]]; then
            log_warn "Service $service_name uses privileged port: $port"
            ((warnings++))
        fi
    fi
    
    # Validate image tag format
    local image_tag
    image_tag=$(get_yaml_value "$config_file" "$service_name.image_tag" "")
    if [[ -n "$image_tag" ]]; then
        if ! [[ "$image_tag" =~ ^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$ ]]; then
            log_warn "Service $service_name has unusual image tag format: $image_tag"
            ((warnings++))
        fi
    fi
    
    # Validate health check command
    local healthcheck_cmd
    healthcheck_cmd=$(get_yaml_value "$config_file" "$service_name.healthcheck_cmd" "")
    if [[ -n "$healthcheck_cmd" ]]; then
        if [[ "$healthcheck_cmd" =~ localhost ]]; then
            log_debug "Service $service_name health check uses localhost"
        fi
    else
        log_warn "Service $service_name has no health check command"
        ((warnings++))
    fi
    
    # Service-specific validation
    case "$service_name" in
        "api"|"app"|"data"|"web"|"worker")
            validate_application_service "$config_file" "$service_name" || ((warnings++))
            ;;
        "training"|"transformer")
            validate_gpu_service "$config_file" "$service_name" || ((warnings++))
            ;;
    esac
    
    # Return result
    if [[ $errors -gt 0 ]]; then
        return 2
    elif [[ $warnings -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Validate application service
validate_application_service() {
    local config_file="$1"
    local service_name="$2"
    local warnings=0
    
    # Check for Python-specific settings
    local config_file_path
    config_file_path=$(get_yaml_value "$config_file" "$service_name.config_file" "")
    if [[ -n "$config_file_path" ]]; then
        if [[ "$config_file_path" != /app/config/* ]]; then
            log_warn "Service $service_name config file not in standard location: $config_file_path"
            ((warnings++))
        fi
    fi
    
    return $warnings
}

# Validate GPU service
validate_gpu_service() {
    local config_file="$1"
    local service_name="$2"
    local warnings=0
    
    # Check for GPU-specific settings
    local cuda_devices
    cuda_devices=$(get_yaml_value "$config_file" "$service_name.cuda_visible_devices" "")
    if [[ -z "$cuda_devices" ]]; then
        log_warn "GPU service $service_name has no CUDA_VISIBLE_DEVICES setting"
        ((warnings++))
    fi
    
    # Check for model-specific settings
    case "$service_name" in
        "training")
            local epochs
            epochs=$(get_yaml_value "$config_file" "$service_name.epochs" "")
            if [[ -n "$epochs" ]]; then
                if ! [[ "$epochs" =~ ^[0-9]+$ ]] || [[ $epochs -lt 1 ]]; then
                    log_warn "Training service has invalid epochs: $epochs"
                    ((warnings++))
                fi
            fi
            ;;
        "transformer")
            local max_seq_len
            max_seq_len=$(get_yaml_value "$config_file" "$service_name.max_sequence_length" "")
            if [[ -n "$max_seq_len" ]]; then
                if ! [[ "$max_seq_len" =~ ^[0-9]+$ ]] || [[ $max_seq_len -lt 1 ]]; then
                    log_warn "Transformer service has invalid max_sequence_length: $max_seq_len"
                    ((warnings++))
                fi
            fi
            ;;
    esac
    
    return $warnings
}

# Validate global service config
validate_global_service_config() {
    local config_file="$1"
    local warnings=0
    
    # Validate global timeout
    local timeout
    timeout=$(get_yaml_value "$config_file" "global.timeout" "")
    if [[ -n "$timeout" ]]; then
        if ! [[ "$timeout" =~ ^[0-9]+$ ]] || [[ $timeout -lt 1 ]]; then
            log_warn "Invalid global timeout: $timeout"
            ((warnings++))
        fi
    fi
    
    # Validate global log level
    local log_level
    log_level=$(get_yaml_value "$config_file" "global.log_level" "")
    if [[ -n "$log_level" ]]; then
        case "$log_level" in
            "DEBUG"|"INFO"|"WARN"|"WARNING"|"ERROR"|"CRITICAL")
                log_debug "Valid global log level: $log_level"
                ;;
            *)
                log_warn "Invalid global log level: $log_level"
                ((warnings++))
                ;;
        esac
    fi
    
    return $warnings
}

# Validate service groups config
validate_service_groups_config() {
    local config_file="$1"
    local warnings=0
    
    # Get all service groups
    local groups
    mapfile -t groups < <(get_yaml_keys "$config_file" "service_groups")
    
    # Get all defined services
    local all_services
    mapfile -t all_services < <(get_yaml_keys "$config_file" "" | grep -v -E '^(global|service_groups|dependencies|health_checks)$')
    
    for group in "${groups[@]}"; do
        # Get services in this group
        local group_services
        mapfile -t group_services < <(yq eval ".service_groups.$group[]" "$config_file" 2>/dev/null)
        
        # Check if all services in group are defined
        for group_service in "${group_services[@]}"; do
            if ! printf '%s\n' "${all_services[@]}" | grep -q "^$group_service$"; then
                # Check if it's a standard service (redis, postgres)
                case "$group_service" in
                    "redis"|"postgres")
                        log_debug "Service group $group references standard service: $group_service"
                        ;;
                    *)
                        log_warn "Service group $group references undefined service: $group_service"
                        ((warnings++))
                        ;;
                esac
            fi
        done
    done
    
    return $warnings
}

# Validate individual service config files
validate_individual_service_configs() {
    local errors=0
    
    if [[ ! -d "$SERVICE_CONFIGS_DIR" ]]; then
        log_error "Service configs directory not found: $SERVICE_CONFIGS_DIR"
        return 2
    fi
    
    log_info "Validating individual service configurations..."
    
    local file_count=0
    for config_file in "$SERVICE_CONFIGS_DIR"/*.yaml; do
        if [[ -f "$config_file" ]]; then
            local service_name
            service_name=$(basename "$config_file" .yaml)
            
            if validate_individual_service_config_file "$config_file" "$service_name"; then
                log_success "✅ $service_name.yaml is valid"
            else
                log_error "❌ $service_name.yaml has errors"
                ((errors++))
            fi
            ((file_count++))
        fi
    done
    
    if [[ $file_count -eq 0 ]]; then
        log_warn "No individual service configuration files found"
        return 1
    fi
    
    return $errors
}

# Validate individual service config file
validate_individual_service_config_file() {
    local config_file="$1"
    local service_name="$2"
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$config_file"; then
        return 1
    fi
    
    # Check for required sections
    local required_sections=("service")
    local errors=0
    
    for section in "${required_sections[@]}"; do
        if ! yaml_path_exists "$config_file" "$section"; then
            log_error "Service $service_name missing required section: $section"
            ((errors++))
        fi
    done
    
    return $errors
}

# =============================================================================
# CROSS-VALIDATION FUNCTIONS
# =============================================================================

# Validate cross-references between configuration files
validate_cross_references() {
    local errors=0
    
    # Validate service port consistency
    validate_service_port_consistency || ((errors++))
    
    # Validate image tag consistency
    validate_image_tag_consistency || ((errors++))
    
    # Validate database references
    validate_database_references || ((errors++))
    
    # Validate network references
    validate_network_references || ((errors++))
    
    return $errors
}

# Validate service port consistency
validate_service_port_consistency() {
    local errors=0
    
    if [[ ! -f "$SERVICES_CONFIG_PATH" ]]; then
        return 0
    fi
    
    # Get all services and their ports
    local services
    mapfile -t services < <(get_yaml_keys "$SERVICES_CONFIG_PATH" "" | grep -v -E '^(global|service_groups|dependencies|health_checks)$')
    
    local used_ports=()
    for service in "${services[@]}"; do
        local port
        port=$(get_yaml_value "$SERVICES_CONFIG_PATH" "$service.service.port" "")
        if [[ -n "$port" ]]; then
            # Check for port conflicts
            for used_port in "${used_ports[@]}"; do
                if [[ "$used_port" == "$port" ]]; then
                    log_error "Port conflict: $port is used by multiple services"
                    ((errors++))
                fi
            done
            used_ports+=("$port")
        fi
    done
    
    return $errors
}

# Validate image tag consistency
validate_image_tag_consistency() {
    local errors=0
    
    # Check if image tags follow consistent naming pattern
    if [[ -f "$SERVICES_CONFIG_PATH" ]]; then
        local services
        mapfile -t services < <(get_yaml_keys "$SERVICES_CONFIG_PATH" "" | grep -v -E '^(global|service_groups|dependencies|health_checks)$')
        
        for service in "${services[@]}"; do
            local image_tag
            image_tag=$(get_yaml_value "$SERVICES_CONFIG_PATH" "$service.image_tag" "")
            if [[ -n "$image_tag" ]]; then
                # Check if it follows the expected pattern
                local expected_pattern
                if [[ -f "$DOCKER_CONFIG_PATH" ]]; then
                    local username
                    username=$(get_yaml_value "$DOCKER_CONFIG_PATH" "system.registry.username" "")
                    local repository
                    repository=$(get_yaml_value "$DOCKER_CONFIG_PATH" "system.registry.repository" "")
                    if [[ -n "$username" && -n "$repository" ]]; then
                        expected_pattern="${username}/${repository}:${service}"
                        if [[ "$image_tag" != "$expected_pattern"* ]]; then
                            log_warn "Service $service image tag doesn't follow expected pattern: $image_tag (expected: $expected_pattern*)"
                        fi
                    fi
                fi
            fi
        done
    fi
    
    return $errors
}

# Validate database references
validate_database_references() {
    local errors=0
    
    # Check if services that reference databases have corresponding database configs
    if [[ -f "$SERVICES_CONFIG_PATH" && -f "$DOCKER_CONFIG_PATH" ]]; then
        # Get available databases
        local databases
        mapfile -t databases < <(get_yaml_keys "$DOCKER_CONFIG_PATH" "databases")
        
        # Check if required databases are defined
        local required_dbs=("redis" "postgres")
        for db in "${required_dbs[@]}"; do
            if ! printf '%s\n' "${databases[@]}" | grep -q "^$db$"; then
                log_error "Required database not configured: $db"
                ((errors++))
            fi
        done
    fi
    
    return $errors
}

# Validate network references
validate_network_references() {
    local errors=0
    
    # This is a placeholder for network validation
    # In a real implementation, you'd check if services reference networks that are defined
    log_debug "Network reference validation - placeholder"
    
    return $errors
}

# =============================================================================
# VALIDATION REPORTING
# =============================================================================

# Generate validation report
generate_validation_report() {
    local output_file="${1:-validation_report.txt}"
    
    log_info "📄 Generating validation report: $output_file"
    
    {
        echo "FKS Trading Systems - Configuration Validation Report"
        echo "Generated: $(date)"
        echo "Validator Version: $VALIDATOR_VERSION"
        echo "=================================================="
        echo ""
        
        # Run validation and capture output
        if validate_all_yaml_files; then
            echo "VALIDATION RESULT: PASSED"
        else
            echo "VALIDATION RESULT: FAILED"
        fi
        
        echo ""
        echo "Configuration Files Checked:"
        echo "  - Main Config: $MAIN_CONFIG_PATH"
        echo "  - Docker Config: $DOCKER_CONFIG_PATH"
        echo "  - Services Config: $SERVICES_CONFIG_PATH"
        
        if [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
            local service_count
            service_count=$(find "$SERVICE_CONFIGS_DIR" -name "*.yaml" -type f | wc -l)
            echo "  - Individual Service Configs: $service_count files"
        fi
        
        echo ""
        echo "For detailed validation output, run:"
        echo "  $0 validate"
        
    } > "$output_file"
    
    log_success "Validation report generated: $output_file"
}

# =============================================================================
# VALIDATOR STATUS AND INFORMATION
# =============================================================================

# Show validator status and information
show_validator_status() {
    log_info "📊 YAML Validator Status (v${VALIDATOR_VERSION})"
    echo ""
    
    # Check dependencies
    log_info "Dependencies:"
    if command -v yq >/dev/null 2>&1; then
        local yq_version
        yq_version=$(yq --version 2>/dev/null | head -1)
        log_info "  ✅ yq: $yq_version"
    else
        log_info "  ❌ yq: Not installed"
    fi
    
    if command -v bc >/dev/null 2>&1; then
        log_info "  ✅ bc: Available (for numeric validation)"
    else
        log_info "  ⚠️  bc: Not available (numeric validation limited)"
    fi
    
    # Check configuration files
    log_info "Configuration Files:"
    local config_files=(
        "$MAIN_CONFIG_PATH:main.yaml"
        "$DOCKER_CONFIG_PATH:docker.yaml"
        "$SERVICES_CONFIG_PATH:services.yaml"
    )
    
    for file_info in "${config_files[@]}"; do
        local file_path="${file_info%:*}"
        local file_name="${file_info#*:}"
        
        if [[ -f "$file_path" ]]; then
            if validate_yaml_syntax "$file_path"; then
                log_info "  ✅ $file_name: Valid syntax"
            else
                log_info "  ❌ $file_name: Syntax errors"
            fi
        else
            log_info "  ❌ $file_name: Not found"
        fi
    done
    
    # Check service configurations
    log_info "Service Configurations:"
    if [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
        local service_count
        service_count=$(find "$SERVICE_CONFIGS_DIR" -name "*.yaml" -type f | wc -l)
        log_info "  📁 Individual configs: $service_count files"
    else
        log_info "  📁 Individual configs: Directory not found"
    fi
    
    # Show validation capabilities
    echo ""
    log_info "Validation Capabilities:"
    log_info "  - Syntax validation (YAML parsing)"
    log_info "  - Structure validation (required sections)"
    log_info "  - Value validation (types, ranges, formats)"
    log_info "  - Cross-reference validation (consistency checks)"
    log_info "  - Security validation (password strength, ports)"
    log_info "  - Best practices validation (warnings)"
}

# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

# Export all functions for external use
export -f validate_all_yaml_files
export -f validate_main_config validate_docker_config validate_services_configuration
export -f validate_individual_service_configs validate_cross_references
export -f generate_validation_report show_validator_status

# Main function for command line usage
main() {
    case "${1:-}" in
        "all"|"validate-all")
            validate_all_yaml_files
            ;;
        "main")
            validate_main_config
            ;;
        "docker")
            validate_docker_config
            ;;
        "services")
            validate_services_configuration
            ;;
        "individual")
            validate_individual_service_configs
            ;;
        "cross"|"cross-references")
            validate_cross_references
            ;;
        "report")
            local output_file="${2:-validation_report.txt}"
            generate_validation_report "$output_file"
            ;;
        "status")
            show_validator_status
            ;;
        "help"|"-h"|"--help")
            cat << EOF
YAML Validator v${VALIDATOR_VERSION} - Validate YAML configuration files

USAGE:
  $0 [command] [arguments]

COMMANDS:
  all, validate-all            Validate all configuration files
  main                         Validate main.yaml only
  docker                       Validate docker.yaml only
  services                     Validate services configuration
  individual                   Validate individual service configs
  cross, cross-references      Validate cross-references between configs
  report [file]                Generate validation report
  status                       Show validator status and capabilities
  help, -h, --help            Show this help

EXAMPLES:
  $0 all                       # Validate all configurations
  $0 main                      # Validate main config only
  $0 report validation.txt     # Generate detailed report

CONFIGURATION FILES:
  ${MAIN_CONFIG_PATH}
  ${DOCKER_CONFIG_PATH}
  ${SERVICES_CONFIG_PATH}

EOF
            ;;
        "")
            show_validator_status
            echo ""
            log_info "Use '$0 all' to validate all configurations or '$0 help' for more options"
            ;;
        *)
            log_error "Unknown command: $1"
            log_info "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi