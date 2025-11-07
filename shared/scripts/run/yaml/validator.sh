#!/bin/bash
# filepath: scripts/yaml/validator.sh
# FKS Trading Systems - YAML Validation Functions

# Prevent multiple sourcing
[[ -n "${FKS_YAML_VALIDATOR_LOADED:-}" ]] && return 0
readonly FKS_YAML_VALIDATOR_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"
source "$SCRIPT_DIR/processor.sh"

# Configuration paths
readonly DOCKER_CONFIG_PATH="${DOCKER_CONFIG_PATH:-./docker_config.yaml}"
readonly SERVICE_CONFIGS_DIR="${SERVICE_CONFIGS_DIR:-./config/services}"
readonly CONFIG_PATH="${CONFIG_PATH:-./config/app_config.yaml}"

# Validate all YAML configuration files
validate_all_yaml_files() {
    log_info "🔍 Validating YAML configuration files..."
    
    local validation_errors=0
    local total_files=0
    
    # Ensure yq is available
    if ! ensure_yq_available; then
        log_error "yq is required for YAML validation"
        return 1
    fi
    
    # Validate docker config
    if validate_docker_config; then
        log_success "✅ docker_config.yaml is valid"
    else
        ((validation_errors++))
    fi
    ((total_files++))
    
    # Validate app config
    if validate_app_config; then
        log_success "✅ app_config.yaml is valid"
    else
        ((validation_errors++))
    fi
    ((total_files++))
    
    # Validate service configs
    local service_errors
    service_errors=$(validate_service_configs)
    validation_errors=$((validation_errors + service_errors))
    
    # Count service config files
    if [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
        local service_count
        service_count=$(find "$SERVICE_CONFIGS_DIR" -name "*.yaml" -type f | wc -l)
        total_files=$((total_files + service_count))
    fi
    
    # Report results
    echo ""
    if [[ $validation_errors -eq 0 ]]; then
        log_success "🎉 All $total_files YAML files are valid!"
        return 0
    else
        log_error "❌ $validation_errors out of $total_files YAML files have errors"
        return 1
    fi
}

# Validate docker configuration file
validate_docker_config() {
    if [[ ! -f "$DOCKER_CONFIG_PATH" ]]; then
        log_error "Docker config file not found: $DOCKER_CONFIG_PATH"
        return 1
    fi
    
    log_info "Validating docker_config.yaml..."
    
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
    local required_sections=("system" "cpu_services" "databases")
    
    for section in "${required_sections[@]}"; do
        if ! yaml_path_exists "$config_file" "$section"; then
            log_error "Missing required section: $section"
            ((errors++))
        fi
    done
    
    # Validate system section
    if yaml_path_exists "$config_file" "system"; then
        validate_system_section "$config_file" || ((errors++))
    fi
    
    # Validate services sections
    if yaml_path_exists "$config_file" "cpu_services"; then
        validate_services_section "$config_file" "cpu_services" || ((errors++))
    fi
    
    if yaml_path_exists "$config_file" "gpu_services"; then
        validate_services_section "$config_file" "gpu_services" || ((errors++))
    fi
    
    # Validate databases section
    if yaml_path_exists "$config_file" "databases"; then
        validate_databases_section "$config_file" || ((errors++))
    fi
    
    return $errors
}

# Validate system section
validate_system_section() {
    local config_file="$1"
    local errors=0
    
    # Check required system fields
    local required_fields=("app.version" "app.environment")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "system.$field"; then
            log_error "Missing required system field: $field"
            ((errors++))
        fi
    done
    
    # Validate environment values
    local environment
    environment=$(get_yaml_value "$config_file" "system.app.environment" "")
    if [[ -n "$environment" ]]; then
        case "$environment" in
            "development"|"staging"|"production")
                log_debug "Valid environment: $environment"
                ;;
            *)
                log_warn "⚠️  Unusual environment value: $environment"
                ;;
        esac
    fi
    
    return $errors
}

# Validate services section
validate_services_section() {
    local config_file="$1"
    local section="$2"
    local errors=0
    
    # Get all services in the section
    local services
    services=($(get_yaml_keys "$config_file" "$section"))
    
    for service in "${services[@]}"; do
        if ! validate_service_definition "$config_file" "$section.$service" "$service"; then
            ((errors++))
        fi
    done
    
    return $errors
}

# Validate individual service definition
validate_service_definition() {
    local config_file="$1"
    local service_path="$2"
    local service_name="$3"
    local errors=0
    
    # Required service fields
    local required_fields=("image_tag" "port" "service_type")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "$service_path.$field"; then
            log_error "Service $service_name missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate port number
    local port
    port=$(get_yaml_value "$config_file" "$service_path.port" "")
    if [[ -n "$port" ]]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
            log_error "Service $service_name has invalid port: $port"
            ((errors++))
        fi
    fi
    
    # Validate image tag format
    local image_tag
    image_tag=$(get_yaml_value "$config_file" "$service_path.image_tag" "")
    if [[ -n "$image_tag" ]]; then
        if ! [[ "$image_tag" =~ ^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$ ]]; then
            log_warn "⚠️  Service $service_name has unusual image tag format: $image_tag"
        fi
    fi
    
    return $errors
}

# Validate databases section
validate_databases_section() {
    local config_file="$1"
    local errors=0
    
    # Get all databases
    local databases
    databases=($(get_yaml_keys "$config_file" "databases"))
    
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
    local required_fields=("image_tag" "port")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "$db_path.$field"; then
            log_error "Database $db_name missing required field: $field"
            ((errors++))
        fi
    done
    
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
    
    return $errors
}

# Validate Redis configuration
validate_redis_config() {
    local config_file="$1"
    local db_path="$2"
    local errors=0
    
    # Redis specific validation
    local password
    password=$(get_yaml_value "$config_file" "$db_path.password" "")
    if [[ -z "$password" ]]; then
        log_warn "⚠️  Redis has no password configured"
    fi
    
    return $errors
}

# Validate app configuration file
validate_app_config() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        log_error "App config file not found: $CONFIG_PATH"
        return 1
    fi
    
    log_info "Validating app_config.yaml..."
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$CONFIG_PATH"; then
        return 1
    fi
    
    # Structure validation
    validate_app_config_structure "$CONFIG_PATH"
}

# Validate app config structure
validate_app_config_structure() {
    local config_file="$1"
    local errors=0
    
    # Required top-level sections
    local required_sections=("app" "model" "data" "training")
    
    for section in "${required_sections[@]}"; do
        if ! yaml_path_exists "$config_file" "$section"; then
            log_error "Missing required section in app config: $section"
            ((errors++))
        fi
    done
    
    # Validate model section
    if yaml_path_exists "$config_file" "model"; then
        validate_model_config "$config_file" || ((errors++))
    fi
    
    # Validate data section
    if yaml_path_exists "$config_file" "data"; then
        validate_data_config "$config_file" || ((errors++))
    fi
    
    # Validate training section
    if yaml_path_exists "$config_file" "training"; then
        validate_training_config "$config_file" || ((errors++))
    fi
    
    return $errors
}

# Validate model configuration
validate_model_config() {
    local config_file="$1"
    local errors=0
    
    # Required model fields
    local required_fields=("type" "d_model" "n_head" "n_layers")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "model.$field"; then
            log_error "Model config missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate model type
    local model_type
    model_type=$(get_yaml_value "$config_file" "model.type" "")
    if [[ -n "$model_type" ]]; then
        case "$model_type" in
            "transformer"|"lstm"|"gru"|"cnn"|"mlp")
                log_debug "Valid model type: $model_type"
                ;;
            *)
                log_warn "⚠️  Unknown model type: $model_type"
                ;;
        esac
    fi
    
    # Validate numeric parameters
    validate_model_numeric_params "$config_file" || ((errors++))
    
    return $errors
}

# Validate model numeric parameters
validate_model_numeric_params() {
    local config_file="$1"
    local errors=0
    
    # Validate d_model
    local d_model
    d_model=$(get_yaml_value "$config_file" "model.d_model" "")
    if [[ -n "$d_model" ]]; then
        if ! [[ "$d_model" =~ ^[0-9]+$ ]] || [[ $d_model -lt 1 ]]; then
            log_error "Invalid d_model value: $d_model"
            ((errors++))
        elif [[ $d_model -gt 2048 ]]; then
            log_warn "⚠️  Very large d_model value: $d_model"
        fi
    fi
    
    # Validate n_head
    local n_head
    n_head=$(get_yaml_value "$config_file" "model.n_head" "")
    if [[ -n "$n_head" ]] && [[ -n "$d_model" ]]; then
        if ! [[ "$n_head" =~ ^[0-9]+$ ]] || [[ $n_head -lt 1 ]]; then
            log_error "Invalid n_head value: $n_head"
            ((errors++))
        elif [[ $((d_model % n_head)) -ne 0 ]]; then
            log_error "d_model ($d_model) must be divisible by n_head ($n_head)"
            ((errors++))
        fi
    fi
    
    # Validate dropout
    local dropout
    dropout=$(get_yaml_value "$config_file" "model.dropout" "")
    if [[ -n "$dropout" ]]; then
        if ! [[ "$dropout" =~ ^[0-9]*\.?[0-9]+$ ]] || (( $(echo "$dropout < 0" | bc -l) )) || (( $(echo "$dropout > 1" | bc -l) )); then
            log_error "Invalid dropout value (must be 0-1): $dropout"
            ((errors++))
        fi
    fi
    
    return $errors
}

# Validate data configuration
validate_data_config() {
    local config_file="$1"
    local errors=0
    
    # Required data fields
    local required_fields=("seq_length" "batch_size")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "data.$field"; then
            log_error "Data config missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate batch size
    local batch_size
    batch_size=$(get_yaml_value "$config_file" "data.batch_size" "")
    if [[ -n "$batch_size" ]]; then
        if ! [[ "$batch_size" =~ ^[0-9]+$ ]] || [[ $batch_size -lt 1 ]]; then
            log_error "Invalid batch_size value: $batch_size"
            ((errors++))
        elif [[ $batch_size -gt 1024 ]]; then
            log_warn "⚠️  Very large batch_size: $batch_size"
        fi
    fi
    
    return $errors
}

# Validate training configuration
validate_training_config() {
    local config_file="$1"
    local errors=0
    
    # Required training fields
    local required_fields=("epochs" "learning_rate")
    
    for field in "${required_fields[@]}"; do
        if ! yaml_path_exists "$config_file" "training.$field"; then
            log_error "Training config missing required field: $field"
            ((errors++))
        fi
    done
    
    # Validate learning rate
    local lr
    lr=$(get_yaml_value "$config_file" "training.learning_rate" "")
    if [[ -n "$lr" ]]; then
        if ! [[ "$lr" =~ ^[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?$ ]] || (( $(echo "$lr <= 0" | bc -l) )); then
            log_error "Invalid learning_rate value: $lr"
            ((errors++))
        fi
    fi
    
    return $errors
}

# Validate service configurations
validate_service_configs() {
    local errors=0
    
    if [[ ! -d "$SERVICE_CONFIGS_DIR" ]]; then
        log_error "Service configs directory not found: $SERVICE_CONFIGS_DIR"
        return 1
    fi
    
    log_info "Validating service configurations..."
    
    for config_file in "$SERVICE_CONFIGS_DIR"/*.yaml; do
        if [[ -f "$config_file" ]]; then
            local service_name
            service_name=$(basename "$config_file" .yaml)
            
            if validate_service_config_file "$config_file" "$service_name"; then
                log_success "✅ $service_name.yaml is valid"
            else
                log_error "❌ $service_name.yaml has errors"
                ((errors++))
            fi
        fi
    done
    
    return $errors
}

# Validate individual service config file
validate_service_config_file() {
    local config_file="$1"
    local service_name="$2"
    
    # Basic syntax validation
    if ! validate_yaml_syntax "$config_file"; then
        return 1

}