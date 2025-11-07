#!/bin/bash
# filepath: scripts/yaml/processor.sh
# FKS Trading Systems - YAML Processing Functions
# Version: 1.0.0 - Aligned with configuration standards

# Prevent multiple sourcing
[[ -n "${FKS_YAML_PROCESSOR_LOADED:-}" ]] && return 0
readonly FKS_YAML_PROCESSOR_LOADED=1

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

# Configuration paths (hardcoded for reliability)
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly MAIN_CONFIG_PATH="${CONFIG_DIR}/main.yaml"
readonly DOCKER_CONFIG_PATH="${CONFIG_DIR}/docker.yaml"
readonly SERVICES_CONFIG_PATH="${CONFIG_DIR}/services.yaml"
readonly SERVICE_CONFIGS_DIR="${CONFIG_DIR}/services"

# Version information
readonly PROCESSOR_VERSION="1.0.0"

# =============================================================================
# YQ INSTALLATION AND MANAGEMENT
# =============================================================================

# Check if yq is available and install if needed
ensure_yq_available() {
    if command -v yq >/dev/null 2>&1; then
        local yq_version
        yq_version=$(yq --version 2>/dev/null | head -1)
        log_debug "yq is available: $yq_version"
        
        # Check if it's the correct version (mikefarah/yq v4+)
        if yq --version 2>/dev/null | grep -q "mikefarah/yq"; then
            return 0
        else
            log_warn "Wrong yq version detected, installing correct version..."
            install_yq
            return $?
        fi
    else
        log_info "yq not found. Installing yq..."
        install_yq
        return $?
    fi
}

# Install yq YAML processor
install_yq() {
    log_info "Installing yq YAML processor (mikefarah/yq)..."
    
    # Detect OS and architecture
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch
    arch=$(uname -m)
    
    # Normalize architecture names
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        i386|i686) arch="386" ;;
        *) 
            log_error "Unsupported architecture: $arch"
            log_info "Supported architectures: amd64, arm64, arm, 386"
            return 1
            ;;
    esac
    
    # Use latest stable version
    local yq_version="v4.40.5"
    local download_url="https://github.com/mikefarah/yq/releases/download/${yq_version}/yq_${os}_${arch}"
    local temp_file="/tmp/yq_$$"
    
    log_info "Downloading yq from: $download_url"
    
    # Download with error handling
    if command -v curl >/dev/null 2>&1; then
        if curl -L --fail --silent --show-error "$download_url" -o "$temp_file"; then
            log_debug "Downloaded yq successfully with curl"
        else
            log_error "Failed to download yq with curl"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget --quiet "$download_url" -O "$temp_file"; then
            log_debug "Downloaded yq successfully with wget"
        else
            log_error "Failed to download yq with wget"
            return 1
        fi
    else
        log_error "Neither curl nor wget found. Please install one of them or install yq manually."
        log_info "Manual installation: https://github.com/mikefarah/yq/releases"
        return 1
    fi
    
    # Verify download
    if [[ ! -f "$temp_file" ]] || [[ ! -s "$temp_file" ]]; then
        log_error "Downloaded file is empty or missing"
        [[ -f "$temp_file" ]] && rm -f "$temp_file"
        return 1
    fi
    
    # Make executable
    chmod +x "$temp_file"
    
    # Install to appropriate location
    local install_path
    if [[ -w "/usr/local/bin" ]]; then
        # Can write to /usr/local/bin directly
        install_path="/usr/local/bin/yq"
        mv "$temp_file" "$install_path"
        log_info "Installed yq to: $install_path"
    elif command -v sudo >/dev/null 2>&1; then
        # Use sudo
        install_path="/usr/local/bin/yq"
        sudo mv "$temp_file" "$install_path"
        log_info "Installed yq to: $install_path (with sudo)"
    else
        # Install to user's local bin
        local user_bin="$HOME/.local/bin"
        mkdir -p "$user_bin"
        install_path="$user_bin/yq"
        mv "$temp_file" "$install_path"
        log_info "Installed yq to: $install_path"
        
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":$user_bin:"* ]]; then
            export PATH="$user_bin:$PATH"
            log_info "Added $user_bin to PATH for current session"
            log_info "Consider adding 'export PATH=\"$user_bin:\$PATH\"' to your shell profile"
        fi
    fi
    
    # Clean up
    [[ -f "$temp_file" ]] && rm -f "$temp_file"
    
    # Verify installation
    if command -v yq >/dev/null 2>&1; then
        local installed_version
        installed_version=$(yq --version 2>/dev/null | head -1)
        log_success "✅ yq installed successfully: $installed_version"
        return 0
    else
        log_error "❌ yq installation failed"
        return 1
    fi
}

# =============================================================================
# YAML PATH AND VARIABLE CONVERSION
# =============================================================================

# Convert YAML path to environment variable name
yaml_path_to_env_var() {
    local yaml_path="$1"
    local prefix="$2"
    
    # Convert YAML path to uppercase environment variable
    # Example: system.app.version -> SYSTEM_APP_VERSION
    # Handle arrays and special characters
    local clean_path
    clean_path=$(echo "$yaml_path" | sed 's/\[[0-9]*\]//g' | sed 's/[^a-zA-Z0-9._]/_/g')
    echo "${prefix}$(echo "$clean_path" | sed 's/\./_/g' | tr '[:lower:]' '[:upper:]')"
}

# Convert environment variable back to YAML path
env_var_to_yaml_path() {
    local env_var="$1"
    local prefix="$2"
    
    # Remove prefix and convert back to YAML path
    local path_part="${env_var#$prefix}"
    echo "${path_part,,}" | sed 's/_/\./g'
}

# Sanitize value for environment variable
sanitize_env_value() {
    local value="$1"
    
    # Handle different value types
    case "$value" in
        # Boolean values
        "true"|"false"|"True"|"False"|"TRUE"|"FALSE")
            echo "${value,,}"
            ;;
        # Numeric values
        *[0-9]*)
            if [[ "$value" =~ ^[+-]?[0-9]+$ ]]; then
                # Integer
                echo "$value"
            elif [[ "$value" =~ ^[+-]?[0-9]*\.[0-9]+([eE][+-]?[0-9]+)?$ ]]; then
                # Float
                echo "$value"
            else
                # String with numbers
                printf '%q' "$value"
            fi
            ;;
        # String values
        *)
            # Quote if contains special characters or spaces
            if [[ "$value" =~ [[:space:]\&\|\<\>\(\)\;\'\"\$\`\\] ]]; then
                printf '%q' "$value"
            else
                echo "$value"
            fi
            ;;
    esac
}

# =============================================================================
# YAML EXTRACTION AND PROCESSING
# =============================================================================

# Extract all leaf values from YAML and convert to env vars
extract_yaml_to_env() {
    local yaml_file="$1"
    local prefix="$2"
    local output_file="$3"
    local section="${4:-}"
    
    if [[ ! -f "$yaml_file" ]]; then
        log_warn "YAML file not found: $yaml_file"
        return 1
    fi
    
    log_debug "Extracting variables from $yaml_file with prefix $prefix"
    if [[ -n "$section" ]]; then
        log_debug "  Section: $section"
    fi
    
    # Build yq expression
    local yq_expr
    if [[ -n "$section" ]]; then
        yq_expr=".$section | paths(scalars) as \$p | [\$p | join(\".\"), getpath(\$p)] | @tsv"
    else
        yq_expr="paths(scalars) as \$p | [\$p | join(\".\"), getpath(\$p)] | @tsv"
    fi
    
    # Extract values using yq
    local extraction_count=0
    while IFS=$'\t' read -r yaml_path value; do
        if [[ -n "$yaml_path" ]] && [[ -n "$value" ]]; then
            local env_var_name
            env_var_name=$(yaml_path_to_env_var "$yaml_path" "$prefix")
            
            # Sanitize the value
            local sanitized_value
            sanitized_value=$(sanitize_env_value "$value")
            
            # Write to output file
            echo "${env_var_name}=${sanitized_value}" >> "$output_file"
            log_debug "  $env_var_name=$sanitized_value"
            ((extraction_count++))
        fi
    done < <(yq eval "$yq_expr" "$yaml_file" 2>/dev/null)
    
    log_debug "Extracted $extraction_count variables from $yaml_file"
    return 0
}

# Extract specific section from YAML
extract_yaml_section() {
    local yaml_file="$1"
    local section="$2"
    local prefix="$3"
    local output_file="$4"
    
    if [[ ! -f "$yaml_file" ]]; then
        log_warn "YAML file not found: $yaml_file"
        return 1
    fi
    
    if ! yaml_path_exists "$yaml_file" "$section"; then
        log_warn "Section '$section' not found in $(basename "$yaml_file")"
        return 1
    fi
    
    log_info "Extracting section '$section' from $(basename "$yaml_file")"
    extract_yaml_to_env "$yaml_file" "$prefix" "$output_file" "$section"
}

# =============================================================================
# YAML QUERY AND MANIPULATION FUNCTIONS
# =============================================================================

# Get a specific value from YAML file
get_yaml_value() {
    local yaml_file="$1"
    local yaml_path="$2"
    local default_value="${3:-}"
    
    if [[ ! -f "$yaml_file" ]]; then
        echo "$default_value"
        return 1
    fi
    
    local value
    value=$(yq eval ".$yaml_path // \"$default_value\"" "$yaml_file" 2>/dev/null)
    echo "$value"
}

# Set a value in YAML file
set_yaml_value() {
    local yaml_file="$1"
    local yaml_path="$2"
    local value="$3"
    local create_backup="${4:-true}"
    
    if [[ ! -f "$yaml_file" ]]; then
        log_error "YAML file not found: $yaml_file"
        return 1
    fi
    
    # Create backup if requested
    if [[ "$create_backup" == "true" ]]; then
        cp "$yaml_file" "${yaml_file}.backup.$(date +%s)"
        log_debug "Created backup of $yaml_file"
    fi
    
    # Set the value
    yq eval ".$yaml_path = \"$value\"" -i "$yaml_file"
    log_debug "Set $yaml_path = $value in $yaml_file"
}

# Check if a YAML path exists
yaml_path_exists() {
    local yaml_file="$1"
    local yaml_path="$2"
    
    if [[ ! -f "$yaml_file" ]]; then
        return 1
    fi
    
    local value
    value=$(yq eval ".$yaml_path" "$yaml_file" 2>/dev/null)
    [[ "$value" != "null" ]]
}

# Get all keys from a YAML file at a specific path
get_yaml_keys() {
    local yaml_file="$1"
    local yaml_path="$2"
    
    if [[ ! -f "$yaml_file" ]]; then
        return 1
    fi
    
    if [[ -z "$yaml_path" ]]; then
        yq eval "keys | .[]" "$yaml_file" 2>/dev/null
    else
        yq eval ".$yaml_path | keys | .[]" "$yaml_file" 2>/dev/null
    fi
}

# Get array length
get_yaml_array_length() {
    local yaml_file="$1"
    local yaml_path="$2"
    
    if [[ ! -f "$yaml_file" ]]; then
        echo "0"
        return 1
    fi
    
    yq eval ".$yaml_path | length" "$yaml_file" 2>/dev/null || echo "0"
}

# =============================================================================
# YAML VALIDATION AND SYNTAX CHECKING
# =============================================================================

# Validate YAML syntax
validate_yaml_syntax() {
    local yaml_file="$1"
    
    if [[ ! -f "$yaml_file" ]]; then
        log_error "YAML file not found: $yaml_file"
        return 1
    fi
    
    if yq eval 'true' "$yaml_file" >/dev/null 2>&1; then
        log_debug "✅ $(basename "$yaml_file") has valid syntax"
        return 0
    else
        log_error "❌ $(basename "$yaml_file") has syntax errors"
        # Show the actual error
        yq eval 'true' "$yaml_file" 2>&1 | head -3 >&2
        return 1
    fi
}

# Check YAML file structure
check_yaml_structure() {
    local yaml_file="$1"
    shift
    local required_paths=("$@")
    
    if [[ ! -f "$yaml_file" ]]; then
        log_error "YAML file not found: $yaml_file"
        return 1
    fi
    
    local errors=0
    for path in "${required_paths[@]}"; do
        if ! yaml_path_exists "$yaml_file" "$path"; then
            log_error "Required path missing in $(basename "$yaml_file"): $path"
            ((errors++))
        fi
    done
    
    return $errors
}

# =============================================================================
# FILE FORMAT CONVERSION
# =============================================================================

# Convert YAML to JSON
yaml_to_json() {
    local yaml_file="$1"
    local json_file="$2"
    
    if [[ ! -f "$yaml_file" ]]; then
        log_error "YAML file not found: $yaml_file"
        return 1
    fi
    
    if yq eval -o=json "$yaml_file" > "$json_file"; then
        log_debug "Converted $(basename "$yaml_file") to JSON: $(basename "$json_file")"
        return 0
    else
        log_error "Failed to convert YAML to JSON"
        return 1
    fi
}

# Convert JSON to YAML
json_to_yaml() {
    local json_file="$1"
    local yaml_file="$2"
    
    if [[ ! -f "$json_file" ]]; then
        log_error "JSON file not found: $json_file"
        return 1
    fi
    
    if yq eval -P "$json_file" > "$yaml_file"; then
        log_debug "Converted $(basename "$json_file") to YAML: $(basename "$yaml_file")"
        return 0
    else
        log_error "Failed to convert JSON to YAML"
        return 1
    fi
}

# =============================================================================
# YAML MERGING AND TEMPLATING
# =============================================================================

# Merge YAML files
merge_yaml_files() {
    local base_file="$1"
    local overlay_file="$2"
    local output_file="$3"
    local merge_strategy="${4:-recursive}"
    
    if [[ ! -f "$base_file" ]]; then
        log_error "Base YAML file not found: $base_file"
        return 1
    fi
    
    if [[ ! -f "$overlay_file" ]]; then
        log_warn "Overlay YAML file not found: $overlay_file, copying base file only"
        cp "$base_file" "$output_file"
        return 0
    fi
    
    log_debug "Merging $(basename "$overlay_file") into $(basename "$base_file") -> $(basename "$output_file")"
    
    case "$merge_strategy" in
        "recursive")
            # Recursive merge (default)
            yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' "$base_file" "$overlay_file" > "$output_file"
            ;;
        "overlay")
            # Simple overlay (overlay replaces base values)
            yq eval-all 'select(fileIndex == 0) + select(fileIndex == 1)' "$base_file" "$overlay_file" > "$output_file"
            ;;
        *)
            log_error "Unknown merge strategy: $merge_strategy"
            return 1
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        log_debug "Successfully merged YAML files"
        return 0
    else
        log_error "Failed to merge YAML files"
        return 1
    fi
}

# Process template with variable substitution
process_yaml_template() {
    local template_file="$1"
    local output_file="$2"
    local vars_file="$3"
    
    if [[ ! -f "$template_file" ]]; then
        log_error "Template file not found: $template_file"
        return 1
    fi
    
    if [[ ! -f "$vars_file" ]]; then
        log_error "Variables file not found: $vars_file"
        return 1
    fi
    
    # Load variables and process template
    # This is a simplified version - could be extended with more sophisticated templating
    local temp_output
    temp_output=$(mktemp)
    
    # Process variable substitutions
    while IFS='=' read -r var_name var_value; do
        if [[ -n "$var_name" ]] && [[ ! "$var_name" =~ ^# ]]; then
            # Simple variable substitution
            sed -i "s/\${${var_name}}/${var_value}/g" "$temp_output"
        fi
    done < "$vars_file"
    
    mv "$temp_output" "$output_file"
    log_debug "Processed template: $(basename "$template_file") -> $(basename "$output_file")"
}

# =============================================================================
# SERVICE CONFIGURATION PROCESSING
# =============================================================================

# Process service configurations from consolidated or individual files
process_service_configs() {
    local output_file="$1"
    
    echo "" >> "$output_file"
    echo "# ==================================================================" >> "$output_file"
    echo "# === SERVICE CONFIGURATION VARIABLES ============================" >> "$output_file"
    echo "# ==================================================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # Try consolidated services.yaml first
    if [[ -f "$SERVICES_CONFIG_PATH" ]]; then
        log_info "Processing consolidated services configuration..."
        process_consolidated_services_config "$output_file"
        return $?
    fi
    
    # Fall back to individual service files
    if [[ -d "$SERVICE_CONFIGS_DIR" ]]; then
        log_info "Processing individual service configurations..."
        process_individual_service_configs "$output_file"
        return $?
    fi
    
    log_warn "No service configurations found"
    return 1
}

# Process consolidated services.yaml file
process_consolidated_services_config() {
    local output_file="$1"
    
    # Get all service keys
    local services
    mapfile -t services < <(get_yaml_keys "$SERVICES_CONFIG_PATH" "")
    
    local processed_count=0
    for service in "${services[@]}"; do
        # Skip special sections
        if [[ "$service" =~ ^(global|service_groups|dependencies|health_checks)$ ]]; then
            continue
        fi
        
        local service_upper
        service_upper=$(echo "$service" | tr '[:lower:]' '[:upper:]')
        
        echo "# --- $service Service Configuration ---" >> "$output_file"
        extract_yaml_section "$SERVICES_CONFIG_PATH" "$service" "${service_upper}_" "$output_file"
        echo "" >> "$output_file"
        
        log_success "✅ Processed $service service config"
        ((processed_count++))
    done
    
    # Process global section if it exists
    if yaml_path_exists "$SERVICES_CONFIG_PATH" "global"; then
        echo "# --- Global Service Configuration ---" >> "$output_file"
        extract_yaml_section "$SERVICES_CONFIG_PATH" "global" "SERVICES_GLOBAL_" "$output_file"
        echo "" >> "$output_file"
        log_success "✅ Processed global service config"
    fi
    
    log_info "Processed $processed_count service configurations from consolidated file"
    return 0
}

# Process individual service configuration files
process_individual_service_configs() {
    local output_file="$1"
    
    local config_count=0
    for config_file in "$SERVICE_CONFIGS_DIR"/*.yaml; do
        if [[ -f "$config_file" ]]; then
            local service_name
            service_name=$(basename "$config_file" .yaml | tr '[:lower:]' '[:upper:]')
            local prefix="${service_name}_"
            
            echo "# --- $service_name Service Configuration ---" >> "$output_file"
            extract_yaml_to_env "$config_file" "$prefix" "$output_file"
            echo "" >> "$output_file"
            
            log_success "✅ Processed $service_name service config"
            ((config_count++))
        fi
    done
    
    if [[ $config_count -eq 0 ]]; then
        log_warn "No service configuration files found in $SERVICE_CONFIGS_DIR"
        return 1
    fi
    
    log_info "Processed $config_count individual service configuration files"
    return 0
}

# =============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# =============================================================================

# Get service list from configurations
get_service_list() {
    local service_type="${1:-all}"
    
    # Try consolidated services config first
    if [[ -f "$SERVICES_CONFIG_PATH" ]]; then
        case "$service_type" in
            "all")
                get_yaml_keys "$SERVICES_CONFIG_PATH" "" | grep -v -E '^(global|service_groups|dependencies|health_checks)$'
                ;;
            *)
                # For specific types, check if they're defined in service_groups
                if yaml_path_exists "$SERVICES_CONFIG_PATH" "service_groups.$service_type"; then
                    yq eval ".service_groups.$service_type[]" "$SERVICES_CONFIG_PATH" 2>/dev/null
                else
                    log_warn "Service type '$service_type' not found in service groups"
                    return 1
                fi
                ;;
        esac
        return 0
    fi
    
    # Fall back to docker config
    if [[ -f "$DOCKER_CONFIG_PATH" ]]; then
        case "$service_type" in
            "cpu")
                get_yaml_keys "$DOCKER_CONFIG_PATH" "services.cpu_services"
                ;;
            "gpu")
                get_yaml_keys "$DOCKER_CONFIG_PATH" "services.gpu_services"
                ;;
            "database")
                get_yaml_keys "$DOCKER_CONFIG_PATH" "databases"
                ;;
            "monitoring")
                get_yaml_keys "$DOCKER_CONFIG_PATH" "monitoring"
                ;;
            "all")
                {
                    get_yaml_keys "$DOCKER_CONFIG_PATH" "services.cpu_services"
                    get_yaml_keys "$DOCKER_CONFIG_PATH" "services.gpu_services"
                    get_yaml_keys "$DOCKER_CONFIG_PATH" "databases"
                    get_yaml_keys "$DOCKER_CONFIG_PATH" "monitoring"
                } | sort -u
                ;;
            *)
                log_error "Unknown service type: $service_type"
                return 1
                ;;
        esac
        return 0
    fi
    
    log_error "No configuration files found to determine service list"
    return 1
}

# Get service groups from configuration
get_service_groups() {
    if [[ -f "$SERVICES_CONFIG_PATH" ]] && yaml_path_exists "$SERVICES_CONFIG_PATH" "service_groups"; then
        get_yaml_keys "$SERVICES_CONFIG_PATH" "service_groups"
    elif [[ -f "$DOCKER_CONFIG_PATH" ]] && yaml_path_exists "$DOCKER_CONFIG_PATH" "service_groups"; then
        get_yaml_keys "$DOCKER_CONFIG_PATH" "service_groups"
    else
        # Default service groups
        echo "core"
        echo "ml"
        echo "web"
        echo "monitoring"
        echo "all"
    fi
}

# Get services in a specific group
get_services_in_group() {
    local group_name="$1"
    
    # Check services config first
    if [[ -f "$SERVICES_CONFIG_PATH" ]] && yaml_path_exists "$SERVICES_CONFIG_PATH" "service_groups.$group_name"; then
        yq eval ".service_groups.$group_name[]" "$SERVICES_CONFIG_PATH" 2>/dev/null
        return 0
    fi
    
    # Check docker config
    if [[ -f "$DOCKER_CONFIG_PATH" ]] && yaml_path_exists "$DOCKER_CONFIG_PATH" "service_groups.$group_name"; then
        yq eval ".service_groups.$group_name[]" "$DOCKER_CONFIG_PATH" 2>/dev/null
        return 0
    fi
    
    # Fallback defaults
    case "$group_name" in
        "core")
            echo "redis"
            echo "postgres"
            echo "api"
            echo "data"
            echo "worker"
            echo "app"
            ;;
        "ml"|"gpu")
            echo "training"
            echo "transformer"
            ;;
        "web")
            echo "web"
            ;;
        "monitoring")
            echo "prometheus"
            echo "grafana"
            ;;
        "all")
            get_service_list "all"
            ;;
        *)
            log_error "Unknown service group: $group_name"
            return 1
            ;;
    esac
}

# =============================================================================
# TEMPLATE CREATION FUNCTIONS
# =============================================================================

# Create a template YAML structure
create_yaml_template() {
    local template_file="$1"
    local template_type="$2"
    
    # Ensure directory exists
    mkdir -p "$(dirname "$template_file")"
    
    case "$template_type" in
        "main_config")
            create_main_config_template "$template_file"
            ;;
        "docker_config")
            create_docker_config_template "$template_file"
            ;;
        "services_config")
            create_services_config_template "$template_file"
            ;;
        "service_config")
            create_individual_service_template "$template_file"
            ;;
        *)
            log_error "Unknown template type: $template_type"
            return 1
            ;;
    esac
}

# Create main config template
create_main_config_template() {
    local template_file="$1"
    
    cat > "$template_file" << 'EOF'
# =================================================================
# === FKS Trading Systems - Main Configuration ===================
# =================================================================

system:
  name: "FKS Trading Systems"
  version: "1.0.0"
  description: "Financial trading framework with multi-service architecture"
  timezone: "America/New_York"

environment:
  mode: "development"  # Options: development, staging, production
  debug: false
  paths:
    project_root: "/home/${USER}/fks"
    config_dir: "/home/${USER}/fks/config"
    data_dir: "/home/${USER}/fks/data"
    logs_dir: "/home/${USER}/fks/logs"
    models_dir: "/home/${USER}/fks/models"

logging:
  level: "INFO"
  file: "/home/${USER}/fks/logs/main.log"
  rotation:
    enabled: true
    max_size: "100MB"
    backup_count: 5

trading:
  mode: "paper"
  initial_balance: 10000
  quote_currency: "USDT"
  max_open_positions: 5

models:
  default_model: "transformer"
  storage:
    models_directory: "/home/${USER}/fks/models"
    format: "pytorch"

market:
  default_symbols:
    - "BTCUSDT"
    - "ETHUSDT"
    - "SOLUSDT"
  default_timeframes:
    - "1h"
    - "4h"
    - "1d"

security:
  authentication:
    enabled: false
    default_secret: "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"
EOF
    
    log_success "Created main config template: $template_file"
}

# Create docker config template
create_docker_config_template() {
    local template_file="$1"
    
    cat > "$template_file" << 'EOF'
# =================================================================
# === FKS Trading Systems - Docker Configuration =================
# =================================================================

system:
  app:
    version: "1.0.0"
    environment: "development"
    timezone: "America/New_York"
  
  registry:
    username: "nuniesmith"
    repository: "fks"
  
  user:
    name: "appuser"
    id: 1088
    group_id: 1088

build:
  parallel: true
  cache: true
  context: "."
  dockerfile_path: "./deployment/docker/Dockerfile"
  dockerfile_gpu_path: "./deployment/docker/Dockerfile"
  
  versions:
    python: "3.11"
    cuda: "12.8.0"
    ubuntu: "ubuntu24.04"
  
  healthcheck:
    interval: "30s"
    timeout: "10s"
    retries: 3
    start_period: "30s"

databases:
  redis:
    image: "redis:7-alpine"
    container_name: "fks_redis"
    port: 6379
    password: "fks_redis_2024_secure!"
    maxmemory: "512mb"
    maxmemory_policy: "allkeys-lru"
    healthcheck_cmd: "redis-cli -a fks_redis_2024_secure! ping | grep PONG"
    restart_policy: "unless-stopped"
  
  postgres:
    image: "postgres:16-alpine"
    container_name: "fks_postgres"
    port: 5432
    database: "financial_data"
    user: "postgres"
    password: "fks_postgres_2024_secure!"
    max_connections: 100
    shared_buffers: "256MB"
    healthcheck_cmd: "pg_isready -U postgres -d financial_data"
    restart_policy: "unless-stopped"

networks:
  frontend:
    name: "fks_frontend"
    driver: "bridge"
    internal: false
  backend:
    name: "fks_backend"
    driver: "bridge"
    internal: false
  database:
    name: "fks_database"
    driver: "bridge"
    internal: true

volumes:
  app_data:
    name: "fks_app_data"
    driver: "local"
  app_logs:
    name: "fks_app_logs"
    driver: "local"
  app_models:
    name: "fks_app_models"
    driver: "local"
  postgres_data:
    name: "fks_postgres_data"
    driver: "local"
  redis_data:
    name: "fks_redis_data"
    driver: "local"

resources:
  api:
    cpu_limit: "2"
    memory_limit: "2048M"
  app:
    cpu_limit: "2"
    memory_limit: "2048M"
  data:
    cpu_limit: "2"
    memory_limit: "2048M"
  web:
    cpu_limit: "1"
    memory_limit: "1024M"
  worker:
    cpu_limit: "2"
    memory_limit: "2048M"
  training:
    cpu_limit: "4"
    memory_limit: "4096M"
  transformer:
    cpu_limit: "4"
    memory_limit: "4096M"
  redis:
    cpu_limit: "1"
    memory_limit: "512M"
  postgres:
    cpu_limit: "2"
    memory_limit: "1024M"

logging:
  driver: "json-file"
  max_size: "100m"
  max_files: "3"

service_groups:
  core:
    - "redis"
    - "postgres"
    - "api"
    - "data"
    - "worker"
    - "app"
  ml:
    - "redis"
    - "postgres"
    - "data"
    - "training"
    - "transformer"
  web:
    - "redis"
    - "postgres"
    - "api"
    - "web"
  all:
    - "redis"
    - "postgres"
    - "api"
    - "data"
    - "worker"
    - "app"
    - "training"
    - "transformer"
    - "web"
EOF
    
    log_success "Created docker config template: $template_file"
}

# Create services config template
create_services_config_template() {
    local template_file="$1"
    
    cat > "$template_file" << 'EOF'
# =================================================================
# === FKS Trading Systems - Services Configuration ===============
# =================================================================

global:
  timeout: 300
  log_level: "INFO"
  environment: "development"

api:
  service:
    host: "0.0.0.0"
    port: 8000
    workers: 4
    timeout: 60
  container_name: "fks_api"
  image_tag: "nuniesmith/fks:api"
  config_file: "/app/config/services/api.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8000/health"
  restart_policy: "unless-stopped"

app:
  service:
    host: "0.0.0.0"
    port: 9000
    workers: 4
    timeout: 300
  container_name: "fks_app"
  image_tag: "nuniesmith/fks:app"
  trading_mode: "paper"
  config_file: "/app/config/services/app.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9000/health"
  restart_policy: "unless-stopped"

data:
  service:
    host: "0.0.0.0"
    port: 9001
    workers: 2
    timeout: 120
  container_name: "fks_data"
  image_tag: "nuniesmith/fks:data"
  config_file: "/app/config/services/data.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9001/health"
  restart_policy: "unless-stopped"

web:
  service:
    host: "0.0.0.0"
    port: 9999
    workers: 4
    timeout: 60
  container_name: "fks_web"
  image_tag: "nuniesmith/fks:web"
  config_file: "/app/config/services/web.yaml"
  healthcheck_cmd: "curl --fail http://localhost:9999/health"
  restart_policy: "unless-stopped"

worker:
  service:
    host: "0.0.0.0"
    port: 8001
    workers: 2
    timeout: 60
  container_name: "fks_worker"
  image_tag: "nuniesmith/fks:worker"
  count: 2
  config_file: "/app/config/services/worker.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8001/health"
  restart_policy: "unless-stopped"

training:
  service:
    host: "0.0.0.0"
    port: 8088
    workers: 1
    timeout: 86400
  container_name: "fks_training"
  image_tag: "nuniesmith/fks:training"
  epochs: 50
  batch_size: 32
  learning_rate: 0.001
  cuda_visible_devices: "0"
  config_file: "/app/config/services/training.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8088/health || nvidia-smi > /dev/null"
  restart_policy: "unless-stopped"

transformer:
  service:
    host: "0.0.0.0"
    port: 8089
    workers: 1
    timeout: 86400
  container_name: "fks_transformer"
  image_tag: "nuniesmith/fks:transformer"
  model_type: "transformer"
  max_sequence_length: 512
  batch_size: 32
  cuda_visible_devices: "0"
  config_file: "/app/config/services/transformer.yaml"
  healthcheck_cmd: "curl --fail http://localhost:8089/health || nvidia-smi > /dev/null"
  restart_policy: "unless-stopped"

service_groups:
  core:
    - "api"
    - "app"
    - "data"
    - "worker"
  ml:
    - "training"
    - "transformer"
  web:
    - "web"
  all:
    - "api"
    - "app"
    - "data"
    - "worker"
    - "training"
    - "transformer"
    - "web"

dependencies:
  api: ["redis", "postgres"]
  app: ["api", "data", "redis", "postgres"]
  data: ["redis", "postgres"]
  web: ["api", "redis", "postgres"]
  worker: ["redis", "postgres"]
  training: ["data", "redis", "postgres"]
  transformer: ["data", "redis", "postgres"]

health_checks:
  enabled: true
  timeout: 10
  interval: 30
  retries: 3
  endpoints:
    api: "http://localhost:8000/health"
    app: "http://localhost:9000/health"
    data: "http://localhost:9001/health"
    web: "http://localhost:9999/health"
    worker: "http://localhost:8001/health"
    training: "http://localhost:8088/health"
    transformer: "http://localhost:8089/health"
EOF
    
    log_success "Created services config template: $template_file"
}

# Create individual service template
create_individual_service_template() {
    local template_file="$1"
    local service_name
    service_name=$(basename "$template_file" .yaml)
    
    cat > "$template_file" << EOF
# ============================================================
# FKS Trading Systems - ${service_name^} Service Configuration
# ============================================================

service:
  host: "0.0.0.0"
  port: 8000
  workers: 2
  timeout: 60
  log_level: "INFO"

# ${service_name^}-specific configuration
${service_name}:
  enabled: true
  # Add ${service_name}-specific settings here

# Health check configuration
health_check:
  enabled: true
  endpoint: "/health"
  interval: 30
  timeout: 10

# Environment variables
environment:
  service_type: "${service_name}"
  config_dir: "/app/config"
  pythonpath: "/app/src"
EOF
    
    log_success "Created individual service template: $template_file"
}

# =============================================================================
# CONFIGURATION STATUS AND INFORMATION
# =============================================================================

# Show processor status and information
show_processor_status() {
    log_info "📊 YAML Processor Status (v${PROCESSOR_VERSION})"
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
                log_info "  ✅ $file_name: Valid"
            else
                log_info "  ⚠️  $file_name: Syntax errors"
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
    
    # Show available functions
    echo ""
    log_info "Available Functions:"
    log_info "  - YAML processing: extract_yaml_to_env, get_yaml_value, set_yaml_value"
    log_info "  - File operations: merge_yaml_files, validate_yaml_syntax"
    log_info "  - Service management: get_service_list, get_service_groups"
    log_info "  - Template creation: create_yaml_template"
}

# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

# Export all functions for external use
export -f ensure_yq_available install_yq
export -f yaml_path_to_env_var env_var_to_yaml_path sanitize_env_value
export -f extract_yaml_to_env extract_yaml_section
export -f get_yaml_value set_yaml_value yaml_path_exists get_yaml_keys get_yaml_array_length
export -f validate_yaml_syntax check_yaml_structure
export -f yaml_to_json json_to_yaml merge_yaml_files process_yaml_template
export -f process_service_configs process_consolidated_services_config process_individual_service_configs
export -f get_service_list get_service_groups get_services_in_group
export -f create_yaml_template create_main_config_template create_docker_config_template
export -f create_services_config_template create_individual_service_template
export -f show_processor_status

# Main function for command line usage
main() {
    case "${1:-}" in
        "status")
            show_processor_status
            ;;
        "install-yq")
            ensure_yq_available
            ;;
        "template")
            local template_type="${2:-main_config}"
            local output_file="${3:-./config/template.yaml}"
            create_yaml_template "$output_file" "$template_type"
            ;;
        "validate")
            local yaml_file="${2:-$MAIN_CONFIG_PATH}"
            validate_yaml_syntax "$yaml_file"
            ;;
        "help"|"-h"|"--help")
            cat << EOF
YAML Processor v${PROCESSOR_VERSION} - YAML processing functions

USAGE:
  $0 [command] [arguments]

COMMANDS:
  status                        Show processor status and dependencies
  install-yq                    Install or update yq YAML processor
  template [type] [file]        Create configuration template
  validate [file]               Validate YAML syntax
  help, -h, --help             Show this help

TEMPLATE TYPES:
  main_config                   Main system configuration
  docker_config                 Docker infrastructure configuration
  services_config               Consolidated services configuration
  service_config                Individual service configuration

EXAMPLES:
  $0 status                     # Show processor status
  $0 template main_config       # Create main config template
  $0 validate config/main.yaml  # Validate YAML file

EOF
            ;;
        "")
            show_processor_status
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