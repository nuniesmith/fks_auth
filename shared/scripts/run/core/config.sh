# filepath: fks/scripts/core/config.sh
# FKS Trading Systems - Configuration Management

# Prevent multiple sourcing
[[ -n "${FKS_CORE_CONFIG_LOADED:-}" ]] && return 0
readonly FKS_CORE_CONFIG_LOADED=1

# Module metadata
readonly CONFIG_MODULE_VERSION="3.1.0"
readonly CONFIG_MODULE_LOADED="$(date +%s)"

# Get script directory (avoid readonly conflicts)
if [[ -z "${CONFIG_SCRIPT_DIR:-}" ]]; then
    readonly CONFIG_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Source dependencies with fallback
if [[ -f "$CONFIG_SCRIPT_DIR/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_SCRIPT_DIR/logging.sh"
elif [[ -f "$(dirname "$CONFIG_SCRIPT_DIR")/core/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$(dirname "$CONFIG_SCRIPT_DIR")/core/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[INFO] $*"; }
    log_warn() { echo "[WARN] $*"; }
    log_error() { echo "[ERROR] $*" >&2; }
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo "[DEBUG] $*" >&2; }
    log_success() { echo "[SUCCESS] $*"; }
fi

# Configuration discovery and paths
declare -g FKS_CONFIG_BASE_DIR="${FKS_CONFIG_BASE_DIR:-$(pwd)}"
declare -g FKS_CONFIG_SEARCH_PATHS=(
    "./config/services"
    "./config" 
    "./configs"
    "."
)

# Default configuration files
declare -g FKS_CONFIG_DEFAULT_FILES=(
    "app.yaml"
    "app_config.yaml"
    "config.yaml"
    "fks.yaml"
)

declare -g FKS_DOCKER_CONFIG_DEFAULT_FILES=(
    "docker.yaml"
    "docker_config.yaml"
    "docker-compose.config.yaml"
)

# Global configuration variables
declare -A FKS_CONFIG
declare -A FKS_DOCKER_CONFIG  
declare -A FKS_SERVICE_CONFIGS
declare -A FKS_ENV_OVERRIDES

# Configuration system status
declare -g FKS_CONFIG_ERRORS=0
declare -g FKS_CONFIG_WARNINGS=0
declare -g FKS_CONFIG_YQ_AVAILABLE=false
declare -g FKS_CONFIG_PYTHON_AVAILABLE=false
declare -g FKS_CONFIG_INITIALIZED=false

# Discovered configuration files
declare -g FKS_DISCOVERED_APP_CONFIG=""
declare -g FKS_DISCOVERED_DOCKER_CONFIG=""
declare -A FKS_DISCOVERED_SERVICE_CONFIGS

# Check available parsing tools
check_config_tools() {
    local tools_found=0
    
    # Check for yq
    if command -v yq >/dev/null 2>&1; then
        FKS_CONFIG_YQ_AVAILABLE=true
        log_debug "✅ yq is available for YAML processing"
        ((tools_found++))
    else
        FKS_CONFIG_YQ_AVAILABLE=false
        log_debug "⚠️  yq not available"
    fi
    
    # Check for Python with yaml module
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import yaml" 2>/dev/null; then
            FKS_CONFIG_PYTHON_AVAILABLE=true
            log_debug "✅ Python with PyYAML is available"
            ((tools_found++))
        else
            FKS_CONFIG_PYTHON_AVAILABLE=false
            log_debug "⚠️  Python available but PyYAML not installed"
        fi
    else
        FKS_CONFIG_PYTHON_AVAILABLE=false
        log_debug "⚠️  Python3 not available"
    fi
    
    if [[ $tools_found -eq 0 ]]; then
        log_warn "No advanced YAML parsing tools available, using fallback methods"
    fi
    
    return 0
}

# Discover configuration files
discover_config_files() {
    log_debug "Discovering configuration files..."
    
    # Clear previous discoveries
    FKS_DISCOVERED_APP_CONFIG=""
    FKS_DISCOVERED_DOCKER_CONFIG=""
    FKS_DISCOVERED_SERVICE_CONFIGS=()
    
    # Search for app configuration
    for search_path in "${FKS_CONFIG_SEARCH_PATHS[@]}"; do
        if [[ ! -d "$search_path" ]]; then
            continue
        fi
        
        for config_file in "${FKS_CONFIG_DEFAULT_FILES[@]}"; do
            local full_path="$search_path/$config_file"
            if [[ -f "$full_path" ]]; then
                FKS_DISCOVERED_APP_CONFIG="$full_path"
                log_debug "Found app config: $full_path"
                break 2
            fi
        done
    done
    
    # Search for Docker configuration
    for search_path in "${FKS_CONFIG_SEARCH_PATHS[@]}"; do
        if [[ ! -d "$search_path" ]]; then
            continue
        fi
        
        for config_file in "${FKS_DOCKER_CONFIG_DEFAULT_FILES[@]}"; do
            local full_path="$search_path/$config_file"
            if [[ -f "$full_path" ]]; then
                FKS_DISCOVERED_DOCKER_CONFIG="$full_path"
                log_debug "Found docker config: $full_path"
                break 2
            fi
        done
    done
    
    # Search for service configurations
    for search_path in "${FKS_CONFIG_SEARCH_PATHS[@]}"; do
        if [[ ! -d "$search_path" ]]; then
            continue
        fi
        
        local service_files
        readarray -t service_files < <(find "$search_path" -maxdepth 2 -name "*.yaml" -o -name "*.yml" 2>/dev/null)
        
        for service_file in "${service_files[@]}"; do
            if [[ -f "$service_file" ]]; then
                local service_name
                service_name=$(basename "$service_file" .yaml)
                service_name=$(basename "$service_name" .yml)
                
                # Skip main config files
                if [[ "$service_name" =~ ^(app|docker|config)(_config)?$ ]]; then
                    continue
                fi
                
                FKS_DISCOVERED_SERVICE_CONFIGS["$service_name"]="$service_file"
                log_debug "Found service config: $service_name -> $service_file"
            fi
        done
    done
    
    log_debug "Configuration discovery completed"
}

# Initialize configuration system
init_config_system() {
    if [[ "$FKS_CONFIG_INITIALIZED" == "true" ]]; then
        log_debug "Configuration system already initialized"
        return 0
    fi
    
    log_debug "Initializing configuration system v$CONFIG_MODULE_VERSION..."
    
    # Reset counters
    FKS_CONFIG_ERRORS=0
    FKS_CONFIG_WARNINGS=0
    
    # Check available tools
    check_config_tools
    
    # Discover configuration files
    discover_config_files
    
    # Set default configurations first
    set_default_configurations
    
    # Load configurations in order of precedence
    load_all_configurations
    
    # Load environment variable overrides
    load_env_overrides
    
    # Validate configurations
    validate_configurations
    
    # Mark as initialized
    FKS_CONFIG_INITIALIZED=true
    
    log_debug "Configuration system initialized (Errors: $FKS_CONFIG_ERRORS, Warnings: $FKS_CONFIG_WARNINGS)"
    
    return 0
}

# Set comprehensive default configurations
set_default_configurations() {
    log_debug "Setting default configurations..."
    
    # App configuration defaults
    FKS_CONFIG["app_name"]="FKS Trading Systems"
    FKS_CONFIG["app_version"]="1.0.0"
    FKS_CONFIG["app_environment"]="development"
    FKS_CONFIG["app_description"]="Advanced Trading Systems Platform"
    
    # Model configuration
    FKS_CONFIG["model_type"]="transformer"
    FKS_CONFIG["model_architecture"]="bert"
    FKS_CONFIG["batch_size"]="32"
    FKS_CONFIG["sequence_length"]="512"
    FKS_CONFIG["learning_rate"]="0.001"
    FKS_CONFIG["epochs"]="100"
    FKS_CONFIG["early_stopping_patience"]="10"
    
    # Training configuration
    FKS_CONFIG["training_mode"]="supervised"
    FKS_CONFIG["validation_split"]="0.2"
    FKS_CONFIG["test_split"]="0.1"
    FKS_CONFIG["random_seed"]="42"
    
    # Data configuration
    FKS_CONFIG["data_format"]="csv"
    FKS_CONFIG["data_encoding"]="utf-8"
    FKS_CONFIG["data_delimiter"]=","
    FKS_CONFIG["data_cache_enabled"]="true"
    
    # Path configurations
    FKS_CONFIG["data_path"]="./data"
    FKS_CONFIG["model_path"]="./models"
    FKS_CONFIG["log_path"]="./logs"
    FKS_CONFIG["cache_path"]="./cache"
    FKS_CONFIG["config_path"]="./config"
    FKS_CONFIG["output_path"]="./output"
    FKS_CONFIG["backup_path"]="./backups"
    
    # Server configuration
    FKS_CONFIG["server_host"]="0.0.0.0"
    FKS_CONFIG["server_port"]="9000"
    FKS_CONFIG["server_workers"]="2"
    FKS_CONFIG["server_timeout"]="30"
    FKS_CONFIG["server_log_level"]="INFO"
    
    # Docker configuration defaults
    FKS_DOCKER_CONFIG["app_version"]="1.0.0"
    FKS_DOCKER_CONFIG["app_environment"]="development"
    FKS_DOCKER_CONFIG["docker_hub_username"]="nuniesmith"
    FKS_DOCKER_CONFIG["docker_registry"]="docker.io"
    FKS_DOCKER_CONFIG["docker_tag"]="latest"
    
    # Service ports
    FKS_DOCKER_CONFIG["api_port"]="8000"
    FKS_DOCKER_CONFIG["app_port"]="9000"
    FKS_DOCKER_CONFIG["web_port"]="9999"
    FKS_DOCKER_CONFIG["training_port"]="8088"
    FKS_DOCKER_CONFIG["monitoring_port"]="8080"
    FKS_DOCKER_CONFIG["metrics_port"]="9090"
    
    # Database ports
    FKS_DOCKER_CONFIG["redis_port"]="6379"
    FKS_DOCKER_CONFIG["postgres_port"]="5432"
    FKS_DOCKER_CONFIG["mongodb_port"]="27017"
    FKS_DOCKER_CONFIG["elasticsearch_port"]="9200"
    
    # Network configuration
    FKS_DOCKER_CONFIG["network_name"]="fks_network"
    FKS_DOCKER_CONFIG["network_driver"]="bridge"
    FKS_DOCKER_CONFIG["network_subnet"]="172.20.0.0/16"
    
    # Resource limits
    FKS_DOCKER_CONFIG["cpu_limit"]="2"
    FKS_DOCKER_CONFIG["memory_limit"]="4g"
    FKS_DOCKER_CONFIG["memory_reservation"]="2g"
    
    log_debug "Default configurations set (${#FKS_CONFIG[@]} app, ${#FKS_DOCKER_CONFIG[@]} docker)"
}

# Load all configurations
load_all_configurations() {
    log_debug "Loading all configurations..."
    
    # Load app configuration
    if [[ -n "$FKS_DISCOVERED_APP_CONFIG" ]]; then
        if load_app_config "$FKS_DISCOVERED_APP_CONFIG"; then
            log_debug "✅ App configuration loaded from $FKS_DISCOVERED_APP_CONFIG"
        else
            log_warn "Failed to load app configuration from $FKS_DISCOVERED_APP_CONFIG"
            ((FKS_CONFIG_WARNINGS++))
        fi
    else
        log_debug "⚠️  No app configuration file found, using defaults"
        ((FKS_CONFIG_WARNINGS++))
    fi
    
    # Load Docker configuration
    if [[ -n "$FKS_DISCOVERED_DOCKER_CONFIG" ]]; then
        if load_docker_config "$FKS_DISCOVERED_DOCKER_CONFIG"; then
            log_debug "✅ Docker configuration loaded from $FKS_DISCOVERED_DOCKER_CONFIG"
        else
            log_warn "Failed to load Docker configuration from $FKS_DISCOVERED_DOCKER_CONFIG"
            ((FKS_CONFIG_WARNINGS++))
        fi
    else
        log_debug "⚠️  No Docker configuration file found, using defaults"
        ((FKS_CONFIG_WARNINGS++))
    fi
    
    # Load service configurations
    load_service_configs
    
    log_debug "Configuration loading completed"
}

# Load application configuration
load_app_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "App config file not found: $config_file"
        return 1
    fi
    
    log_debug "Loading app configuration from $config_file"
    
    # Try different parsing methods in order of preference
    if $FKS_CONFIG_YQ_AVAILABLE; then
        load_app_config_with_yq "$config_file"
    elif $FKS_CONFIG_PYTHON_AVAILABLE; then
        load_app_config_with_python "$config_file"
    else
        load_app_config_fallback "$config_file"
    fi
}

# Load app config using yq
load_app_config_with_yq() {
    local config_file="$1"
    
    log_debug "Using yq to parse app configuration"
    
    # App metadata
    local app_name app_version app_env app_desc
    app_name=$(yq eval '.app.name // .name // "FKS Trading Systems"' "$config_file" 2>/dev/null)
    app_version=$(yq eval '.app.version // .version // "1.0.0"' "$config_file" 2>/dev/null)
    app_env=$(yq eval '.app.environment // .environment // "development"' "$config_file" 2>/dev/null)
    app_desc=$(yq eval '.app.description // .description // "Advanced Trading Systems Platform"' "$config_file" 2>/dev/null)
    
    [[ -n "$app_name" ]] && FKS_CONFIG["app_name"]="$app_name"
    [[ -n "$app_version" ]] && FKS_CONFIG["app_version"]="$app_version"
    [[ -n "$app_env" ]] && FKS_CONFIG["app_environment"]="$app_env"
    [[ -n "$app_desc" ]] && FKS_CONFIG["app_description"]="$app_desc"
    
    # Model configuration
    local model_type model_arch batch_size seq_len lr epochs patience
    model_type=$(yq eval '.model.type // .training.model_type // "transformer"' "$config_file" 2>/dev/null)
    model_arch=$(yq eval '.model.architecture // .model.arch // "bert"' "$config_file" 2>/dev/null)
    batch_size=$(yq eval '.model.batch_size // .training.batch_size // .data.batch_size // "32"' "$config_file" 2>/dev/null)
    seq_len=$(yq eval '.model.sequence_length // .model.max_length // "512"' "$config_file" 2>/dev/null)
    lr=$(yq eval '.training.learning_rate // .model.learning_rate // "0.001"' "$config_file" 2>/dev/null)
    epochs=$(yq eval '.training.epochs // .training.max_epochs // "100"' "$config_file" 2>/dev/null)
    patience=$(yq eval '.training.early_stopping.patience // .training.patience // "10"' "$config_file" 2>/dev/null)
    
    [[ -n "$model_type" ]] && FKS_CONFIG["model_type"]="$model_type"
    [[ -n "$model_arch" ]] && FKS_CONFIG["model_architecture"]="$model_arch"
    [[ -n "$batch_size" ]] && FKS_CONFIG["batch_size"]="$batch_size"
    [[ -n "$seq_len" ]] && FKS_CONFIG["sequence_length"]="$seq_len"
    [[ -n "$lr" ]] && FKS_CONFIG["learning_rate"]="$lr"
    [[ -n "$epochs" ]] && FKS_CONFIG["epochs"]="$epochs"
    [[ -n "$patience" ]] && FKS_CONFIG["early_stopping_patience"]="$patience"
    
    # Paths
    local data_path model_path log_path cache_path config_path output_path backup_path
    data_path=$(yq eval '.paths.data // .data.path // .data_path // "./data"' "$config_file" 2>/dev/null)
    model_path=$(yq eval '.paths.models // .paths.model // .model_path // "./models"' "$config_file" 2>/dev/null)
    log_path=$(yq eval '.paths.logs // .paths.log // .log_path // "./logs"' "$config_file" 2>/dev/null)
    cache_path=$(yq eval '.paths.cache // .cache_path // "./cache"' "$config_file" 2>/dev/null)
    config_path=$(yq eval '.paths.config // .config_path // "./config"' "$config_file" 2>/dev/null)
    output_path=$(yq eval '.paths.output // .output_path // "./output"' "$config_file" 2>/dev/null)
    backup_path=$(yq eval '.paths.backup // .backup_path // "./backups"' "$config_file" 2>/dev/null)
    
    [[ -n "$data_path" ]] && FKS_CONFIG["data_path"]="$data_path"
    [[ -n "$model_path" ]] && FKS_CONFIG["model_path"]="$model_path"
    [[ -n "$log_path" ]] && FKS_CONFIG["log_path"]="$log_path"
    [[ -n "$cache_path" ]] && FKS_CONFIG["cache_path"]="$cache_path"
    [[ -n "$config_path" ]] && FKS_CONFIG["config_path"]="$config_path"
    [[ -n "$output_path" ]] && FKS_CONFIG["output_path"]="$output_path"
    [[ -n "$backup_path" ]] && FKS_CONFIG["backup_path"]="$backup_path"
    
    # Server configuration
    local server_host server_port server_workers server_timeout server_log_level
    server_host=$(yq eval '.server.host // .api.host // "0.0.0.0"' "$config_file" 2>/dev/null)
    server_port=$(yq eval '.server.port // .api.port // "9000"' "$config_file" 2>/dev/null)
    server_workers=$(yq eval '.server.workers // .api.workers // "2"' "$config_file" 2>/dev/null)
    server_timeout=$(yq eval '.server.timeout // .api.timeout // "30"' "$config_file" 2>/dev/null)
    server_log_level=$(yq eval '.server.log_level // .logging.level // "INFO"' "$config_file" 2>/dev/null)
    
    [[ -n "$server_host" ]] && FKS_CONFIG["server_host"]="$server_host"
    [[ -n "$server_port" ]] && FKS_CONFIG["server_port"]="$server_port"
    [[ -n "$server_workers" ]] && FKS_CONFIG["server_workers"]="$server_workers"
    [[ -n "$server_timeout" ]] && FKS_CONFIG["server_timeout"]="$server_timeout"
    [[ -n "$server_log_level" ]] && FKS_CONFIG["server_log_level"]="$server_log_level"
    
    log_debug "App config loaded with yq: ${#FKS_CONFIG[@]} values"
    return 0
}

# Load app config using Python
load_app_config_with_python() {
    local config_file="$1"
    
    log_debug "Using Python to parse app configuration"
    
    # Create a temporary Python script to parse YAML
    local python_script
    python_script=$(cat << 'EOF'
import yaml
import sys
import json

try:
    with open(sys.argv[1], 'r') as f:
        data = yaml.safe_load(f)
    
    # Extract values with fallbacks
    config = {}
    
    # App metadata
    config['app_name'] = data.get('app', {}).get('name', data.get('name', 'FKS Trading Systems'))
    config['app_version'] = data.get('app', {}).get('version', data.get('version', '1.0.0'))
    config['app_environment'] = data.get('app', {}).get('environment', data.get('environment', 'development'))
    
    # Model configuration
    model = data.get('model', {})
    training = data.get('training', {})
    config['model_type'] = model.get('type', training.get('model_type', 'transformer'))
    config['batch_size'] = str(model.get('batch_size', training.get('batch_size', data.get('data', {}).get('batch_size', 32))))
    config['epochs'] = str(training.get('epochs', training.get('max_epochs', 100)))
    
    # Paths
    paths = data.get('paths', {})
    config['data_path'] = paths.get('data', data.get('data_path', './data'))
    config['model_path'] = paths.get('models', paths.get('model', './models'))
    config['log_path'] = paths.get('logs', paths.get('log', './logs'))
    
    # Server configuration
    server = data.get('server', {})
    api = data.get('api', {})
    config['server_host'] = server.get('host', api.get('host', '0.0.0.0'))
    config['server_port'] = str(server.get('port', api.get('port', 9000)))
    
    # Output as shell-friendly format
    for key, value in config.items():
        print(f"{key}={value}")
        
except Exception as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)
    
    # Execute Python script and capture output
    local config_output
    if config_output=$(python3 -c "$python_script" "$config_file" 2>/dev/null); then
        # Parse the output and set configuration values
        while IFS='=' read -r key value; do
            [[ -n "$key" && -n "$value" ]] && FKS_CONFIG["$key"]="$value"
        done <<< "$config_output"
        
        log_debug "App config loaded with Python: ${#FKS_CONFIG[@]} total values"
        return 0
    else
        log_warn "Failed to parse app config with Python"
        return 1
    fi
}

# Load app config using basic text parsing (fallback)
load_app_config_fallback() {
    local config_file="$1"
    
    log_debug "Using fallback text parsing for app configuration"
    
    # Extract basic key-value pairs
    local patterns=(
        "name:" "app_name"
        "version:" "app_version"
        "environment:" "app_environment"
        "batch_size:" "batch_size"
        "epochs:" "epochs"
        "data:" "data_path"
        "models:" "model_path"
        "logs:" "log_path"
    )
    
    for ((i=0; i<${#patterns[@]}; i+=2)); do
        local pattern="${patterns[$i]}"
        local config_key="${patterns[$((i+1))]}"
        
        if grep -q "$pattern" "$config_file" 2>/dev/null; then
            local value
            value=$(grep -E "^\s*${pattern}" "$config_file" | head -1 | sed "s/.*${pattern}\s*//" | sed 's/["\x27]//g' | sed 's/#.*//' | xargs)
            [[ -n "$value" ]] && FKS_CONFIG["$config_key"]="$value"
        fi
    done
    
    log_debug "App config loaded with fallback parsing"
    return 0
}

# Load Docker configuration
load_docker_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Docker config file not found: $config_file"
        return 1
    fi
    
    log_debug "Loading Docker configuration from $config_file"
    
    if $FKS_CONFIG_YQ_AVAILABLE; then
        load_docker_config_with_yq "$config_file"
    elif $FKS_CONFIG_PYTHON_AVAILABLE; then
        load_docker_config_with_python "$config_file"
    else
        load_docker_config_fallback "$config_file"
    fi
}

# Load Docker config using yq
load_docker_config_with_yq() {
    local config_file="$1"
    
    log_debug "Using yq to parse Docker configuration"
    
    # App metadata
    local app_version app_env docker_username docker_registry docker_tag
    app_version=$(yq eval '.app.version // .system.app.version // "1.0.0"' "$config_file" 2>/dev/null)
    app_env=$(yq eval '.app.environment // .system.app.environment // "development"' "$config_file" 2>/dev/null)
    docker_username=$(yq eval '.docker.username // .system.docker_hub.username // .docker_hub.username // "nuniesmith"' "$config_file" 2>/dev/null)
    docker_registry=$(yq eval '.docker.registry // .system.docker.registry // "docker.io"' "$config_file" 2>/dev/null)
    docker_tag=$(yq eval '.docker.tag // .system.docker.tag // "latest"' "$config_file" 2>/dev/null)
    
    [[ -n "$app_version" ]] && FKS_DOCKER_CONFIG["app_version"]="$app_version"
    [[ -n "$app_env" ]] && FKS_DOCKER_CONFIG["app_environment"]="$app_env"
    [[ -n "$docker_username" ]] && FKS_DOCKER_CONFIG["docker_hub_username"]="$docker_username"
    [[ -n "$docker_registry" ]] && FKS_DOCKER_CONFIG["docker_registry"]="$docker_registry"
    [[ -n "$docker_tag" ]] && FKS_DOCKER_CONFIG["docker_tag"]="$docker_tag"
    
    # Service ports with multiple fallback paths
    local service_ports=(
        "api_port" ".services.api.port // .cpu_services.api.port // .ports.api // \"8000\""
        "app_port" ".services.app.port // .cpu_services.app.port // .ports.app // \"9000\""
        "web_port" ".services.web.port // .cpu_services.web.port // .ports.web // \"9999\""
        "training_port" ".services.training.port // .gpu_services.training.port // .ports.training // \"8088\""
        "monitoring_port" ".services.monitoring.port // .ports.monitoring // \"8080\""
        "metrics_port" ".services.metrics.port // .ports.metrics // \"9090\""
    )
    
    for ((i=0; i<${#service_ports[@]}; i+=2)); do
        local port_key="${service_ports[$i]}"
        local port_query="${service_ports[$((i+1))]}"
        local port_value
        port_value=$(yq eval "$port_query" "$config_file" 2>/dev/null)
        [[ -n "$port_value" && "$port_value" != "null" ]] && FKS_DOCKER_CONFIG["$port_key"]="$port_value"
    done
    
    # Database ports
    local db_ports=(
        "redis_port" ".databases.redis.port // .services.redis.port // .ports.redis // \"6379\""
        "postgres_port" ".databases.postgres.port // .services.postgres.port // .ports.postgres // \"5432\""
        "mongodb_port" ".databases.mongodb.port // .services.mongodb.port // .ports.mongodb // \"27017\""
        "elasticsearch_port" ".databases.elasticsearch.port // .services.elasticsearch.port // .ports.elasticsearch // \"9200\""
    )
    
    for ((i=0; i<${#db_ports[@]}; i+=2)); do
        local port_key="${db_ports[$i]}"
        local port_query="${db_ports[$((i+1))]}"
        local port_value
        port_value=$(yq eval "$port_query" "$config_file" 2>/dev/null)
        [[ -n "$port_value" && "$port_value" != "null" ]] && FKS_DOCKER_CONFIG["$port_key"]="$port_value"
    done
    
    # Network configuration
    local network_name network_driver network_subnet
    network_name=$(yq eval '.networks.default.name // .network.name // "fks_network"' "$config_file" 2>/dev/null)
    network_driver=$(yq eval '.networks.default.driver // .network.driver // "bridge"' "$config_file" 2>/dev/null)
    network_subnet=$(yq eval '.networks.default.subnet // .network.subnet // "172.20.0.0/16"' "$config_file" 2>/dev/null)
    
    [[ -n "$network_name" ]] && FKS_DOCKER_CONFIG["network_name"]="$network_name"
    [[ -n "$network_driver" ]] && FKS_DOCKER_CONFIG["network_driver"]="$network_driver"
    [[ -n "$network_subnet" ]] && FKS_DOCKER_CONFIG["network_subnet"]="$network_subnet"
    
    # Resource limits
    local cpu_limit memory_limit memory_reservation
    cpu_limit=$(yq eval '.resources.cpu_limit // .limits.cpu // "2"' "$config_file" 2>/dev/null)
    memory_limit=$(yq eval '.resources.memory_limit // .limits.memory // "4g"' "$config_file" 2>/dev/null)
    memory_reservation=$(yq eval '.resources.memory_reservation // .reservations.memory // "2g"' "$config_file" 2>/dev/null)
    
    [[ -n "$cpu_limit" ]] && FKS_DOCKER_CONFIG["cpu_limit"]="$cpu_limit"
    [[ -n "$memory_limit" ]] && FKS_DOCKER_CONFIG["memory_limit"]="$memory_limit"
    [[ -n "$memory_reservation" ]] && FKS_DOCKER_CONFIG["memory_reservation"]="$memory_reservation"
    
    log_debug "Docker config loaded with yq: ${#FKS_DOCKER_CONFIG[@]} values"
    return 0
}

# Load Docker config using Python
load_docker_config_with_python() {
    local config_file="$1"
    
    log_debug "Using Python to parse Docker configuration"
    
    local python_script
    python_script=$(cat << 'EOF'
import yaml
import sys

try:
    with open(sys.argv[1], 'r') as f:
        data = yaml.safe_load(f)
    
    config = {}
    
    # App metadata
    app = data.get('app', {})
    system = data.get('system', {})
    config['app_version'] = app.get('version', system.get('app', {}).get('version', '1.0.0'))
    config['app_environment'] = app.get('environment', system.get('app', {}).get('environment', 'development'))
    
    # Docker configuration
    docker = data.get('docker', {})
    docker_hub = data.get('docker_hub', system.get('docker_hub', {}))
    config['docker_hub_username'] = docker.get('username', docker_hub.get('username', 'nuniesmith'))
    
    # Service ports
    services = data.get('services', {})
    cpu_services = data.get('cpu_services', {})
    gpu_services = data.get('gpu_services', {})
    ports = data.get('ports', {})
    
    port_mappings = {
        'api_port': [services.get('api', {}).get('port'), cpu_services.get('api', {}).get('port'), ports.get('api'), '8000'],
        'app_port': [services.get('app', {}).get('port'), cpu_services.get('app', {}).get('port'), ports.get('app'), '9000'],
        'web_port': [services.get('web', {}).get('port'), cpu_services.get('web', {}).get('port'), ports.get('web'), '9999'],
        'training_port': [services.get('training', {}).get('port'), gpu_services.get('training', {}).get('port'), ports.get('training'), '8088']
    }
    
    for key, candidates in port_mappings.items():
        for candidate in candidates:
            if candidate is not None:
                config[key] = str(candidate)
                break
    
    # Database ports
    databases = data.get('databases', {})
    db_mappings = {
        'redis_port': [databases.get('redis', {}).get('port'), services.get('redis', {}).get('port'), '6379'],
        'postgres_port': [databases.get('postgres', {}).get('port'), services.get('postgres', {}).get('port'), '5432']
    }
    
    for key, candidates in db_mappings.items():
        for candidate in candidates:
            if candidate is not None:
                config[key] = str(candidate)
                break
    
    # Network configuration
    networks = data.get('networks', {})
    network = data.get('network', {})
    default_network = networks.get('default', {})
    
    config['network_name'] = default_network.get('name', network.get('name', 'fks_network'))
    
    # Output configuration
    for key, value in config.items():
        if value:
            print(f"{key}={value}")
            
except Exception as e:
    print(f"Error parsing Docker YAML: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)
    
    local config_output
    if config_output=$(python3 -c "$python_script" "$config_file" 2>/dev/null); then
        while IFS='=' read -r key value; do
            [[ -n "$key" && -n "$value" ]] && FKS_DOCKER_CONFIG["$key"]="$value"
        done <<< "$config_output"
        
        log_debug "Docker config loaded with Python: ${#FKS_DOCKER_CONFIG[@]} total values"
        return 0
    else
        log_warn "Failed to parse Docker config with Python"
        return 1
    fi
}

# Load Docker config using basic text parsing (fallback)
load_docker_config_fallback() {
    local config_file="$1"
    
    log_debug "Using fallback text parsing for Docker configuration"
    
    # Look for common port patterns
    local common_ports=("8000" "9000" "9999" "8088" "6379" "5432")
    local port_keys=("api_port" "app_port" "web_port" "training_port" "redis_port" "postgres_port")
    
    for i in "${!common_ports[@]}"; do
        local port="${common_ports[$i]}"
        if grep -q "$port" "$config_file" 2>/dev/null; then
            FKS_DOCKER_CONFIG["${port_keys[$i]}"]="$port"
        fi
    done
    
    # Look for username
    if grep -q "username:" "$config_file" 2>/dev/null; then
        local username
        username=$(grep "username:" "$config_file" | head -1 | sed 's/.*username:\s*//' | sed 's/["\x27]//g' | xargs)
        [[ -n "$username" ]] && FKS_DOCKER_CONFIG["docker_hub_username"]="$username"
    fi
    
    log_debug "Docker config loaded with fallback parsing"
    return 0
}

# Load service configurations
load_service_configs() {
    if [[ ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]} -eq 0 ]]; then
        log_debug "No service configurations discovered"
        return 0
    fi
    
    log_debug "Loading ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]} service configurations..."
    
    local loaded_count=0
    for service_name in "${!FKS_DISCOVERED_SERVICE_CONFIGS[@]}"; do
        local config_file="${FKS_DISCOVERED_SERVICE_CONFIGS[$service_name]}"
        
        if load_service_config "$service_name" "$config_file"; then
            ((loaded_count++))
        fi
    done
    
    log_debug "Loaded $loaded_count service configurations"
}

# Load individual service configuration
load_service_config() {
    local service_name="$1"
    local config_file="$2"
    
    if [[ ! -f "$config_file" ]]; then
        log_debug "Service config file not found: $config_file"
        return 1
    fi
    
    local service_prefix="${service_name^^}_"
    
    if $FKS_CONFIG_YQ_AVAILABLE; then
        # Load with yq
        local host port workers log_level
        host=$(yq eval '.server.host // .service.host // .host // "0.0.0.0"' "$config_file" 2>/dev/null)
        port=$(yq eval '.server.port // .service.port // .port // "8000"' "$config_file" 2>/dev/null)
        workers=$(yq eval '.server.workers // .service.workers // .workers // "2"' "$config_file" 2>/dev/null)
        log_level=$(yq eval '.server.log_level // .service.log_level // .log_level // "INFO"' "$config_file" 2>/dev/null)
        
        [[ -n "$host" && "$host" != "null" ]] && FKS_SERVICE_CONFIGS["${service_prefix}HOST"]="$host"
        [[ -n "$port" && "$port" != "null" ]] && FKS_SERVICE_CONFIGS["${service_prefix}PORT"]="$port"
        [[ -n "$workers" && "$workers" != "null" ]] && FKS_SERVICE_CONFIGS["${service_prefix}WORKERS"]="$workers"
        [[ -n "$log_level" && "$log_level" != "null" ]] && FKS_SERVICE_CONFIGS["${service_prefix}LOG_LEVEL"]="$log_level"
    else
        # Fallback parsing
        local patterns=("host:" "port:" "workers:" "log_level:")
        local keys=("HOST" "PORT" "WORKERS" "LOG_LEVEL")
        
        for i in "${!patterns[@]}"; do
            local pattern="${patterns[$i]}"
            local key="${keys[$i]}"
            
            if grep -q "$pattern" "$config_file" 2>/dev/null; then
                local value
                value=$(grep "$pattern" "$config_file" | head -1 | sed "s/.*$pattern\s*//" | sed 's/["\x27]//g' | xargs)
                [[ -n "$value" ]] && FKS_SERVICE_CONFIGS["${service_prefix}${key}"]="$value"
            fi
        done
    fi
    
    log_debug "Loaded configuration for service: $service_name"
    return 0
}

# Load environment variable overrides
load_env_overrides() {
    log_debug "Loading environment variable overrides..."
    
    # Common environment variable mappings
    local env_mappings=(
        "FKS_APP_NAME" "app_name"
        "FKS_APP_VERSION" "app_version"
        "FKS_ENVIRONMENT" "app_environment"
        "FKS_DATA_PATH" "data_path"
        "FKS_MODEL_PATH" "model_path"
        "FKS_LOG_PATH" "log_path"
        "FKS_BATCH_SIZE" "batch_size"
        "FKS_EPOCHS" "epochs"
        "FKS_LEARNING_RATE" "learning_rate"
        "FKS_SERVER_HOST" "server_host"
        "FKS_SERVER_PORT" "server_port"
    )
    
    local override_count=0
    for ((i=0; i<${#env_mappings[@]}; i+=2)); do
        local env_var="${env_mappings[$i]}"
        local config_key="${env_mappings[$((i+1))]}"
        
        if [[ -n "${!env_var:-}" ]]; then
            FKS_CONFIG["$config_key"]="${!env_var}"
            FKS_ENV_OVERRIDES["$config_key"]="${!env_var}"
            ((override_count++))
        fi
    done
    
    # Docker environment overrides
    local docker_env_mappings=(
        "FKS_API_PORT" "api_port"
        "FKS_APP_PORT" "app_port"
        "FKS_WEB_PORT" "web_port"
        "FKS_TRAINING_PORT" "training_port"
        "FKS_REDIS_PORT" "redis_port"
        "FKS_POSTGRES_PORT" "postgres_port"
        "FKS_DOCKER_USERNAME" "docker_hub_username"
        "FKS_NETWORK_NAME" "network_name"
    )
    
    for ((i=0; i<${#docker_env_mappings[@]}; i+=2)); do
        local env_var="${docker_env_mappings[$i]}"
        local config_key="${docker_env_mappings[$((i+1))]}"
        
        if [[ -n "${!env_var:-}" ]]; then
            FKS_DOCKER_CONFIG["$config_key"]="${!env_var}"
            FKS_ENV_OVERRIDES["docker_$config_key"]="${!env_var}"
            ((override_count++))
        fi
    done
    
    if [[ $override_count -gt 0 ]]; then
        log_debug "Applied $override_count environment variable overrides"
    else
        log_debug "No environment variable overrides found"
    fi
}

# Validate configurations
validate_configurations() {
    log_debug "Validating configurations..."
    
    local errors=0
    local warnings=0
    
    # Validate required fields
    local required_fields=("app_name" "app_version" "app_environment")
    for field in "${required_fields[@]}"; do
        if [[ -z "${FKS_CONFIG[$field]:-}" ]]; then
            log_warn "Required field missing: $field"
            ((warnings++))
        fi
    done
    
    # Validate numeric fields
    local numeric_fields=("batch_size" "epochs" "server_port")
    for field in "${numeric_fields[@]}"; do
        local value="${FKS_CONFIG[$field]:-}"
        if [[ -n "$value" ]] && ! [[ "$value" =~ ^[0-9]+$ ]]; then
            log_warn "Non-numeric value for $field: $value"
            ((warnings++))
        fi
    done
    
    # Validate ports
    validate_port_configuration
    local port_errors=$?
    ((warnings += port_errors))
    
    # Validate paths
    validate_path_configuration
    local path_errors=$?
    ((warnings += path_errors))
    
    # Check for port conflicts
    check_port_conflicts
    
    FKS_CONFIG_ERRORS=$errors
    FKS_CONFIG_WARNINGS=$warnings
    
    log_debug "Configuration validation completed (Errors: $errors, Warnings: $warnings)"
    return 0
}

# Validate port configuration
validate_port_configuration() {
    local port_errors=0
    
    # Check all Docker ports
    local port_keys=("api_port" "app_port" "web_port" "training_port" "redis_port" "postgres_port" "monitoring_port" "metrics_port")
    
    for port_key in "${port_keys[@]}"; do
        local port_value="${FKS_DOCKER_CONFIG[$port_key]:-}"
        
        if [[ -n "$port_value" ]]; then
            if ! [[ "$port_value" =~ ^[0-9]+$ ]]; then
                log_warn "Invalid port format for $port_key: $port_value"
                ((port_errors++))
            elif [[ $port_value -lt 1 || $port_value -gt 65535 ]]; then
                log_warn "Port out of range for $port_key: $port_value"
                ((port_errors++))
            elif [[ $port_value -lt 1024 ]] && [[ $(id -u) -ne 0 ]]; then
                log_warn "Privileged port requires root access: $port_key=$port_value"
            fi
        fi
    done
    
    return $port_errors
}

# Validate path configuration
validate_path_configuration() {
    local path_errors=0
    
    local path_keys=("data_path" "model_path" "log_path" "cache_path" "output_path" "backup_path")
    
    for path_key in "${path_keys[@]}"; do
        local path_value="${FKS_CONFIG[$path_key]:-}"
        
        if [[ -n "$path_value" ]]; then
            # Check if path is valid (basic validation)
            if [[ "$path_value" =~ [[:space:]] ]]; then
                log_warn "Path contains spaces: $path_key=$path_value"
                ((path_errors++))
            fi
            
            # Check if critical paths exist
            if [[ "$path_key" == "data_path" ]] && [[ ! -d "$path_value" ]]; then
                log_warn "Data path does not exist: $path_value"
                ((path_errors++))
            fi
        fi
    done
    
    return $path_errors
}

# Check for port conflicts
check_port_conflicts() {
    local used_ports=()
    local conflicts=0
    
    # Collect all configured ports
    for port_key in "${!FKS_DOCKER_CONFIG[@]}"; do
        if [[ "$port_key" == *"_port" ]]; then
            local port_value="${FKS_DOCKER_CONFIG[$port_key]}"
            
            if [[ " ${used_ports[*]} " =~ " ${port_value} " ]]; then
                log_warn "Port conflict detected: $port_value used by multiple services"
                ((conflicts++))
            else
                used_ports+=("$port_value")
            fi
        fi
    done
    
    if [[ $conflicts -gt 0 ]]; then
        log_debug "Found $conflicts port conflicts"
        ((FKS_CONFIG_WARNINGS += conflicts))
    fi
}

# Configuration getter functions
get_config_value() {
    local key="$1"
    local default_value="${2:-}"
    
    # Check environment overrides first
    if [[ -n "${FKS_ENV_OVERRIDES[$key]:-}" ]]; then
        echo "${FKS_ENV_OVERRIDES[$key]}"
        return 0
    fi
    
    # Check app config
    if [[ -n "${FKS_CONFIG[$key]:-}" ]]; then
        echo "${FKS_CONFIG[$key]}"
        return 0
    fi
    
    # Check Docker config
    if [[ -n "${FKS_DOCKER_CONFIG[$key]:-}" ]]; then
        echo "${FKS_DOCKER_CONFIG[$key]}"
        return 0
    fi
    
    # Check service configs
    if [[ -n "${FKS_SERVICE_CONFIGS[$key]:-}" ]]; then
        echo "${FKS_SERVICE_CONFIGS[$key]}"
        return 0
    fi
    
    # Check environment variables with FKS_ prefix
    local env_key="FKS_${key^^}"
    if [[ -n "${!env_key:-}" ]]; then
        echo "${!env_key}"
        return 0
    fi
    
    # Return default if provided
    if [[ -n "$default_value" ]]; then
        echo "$default_value"
        return 0
    fi
    
    # Key not found
    return 1
}

# Configuration setter functions
set_config_value() {
    local key="$1"
    local value="$2"
    local config_type="${3:-app}"
    
    case "$config_type" in
        "app")
            FKS_CONFIG["$key"]="$value"
            ;;
        "docker")
            FKS_DOCKER_CONFIG["$key"]="$value"
            ;;
        "service")
            FKS_SERVICE_CONFIGS["$key"]="$value"
            ;;
        "env")
            FKS_ENV_OVERRIDES["$key"]="$value"
            ;;
        *)
            log_error "Unknown config type: $config_type"
            return 1
            ;;
    esac
    
    log_debug "Set config value: $key=$value ($config_type)"
    return 0
}

# Export configuration as environment variables
export_config_as_env() {
    local prefix="${1:-FKS_}"
    local export_count=0
    
    log_debug "Exporting configuration as environment variables with prefix: $prefix"
    
    # Export app config
    for key in "${!FKS_CONFIG[@]}"; do
        local env_var="${prefix}${key^^}"
        export "$env_var"="${FKS_CONFIG[$key]}"
        ((export_count++))
    done
    
    # Export Docker config
    for key in "${!FKS_DOCKER_CONFIG[@]}"; do
        local env_var="${prefix}DOCKER_${key^^}"
        export "$env_var"="${FKS_DOCKER_CONFIG[$key]}"
        ((export_count++))
    done
    
    # Export service configs
    for key in "${!FKS_SERVICE_CONFIGS[@]}"; do
        local env_var="${prefix}SERVICE_${key}"
        export "$env_var"="${FKS_SERVICE_CONFIGS[$key]}"
        ((export_count++))
    done
    
    log_debug "Exported $export_count configuration variables"
}

# configuration summary
show_config_summary() {
    local show_details="${1:-false}"
    
    echo ""
    echo "🔧 Configuration Summary"
    echo "════════════════════════════════════════════════════════════════"
    
    # System status
    echo "📊 System Status:"
    echo "  Configuration Version: v$CONFIG_MODULE_VERSION"
    echo "  Initialization: $($FKS_CONFIG_INITIALIZED && echo "✅ Complete" || echo "❌ Incomplete")"
    echo "  YAML Parser: $($FKS_CONFIG_YQ_AVAILABLE && echo "✅ yq" || ($FKS_CONFIG_PYTHON_AVAILABLE && echo "✅ Python" || echo "⚠️  Fallback"))"
    echo "  Errors: $FKS_CONFIG_ERRORS | Warnings: $FKS_CONFIG_WARNINGS"
    echo "  Env Overrides: ${#FKS_ENV_OVERRIDES[@]}"
    echo ""
    
    # Application configuration
    echo "🚀 Application Configuration:"
    echo "  Name: ${FKS_CONFIG[app_name]:-Not set}"
    echo "  Version: ${FKS_CONFIG[app_version]:-Not set}"
    echo "  Environment: ${FKS_CONFIG[app_environment]:-Not set}"
    echo "  Description: ${FKS_CONFIG[app_description]:-Not set}"
    echo ""
    
    # Model configuration
    echo "🤖 Model Configuration:"
    echo "  Type: ${FKS_CONFIG[model_type]:-Not set}"
    echo "  Architecture: ${FKS_CONFIG[model_architecture]:-Not set}"
    echo "  Batch Size: ${FKS_CONFIG[batch_size]:-Not set}"
    echo "  Epochs: ${FKS_CONFIG[epochs]:-Not set}"
    echo "  Learning Rate: ${FKS_CONFIG[learning_rate]:-Not set}"
    echo ""
    
    # Server configuration
    echo "🌐 Server Configuration:"
    echo "  Host: ${FKS_CONFIG[server_host]:-Not set}"
    echo "  Port: ${FKS_CONFIG[server_port]:-Not set}"
    echo "  Workers: ${FKS_CONFIG[server_workers]:-Not set}"
    echo "  Log Level: ${FKS_CONFIG[server_log_level]:-Not set}"
    echo ""
    
    # Docker configuration
    echo "🐳 Docker Configuration:"
    echo "  Registry: ${FKS_DOCKER_CONFIG[docker_registry]:-Not set}"
    echo "  Username: ${FKS_DOCKER_CONFIG[docker_hub_username]:-Not set}"
    echo "  Tag: ${FKS_DOCKER_CONFIG[docker_tag]:-Not set}"
    echo "  Network: ${FKS_DOCKER_CONFIG[network_name]:-Not set}"
    echo ""
    
    # Service ports
    echo "🔌 Service Ports:"
    echo "  API: ${FKS_DOCKER_CONFIG[api_port]:-Not set}"
    echo "  App: ${FKS_DOCKER_CONFIG[app_port]:-Not set}"
    echo "  Web: ${FKS_DOCKER_CONFIG[web_port]:-Not set}"
    echo "  Training: ${FKS_DOCKER_CONFIG[training_port]:-Not set}"
    echo "  Monitoring: ${FKS_DOCKER_CONFIG[monitoring_port]:-Not set}"
    echo "  Metrics: ${FKS_DOCKER_CONFIG[metrics_port]:-Not set}"
    echo ""
    
    # Database ports
    echo "🗄️  Database Ports:"
    echo "  Redis: ${FKS_DOCKER_CONFIG[redis_port]:-Not set}"
    echo "  PostgreSQL: ${FKS_DOCKER_CONFIG[postgres_port]:-Not set}"
    echo "  MongoDB: ${FKS_DOCKER_CONFIG[mongodb_port]:-Not set}"
    echo "  Elasticsearch: ${FKS_DOCKER_CONFIG[elasticsearch_port]:-Not set}"
    echo ""
    
    # Paths
    echo "📁 Paths:"
    echo "  Data: ${FKS_CONFIG[data_path]:-Not set}"
    echo "  Models: ${FKS_CONFIG[model_path]:-Not set}"
    echo "  Logs: ${FKS_CONFIG[log_path]:-Not set}"
    echo "  Cache: ${FKS_CONFIG[cache_path]:-Not set}"
    echo "  Output: ${FKS_CONFIG[output_path]:-Not set}"
    echo "  Backup: ${FKS_CONFIG[backup_path]:-Not set}"
    echo ""
    
    # Configuration files status
    echo "📄 Configuration Files:"
    echo "  App Config: $([ -n "$FKS_DISCOVERED_APP_CONFIG" ] && echo "✅ $FKS_DISCOVERED_APP_CONFIG" || echo "❌ Not found")"
    echo "  Docker Config: $([ -n "$FKS_DISCOVERED_DOCKER_CONFIG" ] && echo "✅ $FKS_DISCOVERED_DOCKER_CONFIG" || echo "❌ Not found")"
    echo "  Service Configs: ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]} files"
    
    if [[ "$show_details" == "true" && ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]} -gt 0 ]]; then
        for service in "${!FKS_DISCOVERED_SERVICE_CONFIGS[@]}"; do
            echo "    - $service: ${FKS_DISCOVERED_SERVICE_CONFIGS[$service]}"
        done
    fi
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
}

# Configuration health check
config_health_check() {
    echo ""
    echo "🏥 Configuration Health Check"
    echo "════════════════════════════════════════════════════════════════"
    
    local health_score=0
    local total_checks=12
    local critical_issues=0
    
    # Check 1: System initialization
    if [[ "$FKS_CONFIG_INITIALIZED" == "true" ]]; then
        echo "✅ Configuration system initialized"
        ((health_score++))
    else
        echo "❌ Configuration system not initialized"
        ((critical_issues++))
    fi
    
    # Check 2: YAML parsing capability
    if $FKS_CONFIG_YQ_AVAILABLE || $FKS_CONFIG_PYTHON_AVAILABLE; then
        echo "✅ Advanced YAML parsing available"
        ((health_score++))
    else
        echo "⚠️  Using fallback YAML parsing"
    fi
    
    # Check 3: App configuration file
    if [[ -n "$FKS_DISCOVERED_APP_CONFIG" ]]; then
        echo "✅ App configuration file found"
        ((health_score++))
    else
        echo "⚠️  App configuration file missing"
    fi
    
    # Check 4: Docker configuration file
    if [[ -n "$FKS_DISCOVERED_DOCKER_CONFIG" ]]; then
        echo "✅ Docker configuration file found"
        ((health_score++))
    else
        echo "⚠️  Docker configuration file missing"
    fi
    
    # Check 5: Required app fields
    local required_fields=("app_name" "app_version" "app_environment")
    local missing_fields=0
    for field in "${required_fields[@]}"; do
        [[ -z "${FKS_CONFIG[$field]:-}" ]] && ((missing_fields++))
    done
    
    if [[ $missing_fields -eq 0 ]]; then
        echo "✅ All required app fields configured"
        ((health_score++))
    else
        echo "⚠️  $missing_fields required app fields missing"
    fi
    
    # Check 6: Port configuration
    local port_issues=0
    local port_keys=("api_port" "app_port" "web_port")
    for port_key in "${port_keys[@]}"; do
        local port_value="${FKS_DOCKER_CONFIG[$port_key]:-}"
        if [[ -n "$port_value" ]] && [[ "$port_value" =~ ^[0-9]+$ ]] && [[ $port_value -ge 1 && $port_value -le 65535 ]]; then
            ((health_score++))
            break
        else
            ((port_issues++))
        fi
    done
    
    if [[ $port_issues -eq 0 ]]; then
        echo "✅ Port configuration is valid"
    else
        echo "⚠️  Port configuration issues detected"
    fi
    
    # Check 7: Path configuration
    local critical_paths=("data_path" "model_path" "log_path")
    local path_issues=0
    for path_key in "${critical_paths[@]}"; do
        local path_value="${FKS_CONFIG[$path_key]:-}"
        if [[ -n "$path_value" ]]; then
            ((health_score++))
            break
        else
            ((path_issues++))
        fi
    done
    
    if [[ $path_issues -eq 0 ]]; then
        echo "✅ Critical paths configured"
    else
        echo "⚠️  Some critical paths not configured"
    fi
    
    # Check 8: Configuration errors
    if [[ $FKS_CONFIG_ERRORS -eq 0 ]]; then
        echo "✅ No configuration errors"
        ((health_score++))
    else
        echo "❌ $FKS_CONFIG_ERRORS configuration errors present"
        ((critical_issues++))
    fi
    
    # Check 9: Port conflicts
    local used_ports=()
    local conflicts=0
    for port_key in "${!FKS_DOCKER_CONFIG[@]}"; do
        if [[ "$port_key" == *"_port" ]]; then
            local port_value="${FKS_DOCKER_CONFIG[$port_key]}"
            if [[ " ${used_ports[*]} " =~ " ${port_value} " ]]; then
                echo "⚠️  Port conflict detected: $port_value used by multiple services"
                ((conflicts++))
            else
                used_ports+=("$port_value")
            fi
        fi
    done
    if [[ $conflicts -eq 0 ]]; then
        echo "✅ No port conflicts detected"
        ((health_score++))
    else
        echo "⚠️  $conflicts port conflicts detected"
        ((critical_issues++))
    fi
    # Check 10: Environment variable overrides
    if [[ ${#FKS_ENV_OVERRIDES[@]} -gt 0 ]]; then
        echo "✅ Environment variable overrides applied: ${#FKS_ENV_OVERRIDES[@]}"
        ((health_score++))
    else
        echo "⚠️  No environment variable overrides found"
    fi
    # Check 11: Service configurations
    if [[ ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]} -gt 0 ]]; then
        echo "✅ Service configurations discovered: ${#FKS_DISCOVERED_SERVICE_CONFIGS[@]}"
        ((health_score++))
    else
        echo "⚠️  No service configurations discovered"
    fi
    # Check 12: Service configuration loading
    local service_loaded_count=0
    for service_name in "${!FKS_DISCOVERED_SERVICE_CONFIGS[@]}"; do
        local config_file="${FKS_DISCOVERED_SERVICE_CONFIGS[$service_name]}"
        if load_service_config "$service_name" "$config_file"; then
            ((service_loaded_count++))
        fi
    done
    if [[ $service_loaded_count -gt 0 ]]; then
        echo "✅ $service_loaded_count service configurations loaded successfully"
        ((health_score++))
    else
        echo "⚠️  No service configurations loaded"
    fi
    # Final health score
    local health_percentage=$((health_score * 100 / total_checks))
    echo ""
    echo "🏁 Health Check Summary:"
    echo "Overall Health: $health_percentage%"

    if [[ $critical_issues -gt 0 ]]; then
        echo "Critical Issues: $critical_issues"
        echo "Please address the critical issues to ensure system stability."
    else
        echo "All systems operational with no critical issues."
    fi
    echo "════════════════════════════════════════════════════════════════"
    return 0
}
# Main configuration loading function
load_configuration() {
    # Load environment variables
    load_env_variables

    # Validate configuration
    validate_configuration

    # Perform health checks
    perform_health_checks

    return 0
}