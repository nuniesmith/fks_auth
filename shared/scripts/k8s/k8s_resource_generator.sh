#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Resource Generator
# Description: Generates Kubernetes resource manifests from configuration files
#              and Docker Compose services
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/k8s_config.sh"
source "${SCRIPT_DIR}/k8s_utils.sh"

# Default resource types to generate
RESOURCE_TYPES=${RESOURCE_TYPES:-"configmap,deployment,service"}
DEBUG_MODE=${DEBUG_MODE:-"false"}
COMPOSE_FILE=${COMPOSE_FILE:-""}

# ----------------------------------------------------------------------
# SOURCE FILE DETECTION AND SAMPLE GENERATION
# ----------------------------------------------------------------------

# Function to check and report on available source files
check_source_files() {
    log_info "=== Source File Detection ==="
    log_info "Checking for source files to generate resources from..."
    
    # Check for base config directory
    local base_config_dir="${BASE_DIR:-/home/$USER/fks}/config"
    log_info "Base config directory: $base_config_dir"
    
    if [[ ! -d "$base_config_dir" ]]; then
        log_warn "Base config directory does not exist: $base_config_dir"
        echo -e "${YELLOW}Would you like to create the config directory? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            mkdir -p "$base_config_dir"
            log_info "Created config directory: $base_config_dir"
        else
            log_error "No config directory available. Cannot generate resources without source files."
            return 1
        fi
    else
        log_info "Found base config directory: $base_config_dir"
    fi
    
    # Check for FKS config directory
    local fks_config_dir="${base_config_dir}/fks"
    log_info "FKS config directory: $fks_config_dir"
    
    if [[ ! -d "$fks_config_dir" ]]; then
        log_warn "FKS config directory does not exist: $fks_config_dir"
        echo -e "${YELLOW}Would you like to create the FKS config directory? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            mkdir -p "$fks_config_dir"
            log_info "Created FKS config directory: $fks_config_dir"
        else
            log_warn "No FKS config directory available."
        fi
    else
        log_info "Found FKS config directory: $fks_config_dir"
    fi
    
    # Count YAML files in each directory
    local yaml_count=$(find "$base_config_dir" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | wc -l)
    local fks_yaml_count=0
    if [[ -d "$fks_config_dir" ]]; then
        fks_yaml_count=$(find "$fks_config_dir" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | wc -l)
    fi
    
    log_info "Found $yaml_count YAML files in base config directory"
    log_info "Found $fks_yaml_count YAML files in FKS config directory"
    
    # Check if we have any source files at all
    if [[ $yaml_count -eq 0 && $fks_yaml_count -eq 0 && -z "$COMPOSE_FILE" ]]; then
        log_warn "No source files found to generate resources from."
        log_info "Resources can be generated from:"
        log_info "  1. YAML files in $base_config_dir or its subdirectories"
        log_info "  2. YAML files in $fks_config_dir or its subdirectories"
        log_info "  3. A Docker Compose file"
        
        echo -e "${YELLOW}Would you like to create sample config files? (y/n)${NC}"
        read -r create_sample
        if [[ "$create_sample" =~ ^[Yy]$ ]]; then
            create_sample_config "$fks_config_dir"
            return 0
        else
            echo -e "${YELLOW}Do you want to specify a Docker Compose file instead? (y/n)${NC}"
            read -r use_compose
            if [[ "$use_compose" =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}Enter the path to the Docker Compose file:${NC} "
                read -r compose_file
                if [[ -f "$compose_file" ]]; then
                    COMPOSE_FILE="$compose_file"
                    log_info "Using Docker Compose file: $COMPOSE_FILE"
                    return 0
                else
                    log_error "Docker Compose file not found: $compose_file"
                    return 1
                fi
            else
                log_error "No source files available. Cannot generate resources."
                return 1
            fi
        fi
    fi
    
    # Report on found config files
    if [[ $yaml_count -gt 0 || $fks_yaml_count -gt 0 ]]; then
        log_info "Source files are available for resource generation."
        if [[ "$DEBUG_MODE" == "true" ]]; then
            log_info "Listing available YAML files:"
            find "$base_config_dir" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | while read -r file; do
                log_info "  - $file"
            done
        fi
        return 0
    fi
    
    return 1
}

# Function to create a sample configuration
create_sample_config() {
    local config_dir="$1"
    
    # Create directory structure
    mkdir -p "$config_dir/app"
    mkdir -p "$config_dir/components"
    mkdir -p "$config_dir/data"
    
    # Create a sample app configuration
    cat > "$config_dir/app/app-config.yaml" << EOF
# Sample application configuration
app:
  name: sample-app
  version: 1.0.0
  port: 8080
  
database:
  host: postgres
  port: 5432
  user: postgres
  
cache:
  host: redis
  port: 6379
EOF

    # Create a sample service configuration
    cat > "$config_dir/app/service.yaml" << EOF
# Sample service configuration
service:
  name: sample-app
  type: ClusterIP
  port: 8080
  targetPort: 8080
EOF

    # Create a sample secrets file
    cat > "$config_dir/app/secret.yaml" << EOF
# Sample secrets - NOTE: In production, don't commit actual secrets
database_password: change_me
api_key: sample_api_key_replace_me
EOF

    log_info "Created sample configuration files in $config_dir"
    log_info "You can now use these files as a basis for resource generation."
}

# ----------------------------------------------------------------------
# ERROR HANDLING
# ----------------------------------------------------------------------

# Error handler function
handle_error() {
    local exit_code=$?
    local line_no=$1
    
    if [ $exit_code -ne 0 ]; then
        log_error "Error on line $line_no: Command exited with status $exit_code"
        
        # Additional debug info if enabled
        if [ "$DEBUG_MODE" == "true" ]; then
            log_info "Stack trace:"
            local i=0
            while caller $i; do
                ((i++))
            done
        fi
    fi
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# ----------------------------------------------------------------------
# RESOURCE TYPE UTILITIES
# ----------------------------------------------------------------------

# Check if a resource type is enabled
is_resource_type_enabled() {
    local resource_type="$1"
    if [[ "$RESOURCE_TYPES" == *"$resource_type"* || "$RESOURCE_TYPES" == "all" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# Clear existing resource directories
clear_resource_dirs() {
    local output_base_dir="${1:-$MANIFESTS_DIR}"
    
    # Define resource types to check
    local resource_dirs=(
        "configmaps"
        "secrets"
        "services"
        "ingress"
        "deployments"
        "statefulsets"
        "daemonsets"
        "jobs"
        "cronjobs"
        "pvcs"
        "networkpolicies"
        "roles"
        "serviceaccounts"
    )
    
    for dir in "${resource_dirs[@]}"; do
        # Extract resource type by removing trailing 's'
        local resource_type="${dir%s}"
        
        if [[ "$(is_resource_type_enabled "$resource_type")" == "true" ]]; then
            local resource_dir="${output_base_dir}/${dir}"
            
            if [[ -d "$resource_dir" ]]; then
                log_info "Clearing existing $dir directory: $resource_dir"
                rm -rf "${resource_dir:?}/"*
            else
                log_info "Creating $dir directory: $resource_dir"
                mkdir -p "$resource_dir"
            fi
        fi
    done
    
    log_info "Resource directories prepared"
}

# Function to display a summary of processed files
display_processing_summary() {
    local output_base_dir="${1:-$MANIFESTS_DIR}"
    local processed_files=0
    
    log_info "=== Resource Generation Summary ==="
    
    # Check each resource type directory
    local resource_dirs=(
        "configmaps"
        "secrets"
        "services"
        "ingress"
        "deployments"
        "statefulsets"
        "daemonsets"
        "pvcs"
        "networkpolicies"
        "roles"
        "serviceaccounts"
    )
    
    for dir in "${resource_dirs[@]}"; do
        if [[ -d "${output_base_dir}/${dir}" ]]; then
            local file_count=$(find "${output_base_dir}/${dir}" -type f -name "*.yaml" | wc -l)
            processed_files=$((processed_files + file_count))
            log_info "Generated $file_count ${dir} files"
        fi
    done
    
    if [[ $processed_files -eq 0 ]]; then
        log_warn "No Kubernetes resource files were generated."
        log_info "This usually happens when no source files were found or when the source files don't match the enabled resource types."
        log_info "Enabled resource types: $RESOURCE_TYPES"
        log_info "Check that your source files exist and have the right format, or try with different resource types."
    else
        log_info "Total Kubernetes resource files generated: $processed_files"
    fi
}

# ----------------------------------------------------------------------
# CONFIGMAP GENERATORS
# ----------------------------------------------------------------------

# Function to generate ConfigMap from YAML file
generate_configmap_from_yaml() {
    local service_name="$1"
    local yaml_file="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local subdir_path="${5:-}"
    
    # Extract filename without path and extension
    local filename=$(basename "$yaml_file")
    
    # Create configmap name - include subdir in name if present
    local configmap_name
    if [[ -n "$subdir_path" ]]; then
        # Convert directory path to dashed format for ConfigMap name
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        configmap_name="${service_name}-${subdir_name}-$(basename "$filename" .yaml)"
    else
        configmap_name="${service_name}-$(basename "$filename" .yaml)"
    fi
    
    # Handle yml extension
    configmap_name="${configmap_name%.yml}"  
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
    fi
    
    # Generate ConfigMap manifest
    local output_file="${output_dir}/${configmap_name}.yaml"
    
    log_info "Generating ConfigMap from $yaml_file for service $service_name..."
    
    # Create ConfigMap header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: ConfigMap
metadata:
  name: $configmap_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
data:
  $filename: |
EOF
    
    # Indent the YAML content by 4 spaces and append to file
    sed 's/^/    /' "$yaml_file" >> "$output_file"
    
    log_info "Generated ConfigMap at $output_file"
    return 0
}

# Function to generate ConfigMap from plain text file (like redis.conf)
generate_configmap_from_file() {
    local service_name="$1"
    local config_file="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local subdir_path="${5:-}"
    
    # Extract filename without path
    local filename=$(basename "$config_file")
    
    # Create configmap name - include subdir in name if present
    local configmap_name
    if [[ -n "$subdir_path" ]]; then
        # Convert directory path to dashed format for ConfigMap name
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        configmap_name="${service_name}-${subdir_name}-${filename/./-}"
    else
        configmap_name="${service_name}-${filename/./-}"
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
    fi
    
    # Generate ConfigMap manifest
    local output_file="${output_dir}/${configmap_name}.yaml"
    
    log_info "Generating ConfigMap from $config_file for service $service_name..."
    
    # Create ConfigMap header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: ConfigMap
metadata:
  name: $configmap_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
data:
  $filename: |
EOF
    
    # Indent the file content by 4 spaces and append to file
    sed 's/^/    /' "$config_file" >> "$output_file"
    
    log_info "Generated ConfigMap at $output_file"
    return 0
}

# Function to generate ConfigMap from environment variables in a compose section
generate_configmap_from_env() {
    local service_name="$1"
    local env_vars="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate ConfigMap manifest
    local output_file="${output_dir}/${service_name}-env.yaml"
    
    log_info "Generating environment ConfigMap for service $service_name..."
    
    # Create ConfigMap header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${service_name}-env
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
data:
EOF
    
    # Process environment variables
    echo "$env_vars" | grep -v "^$" | while IFS= read -r line; do
        # Extract key and value using string manipulation
        if [[ "$line" =~ ([A-Za-z0-9_]+):\ *(.+) ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"
            
            # Skip passwords, tokens, and other sensitive data
            if [[ "$key" == *PASSWORD* || "$key" == *TOKEN* || "$key" == *SECRET* || "$key" == *KEY* ]]; then
                continue
            fi
            
            # Remove quotes if present
            value="${value#\"}"
            value="${value%\"}"
            
            echo "  $key: \"$value\"" >> "$output_file"
        fi
    done
    
    log_info "Generated environment ConfigMap at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# SECRET GENERATORS
# ----------------------------------------------------------------------

# Function to generate Secret from YAML file with sensitive data
generate_secret_from_yaml() {
    local service_name="$1"
    local yaml_file="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local subdir_path="${5:-}"
    
    # Extract filename without path and extension
    local filename=$(basename "$yaml_file")
    
    # Create secret name - include subdir in name if present
    local secret_name
    if [[ -n "$subdir_path" ]]; then
        # Convert directory path to dashed format for Secret name
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        secret_name="${service_name}-${subdir_name}-$(basename "$filename" .yaml)"
    else
        secret_name="${service_name}-$(basename "$filename" .yaml)"
    fi
    
    # Handle yml extension
    secret_name="${secret_name%.yml}"
    secret_name="${secret_name%.secret}"  # Also handle .secret extension
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
    fi
    
    # Generate Secret manifest
    local output_file="${output_dir}/${secret_name}.yaml"
    
    log_info "Generating Secret from $yaml_file for service $service_name..."
    
    # Determine if we should base64 encode the values
    local has_base64_tag=false
    if grep -q "#@no-encode" "$yaml_file"; then
        has_base64_tag=true
    fi
    
    # Create Secret header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: Secret
metadata:
  name: $secret_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
type: Opaque
data:
EOF
    
    # Process the file and encode values
    if [[ "$has_base64_tag" == "true" ]]; then
        # No encoding - just copy as-is (assuming values are already encoded)
        # Extract key-value pairs and format them correctly for a Secret
        grep -v "^#" "$yaml_file" | while IFS=":" read -r key value; do
            if [[ -n "$key" && -n "$value" ]]; then
                # Trim whitespace
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | xargs)
                echo "  $key: $value" >> "$output_file"
            fi
        done
    else
        # Base64 encode each value
        grep -v "^#" "$yaml_file" | while IFS=":" read -r key value; do
            if [[ -n "$key" && -n "$value" ]]; then
                # Trim whitespace
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | xargs)
                # Base64 encode value
                encoded_value=$(echo -n "$value" | base64 -w 0)
                echo "  $key: $encoded_value" >> "$output_file"
            fi
        done
    fi
    
    log_info "Generated Secret at $output_file"
    return 0
}

# Function to generate Secret from environment variables in a compose section
generate_secret_from_env() {
    local service_name="$1"
    local env_vars="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate Secret manifest
    local output_file="${output_dir}/${service_name}-secrets.yaml"
    
    log_info "Generating sensitive environment Secret for service $service_name..."
    
    # Create Secret header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: Secret
metadata:
  name: ${service_name}-secrets
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
type: Opaque
data:
EOF
    
    # Process environment variables
    local has_secrets=false
    
    echo "$env_vars" | grep -v "^$" | while IFS= read -r line; do
        # Extract key and value using string manipulation
        if [[ "$line" =~ ([A-Za-z0-9_]+):\ *(.+) ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"
            
            # Only include passwords, tokens, and other sensitive data
            if [[ "$key" == *PASSWORD* || "$key" == *TOKEN* || "$key" == *SECRET* || "$key" == *KEY* ]]; then
                has_secrets=true
                
                # Remove quotes if present
                value="${value#\"}"
                value="${value%\"}"
                
                # Base64 encode value
                encoded_value=$(echo -n "$value" | base64 -w 0)
                echo "  $key: $encoded_value" >> "$output_file"
            fi
        fi
    done
    
    # If no secrets were found, we don't need the file
    if [[ "$has_secrets" == "false" ]]; then
        rm -f "$output_file"
        log_info "No sensitive environment variables found for service $service_name. No Secret generated."
        return 0
    fi
    
    log_info "Generated sensitive environment Secret at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# SERVICE GENERATORS
# ----------------------------------------------------------------------

# Function to generate Service from YAML configuration
generate_service_from_yaml() {
    local service_name="$1"
    local yaml_file="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local subdir_path="${5:-}"
    
    # Extract filename without path and extension
    local filename=$(basename "$yaml_file")
    local output_service_name="${service_name}"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
        # Add subdir to service name for uniqueness
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        output_service_name="${service_name}-${subdir_name}"
    else
        mkdir -p "$output_dir"
    fi
    
    # Generate Service manifest
    local output_file="${output_dir}/${output_service_name}.yaml"
    
    log_info "Generating Service from $yaml_file for $service_name..."
    
    # Check if the YAML has service configuration
    if ! grep -q "service:" "$yaml_file" && ! grep -q "port:" "$yaml_file"; then
        log_warn "No service configuration found in $yaml_file. Skipping."
        return 0
    fi
    
    # Extract port information using temporary variables
    local port=""
    local target_port=""
    local service_type="ClusterIP"
    local node_port=""
    
    # Read port information
    if grep -q "port:" "$yaml_file"; then
        port=$(grep "port:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    if grep -q "targetPort:" "$yaml_file"; then
        target_port=$(grep "targetPort:" "$yaml_file" | head -1 | awk '{print $2}')
    elif [[ -n "$port" ]]; then
        # Default to same as port if not specified
        target_port="$port"
    fi
    
    if grep -q "type:" "$yaml_file"; then
        service_type=$(grep "type:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    if grep -q "nodePort:" "$yaml_file"; then
        node_port=$(grep "nodePort:" "$yaml_file" | head -1 | awk '{print $2}')
        # NodePort requires service type to be NodePort
        service_type="NodePort"
    fi
    
    # Create Service manifest
    cat <<EOF > "$output_file"
apiVersion: v1
kind: Service
metadata:
  name: $output_service_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  selector:
    app: $service_name
  type: $service_type
EOF
    
    # Add ports section
    if [[ -n "$port" ]]; then
        cat <<EOF >> "$output_file"
  ports:
  - port: $port
    targetPort: $target_port
EOF
        
        if [[ -n "$node_port" ]]; then
            echo "    nodePort: $node_port" >> "$output_file"
        fi
    else
        log_warn "No port information found in $yaml_file. Creating minimal Service."
        cat <<EOF >> "$output_file"
  ports:
  - port: 80
    targetPort: 80
EOF
    fi
    
    log_info "Generated Service at $output_file"
    return 0
}

# Function to generate Service from Docker Compose service definition
generate_service_from_compose() {
    local service_name="$1"
    local compose_section="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate Service manifest
    local output_file="${output_dir}/${service_name}.yaml"
    
    log_info "Generating Service from compose for $service_name..."
    
    # Default service type
    local service_type="ClusterIP"
    
    # Check if ports section exists
    if ! echo "$compose_section" | grep -q "ports:"; then
        # If there's no ports, check for expose only
        if echo "$compose_section" | grep -q "expose:"; then
            # Create a headless service for internal communication only
            cat <<EOF > "$output_file"
apiVersion: v1
kind: Service
metadata:
  name: $service_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  selector:
    app: $service_name
  clusterIP: None
  ports:
EOF
            # Extract exposed ports
            local exposed_ports=$(echo "$compose_section" | grep -A 50 "expose:" | grep -B 50 -m 1 "^[a-z]" | grep -v "expose:" | grep -v "^[a-z]" | sed 's/- //')
            if [[ -n "$exposed_ports" ]]; then
                echo "$exposed_ports" | while read -r port; do
                    # Remove quotes and extract port number
                    port="${port#\"}"
                    port="${port%\"}"
                    
                    cat <<EOF >> "$output_file"
  - port: $port
    targetPort: $port
EOF
                done
            else
                # If no ports defined, add a default one
                cat <<EOF >> "$output_file"
  - port: 80
    targetPort: 80
EOF
            fi
            
            log_info "Generated headless Service at $output_file"
            return 0
        else
            log_warn "No ports or expose configuration found for $service_name. Skipping Service."
            return 0
        fi
    fi
    
    # Extract ports mapping
    local ports_section=$(echo "$compose_section" | grep -A 50 "ports:" | grep -B 50 -m 1 "^[a-z]" | grep -v "ports:" | grep -v "^[a-z]" | sed 's/- //')
    
    # Create basic service header
    cat <<EOF > "$output_file"
apiVersion: v1
kind: Service
metadata:
  name: $service_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  selector:
    app: $service_name
  type: $service_type
  ports:
EOF
    
    # Process ports
    local has_ports=false
    local node_port_found=false
    
    echo "$ports_section" | while read -r port_mapping; do
        # Skip empty lines
        if [[ -z "$port_mapping" ]]; then
            continue
        fi
        
        has_ports=true
        
        # Remove quotes from port mapping
        port_mapping="${port_mapping#\"}"
        port_mapping="${port_mapping%\"}"
        
        # Check for different port formats
        if [[ "$port_mapping" =~ ([0-9]+):([0-9]+) ]]; then
            # Format: "host:container"
            local host_port="${BASH_REMATCH[1]}"
            local container_port="${BASH_REMATCH[2]}"
            
            # If host port is in NodePort range (30000-32767), use NodePort service
            if [[ "$host_port" -ge 30000 && "$host_port" -le 32767 && "$node_port_found" == "false" ]]; then
                service_type="NodePort"
                node_port_found=true
                
                # Update service type
                sed -i "s/type: ClusterIP/type: NodePort/" "$output_file"
                
                cat <<EOF >> "$output_file"
  - port: $container_port
    targetPort: $container_port
    nodePort: $host_port
EOF
            else
                cat <<EOF >> "$output_file"
  - port: $container_port
    targetPort: $container_port
EOF
            fi
        elif [[ "$port_mapping" =~ ([0-9]+):([0-9]+)/([a-z]+) ]]; then
            # Format: "host:container/protocol"
            local host_port="${BASH_REMATCH[1]}"
            local container_port="${BASH_REMATCH[2]}"
            local protocol="${BASH_REMATCH[3]}"
            
            # If host port is in NodePort range (30000-32767), use NodePort service
            if [[ "$host_port" -ge 30000 && "$host_port" -le 32767 && "$node_port_found" == "false" ]]; then
                service_type="NodePort"
                node_port_found=true
                
                # Update service type
                sed -i "s/type: ClusterIP/type: NodePort/" "$output_file"
                
                cat <<EOF >> "$output_file"
  - port: $container_port
    targetPort: $container_port
    nodePort: $host_port
    protocol: ${protocol^}
EOF
            else
                cat <<EOF >> "$output_file"
  - port: $container_port
    targetPort: $container_port
    protocol: ${protocol^}
EOF
            fi
        else
            # Assume it's just a simple port
            local port="$port_mapping"
            
            cat <<EOF >> "$output_file"
  - port: $port
    targetPort: $port
EOF
        fi
    done
    
    # If no ports were added, provide a default
    if [[ "$has_ports" == "false" ]]; then
        cat <<EOF >> "$output_file"
  - port: 80
    targetPort: 80
EOF
    fi
    
    log_info "Generated Service at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# INGRESS GENERATORS
# ----------------------------------------------------------------------
# Function to generate Ingress from YAML configuration
generate_ingress_from_yaml() {
    local service_name="$1"
    local yaml_file="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local subdir_path="${5:-}"
    
    # Extract filename without path and extension
    local filename=$(basename "$yaml_file")
    local output_ingress_name="${service_name}"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
        # Add subdir to ingress name for uniqueness
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        output_ingress_name="${service_name}-${subdir_name}"
    else
        mkdir -p "$output_dir"
    fi
    
    # Generate Ingress manifest
    local output_file="${output_dir}/${output_ingress_name}.yaml"
    
    log_info "Generating Ingress from $yaml_file for $service_name..."
    
    # Check if the YAML has ingress configuration
    if ! grep -q "ingress:" "$yaml_file" && ! grep -q "host:" "$yaml_file" && ! grep -q "path:" "$yaml_file"; then
        log_warn "No ingress configuration found in $yaml_file. Skipping."
        return 0
    fi
    
    # Extract host information
    local host=""
    if grep -q "host:" "$yaml_file"; then
        host=$(grep "host:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    # Extract path information
    local path="/"
    if grep -q "path:" "$yaml_file"; then
        path=$(grep "path:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    # Extract service information
    local backend_service_name="$service_name"
    if grep -q "serviceName:" "$yaml_file"; then
        backend_service_name=$(grep "serviceName:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    # Extract service port
    local backend_service_port="80"
    if grep -q "servicePort:" "$yaml_file"; then
        backend_service_port=$(grep "servicePort:" "$yaml_file" | head -1 | awk '{print $2}')
    elif grep -q "port:" "$yaml_file"; then
        backend_service_port=$(grep "port:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    # Extract TLS information
    local has_tls=false
    local tls_secret_name=""
    if grep -q "tls:" "$yaml_file"; then
        has_tls=true
        if grep -q "secretName:" "$yaml_file"; then
            tls_secret_name=$(grep "secretName:" "$yaml_file" | head -1 | awk '{print $2}')
        else
            tls_secret_name="${service_name}-tls"
        fi
    fi
    
    # Determine API version - prefer networking.k8s.io/v1 for Kubernetes 1.19+
    local api_version="networking.k8s.io/v1"
    
    # Create Ingress manifest
    cat <<EOF > "$output_file"
apiVersion: $api_version
kind: Ingress
metadata:
  name: $output_ingress_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
  annotations:
    kubernetes.io/ingress.class: nginx
EOF
    
    # Add additional annotations for TLS if needed
    if [[ "$has_tls" == "true" ]]; then
        cat <<EOF >> "$output_file"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
EOF
    fi
    
    # Start spec section
    cat <<EOF >> "$output_file"
spec:
EOF
    
    # Add TLS section if needed
    if [[ "$has_tls" == "true" ]]; then
        cat <<EOF >> "$output_file"
  tls:
  - hosts:
    - $host
    secretName: $tls_secret_name
EOF
    fi
    
    # Add rules section
    cat <<EOF >> "$output_file"
  rules:
EOF
    
    # Add host rule if host is specified
    if [[ -n "$host" ]]; then
        cat <<EOF >> "$output_file"
  - host: $host
    http:
      paths:
      - path: $path
        pathType: Prefix
        backend:
          service:
            name: $backend_service_name
            port:
              number: $backend_service_port
EOF
    else
        # Add default rule without host
        cat <<EOF >> "$output_file"
  - http:
      paths:
      - path: $path
        pathType: Prefix
        backend:
          service:
            name: $backend_service_name
            port:
              number: $backend_service_port
EOF
    fi
    
    log_info "Generated Ingress at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# DEPLOYMENT GENERATORS
# ----------------------------------------------------------------------

# Function to generate Deployment from Docker Compose service definition
generate_deployment_from_compose() {
    local service_name="$1"
    local compose_section="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate Deployment manifest
    local output_file="${output_dir}/${service_name}.yaml"
    
    log_info "Generating Deployment for $service_name..."
    
    # Extract the image
    local image=""
    if echo "$compose_section" | grep -q "image:"; then
        image=$(echo "$compose_section" | grep "image:" | head -1 | awk '{print $2}')
    else
        log_warn "No image specified for $service_name. Using a placeholder."
        image="placeholder:latest"
    fi
    
    # Extract environment variables
    local env_vars=""
    if echo "$compose_section" | grep -q "environment:"; then
        env_vars=$(echo "$compose_section" | grep -A 100 "environment:" | grep -B 100 -m 1 "^[a-z]" | grep -v "environment:" | grep -v "^[a-z]")
    fi
    
    # Extract volume mounts
    local volume_mounts=""
    if echo "$compose_section" | grep -q "volumes:"; then
        volume_mounts=$(echo "$compose_section" | grep -A 50 "volumes:" | grep -B 50 -m 1 "^[a-z]" | grep -v "volumes:" | grep -v "^[a-z]" | sed 's/- //')
    fi
    
    # Extract resource limits
    local has_resources=false
    local cpu_limit=""
    local memory_limit=""
    local gpu_limit=""
    
    if echo "$compose_section" | grep -q "deploy:" && echo "$compose_section" | grep -q "resources:"; then
        has_resources=true
        
        # CPU limits
        if echo "$compose_section" | grep -q "cpus:"; then
            cpu_limit=$(echo "$compose_section" | grep "cpus:" | head -1 | awk '{print $2}' | tr -d "'")
        fi
        
        # Memory limits
        if echo "$compose_section" | grep -q "memory:"; then
            memory_limit=$(echo "$compose_section" | grep "memory:" | head -1 | awk '{print $2}')
        fi
        
        # GPU limits (based on service name for now)
        if [[ "$service_name" == "training" || "$service_name" == "watcher" ]]; then
            gpu_limit="1"
        fi
    fi
    
    # Extract command
    local command=""
    if echo "$compose_section" | grep -q "command:"; then
        command=$(echo "$compose_section" | grep -A 10 "command:" | grep -B 10 -m 1 "^[a-z]" | grep -v "command:" | grep -v "^[a-z]")
    fi
    
    # Extract entrypoint
    local entrypoint=""
    if echo "$compose_section" | grep -q "entrypoint:"; then
        entrypoint=$(echo "$compose_section" | grep -A 10 "entrypoint:" | grep -B 10 -m 1 "^[a-z]" | grep -v "entrypoint:" | grep -v "^[a-z]")
    fi
    
    # Extract healthcheck
    local has_healthcheck=false
    local healthcheck_cmd=""
    local healthcheck_interval=""
    local healthcheck_timeout=""
    local healthcheck_retries=""
    local healthcheck_start_period=""
    
    if echo "$compose_section" | grep -q "healthcheck:"; then
        has_healthcheck=true
        
        # Extract healthcheck command
        if echo "$compose_section" | grep -q "test:"; then
            healthcheck_cmd=$(echo "$compose_section" | grep -A 10 "test:" | grep -B 10 -m 1 "^[a-z]" | grep -v "test:" | grep -v "^[a-z]" | grep -o '".*"' | sed 's/"//g')
        fi
        
        # Extract healthcheck interval
        if echo "$compose_section" | grep -q "interval:"; then
            healthcheck_interval=$(echo "$compose_section" | grep "interval:" | head -1 | awk '{print $2}')
        fi
        
        # Extract healthcheck timeout
        if echo "$compose_section" | grep -q "timeout:"; then
            healthcheck_timeout=$(echo "$compose_section" | grep "timeout:" | head -1 | awk '{print $2}')
        fi
        
        # Extract healthcheck retries
        if echo "$compose_section" | grep -q "retries:"; then
            healthcheck_retries=$(echo "$compose_section" | grep "retries:" | head -1 | awk '{print $2}')
        fi
        
        # Extract healthcheck start period
        if echo "$compose_section" | grep -q "start_period:"; then
            healthcheck_start_period=$(echo "$compose_section" | grep "start_period:" | head -1 | awk '{print $2}')
        fi
    fi
    
    # Create ConfigMap and Secret for environment variables if needed
    if [[ -n "$env_vars" ]]; then
        if [[ "$(is_resource_type_enabled 'configmap')" == "true" ]]; then
            generate_configmap_from_env "$service_name" "$env_vars" "${MANIFESTS_DIR}/configmaps" "$namespace"
        fi
        
        if [[ "$(is_resource_type_enabled 'secret')" == "true" ]]; then
            generate_secret_from_env "$service_name" "$env_vars" "${MANIFESTS_DIR}/secrets" "$namespace"
        fi
    fi
    
    # Determine replica count - default to 1, but use 0 for GPU services 
    # that shouldn't start automatically like training
    local replicas=1
    if [[ "$service_name" == "training" ]]; then
        replicas=0
    fi
    
    # Create Deployment header
    cat <<EOF > "$output_file"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $service_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  replicas: $replicas
  selector:
    matchLabels:
      app: $service_name
  template:
    metadata:
      labels:
        app: $service_name
    spec:
      containers:
      - name: $service_name
        image: $image
EOF
    
    # Add command if present
    if [[ -n "$command" ]]; then
        echo "        command:" >> "$output_file"
        echo "$command" | sed 's/- /        - /g' >> "$output_file"
    fi
    
    # Add entrypoint as args if present
    if [[ -n "$entrypoint" ]]; then
        echo "        args:" >> "$output_file"
        echo "$entrypoint" | sed 's/- /        - /g' >> "$output_file"
    fi
    
    # Add env from ConfigMap and Secret
    cat <<EOF >> "$output_file"
        envFrom:
        - configMapRef:
            name: ${service_name}-env
            optional: true
        - secretRef:
            name: ${service_name}-secrets
            optional: true
EOF
    
    # Add resources if present
    if [[ "$has_resources" == "true" ]]; then
        echo "        resources:" >> "$output_file"
        
        # Add requests and limits sections if either CPU or memory is specified
        if [[ -n "$cpu_limit" || -n "$memory_limit" || -n "$gpu_limit" ]]; then
            echo "          limits:" >> "$output_file"
            
            if [[ -n "$cpu_limit" ]]; then
                echo "            cpu: $cpu_limit" >> "$output_file"
            fi
            
            if [[ -n "$memory_limit" ]]; then
                echo "            memory: $memory_limit" >> "$output_file"
            fi
            
            if [[ -n "$gpu_limit" ]]; then
                echo "            nvidia.com/gpu: $gpu_limit" >> "$output_file"
            fi
            
            # Add requests at 50% of limits by default
            echo "          requests:" >> "$output_file"
            
            if [[ -n "$cpu_limit" ]]; then
                # Parse CPU limit and calculate 50%
                if [[ "$cpu_limit" =~ ([0-9]+)(\.[0-9]+)? ]]; then
                    local cpu_value="${BASH_REMATCH[1]}${BASH_REMATCH[2]:-0}"
                    local cpu_request=$(echo "scale=2; $cpu_value / 2" | bc)
                    echo "            cpu: $cpu_request" >> "$output_file"
                fi
            fi
            
            if [[ -n "$memory_limit" ]]; then
                # Parse memory limit and calculate 50%
                if [[ "$memory_limit" =~ ([0-9]+)([A-Za-z]+) ]]; then
                    local mem_value="${BASH_REMATCH[1]}"
                    local mem_unit="${BASH_REMATCH[2]}"
                    local mem_request=$(echo "scale=0; $mem_value / 2" | bc)
                    echo "            memory: ${mem_request}${mem_unit}" >> "$output_file"
                fi
            fi
            
            if [[ -n "$gpu_limit" ]]; then
                echo "            nvidia.com/gpu: $gpu_limit" >> "$output_file"
            fi
        fi
    fi
    
    # Add volume mounts if present
    if [[ -n "$volume_mounts" ]]; then
        echo "        volumeMounts:" >> "$output_file"
        
        echo "$volume_mounts" | while read -r mount; do
            if [[ -n "$mount" ]]; then
                if [[ "$mount" =~ (.+):(.+) ]]; then
                    local host_path="${BASH_REMATCH[1]}"
                    local container_path="${BASH_REMATCH[2]}"
                    
                    # Skip named volumes or relative paths for now
                    if [[ "$host_path" == /* ]]; then
                        # Extract volume name from path
                        local volume_name=$(basename "$host_path" | tr '.' '-')
                        
                        # Add volume mount
                        cat <<EOF >> "$output_file"
        - name: $volume_name
          mountPath: $container_path
EOF
                    fi
                fi
            fi
        done
        
        # Add volumes section
        echo "      volumes:" >> "$output_file"
        
        echo "$volume_mounts" | while read -r mount; do
            if [[ -n "$mount" ]]; then
                if [[ "$mount" =~ (.+):(.+) ]]; then
                    local host_path="${BASH_REMATCH[1]}"
                    local container_path="${BASH_REMATCH[2]}"
                    
                    # Skip named volumes or relative paths for now
                    if [[ "$host_path" == /* ]]; then
                        # Extract volume name from path
                        local volume_name=$(basename "$host_path" | tr '.' '-')
                        
                        # Check if this is a config file that should be a ConfigMap
                        if [[ "$host_path" == */config/* ]]; then
                            # Use ConfigMap for configuration files
                            cat <<EOF >> "$output_file"
      - name: $volume_name
        configMap:
          name: ${service_name}-config
EOF
                        else
                            # Use hostPath for other files
                            cat <<EOF >> "$output_file"
      - name: $volume_name
        hostPath:
          path: $host_path
EOF
                        fi
                    fi
                fi
            fi
        done
    fi
    
    # Add healthcheck if present
    if [[ "$has_healthcheck" == "true" && -n "$healthcheck_cmd" ]]; then
        cat <<EOF >> "$output_file"
        livenessProbe:
          exec:
            command:
            - sh
            - -c
            - $healthcheck_cmd
EOF
        
        if [[ -n "$healthcheck_interval" ]]; then
            # Convert interval to seconds
            if [[ "$healthcheck_interval" =~ ([0-9]+)s ]]; then
                echo "          periodSeconds: ${BASH_REMATCH[1]}" >> "$output_file"
            fi
        fi
        
        if [[ -n "$healthcheck_timeout" ]]; then
            # Convert timeout to seconds
            if [[ "$healthcheck_timeout" =~ ([0-9]+)s ]]; then
                echo "          timeoutSeconds: ${BASH_REMATCH[1]}" >> "$output_file"
            fi
        fi
        
        if [[ -n "$healthcheck_retries" ]]; then
            echo "          failureThreshold: $healthcheck_retries" >> "$output_file"
        fi
        
        if [[ -n "$healthcheck_start_period" ]]; then
            # Convert start period to seconds
            if [[ "$healthcheck_start_period" =~ ([0-9]+)s ]]; then
                echo "          initialDelaySeconds: ${BASH_REMATCH[1]}" >> "$output_file"
            fi
        fi
        
        # Also add readiness probe with the same settings
        cat <<EOF >> "$output_file"
        readinessProbe:
          exec:
            command:
            - sh
            - -c
            - $healthcheck_cmd
EOF
        
        if [[ -n "$healthcheck_interval" ]]; then
            # Convert interval to seconds
            if [[ "$healthcheck_interval" =~ ([0-9]+)s ]]; then
                echo "          periodSeconds: ${BASH_REMATCH[1]}" >> "$output_file"
            fi
        fi
        
        if [[ -n "$healthcheck_timeout" ]]; then
            # Convert timeout to seconds
            if [[ "$healthcheck_timeout" =~ ([0-9]+)s ]]; then
                echo "          timeoutSeconds: ${BASH_REMATCH[1]}" >> "$output_file"
            fi
        fi
        
        if [[ -n "$healthcheck_retries" ]]; then
            echo "          failureThreshold: $healthcheck_retries" >> "$output_file"
        fi
    fi
    
    # Add restart policy for training services
    if [[ "$service_name" == "training" ]]; then
        cat <<EOF >> "$output_file"
      restartPolicy: OnFailure
EOF
    fi
    
    log_info "Generated Deployment at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# STATEFULSET GENERATORS
# ----------------------------------------------------------------------

# Function to generate StatefulSet for databases (Redis, Postgres)
generate_statefulset_for_db() {
    local service_name="$1"
    local compose_section="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate StatefulSet manifest
    local output_file="${output_dir}/${service_name}.yaml"
    
    log_info "Generating StatefulSet for $service_name..."
    
    # Extract the image
    local image=""
    if echo "$compose_section" | grep -q "image:"; then
        image=$(echo "$compose_section" | grep "image:" | head -1 | awk '{print $2}')
    else
        log_warn "No image specified for $service_name. Using a placeholder."
        image="placeholder:latest"
    fi
    
    # Extract environment variables
    local env_vars=""
    if echo "$compose_section" | grep -q "environment:"; then
        env_vars=$(echo "$compose_section" | grep -A 100 "environment:" | grep -B 100 -m 1 "^[a-z]" | grep -v "environment:" | grep -v "^[a-z]")
    fi
    
    # Extract command
    local command=""
    if echo "$compose_section" | grep -q "command:"; then
        command=$(echo "$compose_section" | grep -A 10 "command:" | grep -B 10 -m 1 "^[a-z]" | grep -v "command:" | grep -v "^[a-z]")
    fi
    
    # Extract ports
    local port=""
    if echo "$compose_section" | grep -q "expose:"; then
        port=$(echo "$compose_section" | grep -A 10 "expose:" | grep -B 10 -m 1 "^[a-z]" | grep -v "expose:" | grep -v "^[a-z]" | head -1 | sed 's/- //')
    fi
    
    # Storage size based on service type
    local storage_size="1Gi"
    if [[ "$service_name" == "postgres" ]]; then
        storage_size="5Gi"
    elif [[ "$service_name" == "redis" ]]; then
        storage_size="2Gi"
    fi
    
    # Create ConfigMap and Secret for environment variables if needed
    if [[ -n "$env_vars" ]]; then
        if [[ "$(is_resource_type_enabled 'configmap')" == "true" ]]; then
            generate_configmap_from_env "$service_name" "$env_vars" "${MANIFESTS_DIR}/configmaps" "$namespace"
        fi
        
        if [[ "$(is_resource_type_enabled 'secret')" == "true" ]]; then
            generate_secret_from_env "$service_name" "$env_vars" "${MANIFESTS_DIR}/secrets" "$namespace"
        fi
    fi
    
    # Create PVC for the database
    if [[ "$(is_resource_type_enabled 'pvc')" == "true" ]]; then
        mkdir -p "${MANIFESTS_DIR}/pvcs"
        local pvc_file="${MANIFESTS_DIR}/pvcs/${service_name}-data.yaml"
        
        cat <<EOF > "$pvc_file"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${service_name}-data
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: $storage_size
EOF
        
        log_info "Generated PVC at $pvc_file"
    fi
    
    # Create StatefulSet manifest
    cat <<EOF > "$output_file"
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: $service_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
spec:
  serviceName: $service_name
  replicas: 1
  selector:
    matchLabels:
      app: $service_name
  template:
    metadata:
      labels:
        app: $service_name
    spec:
      containers:
      - name: $service_name
        image: $image
EOF
    
    # Add command if present
    if [[ -n "$command" ]]; then
        echo "        command:" >> "$output_file"
        echo "$command" | sed 's/- /        - /g' >> "$output_file"
    fi
    
    # Add port if present
    if [[ -n "$port" ]]; then
        cat <<EOF >> "$output_file"
        ports:
        - containerPort: $port
EOF
    fi
    
    # Add env from ConfigMap and Secret
    cat <<EOF >> "$output_file"
        envFrom:
        - configMapRef:
            name: ${service_name}-env
            optional: true
        - secretRef:
            name: ${service_name}-secrets
            optional: true
EOF
    
    # Add healthcheck based on service type
    if [[ "$service_name" == "postgres" ]]; then
        cat <<EOF >> "$output_file"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
EOF
    elif [[ "$service_name" == "redis" ]]; then
        cat <<EOF >> "$output_file"
        livenessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
EOF
    fi
    
    # Add resource limits based on service type
    if [[ "$service_name" == "postgres" ]]; then
        cat <<EOF >> "$output_file"
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
          requests:
            cpu: "0.5"
            memory: "512Mi"
EOF
    elif [[ "$service_name" == "redis" ]]; then
        cat <<EOF >> "$output_file"
        resources:
          limits:
            cpu: "1"
            memory: "1Gi"
          requests:
            cpu: "0.2"
            memory: "256Mi"
EOF
    fi
    
    # Add volume mounts
    cat <<EOF >> "$output_file"
        volumeMounts:
        - name: ${service_name}-data
          mountPath: /data
EOF
    
    # Add specific volume mounts based on service type
    if [[ "$service_name" == "postgres" ]]; then
        cat <<EOF >> "$output_file"
          subPath: postgres
      volumes:
      - name: ${service_name}-data
        persistentVolumeClaim:
          claimName: ${service_name}-data
EOF
    elif [[ "$service_name" == "redis" ]]; then
        cat <<EOF >> "$output_file"
          subPath: redis
      volumes:
      - name: ${service_name}-data
        persistentVolumeClaim:
          claimName: ${service_name}-data
EOF
    fi
    
    log_info "Generated StatefulSet at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# DOCKER COMPOSE PARSING
# ----------------------------------------------------------------------

# Function to extract Docker Compose section for a specific service
extract_compose_section() {
    local compose_file="$1"
    local service_name="$2"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Docker Compose file not found: $compose_file"
        return 1
    fi
    
    # Find the service section start
    local service_start=$(grep -n "^$service_name:" "$compose_file" | cut -d ':' -f 1)
    
    if [[ -z "$service_start" ]]; then
        log_error "Service $service_name not found in Docker Compose file"
        return 1
    fi
    
    # Extract the service section
    local section_end=$(tail -n +$((service_start + 1)) "$compose_file" | grep -n "^[a-zA-Z0-9_-]\+:" | head -1 | cut -d ':' -f 1)
    
    if [[ -z "$section_end" ]]; then
        # If no next service is found, take until the end of the file
        tail -n +$service_start "$compose_file"
    else
        # Extract from service start to the line before the next service
        head -n $((service_start + section_end - 1)) "$compose_file" | tail -n +$service_start
    fi
}

# Function to get list of services from Docker Compose file
get_compose_services() {
    local compose_file="$1"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Docker Compose file not found: $compose_file"
        return 1
    fi
    
    # Extract service names (assumes services section starts at beginning of file)
    local in_services=false
    local services=()
    
    # Look for services: section
    while IFS= read -r line; do
        if [[ "$line" =~ ^services: ]]; then
            in_services=true
            continue
        fi
        
        # If we're in the services section and find a line like "service_name:"
        if [[ "$in_services" == "true" && "$line" =~ ^([a-zA-Z0-9_-]+): ]]; then
            services+=("${BASH_REMATCH[1]}")
        fi
        
        # If we hit "networks:" or another top-level section, we're done
        if [[ "$in_services" == "true" && "$line" =~ ^[a-zA-Z0-9_-]+: && ! "$line" =~ ^([a-zA-Z0-9_-]+): ]]; then
            break
        fi
    done < "$compose_file"
    
    # If no services section found, assume old format where services are top-level
    if [[ ${#services[@]} -eq 0 ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([a-zA-Z0-9_-]+): ]]; then
                # Skip certain known top-level sections
                if [[ "${BASH_REMATCH[1]}" != "version" && 
                      "${BASH_REMATCH[1]}" != "networks" && 
                      "${BASH_REMATCH[1]}" != "volumes" ]]; then
                    services+=("${BASH_REMATCH[1]}")
                fi
            fi
        done < "$compose_file"
    fi
    
    # Output the service names
    for service in "${services[@]}"; do
        echo "$service"
    done
}

# Function to determine if a service should be a StatefulSet
is_stateful_service() {
    local service_name="$1"
    local compose_section="$2"
    
    # Database services should be StatefulSets
    if [[ "$service_name" == "redis" || "$service_name" == "postgres" ]]; then
        return 0
    fi
    
    # Check for volumes that suggest statefulness
    if echo "$compose_section" | grep -q "volumes:"; then
        local volume_mounts=$(echo "$compose_section" | grep -A 50 "volumes:" | grep -B 50 -m 1 "^[a-z]" | grep -v "volumes:" | grep -v "^[a-z]" | sed 's/- //')
        
        # Check if any volume mount looks like persistent storage
        echo "$volume_mounts" | while read -r mount; do
            # Check if it's a named volume or has a data/db path
            if [[ "$mount" =~ :/data || "$mount" =~ :/db || "$mount" =~ :/var/lib ]]; then
                return 0
            fi
        done
    fi
    
    return 1
}

# ----------------------------------------------------------------------
# DOCKER COMPOSE TO KUBERNETES CONVERSION
# ----------------------------------------------------------------------

# Function to process Docker Compose file and generate Kubernetes manifests
process_docker_compose() {
    local compose_file="$1"
    local output_base_dir="$2"
    local namespace="${3:-$NAMESPACE}"
    
    log_info "Processing Docker Compose file: $compose_file"
    
    # Check if file exists
    if [[ ! -f "$compose_file" ]]; then
        log_error "Docker Compose file not found: $compose_file"
        return 1
    fi
    
    # Get list of services
    local services=$(get_compose_services "$compose_file")
    
    if [[ -z "$services" ]]; then
        log_error "No services found in Docker Compose file"
        return 1
    fi
    
    # Process each service
    echo "$services" | while read -r service_name; do
        log_info "Processing service: $service_name"
        
        # Extract service section
        local service_section=$(extract_compose_section "$compose_file" "$service_name")
        
        if [[ -z "$service_section" ]]; then
            log_error "Failed to extract service section for $service_name"
            continue
        fi
        
        # Generate Service if enabled
        if [[ "$(is_resource_type_enabled 'service')" == "true" ]]; then
            generate_service_from_compose "$service_name" "$service_section" "${output_base_dir}/services" "$namespace"
        fi
        
        # Determine if this should be a Deployment or StatefulSet
        if is_stateful_service "$service_name" "$service_section"; then
            if [[ "$(is_resource_type_enabled 'statefulset')" == "true" ]]; then
                generate_statefulset_for_db "$service_name" "$service_section" "${output_base_dir}/statefulsets" "$namespace"
            fi
        else
            if [[ "$(is_resource_type_enabled 'deployment')" == "true" ]]; then
                generate_deployment_from_compose "$service_name" "$service_section" "${output_base_dir}/deployments" "$namespace"
            fi
        fi
    done
    
    log_info "Completed processing Docker Compose file"
    return 0
}

# ----------------------------------------------------------------------
# PROCESSING FUNCTIONS
# ----------------------------------------------------------------------

# Function to process a single file based on its content and name
process_file() {
    local service_name="$1"
    local file="$2"
    local output_base_dir="$3"
    local namespace="$4"
    local subdir_path="$5"
    
    local filename=$(basename "$file")
    
    # ConfigMaps (default for most files)
    if [[ "$(is_resource_type_enabled 'configmap')" == "true" ]] && 
       [[ ! "$filename" =~ secret\.ya?ml$ ]] && 
       [[ ! "$filename" =~ service\.ya?ml$ ]] && 
       [[ ! "$filename" =~ ingress\.ya?ml$ ]]; then
        local cm_output_dir="${output_base_dir}/configmaps"
        generate_configmap_from_yaml "$service_name" "$file" "$cm_output_dir" "$namespace" "$subdir_path"
    fi
    
    # Secrets
    if [[ "$(is_resource_type_enabled 'secret')" == "true" ]] && 
       [[ "$filename" =~ secret\.ya?ml$ ]]; then
        local secret_output_dir="${output_base_dir}/secrets"
        generate_secret_from_yaml "$service_name" "$file" "$secret_output_dir" "$namespace" "$subdir_path"
    fi
    
    # Services
    if [[ "$(is_resource_type_enabled 'service')" == "true" ]] && 
       ([[ "$filename" =~ service\.ya?ml$ ]] || grep -q "port:" "$file"); then
        local svc_output_dir="${output_base_dir}/services"
        generate_service_from_yaml "$service_name" "$file" "$svc_output_dir" "$namespace" "$subdir_path"
    fi
    
    # Ingress
    if [[ "$(is_resource_type_enabled 'ingress')" == "true" ]] && 
       ([[ "$filename" =~ ingress\.ya?ml$ ]] || grep -q "host:" "$file" || grep -q "path:" "$file"); then
        local ing_output_dir="${output_base_dir}/ingress"
        generate_ingress_from_yaml "$service_name" "$file" "$ing_output_dir" "$namespace" "$subdir_path"
    fi
}

# Function to process FKS subdirectories
process_fks_subdirectories() {
    local fks_dir="$1"
    local output_base_dir="$2"
    local namespace="${3:-$NAMESPACE}"
    
    log_info "Processing FKS subdirectories from $fks_dir"
    
    # Check if directory exists
    if [[ ! -d "$fks_dir" ]]; then
        log_error "FKS directory not found: $fks_dir"
        return 1
    fi
    
    # First process files in the root directory
    find "$fks_dir" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
        # Process based on resource type and file content
        process_file "fks" "$file" "$output_base_dir" "$namespace" ""
    done
    
    # Process each subdirectory
    local subdirs=("app" "components" "data" "environments" "infrastructure" "models" "network")
    
    for subdir in "${subdirs[@]}"; do
        local subdir_path="${fks_dir}/${subdir}"
        
        if [[ -d "$subdir_path" ]]; then
            log_info "Processing subdirectory: $subdir"
            
            # Process files in the subdirectory
            find "$subdir_path" -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
                process_file "fks" "$file" "$output_base_dir" "$namespace" "$subdir"
            done
            
            # Process nested subdirectories
            find "$subdir_path" -mindepth 1 -maxdepth 1 -type d | while read -r nested_dir; do
                local nested_subdir=$(basename "$nested_dir")
                local nested_path="${subdir}/${nested_subdir}"
                
                log_info "Processing nested subdirectory: $nested_path"
                
                find "$nested_dir" -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
                    process_file "fks" "$file" "$output_base_dir" "$namespace" "$nested_path"
                done
            done
        fi
    done
    
    log_info "Completed processing FKS subdirectories"
    return 0
}

# ----------------------------------------------------------------------
# MAIN FUNCTION
# ----------------------------------------------------------------------

# Main function
main() {
    log_info "Starting Kubernetes resource generation..."
    log_info "Generating resource types: $RESOURCE_TYPES"
    
    # Define base config directories
    local base_config_dir="${BASE_DIR:-/home/$USER/fks}/config"
    
    # Check for source files - add this call here
    check_source_files || {
        log_error "Cannot proceed with resource generation due to missing source files."
        return 1
    }
    
    # Clear existing resource directories
    clear_resource_dirs "$MANIFESTS_DIR"
    
    # Process Docker Compose file if provided
    if [[ -n "$COMPOSE_FILE" ]]; then
        process_docker_compose "$COMPOSE_FILE" "$MANIFESTS_DIR" "$NAMESPACE"
    fi
    
    # Process FKS configurations with subdirectories
    local fks_config_dir="${base_config_dir}/fks"
    if [[ -d "$fks_config_dir" ]]; then
        log_info "Processing FKS configuration directory: $fks_config_dir"
        process_fks_subdirectories "$fks_config_dir" "$MANIFESTS_DIR" "$NAMESPACE"
    else
        log_warn "FKS config directory not found: $fks_config_dir"
    fi
    
    # Display summary of what was generated
    display_processing_summary "$MANIFESTS_DIR"
    
    log_info "Kubernetes resource generation complete. Resources saved to: $MANIFESTS_DIR"
}

# ----------------------------------------------------------------------
# COMMAND LINE PARSING
# ----------------------------------------------------------------------

# Parse command line arguments
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -r, --resource TYPES        Resource types to generate (comma-separated)"
    echo "                              Available types: configmap,secret,service,ingress,deployment,statefulset,pvc,all"
    echo "  -n, --namespace NAMESPACE   Kubernetes namespace"
    echo "  -o, --output DIR            Output base directory for resources"
    echo "  -c, --compose FILE          Docker Compose file to convert to Kubernetes resources"
    echo "  -d, --debug                 Enable debug mode"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --resource configmap"
    echo "  $0 --resource all --namespace prod"
    echo "  $0 --compose docker-compose.yml --resource deployment,service"
    exit 0
}

# Default values
OUTPUT_DIR="$MANIFESTS_DIR"
NAMESPACE_ARG="$NAMESPACE"
RESOURCE_TYPES_ARG="$RESOURCE_TYPES"
COMPOSE_FILE_ARG=""
DEBUG_MODE_ARG="false"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--resource)
            RESOURCE_TYPES_ARG="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE_ARG="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -c|--compose)
            COMPOSE_FILE_ARG="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG_MODE_ARG="true"
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            log_warn "Unknown option: $1"
            shift
            ;;
    esac
done

# Set updated values
if [[ -n "$RESOURCE_TYPES_ARG" ]]; then
    RESOURCE_TYPES="$RESOURCE_TYPES_ARG"
fi

if [[ -n "$NAMESPACE_ARG" ]]; then
    NAMESPACE="$NAMESPACE_ARG"
fi

if [[ -n "$OUTPUT_DIR" ]]; then
    MANIFESTS_DIR="$OUTPUT_DIR"
fi

if [[ -n "$COMPOSE_FILE_ARG" ]]; then
    COMPOSE_FILE="$COMPOSE_FILE_ARG"
fi

DEBUG_MODE="$DEBUG_MODE_ARG"

# Run the main function
main

log_info "Script completed successfully"