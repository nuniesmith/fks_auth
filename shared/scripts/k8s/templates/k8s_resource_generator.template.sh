#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Resource Generator Template
# Description: Template for generating Kubernetes resources from 
#              configuration files and Docker Compose services
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/k8s_config.sh"
source "${SCRIPT_DIR}/k8s_utils.sh"

# Default resource types to generate
RESOURCE_TYPES=${RESOURCE_TYPES:-"configmap,deployment,service"}
DEBUG_MODE=${DEBUG_MODE:-"false"}
COMPOSE_FILE=${COMPOSE_FILE:-""}
DRY_RUN=${DRY_RUN:-"false"}

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

# Prepare output directories for enabled resource types
prepare_resource_dirs() {
    local output_base_dir="${1:-$MANIFESTS_DIR}"
    local clean=${2:-"true"}
    
    # Define all supported resource types
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
            
            if [[ -d "$resource_dir" && "$clean" == "true" ]]; then
                log_info "Clearing existing $dir directory: $resource_dir"
                rm -rf "${resource_dir:?}/"*
            elif [[ ! -d "$resource_dir" ]]; then
                log_info "Creating $dir directory: $resource_dir"
                mkdir -p "$resource_dir"
            fi
        fi
    done
    
    log_info "Resource directories prepared"
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
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create ConfigMap at $output_file"
        return 0
    fi
    
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

# Function to generate ConfigMap from plain text file
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
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create ConfigMap at $output_file"
        return 0
    fi
    
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
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create Secret at $output_file"
        return 0
    fi
    
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
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create Service at $output_file"
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
    local ingress_name="${service_name}"
    
    # If subdir_path exists, create corresponding subdirectory in output
    if [[ -n "$subdir_path" ]]; then
        mkdir -p "${output_dir}/${subdir_path}"
        output_dir="${output_dir}/${subdir_path}"
        # Add subdir to ingress name for uniqueness
        local subdir_name=$(echo "$subdir_path" | tr '/' '-')
        ingress_name="${service_name}-${subdir_name}"
    else
        mkdir -p "$output_dir"
    fi
    
    # Generate Ingress manifest
    local output_file="${output_dir}/${ingress_name}.yaml"
    
    log_info "Generating Ingress from $yaml_file for $service_name..."
    
    # Check if the YAML has ingress configuration
    if ! grep -q "ingress:" "$yaml_file" && ! grep -q "host:" "$yaml_file" && ! grep -q "path:" "$yaml_file"; then
        log_warn "No ingress configuration found in $yaml_file. Skipping."
        return 0
    fi
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create Ingress at $output_file"
        return 0
    fi
    
    # Extract ingress information
    local host=""
    local path="/"
    local service_port="80"
    local tls_secret=""
    
    # Read ingress information
    if grep -q "host:" "$yaml_file"; then
        host=$(grep "host:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    if grep -q "path:" "$yaml_file"; then
        path=$(grep "path:" "$yaml_file" | head -1 | awk '{$1=""; print $0}' | xargs)
    fi
    
    if grep -q "servicePort:" "$yaml_file"; then
        service_port=$(grep "servicePort:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    if grep -q "port:" "$yaml_file" && [[ -z "$service_port" ]]; then
        service_port=$(grep "port:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    if grep -q "tlsSecret:" "$yaml_file"; then
        tls_secret=$(grep "tlsSecret:" "$yaml_file" | head -1 | awk '{print $2}')
    fi
    
    # Create Ingress manifest
    cat <<EOF > "$output_file"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: $ingress_name
  namespace: $namespace
  labels:
    app: $service_name
    part-of: fks
  annotations:
    kubernetes.io/ingress.class: nginx
EOF
    
    # Add spec section
    cat <<EOF >> "$output_file"
spec:
EOF
    
    # Add TLS section if a secret is specified
    if [[ -n "$tls_secret" && -n "$host" ]]; then
        cat <<EOF >> "$output_file"
  tls:
  - hosts:
    - $host
    secretName: $tls_secret
EOF
    fi
    
    # Add rules section
    cat <<EOF >> "$output_file"
  rules:
EOF
    
    if [[ -n "$host" ]]; then
        cat <<EOF >> "$output_file"
  - host: $host
    http:
      paths:
      - path: $path
        pathType: Prefix
        backend:
          service:
            name: $service_name
            port:
              number: $service_port
EOF
    else
        # Default rule with no host
        cat <<EOF >> "$output_file"
  - http:
      paths:
      - path: $path
        pathType: Prefix
        backend:
          service:
            name: $service_name
            port:
              number: $service_port
EOF
    fi
    
    log_info "Generated Ingress at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# DEPLOYMENT GENERATORS
# ----------------------------------------------------------------------

# Function to generate a basic Deployment manifest
generate_basic_deployment() {
    local service_name="$1"
    local image_name="$2"
    local output_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    local container_port="${5:-80}"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Generate Deployment manifest
    local output_file="${output_dir}/${service_name}.yaml"
    
    log_info "Generating basic Deployment for $service_name..."
    
    # Skip actual file creation if in dry run mode
    if [ "$DRY_RUN" == "true" ]; then
        log_info "DRY RUN: Would create Deployment at $output_file"
        return 0
    fi
    
    # Create Deployment manifest
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
        image: $image_name
        ports:
        - containerPort: $container_port
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
        envFrom:
        - configMapRef:
            name: ${service_name}-env
            optional: true
        - secretRef:
            name: ${service_name}-secrets
            optional: true
EOF
    
    log_info "Generated Deployment at $output_file"
    return 0
}

# ----------------------------------------------------------------------
# DOCKER COMPOSE INTEGRATION
# ----------------------------------------------------------------------

# Function to extract and convert Docker Compose services (simplified template version)
# This is a placeholder for future implementation
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
    
    # Placeholder implementation - extract service names
    log_info "Extracting services from Docker Compose file..."
    
    # Get service names (basic implementation - only works with simple compose files)
    local services=$(grep -E "^[a-zA-Z0-9_-]+:" "$compose_file" | grep -v "version:" | grep -v "services:" | sed 's/:.*$//')
    
    if [[ -z "$services" ]]; then
        log_warn "No services found in Docker Compose file or format not recognized"
        return 1
    fi
    
    log_info "Found services: $services"
    log_info "TO-DO: Implement full Docker Compose conversion"
    
    # This is where you would implement the Docker Compose conversion
    # For each service, generate appropriate Kubernetes resources
    
    return 0
}

# ----------------------------------------------------------------------
# FILE PROCESSING FUNCTIONS
# ----------------------------------------------------------------------

# Process a single file based on its content and name
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

# Process configuration directory by traversing its structure
process_config_directory() {
    local service_name="$1"
    local config_dir="$2"
    local output_base_dir="$3"
    local namespace="${4:-$NAMESPACE}"
    
    log_info "Processing config directory for $service_name: $config_dir"
    
    # Check if directory exists
    if [[ ! -d "$config_dir" ]]; then
        log_error "Config directory not found: $config_dir"
        return 1
    fi
    
    # Process files in the root directory
    find "$config_dir" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
        process_file "$service_name" "$file" "$output_base_dir" "$namespace" ""
    done
    
    # Process subdirectories (one level deep)
    find "$config_dir" -maxdepth 1 -type d -not -path "$config_dir" | while read -r subdir; do
        local subdir_name=$(basename "$subdir")
        
        log_info "Processing subdirectory: $subdir_name"
        
        # Process files in the subdirectory
        find "$subdir" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
            process_file "$service_name" "$file" "$output_base_dir" "$namespace" "$subdir_name"
        done
    done
    
    # Generate a basic deployment if requested and no existing deployment found
    if [[ "$(is_resource_type_enabled 'deployment')" == "true" ]]; then
        # Check if a deployment already exists for this service
        local deployment_dir="${output_base_dir}/deployments"
        local existing_deployment=$(find "$deployment_dir" -name "${service_name}*.yaml" 2>/dev/null)
        
        if [[ -z "$existing_deployment" ]]; then
            log_info "No existing deployment found for $service_name, generating a basic one"
            generate_basic_deployment "$service_name" "${service_name}:latest" "$deployment_dir" "$namespace"
        fi
    fi
    
    log_info "Completed processing configs for $service_name"
    return 0
}

# ----------------------------------------------------------------------
# VALIDATION FUNCTIONS
# ----------------------------------------------------------------------

# Function to validate generated YAML files against Kubernetes schemas
validate_yaml_files() {
    local output_base_dir="${1:-$MANIFESTS_DIR}"
    
    log_info "Validating generated YAML files..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found, skipping validation."
        return 1
    fi
    
    # Find all YAML files recursively
    local yaml_files=$(find "$output_base_dir" -type f \( -name "*.yaml" -o -name "*.yml" \))
    local error_count=0
    local success_count=0
    
    if [[ -z "$yaml_files" ]]; then
        log_warn "No YAML files found for validation."
        return 0
    fi
    
    # Validate each file
    echo "$yaml_files" | while read -r file; do
        log_info "Validating: $file"
        
        if kubectl apply --dry-run=client -f "$file" &> /dev/null; then
            log_info "✓ $file is valid"
            ((success_count++))
        else
            log_error "✗ $file is invalid"
            kubectl apply --dry-run=client -f "$file" || true
            ((error_count++))
        fi
    done
    
    log_info "Validation complete: $success_count files valid, $error_count files invalid"
    
    if [[ "$error_count" -gt 0 ]]; then
        return 1
    fi
    
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
    
    # Prepare resource directories
    prepare_resource_dirs "$MANIFESTS_DIR"
    
    # Process Docker Compose file if provided
    if [[ -n "$COMPOSE_FILE" ]]; then
        log_info "Processing Docker Compose file: $COMPOSE_FILE"
        process_docker_compose "$COMPOSE_FILE" "$MANIFESTS_DIR" "$NAMESPACE"
    else
        # Process service directories
        local services=("redis" "postgres" "fks" "nginx" "datadog" "prometheus" "grafana")
        
        for service in "${services[@]}"; do
            local service_config_dir="${base_config_dir}/${service}"
            
            if [[ -d "$service_config_dir" ]]; then
                log_info "Processing service: $service"
                process_config_directory "$service" "$service_config_dir" "$MANIFESTS_DIR" "$NAMESPACE"
            else
                log_info "Service directory not found for $service, skipping"
            fi
        done
    fi
    
    # Validate generated files if not in dry run mode
    if [[ "$DRY_RUN" != "true" ]]; then
        validate_yaml_files "$MANIFESTS_DIR"
    fi
    
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
    echo "  -y, --dry-run               Dry run (don't create files)"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --resource configmap,deployment"
    echo "  $0 --resource all --namespace prod"
    echo "  $0 --compose docker-compose.yml"
    echo "  $0 --dry-run --resource all"
    exit 0
}

# Default values
OUTPUT_DIR="$MANIFESTS_DIR"
NAMESPACE_ARG="$NAMESPACE"
RESOURCE_TYPES_ARG="$RESOURCE_TYPES"
COMPOSE_FILE_ARG=""
DEBUG_MODE_ARG="false"
DRY_RUN_ARG="false"

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
        -y|--dry-run)
            DRY_RUN_ARG="true"
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
DRY_RUN="$DRY_RUN_ARG"

# Run the main function
main

log_info "Script completed successfully"