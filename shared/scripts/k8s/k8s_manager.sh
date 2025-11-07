#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Manager for Manjaro
# Description: A comprehensive script to manage Kubernetes resources on Manjaro Linux,
#              including setup, resource generation, and application management.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and utilities
source "${SCRIPT_DIR}/k8s_config.sh"
source "${SCRIPT_DIR}/k8s_utils.sh"

# ----------------------------------------------------------------------
# KUBERNETES FUNCTIONS
# ----------------------------------------------------------------------
check_k8s_connection() {
    # Attempt to connect to the Kubernetes API server
    if ! kubectl cluster-info &>/dev/null; then
        return 1
    fi
    return 0
}

check_or_create_namespace() {
    log_info "Verifying namespace: $NAMESPACE"
    
    if ! check_command "kubectl"; then
        log_error "kubectl is not installed."
        return 1
    fi
    
    # First check if we can connect to the cluster
    if ! check_k8s_connection; then
        log_warn "Cannot connect to Kubernetes cluster. Is it running?"
        log_warn "Start Minikube or configure kubectl before managing namespaces."
        return 1
    fi
    
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_warn "Namespace $NAMESPACE does not exist. Creating it..."
        if ! kubectl create namespace "$NAMESPACE"; then
            log_error "Failed to create namespace $NAMESPACE."
            return 1
        else
            log_info "Namespace $NAMESPACE created successfully."
        fi
    else
        log_info "Namespace $NAMESPACE already exists."
    fi
    
    # Set this as the default namespace in kubectl config
    log_info "Setting default namespace to $NAMESPACE..."
    if kubectl config set-context --current --namespace="$NAMESPACE"; then
        log_info "Default namespace set to $NAMESPACE."
    else
        log_warn "Failed to set default namespace to $NAMESPACE."
    fi
    
    return 0
}

apply_yaml_files() {
    log_info "Applying all YAML files in $K8S_BASE_PATH"
    
    if ! check_command "kubectl"; then
        log_error "kubectl is not installed."
        return 1
    fi
    
    if ! check_k8s_connection; then
        log_error "Cannot connect to Kubernetes cluster. Is it running?"
        return 1
    fi
    
    if [[ ! -d "$K8S_BASE_PATH" ]]; then
        log_error "The specified Kubernetes base directory '$K8S_BASE_PATH' does not exist."
        return 1
    fi
    
    find "$K8S_BASE_PATH" -type f -name '*.yaml' | while read -r yaml_file; do
        log_info "Applying file: $yaml_file"
        if ! kubectl apply -f "$yaml_file" -n "$NAMESPACE"; then
            log_error "Failed to apply $yaml_file. Skipping."
        else
            log_info "Successfully applied $yaml_file"
        fi
    done
}

restart_k8s_deployments() {
    log_info "Restarting all deployments in namespace: $NAMESPACE"
    
    if ! check_command "kubectl"; then
        log_error "kubectl is not installed."
        return 1
    fi
    
    if ! check_k8s_connection; then
        log_error "Cannot connect to Kubernetes cluster. Is it running?"
        return 1
    fi
    
    local deployments
    deployments=$(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    if [[ -z "$deployments" ]]; then
        log_warn "No deployments found in namespace $NAMESPACE."
        return 0
    fi
    
    for deployment in $deployments; do
        log_info "Restarting deployment: $deployment"
        if ! kubectl rollout restart deployment "$deployment" -n "$NAMESPACE"; then
            log_error "Failed to restart deployment: $deployment. Skipping."
        else
            log_info "Successfully restarted deployment: $deployment"
        fi
    done
}

# ----------------------------------------------------------------------
# CLUSTER SETUP AND REMOVAL FUNCTIONS
# ----------------------------------------------------------------------
run_master_script() {
    log_info "Running master setup script: $MASTER_SCRIPT"
    
    if ! check_script "$MASTER_SCRIPT" "Master setup"; then
        log_warn "Master script not found or not executable."
        echo -e "${YELLOW}Would you like to create this script now? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            create_script "Master setup" "$MASTER_SCRIPT" "${SCRIPT_DIR}/templates/install_k8s_master.template"
        else
            return 1
        fi
    fi
    
    bash "$MASTER_SCRIPT"
    check_success "Running master script"
}

run_worker_script() {
    log_info "Running worker setup script: $WORKER_SCRIPT"
    
    if ! check_script "$WORKER_SCRIPT" "Worker setup"; then
        log_warn "Worker script not found or not executable."
        echo -e "${YELLOW}Would you like to create this script now? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            create_script "Worker setup" "$WORKER_SCRIPT" "${SCRIPT_DIR}/templates/install_k8s_worker.template"
        else
            return 1
        fi
    fi
    
    bash "$WORKER_SCRIPT"
    check_success "Running worker script"
}

run_remove_script() {
    log_info "Running removal script: $REMOVE_SCRIPT"
    
    if ! check_script "$REMOVE_SCRIPT" "Removal"; then
        log_warn "Removal script not found or not executable."
        echo -e "${YELLOW}Would you like to create this script now? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            create_script "Removal" "$REMOVE_SCRIPT" "${SCRIPT_DIR}/templates/remove_k8s.template"
        else
            return 1
        fi
    fi
    
    bash "$REMOVE_SCRIPT"
    check_success "Running removal script"
}

# ----------------------------------------------------------------------
# RESOURCE MANAGEMENT FUNCTIONS
# ----------------------------------------------------------------------

# Run the enhanced Resource Generator script with improved capabilities
run_resource_generator() {
    local RESOURCE_GENERATOR="${SCRIPT_DIR}/k8s_resource_generator.sh"
    log_info "Running Kubernetes Resource Generator: $RESOURCE_GENERATOR"
    
    # Check if the resource generator exists
    if ! check_script "$RESOURCE_GENERATOR" "Resource generator"; then
        log_warn "Resource generator script not found or not executable."
        echo -e "${YELLOW}Would you like to create this script now? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            # Create a temporary template for the resource generator
            log_info "Please wait while we set up the resource generator..."
            
            echo -e "${YELLOW}This will create a comprehensive resource generator that can create multiple Kubernetes resource types.${NC}"
            echo -e "${YELLOW}Do you want to proceed? (y/n)${NC}"
            read -r confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log_info "Operation cancelled."
                return 1
            fi
            
            # Create the resource generator from the provided template
            log_info "Creating resource generator script. This may take a moment..."
            cp "${SCRIPT_DIR}/templates/k8s_resource_generator.template" "$RESOURCE_GENERATOR" 2>/dev/null || {
                log_warn "Template not found, creating basic script structure."
                # Create a simplified version with core functionality
                cat > "$RESOURCE_GENERATOR" << 'EOF'
#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Resource Generator
# Description: Generates Kubernetes resource manifests from configuration files
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/k8s_config.sh"
source "${SCRIPT_DIR}/k8s_utils.sh"

# Default resource types to generate
RESOURCE_TYPES=${RESOURCE_TYPES:-"configmap,deployment,service"}
DEBUG_MODE=${DEBUG_MODE:-"false"}
COMPOSE_FILE=${COMPOSE_FILE:-""}

# Basic error handling
handle_error() {
    local exit_code=$?
    local line_no=$1
    
    if [ $exit_code -ne 0 ]; then
        log_error "Error on line $line_no: Command exited with status $exit_code"
    fi
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Main function stub - replace with your implementation
main() {
    log_info "Starting Kubernetes resource generation..."
    log_info "Resource types to generate: $RESOURCE_TYPES"
    
    log_info "This is a placeholder for the resource generator."
    log_info "Please replace this script with the full implementation."
    log_info "See the documentation for details on how to use the resource generator."
}

# Parse command line arguments
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -r, --resource TYPES        Resource types to generate (comma-separated)"
    echo "  -n, --namespace NAMESPACE   Kubernetes namespace"
    echo "  -c, --compose FILE          Docker Compose file to convert"
    echo "  -d, --debug                 Enable debug mode"
    echo "  -h, --help                  Show this help message"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--resource)
            RESOURCE_TYPES="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -c|--compose)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG_MODE="true"
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

# Run the main function
main
EOF
            }
            
            chmod +x "$RESOURCE_GENERATOR"
            log_info "Created resource generator script. Please ensure it has the proper implementation."
            
            # Ask if user wants to edit it now
            echo -e "${YELLOW}Would you like to edit the script now? (y/n)${NC}"
            read -r edit_choice
            if [[ "$edit_choice" =~ ^[Yy]$ ]]; then
                ${EDITOR:-nano} "$RESOURCE_GENERATOR"
            else
                log_warn "Please ensure $RESOURCE_GENERATOR has the proper implementation before using it."
                return 1
            fi
        else
            return 1
        fi
    fi
    
    # Show available resource type options to the user with clearer descriptions
    echo -e "${BLUE}=== Available Kubernetes Resource Types ===${NC}"
    echo -e "${GREEN}configmap${NC} - Generate ConfigMap resources for configuration data"
    echo -e "${GREEN}secret${NC} - Generate Secret resources for sensitive data"
    echo -e "${GREEN}service${NC} - Generate Service resources for exposing applications"
    echo -e "${GREEN}ingress${NC} - Generate Ingress resources for external HTTP/HTTPS access"
    echo -e "${GREEN}deployment${NC} - Generate Deployment resources for stateless applications"
    echo -e "${GREEN}statefulset${NC} - Generate StatefulSet resources for stateful applications"
    echo -e "${GREEN}pvc${NC} - Generate PersistentVolumeClaim resources for storage"
    echo -e "${GREEN}networkpolicy${NC} - Generate NetworkPolicy resources for network security"
    echo -e "${GREEN}role${NC} - Generate Role and RoleBinding resources for RBAC"
    echo -e "${GREEN}serviceaccount${NC} - Generate ServiceAccount resources for pod identity"
    echo -e "${GREEN}all${NC} - Generate all resource types"
    echo
    
    # Prompt for resource types with a more comprehensive default
    echo -e "${BLUE}Resource types to generate (comma-separated or 'all'): [configmap,secret,service,deployment]${NC} "
    read -r resource_types
    
    # Default to a more comprehensive set if empty
    resource_types=${resource_types:-"configmap,secret,service,deployment"}
    
    # Check if Docker Compose processing is needed
    local compose_file=""
    echo -e "${BLUE}Do you want to generate resources from a Docker Compose file? (y/n)${NC} "
    read -r use_compose
    if [[ "$use_compose" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Enter the path to the Docker Compose file:${NC} "
        read -r compose_file
        
        if [[ ! -f "$compose_file" ]]; then
            log_error "Docker Compose file not found: $compose_file"
            echo -e "${YELLOW}Would you like to try a different path? (y/n)${NC}"
            read -r retry_compose
            if [[ "$retry_compose" =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}Enter the path to the Docker Compose file:${NC} "
                read -r compose_file
                
                if [[ ! -f "$compose_file" ]]; then
                    log_error "Docker Compose file not found again. Continuing without Docker Compose processing."
                    compose_file=""
                fi
            else
                compose_file=""
            fi
        fi
    fi
    
    # Additional arguments to pass
    local additional_args=""
    
    # Add compose file if provided
    if [[ -n "$compose_file" ]]; then
        additional_args="$additional_args --compose \"$compose_file\""
    fi
    
    # Ask for debug mode
    echo -e "${BLUE}Enable debug mode? (y/n)${NC} "
    read -r debug_mode
    if [[ "$debug_mode" =~ ^[Yy]$ ]]; then
        additional_args="$additional_args --debug"
    fi
    
    # Run the script with provided resource types and pass any additional arguments
    log_info "Running resource generator with types: $resource_types"
    
    # Display a summary before proceeding
    echo -e "${YELLOW}=== Resource Generation Summary ===${NC}"
    echo -e "${YELLOW}Resource Types:${NC} $resource_types"
    echo -e "${YELLOW}Namespace:${NC} $NAMESPACE"
    if [[ -n "$compose_file" ]]; then
        echo -e "${YELLOW}Docker Compose File:${NC} $compose_file"
    fi
    echo -e "${YELLOW}Debug Mode:${NC} $debug_mode"
    echo
    echo -e "${BLUE}Proceed with generation? (y/n)${NC} "
    read -r proceed
    
    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Resource generation cancelled."
        return 0
    fi
    
    # Use eval to properly handle the additional arguments
    if ! eval "bash \"$RESOURCE_GENERATOR\" --resource \"$resource_types\" --namespace \"$NAMESPACE\" $additional_args"; then
        log_error "Resource generator encountered errors. Please check the logs."
        return 1
    fi
    
    log_info "Resource generation completed successfully."
    check_success "Running resource generator" 
}

# Run the enhanced apply resources script
run_apply_resources_script() {
    log_info "Running enhanced resource application workflow for namespace: $NAMESPACE"
    log_info "This will: 1) Delete namespace, 2) Create namespace, 3) Generate resources, 4) Apply resources"
    
    # Confirm before proceeding since this is destructive
    echo -e "${YELLOW}WARNING: This will DELETE the namespace '$NAMESPACE' and all resources in it.${NC}"
    echo -e "${YELLOW}Do you want to continue? (y/n)${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled."
        return 0
    fi
    
    if ! check_script "$APPLY_RESOURCES_SCRIPT" "Resource application"; then
        log_warn "Apply resources script not found or not executable."
        echo -e "${YELLOW}Would you like to create this script now? (y/n)${NC}"
        read -r create_choice
        if [[ "$create_choice" =~ ^[Yy]$ ]]; then
            create_script "Apply resources" "$APPLY_RESOURCES_SCRIPT" "${SCRIPT_DIR}/templates/apply_resources.template"
        else
            return 1
        fi
    fi
    
    # Check if the resource generator exists
    local RESOURCE_GENERATOR="${SCRIPT_DIR}/k8s_resource_generator.sh"
    if ! check_script "$RESOURCE_GENERATOR" "Resource generator"; then
        log_warn "The resource generator script ($RESOURCE_GENERATOR) is required but not found."
        echo -e "${YELLOW}Would you like to set up the resource generator script first? (y/n)${NC}"
        read -r setup_choice
        if [[ "$setup_choice" =~ ^[Yy]$ ]]; then
            run_resource_generator
        else
            log_warn "Proceeding without resource generator script. Resources may not be generated properly."
        fi
    fi
    
    # Ask which resource types to generate with clearer descriptions
    echo -e "${BLUE}=== Available Kubernetes Resource Types ===${NC}"
    echo -e "${GREEN}configmap${NC} - Generate ConfigMap resources for configuration data"
    echo -e "${GREEN}secret${NC} - Generate Secret resources for sensitive data"
    echo -e "${GREEN}service${NC} - Generate Service resources for exposing applications"
    echo -e "${GREEN}ingress${NC} - Generate Ingress resources for external HTTP/HTTPS access"
    echo -e "${GREEN}deployment${NC} - Generate Deployment resources for stateless applications"
    echo -e "${GREEN}statefulset${NC} - Generate StatefulSet resources for stateful applications"
    echo -e "${GREEN}pvc${NC} - Generate PersistentVolumeClaim resources for storage"
    echo -e "${GREEN}networkpolicy${NC} - Generate NetworkPolicy resources for network security"
    echo -e "${GREEN}role${NC} - Generate Role and RoleBinding resources for RBAC"
    echo -e "${GREEN}serviceaccount${NC} - Generate ServiceAccount resources for pod identity"
    echo -e "${GREEN}all${NC} - Generate all resource types"
    echo
    
    # Prompt for resource types with a more comprehensive default
    echo -e "${BLUE}Resource types to generate before applying (comma-separated or 'all'): [configmap,secret,service,deployment]${NC} "
    read -r resource_types
    
    # Default to a more comprehensive set if empty
    resource_types=${resource_types:-"configmap,secret,service,deployment"}
    
    # Set the resource types for the apply script to use
    export RESOURCE_TYPES="$resource_types"
    
    # Ask about applying secrets
    echo -e "${BLUE}Apply secrets? (y/n)${NC} "
    read -r apply_secrets
    if [[ "$apply_secrets" =~ ^[Yy]$ ]]; then
        export APPLY_SECRETS="true"
    else
        export APPLY_SECRETS="false"
    fi
    
    # Ask about validation
    echo -e "${BLUE}Validate resources? (y/n)${NC} "
    read -r validate
    if [[ "$validate" =~ ^[Yy]$ ]]; then
        export VALIDATE="true"
    else
        export VALIDATE="false"
    fi
    
    # Display a summary before proceeding
    echo -e "${YELLOW}=== Resource Application Summary ===${NC}"
    echo -e "${YELLOW}Resource Types:${NC} $resource_types"
    echo -e "${YELLOW}Namespace:${NC} $NAMESPACE"
    echo -e "${YELLOW}Apply Secrets:${NC} $APPLY_SECRETS"
    echo -e "${YELLOW}Validate Resources:${NC} $VALIDATE"
    echo
    echo -e "${BLUE}Proceed with resource application? (y/n)${NC} "
    read -r proceed
    
    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Resource application cancelled."
        return 0
    fi
    
    # Run the apply resources script
    log_info "Starting resource application process with resource types: $resource_types"
    bash "$APPLY_RESOURCES_SCRIPT" --namespace "$NAMESPACE"
    
    local result=$?
    if [ $result -eq 0 ]; then
        log_info "Resource application completed successfully."
    else
        log_error "Resource application encountered errors. Please check the logs."
    fi
    
    check_success "Running apply resources script" $result
}

# ----------------------------------------------------------------------
# DOCKER COMPOSE CONVERSION FUNCTIONS
# ----------------------------------------------------------------------
convert_docker_compose() {
    log_info "Converting Docker Compose to Kubernetes resources"
    
    local RESOURCE_GENERATOR="${SCRIPT_DIR}/k8s_resource_generator.sh"
    
    # Check if the resource generator exists
    if ! check_script "$RESOURCE_GENERATOR" "Resource generator"; then
        log_warn "Resource generator script not found or not executable."
        echo -e "${YELLOW}Would you like to set up the resource generator script first? (y/n)${NC}"
        read -r setup_choice
        if [[ "$setup_choice" =~ ^[Yy]$ ]]; then
            run_resource_generator
            return $?
        else
            log_error "Cannot convert Docker Compose without the resource generator script."
            return 1
        fi
    fi
    
    # Ask for the Docker Compose file
    echo -e "${BLUE}Enter the path to the Docker Compose file:${NC} "
    read -r compose_file
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Docker Compose file not found: $compose_file"
        return 1
    fi
    
    # Ask which resource types to generate with clearer descriptions
    echo -e "${BLUE}=== Available Kubernetes Resource Types ===${NC}"
    echo -e "${GREEN}configmap${NC} - Generate ConfigMap resources for configuration data"
    echo -e "${GREEN}secret${NC} - Generate Secret resources for sensitive data"
    echo -e "${GREEN}service${NC} - Generate Service resources for exposing applications"
    echo -e "${GREEN}deployment${NC} - Generate Deployment resources for stateless applications"
    echo -e "${GREEN}statefulset${NC} - Generate StatefulSet resources for stateful applications"
    echo -e "${GREEN}all${NC} - Generate all resource types"
    echo
    
    # Prompt for resource types with a more comprehensive default
    echo -e "${BLUE}Resource types to generate (comma-separated or 'all'): [configmap,secret,service,deployment,statefulset]${NC} "
    read -r resource_types
    
    # Default to all if empty for Docker Compose conversion
    resource_types=${resource_types:-"configmap,secret,service,deployment,statefulset"}
    
    # Display a summary before proceeding
    echo -e "${YELLOW}=== Docker Compose Conversion Summary ===${NC}"
    echo -e "${YELLOW}Docker Compose File:${NC} $compose_file"
    echo -e "${YELLOW}Resource Types:${NC} $resource_types"
    echo -e "${YELLOW}Namespace:${NC} $NAMESPACE"
    echo
    echo -e "${BLUE}Proceed with conversion? (y/n)${NC} "
    read -r proceed
    
    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Docker Compose conversion cancelled."
        return 0
    fi
    
    # Run the script to convert Docker Compose
    log_info "Converting Docker Compose with resource types: $resource_types"
    bash "$RESOURCE_GENERATOR" --resource "$resource_types" --namespace "$NAMESPACE" --compose "$compose_file"
    
    local result=$?
    if [ $result -eq 0 ]; then
        log_info "Docker Compose conversion completed successfully."
        
        # Ask if user wants to view the generated files
        echo -e "${BLUE}Would you like to view the generated files? (y/n)${NC} "
        read -r view_files
        if [[ "$view_files" =~ ^[Yy]$ ]]; then
            find "$MANIFESTS_DIR" -type f -name '*.yaml' -exec ls -la {} \;
            
            echo -e "${BLUE}Would you like to apply these resources to the cluster? (y/n)${NC} "
            read -r apply_files
            if [[ "$apply_files" =~ ^[Yy]$ ]]; then
                apply_yaml_files
            fi
        fi
    else
        log_error "Docker Compose conversion encountered errors. Please check the logs."
    fi
    
    check_success "Converting Docker Compose" $result
}

# ----------------------------------------------------------------------
# SPECIFIC RESOURCE GENERATION FUNCTIONS
# ----------------------------------------------------------------------
generate_specific_resources() {
    local resource_type="$1"
    local RESOURCE_GENERATOR="${SCRIPT_DIR}/k8s_resource_generator.sh"
    
    # Check if the resource generator exists
    if ! check_script "$RESOURCE_GENERATOR" "Resource generator"; then
        log_warn "Resource generator script not found or not executable."
        echo -e "${YELLOW}Would you like to set up the resource generator script first? (y/n)${NC}"
        read -r setup_choice
        if [[ "$setup_choice" =~ ^[Yy]$ ]]; then
            run_resource_generator
            return $?
        else
            log_error "Cannot generate resources without the resource generator script."
            return 1
        fi
    fi
    
    # Display a summary before proceeding
    echo -e "${YELLOW}=== Resource Generation Summary ===${NC}"
    echo -e "${YELLOW}Resource Type:${NC} $resource_type"
    echo -e "${YELLOW}Namespace:${NC} $NAMESPACE"
    echo
    echo -e "${BLUE}Proceed with generation? (y/n)${NC} "
    read -r proceed
    
    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Resource generation cancelled."
        return 0
    fi
    
    # Run the script with the specific resource type
    log_info "Generating $resource_type resources"
    bash "$RESOURCE_GENERATOR" --resource "$resource_type" --namespace "$NAMESPACE"
    
    local result=$?
    if [ $result -eq 0 ]; then
        log_info "$resource_type resource generation completed successfully."
        
        # Ask if user wants to view the generated files
        echo -e "${BLUE}Would you like to view the generated files? (y/n)${NC} "
        read -r view_files
        if [[ "$view_files" =~ ^[Yy]$ ]]; then
            find "$MANIFESTS_DIR" -type d -name "*$resource_type*" -exec ls -la {}/*.yaml \; 2>/dev/null || echo "No $resource_type files found."
        fi
    else
        log_error "$resource_type resource generation encountered errors. Please check the logs."
    fi
    
    check_success "Generating $resource_type resources" $result
}

# ----------------------------------------------------------------------
# ADVANCED RESOURCE MANAGEMENT FUNCTIONS
# ----------------------------------------------------------------------
view_applied_resources() {
    log_info "Viewing applied resources in namespace: $NAMESPACE"
    
    if ! check_command "kubectl"; then
        log_error "kubectl is not installed."
        return 1
    fi
    
    if ! check_k8s_connection; then
        log_error "Cannot connect to Kubernetes cluster. Is it running?"
        return 1
    fi
    
    # Show a menu of resource types to view
    local options=(
        "All Resources"
        "Pods"
        "Deployments"
        "StatefulSets"
        "Services"
        "ConfigMaps"
        "Secrets"
        "Ingress"
        "PersistentVolumeClaims"
        "NetworkPolicies"
        "Roles"
        "RoleBindings"
        "ServiceAccounts"
        "Return to Main Menu"
    )
    
    echo -e "${BLUE}Select resource type to view:${NC}"
    for i in "${!options[@]}"; do
        echo -e "${GREEN}$i${NC}) ${options[$i]}"
    done
    
    read -r choice
    
    case "$choice" in
        0)
            kubectl get all -n "$NAMESPACE"
            ;;
        1)
            kubectl get pods -n "$NAMESPACE"
            ;;
        2)
            kubectl get deployments -n "$NAMESPACE"
            ;;
        3)
            kubectl get statefulsets -n "$NAMESPACE"
            ;;
        4)
            kubectl get services -n "$NAMESPACE"
            ;;
        5)
            kubectl get configmaps -n "$NAMESPACE"
            ;;
        6)
            kubectl get secrets -n "$NAMESPACE"
            ;;
        7)
            kubectl get ingress -n "$NAMESPACE"
            ;;
        8)
            kubectl get pvc -n "$NAMESPACE"
            ;;
        9)
            kubectl get networkpolicies -n "$NAMESPACE"
            ;;
        10)
            kubectl get roles -n "$NAMESPACE"
            ;;
        11)
            kubectl get rolebindings -n "$NAMESPACE"
            ;;
        12)
            kubectl get serviceaccounts -n "$NAMESPACE"
            ;;
        13)
            return 0
            ;;
        *)
            log_error "Invalid choice. Please try again."
            ;;
    esac
}

# ----------------------------------------------------------------------
# MINIKUBE FUNCTIONS
# ----------------------------------------------------------------------
start_minikube() {
    log_info "Starting Minikube with driver: ${1:-docker}"
    
    if ! check_command "minikube"; then
        echo -e "${YELLOW}Minikube is not installed. Would you like to install it? (y/n)${NC}"
        read -r install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            install_missing_tools "minikube"
        else
            log_error "Cannot start Minikube without installing it first."
            return 1
        fi
    fi
    
    if ! minikube start --driver="${1:-docker}"; then
        log_error "Failed to start Minikube. Check the logs for details."
        return 1
    fi
    
    log_info "Minikube started successfully."
    kubectl cluster-info
    
    # Now that Minikube is running, we can create/set namespace
    check_or_create_namespace
    
    check_success "Minikube startup"
}

stop_minikube() {
    log_info "Stopping Minikube..."
    
    if ! check_command "minikube"; then
        log_error "Minikube is not installed."
        return 1
    fi
    
    if ! minikube stop; then
        log_error "Failed to stop Minikube."
        return 1
    fi
    
    log_info "Minikube stopped successfully."
}

check_minikube_status() {
    log_info "Checking Minikube status..."
    
    if ! check_command "minikube"; then
        log_error "Minikube is not installed."
        return 1
    fi
    
    if ! minikube status; then
        log_warn "Minikube may not be running properly."
        return 1
    fi
    
    log_info "Minikube is running properly."
}

# ----------------------------------------------------------------------
# UTILITY FUNCTIONS
# ----------------------------------------------------------------------
create_script() {
    local script_type="$1"
    local script_path="$2"
    local template_path="$3"
    
    # Check if template exists
    if [[ ! -f "$template_path" ]]; then
        log_error "Template file not found: $template_path"
        mkdir -p "$(dirname "$template_path")"
        log_info "Created templates directory: $(dirname "$template_path")"
        log_warn "You'll need to provide template content manually."
        return 1
    fi
    
    mkdir -p "$(dirname "$script_path")"
    log_info "Creating $script_type script at: $script_path"
    cp "$template_path" "$script_path"
    chmod +x "$script_path"
    log_info "$script_type script created successfully."
}

change_namespace() {
    echo -e "${BLUE}Current namespace is: ${YELLOW}$NAMESPACE${NC}"
    echo -e "${BLUE}Enter new namespace name:${NC} "
    read -r new_namespace
    
    if [[ -z "$new_namespace" ]]; then
        log_warn "Namespace cannot be empty. Keeping current namespace: $NAMESPACE"
        return 0
    fi
    
    # Set the new namespace
    NAMESPACE="$new_namespace"
    export NAMESPACE
    
    log_info "Namespace changed to: $NAMESPACE"
    
    # Update in kubectl config if connected to a cluster
    if check_k8s_connection; then
        log_info "Updating kubectl context to use namespace: $NAMESPACE"
        if kubectl config set-context --current --namespace="$NAMESPACE"; then
            log_info "kubectl context updated to use namespace: $NAMESPACE"
        else
            log_warn "Failed to update kubectl context. You may need to create the namespace first."
        fi
    fi
}

check_directory_structure() {
    log_info "Checking directory structure..."
    
    # Define the directories we want to check
    local dirs=(
        "$SCRIPT_DIR"
        "$K8S_BASE_PATH"
        "${K8S_BASE_PATH}/manifests"
        "${K8S_BASE_PATH}/manifests/configmaps"
        "${K8S_BASE_PATH}/manifests/secrets"
        "${K8S_BASE_PATH}/manifests/services"
        "${K8S_BASE_PATH}/manifests/deployments"
        "${K8S_BASE_PATH}/manifests/statefulsets"
        "${K8S_BASE_PATH}/manifests/ingress"
        "${K8S_BASE_PATH}/manifests/pvcs"
        "${K8S_BASE_PATH}/manifests/networkpolicies"
        "${K8S_BASE_PATH}/manifests/roles"
        "${K8S_BASE_PATH}/manifests/serviceaccounts"
        "${SCRIPT_DIR}/templates"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Directory exists: $dir"
        else
            log_warn "Directory does not exist: $dir"
            echo -e "${YELLOW}Would you like to create this directory? (y/n)${NC}"
            read -r create_choice
            if [[ "$create_choice" =~ ^[Yy]$ ]]; then
                mkdir -p "$dir"
                log_info "Created directory: $dir"
            fi
        fi
    done
    
    # Check for the required scripts
    local scripts=(
        "${SCRIPT_DIR}/k8s_config.sh"
        "${SCRIPT_DIR}/k8s_utils.sh"
        "${SCRIPT_DIR}/k8s_resource_generator.sh"
        "${SCRIPT_DIR}/menu_handler.sh"
        "$APPLY_RESOURCES_SCRIPT"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            log_info "Script exists: $script"
        else
            log_warn "Script does not exist: $script"
        fi
    done
}

# Function to access Kubernetes dashboard
access_k8s_dashboard() {
    log_info "Accessing Kubernetes Dashboard..."
    
    if ! check_command "kubectl"; then
        log_error "kubectl is not installed."
        return 1
    fi
    
    if ! check_k8s_connection; then
        log_error "Cannot connect to Kubernetes cluster. Is it running?"
        return 1
    fi
    
    # Check if dashboard is deployed
    if ! kubectl get deployment kubernetes-dashboard -n kube-system &>/dev/null; then
        log_warn "Kubernetes Dashboard not found. Would you like to deploy it? (y/n)"
        read -r deploy_choice
        if [[ "$deploy_choice" =~ ^[Yy]$ ]]; then
            log_info "Deploying Kubernetes Dashboard..."
            kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
            
            # Create admin-user and role binding
            kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
EOF
        else
            log_warn "Dashboard deployment cancelled."
            return 1
        fi
    fi
    
    # Get token for admin-user
    log_info "Retrieving authentication token..."
    local token=""
    
    # Different token retrieval methods based on Kubernetes version
    if kubectl get secret -n kube-system &>/dev/null; then
        # For Kubernetes v1.24+
        if kubectl get secret -n kube-system -o name | grep -q "admin-user-token"; then
            token=$(kubectl -n kube-system get secret $(kubectl -n kube-system get secret | grep admin-user-token | awk '{print $1}') -o jsonpath='{.data.token}' | base64 --decode)
        else
            # Create token for admin-user
            kubectl create token admin-user -n kube-system
            token=$(kubectl create token admin-user -n kube-system)
        fi
    else
        log_warn "Unable to retrieve authentication token."
    fi
    
    if [[ -n "$token" ]]; then
        log_info "Authentication token:"
        echo "$token"
        echo
        log_info "Save this token to log in to the dashboard."
    fi
    
    # Start the proxy
    log_info "Starting Kubernetes Dashboard proxy..."
    log_info "Open http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/ in your browser"
    log_info "Press Ctrl+C to stop the proxy when done."
    
    kubectl proxy
}

# ----------------------------------------------------------------------
# SCRIPT ENTRY POINT
# ----------------------------------------------------------------------
main() {
    # Check for required tools
    check_k8s_tools
    
    # Export all variables to environment
    export_variables
    
    # Try to ensure namespace exists but don't fail if cluster is not running
    check_or_create_namespace || true
    
    # Ensure the templates directory exists
    mkdir -p "${SCRIPT_DIR}/templates"
    
    # Source the menu handler script
    if [[ -f "${SCRIPT_DIR}/menu_handler.sh" ]]; then
        source "${SCRIPT_DIR}/menu_handler.sh"
        # Call the main menu function from the menu handler
        main_menu
    else
        log_error "Menu handler script not found at: ${SCRIPT_DIR}/menu_handler.sh"
        log_info "Creating a basic menu handler..."
        
        cat << 'EOF' > "${SCRIPT_DIR}/menu_handler.sh"
#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Menu Handler
# Description: Menu system for Kubernetes management
# ============================================================

# Define the main menu
main_menu() {
    local options=(
        "Set up Kubernetes Master Node"
        "Set up Kubernetes Worker Node"
        "Remove Kubernetes Setup"
        "Start Minikube"
        "Stop Minikube"
        "Check Minikube Status"
        "Reset & Apply K8s Resources"
        "Generate Kubernetes Resources"
        "Generate Specific Resources"
        "Convert Docker Compose to K8s"
        "Restart All Deployments"
        "View Kubernetes Resources"
        "Access Kubernetes Dashboard"
        "Change Namespace"
        "Check Directory Structure"
        "Exit"
    )

    while true; do
        print_header "Kubernetes Management Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                run_master_script
                ;;
            1)
                run_worker_script
                ;;
            2)
                run_remove_script
                ;;
            3)
                echo -e "${BLUE}Enter driver (default: docker):${NC} "
                read -r driver
                start_minikube "${driver:-docker}"
                ;;
            4)
                stop_minikube
                ;;
            5)
                check_minikube_status
                ;;
            6)
                run_apply_resources_script
                ;;
            7)
                run_resource_generator
                ;;
            8)
                generate_specific_resources_menu
                ;;
            9)
                convert_docker_compose
                ;;
            10)
                restart_k8s_deployments
                ;;
            11)
                view_k8s_resources_menu
                ;;
            12)
                access_k8s_dashboard
                ;;
            13)
                change_namespace
                ;;
            14)
                check_directory_structure
                ;;
            15)
                log_info "Exiting Kubernetes Manager."
                exit 0
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

# Generate specific resources menu
generate_specific_resources_menu() {
    local options=(
        "ConfigMaps"
        "Secrets"
        "Services"
        "Ingress Resources"
        "Deployments"
        "StatefulSets"
        "DaemonSets"
        "PersistentVolumeClaims"
        "NetworkPolicies"
        "Roles and RoleBindings"
        "ServiceAccounts"
        "Return to Main Menu"
    )
    
    while true; do
        print_header "Generate Specific Resources Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                generate_specific_resources "configmap"
                ;;
            1)
                generate_specific_resources "secret"
                ;;
            2)
                generate_specific_resources "service"
                ;;
            3)
                generate_specific_resources "ingress"
                ;;
            4)
                generate_specific_resources "deployment"
                ;;
            5)
                generate_specific_resources "statefulset"
                ;;
            6)
                generate_specific_resources "daemonset"
                ;;
            7)
                generate_specific_resources "pvc"
                ;;
            8)
                generate_specific_resources "networkpolicy"
                ;;
            9)
                generate_specific_resources "role"
                ;;
            10)
                generate_specific_resources "serviceaccount"
                ;;
            11)
                return
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

# View Kubernetes resources menu
view_k8s_resources_menu() {
    local options=(
        "View All Resources"
        "View Pods"
        "View Deployments"
        "View StatefulSets"
        "View Services"
        "View ConfigMaps"
        "View Secrets"
        "View Ingress"
        "View PersistentVolumeClaims"
        "View NetworkPolicies"
        "View Roles and RoleBindings"
        "View ServiceAccounts"
        "View Pod Logs"
        "Return to Main Menu"
    )
    
    while true; do
        print_header "Kubernetes Resources Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                kubectl get all -n "$NAMESPACE"
                ;;
            1)
                kubectl get pods -n "$NAMESPACE"
                ;;
            2)
                kubectl get deployments -n "$NAMESPACE"
                ;;
            3)
                kubectl get statefulsets -n "$NAMESPACE"
                ;;
            4)
                kubectl get services -n "$NAMESPACE"
                ;;
            5)
                kubectl get configmaps -n "$NAMESPACE"
                ;;
            6)
                kubectl get secrets -n "$NAMESPACE"
                ;;
            7)
                kubectl get ingress -n "$NAMESPACE"
                ;;
            8)
                kubectl get pvc -n "$NAMESPACE"
                ;;
            9)
                kubectl get networkpolicies -n "$NAMESPACE"
                ;;
            10)
                kubectl get roles,rolebindings -n "$NAMESPACE"
                ;;
            11)
                kubectl get serviceaccounts -n "$NAMESPACE"
                ;;
            12)
                view_k8s_pod_logs
                ;;
            13)
                return
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

# View Kubernetes pod logs
view_k8s_pod_logs() {
    log_info "Checking pods in namespace: $NAMESPACE"
    kubectl get pods -n "$NAMESPACE"
    
    echo -e "${BLUE}Enter the pod name:${NC} "
    read -r pod_name
    
    if [[ -z "$pod_name" ]]; then
        log_error "Pod name cannot be empty."
        return 1
    fi
    
    if ! kubectl get pod "$pod_name" -n "$NAMESPACE" &>/dev/null; then
        log_error "Pod $pod_name not found in namespace $NAMESPACE."
        return 1
    fi
    
    # Check if pod has multiple containers
    local containers
    containers=$(kubectl get pod "$pod_name" -n "$NAMESPACE" -o jsonpath='{.spec.containers[*].name}')
    container_count=$(echo "$containers" | wc -w)
    
    local container=""
    if [[ $container_count -gt 1 ]]; then
        log_info "Pod has multiple containers. Available containers: $containers"
        echo -e "${BLUE}Enter container name (leave blank for first container):${NC} "
        read -r container
    fi
    
    log_info "Found pod: $pod_name. Fetching logs..."
    
    local options=(
        "Current Logs"
        "Previous Logs"
        "Follow Logs"
        "All Containers"
        "Return to Resources Menu"
    )
    
    echo "Log Options for $pod_name:"
    for i in "${!options[@]}"; do
        echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
    done
    
    echo -e "${BLUE}Enter your choice:${NC} "
    read -r log_choice
    
    # Build the container arg
    local container_arg=""
    if [[ -n "$container" ]]; then
        container_arg="-c $container"
    fi
    
    case "$log_choice" in
        0)
            log_info "Displaying current logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" $container_arg || log_error "Failed to fetch current logs."
            ;;
        1)
            log_info "Displaying previous logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" --previous $container_arg || log_error "Failed to fetch previous logs."
            ;;
        2)
            log_info "Following logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" -f $container_arg || log_error "Failed to follow logs."
            ;;
        3)
            log_info "Displaying logs for all containers in $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" --all-containers=true || log_error "Failed to fetch logs for all containers."
            ;;
        4)
            return
            ;;
        *)
            log_error "Invalid choice. Please select a valid option."
            ;;
    esac
}

# Function to print a nice header for menus
print_header() {
    local title="$1"
    local width=80
    local line=$(printf '%*s\n' "$width" '' | tr ' ' '=')
    
    echo -e "\n${GREEN}$line${NC}"
    echo -e "${GREEN}$(printf '%*s\n' $(((${#title}+$width)/2)) "$title")${NC}"
    echo -e "${GREEN}$line${NC}\n"
}
EOF
        chmod +x "${SCRIPT_DIR}/menu_handler.sh"
        log_info "Basic menu handler created. You may want to customize it further."
        source "${SCRIPT_DIR}/menu_handler.sh"
        main_menu
    fi
}

# Start the script
main