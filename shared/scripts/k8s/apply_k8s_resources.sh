#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration

# Directories and file paths
K8S_USER=${K8S_USER:-"$USER"}
BASE_DIR=${BASE_DIR:-"/home/$K8S_USER/fks"}
K8S_BASE_PATH=${K8S_BASE_PATH:-"$BASE_DIR/deployment/k8s"}
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Namespace and resource configurations
NAMESPACE=${NAMESPACE:-"fks_development"}
MANIFESTS_DIR=${MANIFESTS_DIR:-"$K8S_BASE_PATH/manifests"}
APPLY_SECRETS=${APPLY_SECRETS:-"false"}
VALIDATE=${VALIDATE:-"true"}
DELETE_NAMESPACE=${DELETE_NAMESPACE:-"true"}
NON_INTERACTIVE=${NON_INTERACTIVE:-"false"}
WAIT_FOR_READINESS=${WAIT_FOR_READINESS:-"true"}
APPLY_TIMEOUT=${APPLY_TIMEOUT:-"300"} # 5 minutes timeout for resource readiness
SPECIFIC_RESOURCES=${SPECIFIC_RESOURCES:-""}

# Resource types to generate
RESOURCE_TYPES=${RESOURCE_TYPES:-"configmap"}

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

prompt() {
    echo -e "${BLUE}[PROMPT]${NC} $1"
}

# Error handler
handle_error() {
    local exit_code=$?
    local line_no=$1
    
    if [ $exit_code -ne 0 ]; then
        error "Error on line $line_no: Command exited with status $exit_code"
    fi
}

# Setup error handling
trap 'handle_error $LINENO' ERR

# Check if kubectl is installed
check_prerequisites() {
    log "Checking prerequisites..."
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install it and try again."
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &>/dev/null; then
        error "Cannot connect to Kubernetes cluster. Make sure your cluster is running and kubectl is properly configured."
    fi
    
    log "Prerequisites check passed."
}

# Check if we need sudo for kubectl
needs_sudo() {
    if kubectl get namespace default &> /dev/null; then
        echo ""
    else
        echo "sudo"
    fi
}

# Wait for resource to be ready
wait_for_resource_ready() {
    local resource_type="$1"
    local resource_name="$2"
    local max_wait="${3:-$APPLY_TIMEOUT}"
    
    if [ "$WAIT_FOR_READINESS" != "true" ]; then
        return 0
    fi
    
    log "Waiting for $resource_type/$resource_name to be ready (timeout: ${max_wait}s)..."
    local start_time=$(date +%s)
    local SUDO=$(needs_sudo)
    
    while true; do
        if $SUDO kubectl wait --for=condition=Available "$resource_type/$resource_name" -n "$NAMESPACE" --timeout=10s &>/dev/null; then
            log "$resource_type/$resource_name is ready"
            return 0
        fi
        
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $max_wait ]; then
            warn "$resource_type/$resource_name not ready after ${max_wait}s, continuing anyway"
            return 1
        fi
        
        sleep 5
    done
}

# Ensure the manifests directory exists
check_manifests_dir() {
    if [ ! -d "$MANIFESTS_DIR" ]; then
        error "Manifests directory '$MANIFESTS_DIR' does not exist."
    fi

    # Check if the required subdirectories exist
    local required_dirs=("configmaps" "deployments" "pvcs" "ingress" "roles" "services" "serviceaccounts" "secrets" "statefulsets" "daemonsets" "jobs" "cronjobs")
    local missing_dirs=()

    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$MANIFESTS_DIR/$dir" ]; then
            missing_dirs+=("$dir")
        fi
    done

    if [ ${#missing_dirs[@]} -ne 0 ]; then
        warn "The following manifest subdirectories are missing: ${missing_dirs[*]}"
        warn "Some resources may not be applied."
        
        if [ "$NON_INTERACTIVE" != "true" ]; then
            sleep 2
        fi
    fi
    
    # Specifically check for secrets directory if APPLY_SECRETS is true
    if [ "$APPLY_SECRETS" == "true" ] && [ ! -d "$MANIFESTS_DIR/secrets" ]; then
        warn "Secrets directory ($MANIFESTS_DIR/secrets) does not exist but APPLY_SECRETS is set to true."
        
        if [ "$NON_INTERACTIVE" != "true" ]; then
            read -p "Do you want to continue without secrets? (y/n): " continue_without_secrets
            if [[ ! "$continue_without_secrets" =~ ^[Yy]$ ]]; then
                error "Aborting as requested."
            fi
        else
            log "Continuing without secrets in non-interactive mode."
        fi
    fi
}

# Apply kubernetes resources from a directory and its subdirectories
apply_resources() {
    local resource_type=$1
    local dir="$MANIFESTS_DIR/$2"
    
    # Skip if SPECIFIC_RESOURCES is set and doesn't include this resource type
    if [ -n "$SPECIFIC_RESOURCES" ]; then
        if [[ ! "$SPECIFIC_RESOURCES" =~ (^|,)$2(,|$) && "$SPECIFIC_RESOURCES" != "all" ]]; then
            log "Skipping $resource_type as it's not in the specified resources list: $SPECIFIC_RESOURCES"
            return 0
        fi
    fi
    
    # Skip if directory doesn't exist
    if [ ! -d "$dir" ]; then
        warn "Directory for $resource_type ($dir) does not exist. Skipping."
        return 0
    fi
    
    # Check if directory contains any yaml/yml/json files (including in subdirectories)
    if [ -z "$(find "$dir" -type f -name "*.yaml" -o -name "*.yml" -o -name "*.json" 2>/dev/null)" ]; then
        warn "No $resource_type manifests found in $dir or its subdirectories. Skipping."
        return 0
    fi
    
    log "Applying $resource_type..."
    
    local validate_flag=""
    if [ "$VALIDATE" != "true" ]; then
        validate_flag="--validate=false"
        warn "Validation is disabled. This is not recommended for production."
    fi
    
    local SUDO=$(needs_sudo)
    local success_count=0
    local failure_count=0
    
    # Create temporary files to store success/failure counts to fix subshell variable scope issue
    local tmp_success=$(mktemp)
    local tmp_failure=$(mktemp)
    local tmp_resources=$(mktemp)
    echo "0" > "$tmp_success"
    echo "0" > "$tmp_failure"
    
    # Find and apply all yaml, yml, and json files, including in subdirectories
    find "$dir" -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) | sort | while read -r file; do
        log "Applying file: $file"
        
        # Extract resource type and name for later use in waiting
        local resource_name=""
        if grep -q "kind:" "$file" && grep -q "metadata:" "$file" && grep -q "name:" "$file"; then
            local kind=$(grep -m 1 "kind:" "$file" | awk '{print $2}')
            resource_name=$(grep -A 10 "metadata:" "$file" | grep -m 1 "name:" | awk '{print $2}')
            echo "$kind|$resource_name" >> "$tmp_resources"
        fi
        
        # Apply the resource
        if ! $SUDO kubectl apply -f "$file" -n "$NAMESPACE" $validate_flag; then
            warn "Failed to apply $file."
            echo $(($(cat "$tmp_failure")+1)) > "$tmp_failure"
        else
            log "Successfully applied $file"
            echo $(($(cat "$tmp_success")+1)) > "$tmp_success"
            
            # Wait for the resource to be ready if it's a type that can be waited on
            if [ -n "$resource_name" ] && [[ "$kind" =~ ^(Deployment|StatefulSet|DaemonSet|Job)$ ]]; then
                wait_for_resource_ready "$kind" "$resource_name"
            fi
        fi
    done
    
    # Retrieve the counts from temporary files
    success_count=$(cat "$tmp_success")
    failure_count=$(cat "$tmp_failure")
    
    # Process resources file to extract unique resources
    if [ -f "$tmp_resources" ] && [ -s "$tmp_resources" ]; then
        log "Applied resources:"
        sort "$tmp_resources" | uniq | while read -r resource_info; do
            local kind=$(echo "$resource_info" | cut -d'|' -f1)
            local name=$(echo "$resource_info" | cut -d'|' -f2)
            log "  - $kind/$name"
        done
    fi
    
    # Clean up temporary files
    rm -f "$tmp_success" "$tmp_failure" "$tmp_resources"
    
    if [ $failure_count -gt 0 ]; then
        warn "Applied $success_count files, but failed to apply $failure_count files."
        
        if [ "$NON_INTERACTIVE" != "true" ]; then
            read -p "Press Enter to continue..."
        fi
    else
        if [ $success_count -gt 0 ]; then
            log "All $resource_type resources applied successfully ($success_count files)."
        else
            warn "No $resource_type resources were applied."
        fi
    fi
}

# Delete namespace if it exists
delete_namespace() {
    if [ "$DELETE_NAMESPACE" != "true" ]; then
        log "Skipping namespace deletion as DELETE_NAMESPACE=$DELETE_NAMESPACE"
        return 0
    fi
    
    log "Checking if namespace exists: $NAMESPACE"
    local SUDO=$(needs_sudo)
    
    if $SUDO kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log "Deleting namespace: $NAMESPACE"
        
        if [ "$NON_INTERACTIVE" != "true" ]; then
            prompt "Are you sure you want to delete namespace '$NAMESPACE' and all resources in it? (y/n): "
            read -r confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log "Namespace deletion cancelled. Exiting."
                exit 0
            fi
        fi
        
        if ! $SUDO kubectl delete namespace "$NAMESPACE" --wait=true; then
            warn "Failed to delete namespace $NAMESPACE. Will try to continue anyway."
            sleep 5
        else
            log "Namespace $NAMESPACE deleted successfully."
            # Wait a moment to ensure the namespace is fully deleted
            log "Waiting for namespace deletion to complete..."
            sleep 10
        fi
    else
        log "Namespace $NAMESPACE does not exist. Skipping deletion."
    fi
}

# Create namespace
create_namespace() {
    log "Creating namespace: $NAMESPACE"
    local SUDO=$(needs_sudo)
    
    # Make sure the namespace doesn't exist (it should be deleted already, but check again)
    if $SUDO kubectl get namespace "$NAMESPACE" &>/dev/null; then
        warn "Namespace $NAMESPACE still exists. Will try to continue anyway."
    else
        if ! $SUDO kubectl create namespace "$NAMESPACE"; then
            error "Failed to create namespace $NAMESPACE. Exiting."
        fi
        log "Namespace $NAMESPACE created successfully."
        
        # Add environment label based on namespace name
        $SUDO kubectl label namespace "$NAMESPACE" environment="${NAMESPACE/-*/}" --overwrite
    fi
}

# Generate resources
generate_resources() {
    local RESOURCE_GENERATOR="${SCRIPT_DIR}/k8s_resource_generator.sh"
    log "Generating Kubernetes resources using: $RESOURCE_GENERATOR"
    
    if [ ! -f "$RESOURCE_GENERATOR" ]; then
        # Fall back to the old configmap generator if the resource generator doesn't exist
        local GENERATE_CONFIGMAPS_SCRIPT="${SCRIPT_DIR}/generate_configmaps.sh"
        if [ ! -f "$GENERATE_CONFIGMAPS_SCRIPT" ]; then
            warn "Neither resource generator nor ConfigMap generator script found."
            warn "Skipping resource generation."
            return 1
        fi
        
        log "Resource generator not found. Falling back to ConfigMap generator."
        if ! bash "$GENERATE_CONFIGMAPS_SCRIPT" --namespace "$NAMESPACE"; then
            warn "ConfigMap generation encountered errors. Will try to continue anyway."
        else
            log "ConfigMaps generated successfully."
        fi
        return 0
    fi
    
    # Determine resource types to generate
    local resource_arg="$RESOURCE_TYPES"
    if [ -n "$SPECIFIC_RESOURCES" ]; then
        resource_arg="$SPECIFIC_RESOURCES"
    fi
    
    log "Running resource generator with types: $resource_arg"
    if ! bash "$RESOURCE_GENERATOR" --resource "$resource_arg" --namespace "$NAMESPACE"; then
        warn "Resource generation encountered errors. Will try to continue anyway."
    else
        log "Resources generated successfully."
    fi
}

# Create backup of existing resources
backup_existing_resources() {
    if [ "$DELETE_NAMESPACE" == "true" ]; then
        # No need to backup if we're deleting the namespace
        return 0
    fi
    
    log "Creating backup of existing resources in namespace $NAMESPACE..."
    local SUDO=$(needs_sudo)
    local backup_dir="${MANIFESTS_DIR}/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup key resource types
    for resource_type in deployments services configmaps statefulsets daemonsets ingresses pvc roles rolebindings serviceaccounts; do
        $SUDO kubectl get -n "$NAMESPACE" "$resource_type" -o yaml > "${backup_dir}/${resource_type}.yaml" 2>/dev/null || true
    done
    
    # Backup secrets if needed
    if [ "$APPLY_SECRETS" == "true" ]; then
        $SUDO kubectl get -n "$NAMESPACE" secrets -o yaml > "${backup_dir}/secrets.yaml" 2>/dev/null || true
    fi
    
    log "Backup created at $backup_dir"
}

# Verify resources
verify_resources() {
    log "Verifying resources in namespace: $NAMESPACE"
    local SUDO=$(needs_sudo)
    
    log "Pods, Deployments, Services, and other resources:"
    $SUDO kubectl get all -n "$NAMESPACE"
    
    log "Persistent Volume Claims:"
    $SUDO kubectl get pvc -n "$NAMESPACE" 2>/dev/null || log "No PVCs found"
    
    log "ConfigMaps:"
    $SUDO kubectl get configmap -n "$NAMESPACE" 2>/dev/null || log "No ConfigMaps found"
    
    log "StatefulSets:"
    $SUDO kubectl get statefulset -n "$NAMESPACE" 2>/dev/null || log "No StatefulSets found"
    
    log "DaemonSets:"
    $SUDO kubectl get daemonset -n "$NAMESPACE" 2>/dev/null || log "No DaemonSets found"
    
    log "Secrets:"
    if [ "$APPLY_SECRETS" == "true" ]; then
        $SUDO kubectl get secrets -n "$NAMESPACE" 2>/dev/null || log "No Secrets found"
    else
        log "Secrets check skipped because APPLY_SECRETS=$APPLY_SECRETS"
    fi
    
    log "Ingresses:"
    $SUDO kubectl get ingress -n "$NAMESPACE" 2>/dev/null || log "No Ingresses found"
    
    log "Service Accounts:"
    $SUDO kubectl get serviceaccount -n "$NAMESPACE" 2>/dev/null || log "No Service Accounts found"
    
    log "Roles and RoleBindings:"
    $SUDO kubectl get roles,rolebindings -n "$NAMESPACE" 2>/dev/null || log "No Roles or RoleBindings found"
    
    log "Jobs and CronJobs:"
    $SUDO kubectl get jobs,cronjobs -n "$NAMESPACE" 2>/dev/null || log "No Jobs or CronJobs found"
    
    # Check pod status and readiness
    log "Checking pod status and readiness:"
    $SUDO kubectl get pods -n "$NAMESPACE" -o wide
    
    # Check any failed pods and show their logs
    local failed_pods=$($SUDO kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Failed -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    if [ -n "$failed_pods" ]; then
        warn "Failed pods detected:"
        for pod in $failed_pods; do
            warn "  Pod $pod is in Failed state."
            if [ "$NON_INTERACTIVE" != "true" ]; then
                prompt "Would you like to see the logs for this pod? (y/n): "
                read -r show_logs
                if [[ "$show_logs" =~ ^[Yy]$ ]]; then
                    $SUDO kubectl logs "$pod" -n "$NAMESPACE"
                fi
            fi
        done
    fi
}

# Main function
main() {
    log "Starting the enhanced Kubernetes resources application process"
    
    check_prerequisites
    check_manifests_dir
    
    # Backup existing resources if not deleting namespace
    if [ "$DELETE_NAMESPACE" != "true" ]; then
        backup_existing_resources
    fi
    
    # Delete namespace if it exists and if DELETE_NAMESPACE is true
    if [ "$DELETE_NAMESPACE" == "true" ]; then
        delete_namespace
    fi
    
    # Create namespace if it doesn't exist
    create_namespace
    
    # Generate resources from config directory
    generate_resources
    
    # Apply resources in a sensible order - first the ones without dependencies
    log "About to apply ConfigMaps..."
    apply_resources "ConfigMaps" "configmaps"
    log "ConfigMaps processing complete"
    
    log "About to apply Secrets..."
    if [ "$APPLY_SECRETS" == "true" ]; then
        apply_resources "Secrets" "secrets"
    else
        log "Skipping secrets because APPLY_SECRETS=$APPLY_SECRETS"
    fi
    log "Secrets processing complete"
    
    log "About to apply Persistent Volume Claims..."
    apply_resources "Persistent Volume Claims" "pvcs"
    log "PVCs processing complete"
    
    log "About to apply Service Accounts..."
    apply_resources "Service Accounts" "serviceaccounts"
    log "Service Accounts processing complete"
    
    log "About to apply Roles and Role Bindings..."
    apply_resources "Roles and Role Bindings" "roles"
    log "Roles processing complete"
    
    # Then apply services
    log "About to apply Services..."
    apply_resources "Services" "services"
    log "Services processing complete"
    
    # Apply stateful workloads first
    log "About to apply StatefulSets..."
    apply_resources "StatefulSets" "statefulsets"
    log "StatefulSets processing complete"
    
    log "About to apply DaemonSets..."
    apply_resources "DaemonSets" "daemonsets"
    log "DaemonSets processing complete"
    
    # Apply regular deployments
    log "About to apply Deployments..."
    apply_resources "Deployments" "deployments"
    log "Deployments processing complete"
    
    # Apply jobs
    log "About to apply Jobs..."
    apply_resources "Jobs" "jobs"
    log "Jobs processing complete"
    
    log "About to apply CronJobs..."
    apply_resources "CronJobs" "cronjobs"
    log "CronJobs processing complete"
    
    # Finally, apply ingress resources
    log "About to apply Ingress Resources..."
    apply_resources "Ingress Resources" "ingress"
    log "Ingress processing complete"
    
    # Verify the applied resources
    verify_resources
    
    log "All resources have been applied to namespace '$NAMESPACE'"
}

# Show script usage
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -n, --namespace NAMESPACE   Set the Kubernetes namespace (default: $NAMESPACE)"
    echo "  -d, --dir DIRECTORY         Set the manifests directory (default: $MANIFESTS_DIR)"
    echo "  -s, --secrets               Apply secrets (default: false)"
    echo "  -v, --validate BOOL         Enable/disable validation (default: true)"
    echo "  -r, --resource TYPES        Resource types to generate (default: configmap)"
    echo "  -k, --keep-namespace        Keep namespace (don't delete it first)"
    echo "  -w, --wait-for-readiness    Wait for resources to be ready (default: true)"
    echo "  -t, --timeout SECONDS       Timeout in seconds for resource readiness (default: 300)"
    echo "  -o, --only RESOURCES        Only apply specific resources (comma-separated)"
    echo "  -q, --quiet                 Non-interactive mode (no prompts)"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  NAMESPACE                   Set the Kubernetes namespace"
    echo "  MANIFESTS_DIR               Set the manifests directory"
    echo "  APPLY_SECRETS               Set to 'true' to apply secrets"
    echo "  VALIDATE                    Set to 'false' to disable validation"
    echo "  RESOURCE_TYPES              Set resource types to generate (comma-separated)"
    echo "  DELETE_NAMESPACE            Set to 'false' to keep the namespace"
    echo "  NON_INTERACTIVE             Set to 'true' for non-interactive mode"
    echo "  WAIT_FOR_READINESS          Set to 'false' to skip waiting for resource readiness"
    echo "  APPLY_TIMEOUT               Set timeout in seconds for resource readiness"
    echo "  SPECIFIC_RESOURCES          Only apply specific resources (comma-separated)"
    echo ""
    echo "Examples:"
    echo "  $0 --namespace fks_production"
    echo "  NAMESPACE=fks_staging $0"
    echo "  $0 --resource configmap,secret,service"
    echo "  $0 --only deployments,services"
    echo "  $0 --keep-namespace --only configmaps"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -d|--dir)
            MANIFESTS_DIR="$2"
            shift 2
            ;;
        -s|--secrets)
            APPLY_SECRETS="true"
            shift
            ;;
        -v|--validate)
            VALIDATE="$2"
            shift 2
            ;;
        -r|--resource)
            RESOURCE_TYPES="$2"
            shift 2
            ;;
        -k|--keep-namespace)
            DELETE_NAMESPACE="false"
            shift
            ;;
        -w|--wait-for-readiness)
            WAIT_FOR_READINESS="$2"
            shift 2
            ;;
        -t|--timeout)
            APPLY_TIMEOUT="$2"
            shift 2
            ;;
        -o|--only)
            SPECIFIC_RESOURCES="$2"
            shift 2
            ;;
        -q|--quiet)
            NON_INTERACTIVE="true"
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            warn "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Run the main function
main