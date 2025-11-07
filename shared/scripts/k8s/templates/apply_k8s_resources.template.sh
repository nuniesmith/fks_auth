#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
# Define the namespace (can be overridden by environment variable)
NAMESPACE=${NAMESPACE:-"fks_development"}
MANIFESTS_DIR=${MANIFESTS_DIR:-"manifests"}
APPLY_SECRETS=${APPLY_SECRETS:-"false"}
VALIDATE=${VALIDATE:-"true"}
DELETE_NAMESPACE=${DELETE_NAMESPACE:-"true"}
NON_INTERACTIVE=${NON_INTERACTIVE:-"false"}
WAIT_FOR_READINESS=${WAIT_FOR_READINESS:-"true"}
APPLY_TIMEOUT=${APPLY_TIMEOUT:-"300"}
SPECIFIC_RESOURCES=${SPECIFIC_RESOURCES:-""}

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

# Set up error handling
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
    
    # Find and apply all yaml, yml, and json files, including in subdirectories
    find "$dir" -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) | sort | while read -r file; do
        log "Applying file: $file"
        
        # Extract resource type and name for later use in waiting
        local resource_name=""
        if grep -q "kind:" "$file" && grep -q "metadata:" "$file" && grep -q "name:" "$file"; then
            local kind=$(grep -m 1 "kind:" "$file" | awk '{print $2}')
            resource_name=$(grep -A 10 "metadata:" "$file" | grep -m 1 "name:" | awk '{print $2}')
        fi
        
        # Apply the resource
        if ! $SUDO kubectl apply -f "$file" -n "$NAMESPACE" $validate_flag; then
            warn "Failed to apply $file."
            ((failure_count++))
        else
            log "Successfully applied $file"
            ((success_count++))
            
            # Wait for the resource to be ready if it's a type that can be waited on
            if [ -n "$resource_name" ] && [[ "$kind" =~ ^(Deployment|StatefulSet|DaemonSet|Job)$ ]]; then
                wait_for_resource_ready "$kind" "$resource_name"
            fi
        fi
    done
    
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
        
        # Add labels
        $SUDO kubectl label namespace "$NAMESPACE" environment="${NAMESPACE/-*/}" --overwrite
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
    
    # Check available resource types
    for resource in configmap pvc statefulset daemonset ingress serviceaccount role rolebinding job cronjob; do
        log "$(tr '[:lower:]' '[:upper:]' <<< ${resource:0:1})${resource:1}s:"
        $SUDO kubectl get $resource -n "$NAMESPACE" 2>/dev/null || log "No ${resource}s found"
    done
    
    if [ "$APPLY_SECRETS" == "true" ]; then
        log "Secrets:"
        $SUDO kubectl get secrets -n "$NAMESPACE" 2>/dev/null || log "No Secrets found"
    fi
    
    # Check pod status
    log "Checking pod status:"
    $SUDO kubectl get pods -n "$NAMESPACE" -o wide
}

# Main function
main() {
    log "Starting Kubernetes resource application process"
    
    check_prerequisites
    
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
    
    # Apply resources in a sensible order
    apply_resources "ConfigMaps" "configmaps"
    
    if [ "$APPLY_SECRETS" == "true" ]; then
        apply_resources "Secrets" "secrets"
    else
        log "Skipping secrets because APPLY_SECRETS=$APPLY_SECRETS"
    fi
    
    apply_resources "Persistent Volume Claims" "pvcs"
    apply_resources "Service Accounts" "serviceaccounts"
    apply_resources "Roles and Role Bindings" "roles"
    apply_resources "Services" "services"
    apply_resources "StatefulSets" "statefulsets"
    apply_resources "DaemonSets" "daemonsets"
    apply_resources "Deployments" "deployments"
    apply_resources "Jobs" "jobs"
    apply_resources "CronJobs" "cronjobs"
    apply_resources "Ingress Resources" "ingress"
    
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
    echo "  -k, --keep-namespace        Keep namespace (don't delete it first)"
    echo "  -w, --wait-for-readiness    Wait for resources to be ready (default: true)"
    echo "  -t, --timeout SECONDS       Timeout in seconds for resource readiness (default: 300)"
    echo "  -o, --only RESOURCES        Only apply specific resources (comma-separated)"
    echo "  -q, --quiet                 Non-interactive mode (no prompts)"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --namespace fks_production"
    echo "  $0 --keep-namespace --only configmaps,services"
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