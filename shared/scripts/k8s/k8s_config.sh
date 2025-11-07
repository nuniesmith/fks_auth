#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Configuration
# Description: Configuration variables for Kubernetes management scripts
# ============================================================

# ----------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------
# Base user, can be customized
K8S_USER=${K8S_USER:-"$USER"}

# Directories and file paths
BASE_DIR=${BASE_DIR:-"/home/$K8S_USER/fks"}
SCRIPT_DIR=${SCRIPT_DIR:-"$BASE_DIR/scripts/k8s"}
MASTER_SCRIPT=${MASTER_SCRIPT:-"$SCRIPT_DIR/install_k8s_master.sh"}
WORKER_SCRIPT=${WORKER_SCRIPT:-"$SCRIPT_DIR/install_k8s_worker.sh"}
REMOVE_SCRIPT=${REMOVE_SCRIPT:-"$SCRIPT_DIR/remove_k8s.sh"}
APPLY_RESOURCES_SCRIPT=${APPLY_RESOURCES_SCRIPT:-"$SCRIPT_DIR/apply-k8s-resources.sh"}

# Kubernetes configurations
KUBE_HOME=${KUBE_HOME:-"$HOME/.kube"}
KUBE_CONFIG=${KUBE_CONFIG:-"$KUBE_HOME/config"}
MINIKUBE_HOME=${MINIKUBE_HOME:-"$HOME/.minikube"}
K8S_BASE_PATH=${K8S_BASE_PATH:-"$BASE_DIR/deployment/k8s"}
LOG_DIR=${LOG_DIR:-"$BASE_DIR/logs"}
LOG_FILE=${LOG_FILE:-"$LOG_DIR/k8s_manager.log"}

# Default IP address used for multiple settings
DEFAULT_IP=${DEFAULT_IP:-"100.115.54.104"}

# Namespace and resource configurations
NAMESPACE=${NAMESPACE:-"fks_development"}
MANIFESTS_DIR=${MANIFESTS_DIR:-"$K8S_BASE_PATH/manifests"}
APPLY_SECRETS=${APPLY_SECRETS:-"false"}
VALIDATE=${VALIDATE:-"true"}

# Default resource types to generate
# Use comma-separated values: configmap,secret,service,deployment,statefulset,pvc,ingress,networkpolicy,role,serviceaccount
RESOURCE_TYPES=${RESOURCE_TYPES:-"configmap,secret,service,deployment"}

# Resource generation settings
DOCKER_COMPOSE_AUTO_CONVERT=${DOCKER_COMPOSE_AUTO_CONVERT:-"false"}
RESOURCE_GENERATOR_DEBUG=${RESOURCE_GENERATOR_DEBUG:-"false"}
DEFAULT_REPLICAS=${DEFAULT_REPLICAS:-"1"}
USE_RESOURCE_LIMITS=${USE_RESOURCE_LIMITS:-"true"}
DEFAULT_CPU_LIMIT=${DEFAULT_CPU_LIMIT:-"500m"}
DEFAULT_MEMORY_LIMIT=${DEFAULT_MEMORY_LIMIT:-"512Mi"}

# Network configurations
ADVERTISE_ADDRESS=${ADVERTISE_ADDRESS:-"$DEFAULT_IP"}
POD_SUBNET=${POD_SUBNET:-"10.24.0.0/16"}
SERVICE_SUBNET=${SERVICE_SUBNET:-"10.96.0.0/12"}

# Master node configurations
MASTER_IP=${MASTER_IP:-"$DEFAULT_IP"}
MASTER_PORT=${MASTER_PORT:-"6443"}
KUBE_TOKEN=${KUBE_TOKEN:-""}
CA_CERT_HASH=${CA_CERT_HASH:-""}
JOIN_COMMAND_FILE=${JOIN_COMMAND_FILE:-""}

# Removal configurations
REMOVE_DOCKER=${REMOVE_DOCKER:-"false"}
REMOVE_MINIKUBE=${REMOVE_MINIKUBE:-"true"}
REMOVE_CONFIG_ONLY=${REMOVE_CONFIG_ONLY:-"false"}
FORCE=${FORCE:-"false"}

# Create necessary directories
mkdir -p "$LOG_DIR" "$K8S_BASE_PATH/manifests" &>/dev/null || true
chmod 700 "$LOG_DIR" &>/dev/null || true

# Create manifest resource type directories
for resource_type in configmaps secrets services deployments statefulsets ingress pvcs networkpolicies roles serviceaccounts daemonsets; do
    mkdir -p "$MANIFESTS_DIR/$resource_type" &>/dev/null || true
done

# Verify permissions and directories
if [[ ! -w "$LOG_DIR" ]]; then
    echo "Error: Log directory $LOG_DIR is not writable" >&2
    # Continue anyway, we might be able to fix this later
fi

# Ensure the manifests directory exists
if [[ ! -d "$MANIFESTS_DIR" ]]; then
    mkdir -p "$MANIFESTS_DIR" &>/dev/null || true
    echo "Created manifests directory: $MANIFESTS_DIR" >&2
fi

# Create templates directory if it doesn't exist
TEMPLATES_DIR="$SCRIPT_DIR/templates"
mkdir -p "$TEMPLATES_DIR" &>/dev/null || true

# Generate a random script ID for this run (useful for temporary files)
SCRIPT_ID="$(date +%s)_$RANDOM"

# Export important variables for use in scripts that source this file
export_variables() {
    export K8S_USER BASE_DIR SCRIPT_DIR 
    export MASTER_SCRIPT WORKER_SCRIPT REMOVE_SCRIPT APPLY_RESOURCES_SCRIPT
    export KUBE_HOME KUBE_CONFIG MINIKUBE_HOME K8S_BASE_PATH
    export LOG_DIR LOG_FILE
    export DEFAULT_IP
    export NAMESPACE MANIFESTS_DIR APPLY_SECRETS VALIDATE
    export RESOURCE_TYPES DOCKER_COMPOSE_AUTO_CONVERT RESOURCE_GENERATOR_DEBUG
    export DEFAULT_REPLICAS USE_RESOURCE_LIMITS DEFAULT_CPU_LIMIT DEFAULT_MEMORY_LIMIT
    export ADVERTISE_ADDRESS POD_SUBNET SERVICE_SUBNET
    export MASTER_IP MASTER_PORT KUBE_TOKEN CA_CERT_HASH JOIN_COMMAND_FILE
    export REMOVE_DOCKER REMOVE_MINIKUBE REMOVE_CONFIG_ONLY FORCE
    export TEMPLATES_DIR SCRIPT_ID
}

# Check if this script is being sourced or executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script is meant to be sourced, not executed directly."
    echo "To source this script, use: source ${BASH_SOURCE[0]}"
    exit 1
fi