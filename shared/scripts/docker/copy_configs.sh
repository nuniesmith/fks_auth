#!/bin/bash
# script to copy configuration files into the container at runtime
# Supports Docker volumes and Kubernetes ConfigMaps
set -eo pipefail

# --------------------------------------
# Configuration & Environment Variables
# --------------------------------------
CONFIG_SRC="${CONFIG_SRC:-/config-src}"  # Source directory for configs
CONFIG_DEST="${CONFIG_DEST:-/app/config/fks}"  # Destination directory
CONFIG_ENV="${CONFIG_ENV:-development}"  # Environment (development, staging, production)
SERVICE_TYPE="${SERVICE_TYPE:-app}"      # Current service type
BACKUP_CONFIGS="${BACKUP_CONFIGS:-true}" # Whether to backup existing configs
VALIDATE_YAML="${VALIDATE_YAML:-true}"   # Whether to validate YAML syntax
DEBUG_MODE="${DEBUG_MODE:-false}"        # Enable debug output

# --------------------------------------
# Utility Functions
# --------------------------------------

# Colorized logging functions
log_info() { echo -e "\033[0;32m[INFO]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "\033[0;33m[WARN]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_debug() { if [ "${DEBUG_MODE}" = "true" ]; then echo -e "\033[0;36m[DEBUG]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1"; fi; }
log_section() { echo -e "\n\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ [${1}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"; }

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Check available disk space
check_disk_space() {
    local required_space_kb=10240  # 10MB minimum
    local available_space_kb
    
    if command_exists df; then
        available_space_kb=$(df -k "$(dirname "${CONFIG_DEST}")" | tail -1 | awk '{print $4}')
        if [ "${available_space_kb}" -lt "${required_space_kb}" ]; then
            log_warn "Low disk space: ${available_space_kb}KB available, recommended minimum is ${required_space_kb}KB"
            return 1
        fi
    fi
    return 0
}

# Validate YAML syntax if python is available
validate_yaml() {
    local yaml_file="$1"
    
    if [ "${VALIDATE_YAML}" != "true" ]; then
        return 0
    fi
    
    if ! command_exists python; then
        log_debug "Python not available, skipping YAML validation"
        return 0
    fi
    
    if python -c "import yaml; yaml.safe_load(open('${yaml_file}'))" 2>/dev/null; then
        log_debug "✓ YAML validation passed: ${yaml_file}"
        return 0
    else
        log_warn "⚠ YAML validation failed: ${yaml_file} - file may have syntax errors"
        return 1
    fi
}

# Create directory and check if successful
create_directory() {
    local dir="$1"
    
    if [ ! -d "${dir}" ]; then
        log_debug "Creating directory: ${dir}"
        mkdir -p "${dir}" 2>/dev/null || {
            log_error "Failed to create directory: ${dir}"
            return 1
        }
    fi
    
    if [ ! -w "${dir}" ]; then
        log_error "Directory not writable: ${dir}"
        return 1
    fi
    
    return 0
}

# Make backup of existing file if it exists
backup_file() {
    local file="$1"
    
    if [ "${BACKUP_CONFIGS}" != "true" ]; then
        return 0
    fi
    
    if [ -f "${file}" ]; then
        local backup_file="${file}.bak.$(date '+%Y%m%d%H%M%S')"
        log_debug "Backing up ${file} to ${backup_file}"
        cp "${file}" "${backup_file}" 2>/dev/null || {
            log_warn "Failed to backup file: ${file}"
            return 1
        }
    fi
    
    return 0
}

# Copy file if it exists in source and validate YAML
copy_file() {
    local src="$1"
    local dest="$2"
    
    if [ -f "${src}" ]; then
        # Create destination directory if it doesn't exist
        create_directory "$(dirname "${dest}")" || return 1
        
        # Backup existing file
        backup_file "${dest}"
        
        # Copy the file
        log_debug "Copying ${src} → ${dest}"
        cp -p "${src}" "${dest}" 2>/dev/null || {
            log_error "Failed to copy file: ${src} → ${dest}"
            return 1
        }
        
        # Validate YAML syntax
        if [[ "${dest}" == *.yaml || "${dest}" == *.yml ]]; then
            validate_yaml "${dest}"
        fi
        
        return 0
    else
        log_debug "Source file not found: ${src}"
        return 1
    fi
}

# Copy a directory recursively if it exists
copy_directory() {
    local src_dir="$1"
    local dest_dir="$2"
    
    if [ ! -d "${src_dir}" ]; then
        log_debug "Source directory not found: ${src_dir}"
        return 1
    fi
    
    # Create destination directory
    create_directory "${dest_dir}" || return 1
    
    # Use rsync if available for more efficient copying
    if command_exists rsync; then
        log_debug "Using rsync to copy directory: ${src_dir} → ${dest_dir}"
        rsync -a "${src_dir}/" "${dest_dir}/" 2>/dev/null || {
            log_error "Failed to copy directory with rsync: ${src_dir} → ${dest_dir}"
            return 1
        }
    else
        # Fallback to cp
        log_debug "Using cp to copy directory: ${src_dir} → ${dest_dir}"
        cp -R "${src_dir}"/* "${dest_dir}/" 2>/dev/null || {
            log_error "Failed to copy directory: ${src_dir} → ${dest_dir}"
            return 1
        }
    fi
    
    # Validate all YAML files in the directory
    if [ "${VALIDATE_YAML}" = "true" ] && command_exists find; then
        log_debug "Validating YAML files in: ${dest_dir}"
        find "${dest_dir}" -type f \( -name "*.yaml" -o -name "*.yml" \) -exec bash -c "validate_yaml {}" \;
    fi
    
    return 0
}

# --------------------------------------
# Main Logic
# --------------------------------------

log_section "CONFIG COPY"
log_info "Copying configuration files from ${CONFIG_SRC} to ${CONFIG_DEST}"
log_info "Environment: ${CONFIG_ENV}"
log_info "Service type: ${SERVICE_TYPE}"

# Check if source directory exists
if [ ! -d "${CONFIG_SRC}" ]; then
    log_warn "Source directory not found: ${CONFIG_SRC}"
    log_info "No configuration files to copy. Using default configurations."
    exit 0
fi

# Check available disk space
check_disk_space || log_warn "Proceeding despite low disk space"

# Create main destination directory
create_directory "${CONFIG_DEST}" || {
    log_error "Failed to create destination directory: ${CONFIG_DEST}"
    exit 1
}

# Define directory structure
DIRECTORIES=(
    "environments"
    "data"
    "models"
    "app"
    "infrastructure"
    "node_network"
)

# Create directory structure
for dir in "${DIRECTORIES[@]}"; do
    create_directory "${CONFIG_DEST}/${dir}"
done

# -------------------------------------
# 1. First attempt to copy whole directory structure if it exists
# -------------------------------------
if [ -d "${CONFIG_SRC}/fks" ]; then
    log_info "Found FKS config directory, copying entire structure"
    if copy_directory "${CONFIG_SRC}/fks" "${CONFIG_DEST}"; then
        log_info "Successfully copied entire FKS configuration directory"
        # Still need to check for service-specific configs outside the structure
        if copy_file "${CONFIG_SRC}/${SERVICE_TYPE}.yaml" "${CONFIG_DEST}/${SERVICE_TYPE}.yaml"; then
            log_info "Copied service-specific configuration: ${SERVICE_TYPE}.yaml"
        fi
        exit 0
    else
        log_warn "Failed to copy entire directory, falling back to individual file copy"
    fi
fi

# -------------------------------------
# 2. Copy individual files if directory copy failed or structure is different
# -------------------------------------
log_info "Copying individual configuration files"

# Counter for successful copies
COPIED_COUNT=0
FAILED_COUNT=0

# Copy main config file
if copy_file "${CONFIG_SRC}/main.yaml" "${CONFIG_DEST}/main.yaml"; then
    ((COPIED_COUNT++))
else
    ((FAILED_COUNT++))
fi

# Copy environment config files
if copy_file "${CONFIG_SRC}/environments/base.yaml" "${CONFIG_DEST}/environments/base.yaml"; then
    ((COPIED_COUNT++))
else
    ((FAILED_COUNT++))
fi

if copy_file "${CONFIG_SRC}/environments/${CONFIG_ENV}.yaml" "${CONFIG_DEST}/environments/${CONFIG_ENV}.yaml"; then
    ((COPIED_COUNT++))
else
    ((FAILED_COUNT++))
fi

# Copy service config files - standard services
SERVICE_FILES=(
    "api.yaml"
    "worker.yaml"
    "app.yaml"
    "data.yaml"
    "web.yaml"
    "training.yaml"
)

# Copy service files
for file in "${SERVICE_FILES[@]}"; do
    if copy_file "${CONFIG_SRC}/${file}" "${CONFIG_DEST}/${file}"; then
        ((COPIED_COUNT++))
    else
        ((FAILED_COUNT++))
    fi
done

# Always try to copy the current service type config
if [ -n "${SERVICE_TYPE}" ] && ! [[ " ${SERVICE_FILES[@]} " =~ " ${SERVICE_TYPE}.yaml " ]]; then
    if copy_file "${CONFIG_SRC}/${SERVICE_TYPE}.yaml" "${CONFIG_DEST}/${SERVICE_TYPE}.yaml"; then
        log_info "Copied service-specific configuration: ${SERVICE_TYPE}.yaml"
        ((COPIED_COUNT++))
    else
        ((FAILED_COUNT++))
    fi
fi

# Copy domain-specific config files
DATA_FILES=(
    "data/sources.yaml"
    "data/features.yaml"
)

MODELS_FILES=(
    "models/common.yaml"
    "models/bayesian.yaml"
    "models/xgboost.yaml"
)

APP_FILES=(
    "app/server.yaml"
    "app/ui.yaml"
    "app/charts.yaml"
)

INFRASTRUCTURE_FILES=(
    "infrastructure/global.yaml"
    "infrastructure/build.yaml"
    "infrastructure/services.yaml"
    "infrastructure/external.yaml"
)

NETWORK_FILES=(
    "node_network/registry.yaml"
    "node_network/node.yaml"
    "node_network/connector.yaml"
)

# Combine all domain files
DOMAIN_FILES=(
    "${DATA_FILES[@]}"
    "${MODELS_FILES[@]}"
    "${APP_FILES[@]}"
    "${INFRASTRUCTURE_FILES[@]}"
    "${NETWORK_FILES[@]}"
)

# Copy domain files
for file in "${DOMAIN_FILES[@]}"; do
    if copy_file "${CONFIG_SRC}/${file}" "${CONFIG_DEST}/${file}"; then
        ((COPIED_COUNT++))
    else
        ((FAILED_COUNT++))
    fi
done

# Check for environment-specific service config
if copy_file "${CONFIG_SRC}/${SERVICE_TYPE}.${CONFIG_ENV}.yaml" "${CONFIG_DEST}/${SERVICE_TYPE}.yaml"; then
    log_info "Copied environment-specific service configuration: ${SERVICE_TYPE}.${CONFIG_ENV}.yaml"
    ((COPIED_COUNT++))
fi

# Report results
log_section "RESULTS"
log_info "Configuration copy completed: ${COPIED_COUNT} files copied, ${FAILED_COUNT} files not found in source"

if [ ${COPIED_COUNT} -eq 0 ]; then
    log_warn "No configuration files were copied. Using default configurations."
    exit 0
else
    log_info "Configuration files copied successfully."
    exit 0
fi