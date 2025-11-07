#!/bin/bash
# Initialize configuration files for FKS services
set -e

# Import common functions if available
if [ -f "/app/scripts/docker/common.sh" ]; then
    source "/app/scripts/docker/common.sh"
else
    # Define minimal logging functions
    log_info() { echo -e "[INFO] $1"; }
    log_warn() { echo -e "[WARN] $1" >&2; }
    log_error() { echo -e "[ERROR] $1" >&2; }
fi

# Set default variables with more robust defaults
APP_DIR=${APP_DIR:-/app}
CONFIG_DIR=${CONFIG_DIR:-${APP_DIR}/config}
SERVICE_TYPE=${SERVICE_TYPE:-app}
SERVICE_NAME=${SERVICE_NAME:-fks_${SERVICE_TYPE}}
SERVICE_PORT=${SERVICE_PORT:-8000}
USER_NAME=${USER_NAME:-appuser}

log_info "Setting up configuration files for ${SERVICE_TYPE} service"

# Create core config directory with error handling
if ! mkdir -p "${CONFIG_DIR}/fks"; then
    log_error "Failed to create configuration directory ${CONFIG_DIR}/fks"
    exit 1
fi

# Define all config files that need to be created
CONFIG_FILES=(
    # Base config files
    "${CONFIG_DIR}/fks/main.yaml"
    
    # Environment configs
    "${CONFIG_DIR}/fks/environments/base.yaml"
    "${CONFIG_DIR}/fks/environments/development.yaml"
    "${CONFIG_DIR}/fks/environments/staging.yaml"
    "${CONFIG_DIR}/fks/environments/production.yaml"
    
    # Service configs
    "${CONFIG_DIR}/fks/api.yaml"
    "${CONFIG_DIR}/fks/worker.yaml"
    "${CONFIG_DIR}/fks/app.yaml"
    "${CONFIG_DIR}/fks/data.yaml"
    "${CONFIG_DIR}/fks/pine.yaml"
    "${CONFIG_DIR}/fks/web.yaml"
    "${CONFIG_DIR}/fks/training.yaml"
    "${CONFIG_DIR}/fks/watcher.yaml"
    "${CONFIG_DIR}/fks/market.yaml"
    
    # Network configs
    "${CONFIG_DIR}/fks/node_network/registry.yaml"
    "${CONFIG_DIR}/fks/node_network/node.yaml"
    "${CONFIG_DIR}/fks/node_network/connector.yaml"
    
    # Data configs
    "${CONFIG_DIR}/fks/data/sources.yaml"
    "${CONFIG_DIR}/fks/data/features.yaml"
    
    # Model configs
    "${CONFIG_DIR}/fks/models/common.yaml"
    "${CONFIG_DIR}/fks/models/bayesian.yaml"
    "${CONFIG_DIR}/fks/models/xgboost.yaml"
    
    # App configs
    "${CONFIG_DIR}/fks/app/server.yaml"
    "${CONFIG_DIR}/fks/app/ui.yaml"
    "${CONFIG_DIR}/fks/app/charts.yaml"
    
    # Infrastructure configs
    "${CONFIG_DIR}/fks/infrastructure/global.yaml"
    "${CONFIG_DIR}/fks/infrastructure/build.yaml"
    "${CONFIG_DIR}/fks/infrastructure/services.yaml"
    "${CONFIG_DIR}/fks/infrastructure/external.yaml"
)

# Create each config file if it doesn't exist
for config_file in "${CONFIG_FILES[@]}"; do
    # Create directory if needed
    mkdir -p "$(dirname "$config_file")" 2>/dev/null || {
        log_warn "Could not create directory for $config_file"
        continue
    }

    # Create file if it doesn't exist
    if [ ! -f "$config_file" ]; then
        # Create file with minimal content
        {
            echo "# Configuration file for FKS Trading Systems"
            echo "# Auto-generated on $(date)"
            echo ""

            # Add basic content based on file type
            if [[ "$config_file" == *"${SERVICE_TYPE}.yaml"* ]]; then
                echo "service:"
                echo "  name: ${SERVICE_NAME}"
                echo "  port: ${SERVICE_PORT}"
            fi
        } > "$config_file" || log_warn "Failed to create config file: $config_file"
    fi
done

# Create service-specific config if it doesn't exist
SERVICE_CONFIG="${CONFIG_DIR}/fks/${SERVICE_TYPE}.yaml"
if [ ! -f "$SERVICE_CONFIG" ]; then
    {
        echo "# Configuration for ${SERVICE_TYPE} service"
        echo "service:"
        echo "  name: ${SERVICE_NAME}"
        echo "  port: ${SERVICE_PORT}"
    } > "$SERVICE_CONFIG" || log_error "Failed to create service configuration: $SERVICE_CONFIG"
    
    log_info "Created service configuration: $SERVICE_CONFIG"
fi

# Set permissions with better error handling
if ! chmod -R 775 "${CONFIG_DIR}/fks" 2>/dev/null; then
    log_warn "Could not set permissions for ${CONFIG_DIR}/fks"
fi

# Set ownership if running as root
if [ "$(id -u)" = "0" ]; then
    if ! chown -R ${USER_NAME}:${USER_NAME} "${CONFIG_DIR}/fks" 2>/dev/null; then
        log_warn "Could not set ownership of ${CONFIG_DIR}/fks to ${USER_NAME}"
    fi
fi

log_info "Configuration setup complete"