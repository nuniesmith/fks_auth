#!/bin/bash
# Setup all required directories for FKS services
# This script can be used during both build and container startup

# Import common functions if available
if [ -f "/app/scripts/docker/common.sh" ]; then
    source "/app/scripts/docker/common.sh"
else
    # Define minimal logging and directory creation functions
    log_info() { echo -e "[INFO] $1"; }
    create_and_verify_dir() { mkdir -p "$1" 2>/dev/null || echo "Failed to create $1"; }

    # Base directories
    APP_DIR=${APP_DIR:-/app}
    SRC_DIR=${SRC_DIR:-${APP_DIR}/src}
    DATA_DIR=${DATA_DIR:-${APP_DIR}/data}
    CONFIG_DIR=${CONFIG_DIR:-${APP_DIR}/config}
    SERVICE_TYPE=${SERVICE_TYPE:-app}
    SERVICE_NAME=${SERVICE_NAME:-fks_${SERVICE_TYPE}}
    SERVICE_RUNTIME=${SERVICE_RUNTIME:-python}
    USER_NAME=${USER_NAME:-appuser}
fi

log_info "Setting up directories for ${SERVICE_TYPE} service"

# Core directories needed by all services
CORE_DIRS=(
    "${APP_DIR}/logs"
    "${APP_DIR}/data"
    "${APP_DIR}/docs"
    "${APP_DIR}/outputs"
    "${APP_DIR}/models"
    "${APP_DIR}/bin"
    "${APP_DIR}/bin/network"
    "${APP_DIR}/bin/execution"
    "${APP_DIR}/bin/connector"
    "${APP_DIR}/checkpoints"
    "${APP_DIR}/config/fks"
    "${APP_DIR}/config/fks/environments"
    "${APP_DIR}/config/fks/data"
    "${APP_DIR}/config/fks/models"
    "${APP_DIR}/config/fks/app"
    "${APP_DIR}/config/fks/infrastructure"
    "${APP_DIR}/config/fks/node_network"
    "${APP_DIR}/outputs/${SERVICE_NAME}"
    "${APP_DIR}/data/cache/${SERVICE_NAME}"
)

# Create all core directories
for dir in "${CORE_DIRS[@]}"; do
    create_and_verify_dir "$dir"
    chmod -R 775 "$dir" 2>/dev/null || true
done

# Python-specific directories
if [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then
    PYTHON_DIRS=(
        "/home/${USER_NAME}/.matplotlib"
        "/home/${USER_NAME}/.config/kaggle"
        "${APP_DIR}/api"
        "${APP_DIR}/worker"
        "${APP_DIR}/app"
        "${APP_DIR}/data"
        "${APP_DIR}/pine"
        "${APP_DIR}/web"
        "${APP_DIR}/training"
        "${APP_DIR}/watcher"
        "${APP_DIR}/data/raw"
        "${APP_DIR}/data/cleaned"
        "${APP_DIR}/data/processed"
        "${APP_DIR}/data/csv"
        "${APP_DIR}/data/cache"
        "${APP_DIR}/data/models"
        "${APP_DIR}/data/training_results"
        "${APP_DIR}/data/logs"
        "${APP_DIR}/data/storage"
        "${APP_DIR}/data/backtest/results"
        "${SRC_DIR}/data/models"
        "${SRC_DIR}/data/training_results"
        "${SRC_DIR}/data/logs"
        "${SRC_DIR}/data/storage"
    )

    # Create Python-specific directories
    for dir in "${PYTHON_DIRS[@]}"; do
        create_and_verify_dir "$dir"
        chmod -R 777 "$dir" 2>/dev/null || true
    done

    # Touch kaggle config file
    touch "/home/${USER_NAME}/.config/kaggle/kaggle.json" 2>/dev/null || true
    chmod 600 "/home/${USER_NAME}/.config/kaggle/kaggle.json" 2>/dev/null || true
fi

# Service-specific directory setup
case "$SERVICE_TYPE" in
    api)
        create_and_verify_dir "${APP_DIR}/api/static"
        create_and_verify_dir "${APP_DIR}/api/templates"
        ;;
    data)
        create_and_verify_dir "${APP_DIR}/data/raw"
        create_and_verify_dir "${APP_DIR}/data/cleaned"
        create_and_verify_dir "${APP_DIR}/data/processed"
        ;;
    training)
        create_and_verify_dir "${APP_DIR}/models"
        create_and_verify_dir "${APP_DIR}/checkpoints"
        ;;
    watcher)
        create_and_verify_dir "${APP_DIR}/logs/services"
        ;;
esac

# Set proper ownership if running as root
if [ "$(id -u)" = "0" ]; then
    chown -R ${USER_NAME}:${USER_NAME} /app /home/${USER_NAME} 2>/dev/null || true
fi

log_info "Directory setup complete"