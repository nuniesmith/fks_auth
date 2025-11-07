#!/bin/bash
# Container initialization wrapper script
set -e

# Import common functions if available
if [ -f "/app/scripts/docker/common.sh" ]; then
    source "/app/scripts/docker/common.sh"
else
    # Define minimal logging functions
    log_info() { echo -e "[INFO] $1"; }

log_info "Initializing container for ${SERVICE_NAME} service"

# Run config copy script if config source exists
if [ -d "/config-src" ]; then
    log_info "Copying configuration files from /config-src"
    /app/scripts/docker/copy_configs.sh
fi

# Run setup directories script to ensure all paths exist
if [ -f "/app/scripts/docker/setup_directories.sh" ]; then
    log_info "Setting up service directories"
    /app/scripts/docker/setup_directories.sh
fi

# Execute the original entrypoint with all arguments
log_info "Starting service entrypoint"
exec "$@"