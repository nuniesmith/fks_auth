#!/bin/bash
# Update all FKS services with latest templates

set -euo pipefail

FKS_ROOT="/home/jordan/oryx/code/repos/fks"
SERVICES=("fks_api" "fks_auth" "fks_data" "fks_engine" "fks_training" "fks_transformer" "fks_worker" "fks_execution" "fks_nodes" "fks_config" "fks_ninja" "fks_web" "fks_nginx")

for service in "${SERVICES[@]}"; do
    if [[ -d "$FKS_ROOT/$service" ]]; then
        echo "Updating $service..."
        cd "$FKS_ROOT/$service"
        
        # Copy service management script
        cp "$FKS_ROOT/shared/scripts/templates/fks-service.sh" ./
        
        # Set service-specific environment
        SERVICE_NAME=$(echo "$service" | tr '_' '-')
        sed -i "s/FKS_SERVICE_NAME:-fks-service/FKS_SERVICE_NAME:-$SERVICE_NAME/g" fks-service.sh
        
        echo "✅ Updated $service"
    fi
done
