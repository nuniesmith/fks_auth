#!/bin/bash

# FKS Trading Systems - Localhost to Domain Migration Script
# This script systematically updates all localhost references to production domains

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Domain configuration
DOMAIN="fkstrading.xyz"
PROJECT_ROOT="/home/jordan/fks"

# Service mappings
declare -A SERVICE_PORTS=(
    ["api"]="8000"
    ["data"]="9001"
    ["web"]="3000"
    ["worker"]="8001"
    ["nginx"]="80"
    ["ssl-nginx"]="443"
    ["vscode"]="8081"
    ["nodes"]="8080"
    ["authelia"]="9000"
    ["db"]="5432"
    ["cache"]="6379"
    ["ninja"]="7496"
    ["monitor"]="3000"
    ["grafana"]="3001"
    ["prometheus"]="9090"
    ["training"]="8088"
    #!/usr/bin/env bash
    # Shim: migrate-localhost-to-domains moved to migration/migrate-localhost-to-domains.sh
    set -euo pipefail
    NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migration/migrate-localhost-to-domains.sh"
    if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
    
    local env_files=(
        ".env"
        ".env.example" 
        ".env.production"
        ".env.test"
        "src/web/react/.env"
    )
    
    for file in "${env_files[@]}"; do
        local filepath="${PROJECT_ROOT}/${file}"
        if [[ -f "$filepath" ]]; then
            print_info "Updating: $file"
            backup_file "$filepath"
            
            # Update API URLs
            sed -i "s|API_URL=.*localhost.*|API_URL=https://api.${DOMAIN}|g" "$filepath"
            sed -i "s|REACT_APP_API_URL=.*localhost.*|REACT_APP_API_URL=https://api.${DOMAIN}|g" "$filepath"
            sed -i "s|REACT_APP_DATA_URL=.*localhost.*|REACT_APP_DATA_URL=https://data.${DOMAIN}|g" "$filepath"
            sed -i "s|REACT_APP_WS_URL=.*localhost.*|REACT_APP_WS_URL=wss://api.${DOMAIN}/ws|g" "$filepath"
            sed -i "s|WS_URL=.*localhost.*|WS_URL=wss://api.${DOMAIN}/ws|g" "$filepath"
            sed -i "s|DOMAIN_NAME=.*localhost|DOMAIN_NAME=${DOMAIN}|g" "$filepath"
            
            print_info "✓ Updated: $file"
        fi
    done
}

update_github_workflows() {
    print_step "Updating GitHub Workflows"
    
    local workflow_file="${PROJECT_ROOT}/.github/workflows/00-complete.yml"
    if [[ -f "$workflow_file" ]]; then
        print_info "Updating: GitHub workflow"
        backup_file "$workflow_file"
        
        # Update workflow URLs to use domain variables
        sed -i "s|http://localhost:8000|https://api.${DOMAIN}|g" "$workflow_file"
        sed -i "s|http://localhost:3000|https://app.${DOMAIN}|g" "$workflow_file"
        sed -i "s|http://localhost:9001|https://data.${DOMAIN}|g" "$workflow_file"
        sed -i "s|http://localhost|https://app.${DOMAIN}|g" "$workflow_file"
        
        print_info "✓ Updated: GitHub workflow"
    fi
}

update_config_files() {
    print_step "Updating configuration files"
    
    # Update nginx configurations
    find "${PROJECT_ROOT}/config" -name "*.conf" -o -name "*.yaml" -o -name "*.yml" | while read -r file; do
        if [[ -f "$file" ]] && grep -q "localhost" "$file" 2>/dev/null; then
            print_info "Updating config: $(basename "$file")"
            backup_file "$file"
            
            # Update server names and upstream definitions
            sed -i "s|server_name localhost|server_name ${DOMAIN} www.${DOMAIN}|g" "$file"
            sed -i "s|upstream.*localhost|upstream api.${DOMAIN}|g" "$file"
            
            print_info "✓ Updated: $(basename "$file")"
        fi
    done
}

update_scripts() {
    print_step "Updating shell scripts"
    
    local script_files=(
        "start.sh"
        "run.sh"
        "data/start_rithmic.sh"
    )
    
    for file in "${script_files[@]}"; do
        local filepath="${PROJECT_ROOT}/${file}"
        if [[ -f "$filepath" ]]; then
            print_info "Updating script: $file"
            backup_file "$filepath"
            
            # Update status check URLs but keep internal health checks as localhost
            sed -i "s|Web service is accessible at http://localhost:3000|Web service is accessible at https://app.${DOMAIN}|g" "$filepath"
            sed -i "s|API service is accessible at http://localhost:8000|API service is accessible at https://api.${DOMAIN}|g" "$filepath"
            sed -i "s|Nginx is accessible at http://localhost|Nginx is accessible at https://${DOMAIN}|g" "$filepath"
            sed -i "s|Web Interface: http://localhost|Web Interface: https://app.${DOMAIN}|g" "$filepath"
            sed -i "s|API Endpoint: http://localhost:8000|API Endpoint: https://api.${DOMAIN}|g" "$filepath"
            
            print_info "✓ Updated: $file"
        fi
    done
}

update_python_files() {
    print_step "Updating Python configuration files"
    
    # Find Python files with localhost references
    find "${PROJECT_ROOT}/src" -name "*.py" -exec grep -l "localhost" {} \; | while read -r file; do
        if [[ -f "$file" ]]; then
            print_info "Updating Python file: $(basename "$file")"
            backup_file "$file"
            
            # Update CORS origins and API endpoints
            sed -i "s|\"http://localhost:3000\"|\"https://app.${DOMAIN}\"|g" "$file"
            sed -i "s|\"http://localhost:8081\"|\"https://code.${DOMAIN}\"|g" "$file"
            sed -i "s|localhost:8000|api.${DOMAIN}|g" "$file"
            sed -i "s|localhost:9001|data.${DOMAIN}|g" "$file"
            
            print_info "✓ Updated: $(basename "$file")"
        fi
    done
}

update_react_config() {
    print_step "Updating React configuration files"
    
    local react_files=(
        "src/web/react/vite.config.ts"
        "src/web/react/src/config/environment.ts"
        "src/web/react/package.json"
    )
    
    for file in "${react_files[@]}"; do
        local filepath="${PROJECT_ROOT}/${file}"
        if [[ -f "$filepath" ]]; then
            print_info "Updating React config: $(basename "$file")"
            backup_file "$filepath"
            
            # Update proxy targets and environment configs
            sed -i "s|target: ['\"]http://localhost:8000['\"]|target: 'https://api.${DOMAIN}'|g" "$filepath"
            sed -i "s|target: ['\"]http://localhost:9001['\"]|target: 'https://data.${DOMAIN}'|g" "$filepath"
            sed -i "s|ws: true|ws: true, secure: true, changeOrigin: true|g" "$filepath"
            
            print_info "✓ Updated: $(basename "$file")"
        fi
    done
}

create_domain_environment() {
    print_step "Creating production environment file"
    
    local prod_env="${PROJECT_ROOT}/.env.production"
    cat > "$prod_env" <<EOF
# FKS Trading Systems - Production Environment Configuration
# Generated by migrate-localhost-to-domains.sh

# Domain Configuration
DOMAIN_NAME=${DOMAIN}

# Service URLs (Production)
API_URL=https://api.${DOMAIN}
REACT_APP_API_URL=https://api.${DOMAIN}
REACT_APP_DATA_URL=https://data.${DOMAIN}
REACT_APP_WS_URL=wss://api.${DOMAIN}/ws
REACT_APP_VSCODE_URL=https://code.${DOMAIN}

# Vite Configuration
VITE_API_URL=https://api.${DOMAIN}
VITE_DATA_URL=https://data.${DOMAIN}
VITE_WS_URL=wss://api.${DOMAIN}/ws

# Database Configuration
DATABASE_URL=postgresql://fks_user:fks_password@db.${DOMAIN}:5432/fks_trading
REDIS_URL=redis://cache.${DOMAIN}:6379

# SSL/Security
SSL_ENABLED=true
REQUIRE_HTTPS=true
CORS_ORIGIN=https://app.${DOMAIN}

# Monitoring
GRAFANA_URL=https://grafana.${DOMAIN}
PROMETHEUS_URL=https://prometheus.${DOMAIN}

# Trading Platform Integration
NINJATRADER_URL=https://ninja.${DOMAIN}

# AI/ML Services
TRAINING_SERVICE_URL=https://training.${DOMAIN}
TRANSFORMER_SERVICE_URL=https://transformer.${DOMAIN}

# Node Network
NODE_NETWORK_URL=https://nodes.${DOMAIN}

# Authentication
AUTHELIA_URL=https://auth.${DOMAIN}

# Deployment
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=info
EOF

    print_info "✓ Created production environment file"
}

generate_summary() {
    print_step "Migration Summary"
    echo
    print_info "Successfully updated domain references in:"
    echo "  • Docker Compose files"
    echo "  • Environment files"
    echo "  • GitHub Workflows"
    echo "  • Configuration files"
    echo "  • Shell scripts"
    echo "  • Python files"
    echo "  • React configuration"
    echo
    print_info "Domain mappings created:"
    echo "  • Frontend:      https://app.${DOMAIN}"
    echo "  • API:           https://api.${DOMAIN}"
    echo "  • Data Stream:   https://data.${DOMAIN}"
    echo "  • VS Code:       https://code.${DOMAIN}"
    echo "  • Database:      db.${DOMAIN}:5432"
    echo "  • Cache:         cache.${DOMAIN}:6379"
    echo "  • NinjaTrader:   https://ninja.${DOMAIN}"
    echo "  • Monitoring:    https://monitor.${DOMAIN}"
    echo
    print_info "Next steps:"
    echo "  1. Run ./scripts/setup-fks_domains.sh to configure DNS"
    echo "  2. Update your .env file for your environment"
    echo "  3. Restart services with docker-compose up -d"
    echo "  4. Test all endpoints"
    echo
    print_warning "Note: Health checks still use localhost for internal container communication"
    print_warning "This is correct and should not be changed"
}

main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "  FKS Trading Domain Migration"
    echo "========================================"
    echo -e "${NC}"
    
    print_info "Migrating localhost references to ${DOMAIN}"
    echo
    
    # Execute migration steps
    update_docker_compose_files
    update_environment_files
    update_github_workflows
    update_config_files
    update_scripts
    update_python_files
    update_react_config
    create_domain_environment
    
    echo
    generate_summary
}

# Handle script arguments
case "${1:-}" in
    "test")
        # Test mode - show what would be changed without making changes
        print_info "Test mode - showing files that would be updated"
        find "$PROJECT_ROOT" -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.env*" -o -name "*.sh" -o -name "*.py" -o -name "*.ts" -o -name "*.js" -o -name "*.json" \) -exec grep -l "localhost" {} \;
        ;;
    "backup")
        # Create backups of all files before migration
        print_step "Creating backups of all configuration files"
        find "$PROJECT_ROOT" -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.env*" -o -name "*.sh" -o -name "*.py" -o -name "*.ts" -o -name "*.js" \) -exec cp {} {}.backup-$(date +%Y%m%d-%H%M%S) \;
        print_info "✓ Backups created"
        ;;
    *)
        main "$@"
        ;;
esac
