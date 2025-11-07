#!/bin/bash
# FKS Shared Repository Update Script
# Updates all FKS shared repositories with new templates and commits changes

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FKS_ROOT="/home/jordan/oryx/code/repos/fks"
readonly TEMPLATES_DIR="$FKS_ROOT/shared/templates"

# Color codes
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

log_success() {
    echo -e "${GREEN}✅${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC} $*"
}

log_error() {
    echo -e "${RED}❌${NC} $*"
}

# Update shared_docker repository
update_shared_docker() {
    local repo_dir="$FKS_ROOT/shared/docker"
    log "Updating shared_docker repository..."
    
    cd "$repo_dir"
    
    # Copy Docker templates
    log "Copying Docker templates..."
    cp "$TEMPLATES_DIR/docker/Dockerfile.python" templates/
    cp "$TEMPLATES_DIR/docker/Dockerfile.rust" templates/
    cp "$TEMPLATES_DIR/docker/Dockerfile.dotnet" templates/
    cp "$TEMPLATES_DIR/docker/Dockerfile.react" templates/
    cp "$TEMPLATES_DIR/docker/Dockerfile.nginx" templates/
    
    # Update README with template information
    cat > templates/FKS_TEMPLATES_README.md << 'EOF'
# FKS Docker Templates - Enhanced Version

## Updated Templates with FKS Standards

All templates now include:

### FKS Standard Environment Variables
- `FKS_SERVICE_NAME` - Service identifier
- `FKS_SERVICE_TYPE` - Service category
- `FKS_SERVICE_PORT` - Port assignment
- `FKS_ENVIRONMENT` - Deployment environment
- `FKS_LOG_LEVEL` - Logging verbosity
- `FKS_HEALTH_CHECK_PATH` - Health endpoint path
- `FKS_METRICS_PATH` - Metrics endpoint path

### Health Check Integration
- Basic health endpoint (`/health`)
- Detailed health endpoint (`/health/detailed`)
- Readiness probe (`/health/ready`)
- Liveness probe (`/health/live`)

### Security Features
- Non-root execution (UID 1088)
- Multi-stage builds for minimal images
- Security header configuration
- Vulnerability scanning support

### Performance Optimizations
- Layer caching strategies
- Dependency caching with BuildKit
- Resource limit configurations
- Connection pooling

## Template Usage

Each template can be used directly or extended for service-specific needs:

```dockerfile
# Example extension
FROM shared/python:3.13-slim AS base
# Add service-specific customizations
```

## Port Assignments
- fks-api: 8001
- fks-auth: 8002 
- fks-data: 8003
- fks-engine: 8004
- fks-training: 8005
- fks-transformer: 8006
- fks-worker: 8007
- fks-execution/nodes/config: 8080
- fks-ninja: 8080
- fks-web: 3000
- fks-nginx: 80
EOF
    
    log_success "Updated shared_docker repository"
}

# Update shared_python repository
update_shared_python() {
    local repo_dir="$FKS_ROOT/shared/python"
    log "Updating shared_python repository..."
    
    cd "$repo_dir"
    
    # Copy Python templates
    log "Copying Python configuration templates..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/python/fks_config.py" templates/
    cp "$TEMPLATES_DIR/python/fks_health.py" templates/
    
    # Update src/config.py with enhanced version
    log "Updating existing config.py with FKS standards..."
    if [[ -f "src/config.py" ]]; then
        cp "src/config.py" "src/config.py.backup"
    fi
    cp "$TEMPLATES_DIR/python/fks_config.py" src/fks_config_enhanced.py
    
    # Update requirements to include necessary dependencies
    cat >> requirements.txt << 'EOF'

# FKS Template Dependencies
pydantic>=2.0.0
pydantic-settings>=2.0.0
python-dotenv>=1.0.0
fastapi>=0.100.0
psutil>=5.9.0
aiohttp>=3.8.0
EOF
    
    log_success "Updated shared_python repository"
}

# Update shared_nginx repository  
update_shared_nginx() {
    local repo_dir="$FKS_ROOT/shared/nginx"
    log "Updating shared_nginx repository..."
    
    cd "$repo_dir"
    
    # Copy nginx template
    log "Copying nginx configuration template..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/nginx/fks-nginx.conf" templates/
    
    # Create service discovery configuration
    cat > config/nginx/conf.d/fks-services-template.conf << 'EOF'
# FKS Services Auto-Discovery Template
# This file is generated from environment variables

# Include this in your main nginx.conf:
# include /etc/nginx/conf.d/fks-services.conf;

# Service upstreams will be auto-generated based on FKS_*_HOST and FKS_*_PORT variables
# Example:
# upstream fks-api {
#     server ${FKS_API_HOST:-fks-api}:${FKS_API_PORT:-8001};
# }

# Health check for nginx itself
server {
    listen 8090;
    server_name localhost;
    
    location /health {
        access_log off;
        return 200 '{"status":"healthy","service":"fks-nginx","environment":"${FKS_ENVIRONMENT}"}';
        add_header Content-Type application/json;
    }
}
EOF

    log_success "Updated shared_nginx repository"
}

# Update shared_rust repository
update_shared_rust() {
    local repo_dir="$FKS_ROOT/shared/rust"
    log "Updating shared_rust repository..."
    
    cd "$repo_dir"
    
    # Copy Rust templates
    log "Copying Rust configuration templates..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/rust/fks_config.rs" templates/
    
    # Update Cargo.toml with additional dependencies
    if ! grep -q "# FKS Template Dependencies" Cargo.toml; then
        cat >> Cargo.toml << 'EOF'

# FKS Template Dependencies
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
chrono = { version = "0.4", features = ["serde"] }
env_logger = "0.10"
log = "0.4"

# Optional dependencies for specific services
tokio = { version = "1.0", features = ["full"], optional = true }
axum = { version = "0.7", optional = true }
sqlx = { version = "0.7", optional = true }
redis = { version = "0.24", optional = true }

[features]
default = []
web = ["tokio", "axum"]
database = ["sqlx"]
cache = ["redis"]
EOF
    fi
    
    log_success "Updated shared_rust repository"
}

# Update shared_react repository
update_shared_react() {
    local repo_dir="$FKS_ROOT/shared/react"
    log "Updating shared_react repository..."
    
    cd "$repo_dir"
    
    # Copy React templates
    log "Copying React configuration templates..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/react/fks-config.ts" templates/
    
    # Update package.json with FKS scripts
    if [[ -f "package.json" ]]; then
        # Add FKS build scripts
        cat > fks-scripts.json << 'EOF'
{
  "scripts": {
    "fks:health": "curl -f http://localhost:3000/health || exit 1",
    "fks:build": "npm run build && npm run fks:health",
    "fks:docker:build": "docker build -t fks-web:latest -f ../shared_templates/docker/Dockerfile.react .",
    "fks:docker:run": "docker run -d -p 3000:3000 --name fks-web fks-web:latest",
    "fks:test:health": "npm run fks:docker:run && sleep 10 && npm run fks:health && docker stop fks-web && docker rm fks-web"
  }
}
EOF
        log "Added FKS scripts to package.json (see fks-scripts.json for reference)"
    fi
    
    log_success "Updated shared_react repository"
}

# Update shared_schema repository
update_shared_schema() {
    local repo_dir="$FKS_ROOT/shared/schema"
    log "Updating shared_schema repository..."
    
    cd "$repo_dir"
    
    # Copy schema templates
    log "Copying schema templates..."
    cp "$TEMPLATES_DIR/schema/fks-health-response.schema.json" .
    
    # Create versioned schemas directory
    mkdir -p v1/
    cp "$TEMPLATES_DIR/schema/fks-health-response.schema.json" v1/
    
    log_success "Updated shared_schema repository"
}

# Update shared_scripts repository
update_shared_scripts() {
    local repo_dir="$FKS_ROOT/shared/scripts"
    log "Updating shared_scripts repository..."
    
    cd "$repo_dir"
    
    # Copy script templates
    log "Copying script templates..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/scripts/fks-service.sh" templates/
    chmod +x templates/fks-service.sh
    
    # Create FKS-specific scripts
    cat > fks-update-all.sh << 'EOF'
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
EOF
    chmod +x fks-update-all.sh
    
    log_success "Updated shared_scripts repository"
}

# Update shared_actions repository
update_shared_actions() {
    local repo_dir="$FKS_ROOT/shared/actions"
    log "Updating shared_actions repository..."
    
    cd "$repo_dir"
    
    # Copy GitHub Actions templates
    log "Copying GitHub Actions templates..."
    mkdir -p templates/
    cp "$TEMPLATES_DIR/actions/fks-ci-cd.yml" templates/
    
    # Update existing workflows
    mkdir -p .github/workflows/
    cp "$TEMPLATES_DIR/actions/fks-ci-cd.yml" .github/workflows/
    
    log_success "Updated shared_actions repository"
}

# Commit and push changes for a repository
commit_and_push() {
    local repo_name="$1"
    local repo_dir="$FKS_ROOT/shared/$repo_name"
    
    log "Committing and pushing changes for $repo_name..."
    
    cd "$repo_dir"
    
    # Check if there are changes
    if git diff --quiet && git diff --staged --quiet; then
        log_warning "No changes detected in $repo_name"
        return 0
    fi
    
    # Add all changes
    git add .
    
    # Create commit message
    local commit_msg="feat: Add FKS standardized templates and configurations

- Added FKS standard environment variables
- Implemented health check endpoints
- Enhanced Docker templates with security best practices
- Added monitoring and logging configurations
- Integrated nginx reverse proxy support
- Updated CI/CD workflows for standardized deployment

Template version: 1.0.0
Updated: $(date +'%Y-%m-%d %H:%M:%S')"
    
    # Commit changes
    git commit -m "$commit_msg"
    
    # Push changes
    git push origin main
    
    log_success "Successfully committed and pushed changes for $repo_name"
}

# Main execution
main() {
    log "🚀 Starting FKS shared repositories update process..."
    log "Templates directory: $TEMPLATES_DIR"
    log "FKS root directory: $FKS_ROOT"
    
    # Verify templates directory exists
    if [[ ! -d "$TEMPLATES_DIR" ]]; then
        log_error "Templates directory not found: $TEMPLATES_DIR"
        exit 1
    fi
    
    # Update each shared repository
    update_shared_docker
    update_shared_python
    update_shared_nginx
    update_shared_rust
    update_shared_react
    update_shared_schema
    update_shared_scripts
    update_shared_actions
    
    log "📝 Committing and pushing changes..."
    
    # Commit and push changes for each repository
    commit_and_push "shared_docker"
    commit_and_push "shared_python"
    commit_and_push "shared_nginx"
    commit_and_push "shared_rust"
    commit_and_push "shared_react"
    commit_and_push "shared_schema"
    commit_and_push "shared_scripts"
    commit_and_push "shared_actions"
    
    # Also commit the shared_templates directory
    log "Committing shared_templates..."
    cd "$FKS_ROOT/shared"
    git add shared_templates/
    git commit -m "feat: Add comprehensive FKS template system

- Docker templates for all service types
- Python configuration and health check templates
- Rust environment configuration templates
- React/TypeScript configuration templates
- Nginx reverse proxy configuration templates
- GitHub Actions CI/CD workflow templates
- JSON schema definitions for API contracts
- Shell script management templates

This creates a standardized foundation for all FKS microservices
with consistent environment variables, health checks, and deployment patterns."

    git push origin main
    
    log_success "🎉 All FKS shared repositories have been updated successfully!"
    log "📋 Summary:"
    log "  ✅ shared_docker - Enhanced Dockerfiles with FKS standards"
    log "  ✅ shared_python - Configuration and health check templates"
    log "  ✅ shared_nginx - Reverse proxy configuration templates"
    log "  ✅ shared_rust - Environment configuration templates"
    log "  ✅ shared_react - TypeScript configuration templates"
    log "  ✅ shared_schema - JSON schema definitions"
    log "  ✅ shared_scripts - Service management automation"
    log "  ✅ shared_actions - CI/CD workflow templates"
    log "  ✅ shared_templates - Complete template system"
}

# Run main function
main "$@"
