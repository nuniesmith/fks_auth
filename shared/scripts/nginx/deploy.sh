#!/bin/bash
# scripts/deploy.sh
# NGINX Deployment Script
# Supports both bare metal and Docker deployments

set -euo pipefail

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors and formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Default configuration (can be overridden by config file or environment)
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-auto}"  # auto, bare-metal, docker
DEPLOY_PATH="${DEPLOY_PATH:-/opt/nginx-deployment}"
BACKUP_PATH="${BACKUP_PATH:-/opt/nginx-backups}"
NGINX_CONFIG_PATH="${NGINX_CONFIG_PATH:-/etc/nginx}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
NGINX_USER="${NGINX_USER:-http}"
NGINX_GROUP="${NGINX_GROUP:-http}"
DOMAIN="${DOMAIN:-7gram.xyz}"
BACKUP_RETENTION="${BACKUP_RETENTION:-10}"

# Docker specific
COMPOSE_FILE="${COMPOSE_FILE:-${PROJECT_ROOT}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${PROJECT_ROOT}/.env}"

# Global variables
TIMESTAMP=""
BACKUP_DIR=""
DEPLOY_NGINX_CONFIG=false
DEPLOY_WEB_FILES=false

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }
info() { echo -e "${CYAN}ℹ${NC} $1"; }

# Load configuration from file if it exists
load_config() {
    local config_file="${PROJECT_ROOT}/deploy.conf"
    if [[ -f "$config_file" ]]; then
        log "Loading configuration from $config_file"
        # shellcheck source=/dev/null
        source "$config_file"
    fi
}

# Detect deployment type
detect_deployment_type() {
    if [[ "$DEPLOYMENT_TYPE" == "auto" ]]; then
        if command -v docker &> /dev/null && [[ -f "$COMPOSE_FILE" ]]; then
            DEPLOYMENT_TYPE="docker"
            info "Auto-detected Docker deployment"
        else
            DEPLOYMENT_TYPE="bare-metal"
            info "Auto-detected bare metal deployment"
        fi
    fi
}

# Create timestamp for this deployment
init_deployment() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_DIR="$BACKUP_PATH/backup_$TIMESTAMP"
    
    echo "=============================================="
    log "🚀 Starting NGINX Deployment ($DEPLOYMENT_TYPE)"
    log "Timestamp: $TIMESTAMP"
    log "Domain: $DOMAIN"
    echo "=============================================="
}

# =============================================================================
# BACKUP FUNCTIONS
# =============================================================================

create_backup() {
    log "📦 Creating backup of current configuration..."
    
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            create_bare_metal_backup
            ;;
        "docker")
            create_docker_backup
            ;;
        *)
            error "Unknown deployment type: $DEPLOYMENT_TYPE"
            return 1
            ;;
    esac
    
    success "Backup created: $BACKUP_DIR"
    cleanup_old_backups
}

create_bare_metal_backup() {
    sudo mkdir -p "$BACKUP_DIR"
    
    # Backup nginx configuration
    if [[ -d "$NGINX_CONFIG_PATH" ]]; then
        log "Backing up nginx configuration..."
        sudo cp -r "$NGINX_CONFIG_PATH" "$BACKUP_DIR/nginx"
    fi
    
    # Backup web files
    if [[ -d "$WEB_ROOT" ]]; then
        log "Backing up web files..."
        sudo cp -r "$WEB_ROOT" "$BACKUP_DIR/html"
    fi
    
    # Set ownership for backup directory
    sudo chown -R "${USER}:${USER}" "$BACKUP_DIR" 2>/dev/null || true
}

create_docker_backup() {
    mkdir -p "$BACKUP_DIR"
    
    # Backup Docker volumes and configs
    log "Backing up Docker configuration..."
    
    if [[ -d "${PROJECT_ROOT}/config" ]]; then
        cp -r "${PROJECT_ROOT}/config" "$BACKUP_DIR/"
    fi
    
    if [[ -d "${PROJECT_ROOT}/html" ]]; then
        cp -r "${PROJECT_ROOT}/html" "$BACKUP_DIR/"
    fi
    
    # Backup environment file
    if [[ -f "$ENV_FILE" ]]; then
        cp "$ENV_FILE" "$BACKUP_DIR/"
    fi
}

cleanup_old_backups() {
    log "Cleaning up old backups (keeping last $BACKUP_RETENTION)..."
    cd "$BACKUP_PATH"
    ls -t | tail -n +$((BACKUP_RETENTION + 1)) | xargs -r rm -rf
    cd - > /dev/null
}

# =============================================================================
# ROLLBACK FUNCTIONS
# =============================================================================

rollback() {
    local backup_dir="$1"
    
    if [[ -z "$backup_dir" ]] || [[ ! -d "$backup_dir" ]]; then
        error "No valid backup directory provided for rollback"
        return 1
    fi
    
    warning "PERFORMING ROLLBACK to $backup_dir"
    
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            rollback_bare_metal "$backup_dir"
            ;;
        "docker")
            rollback_docker "$backup_dir"
            ;;
        *)
            error "Unknown deployment type: $DEPLOYMENT_TYPE"
            return 1
            ;;
    esac
}

rollback_bare_metal() {
    local backup_dir="$1"
    
    # Restore nginx configuration
    if [[ -d "$backup_dir/nginx" ]]; then
        log "Restoring nginx configuration..."
        sudo cp -r "$backup_dir/nginx/"* "$NGINX_CONFIG_PATH/"
    fi
    
    # Restore web files
    if [[ -d "$backup_dir/html" ]]; then
        log "Restoring web files..."
        sudo cp -r "$backup_dir/html/"* "$WEB_ROOT/"
        sudo chown -R "$NGINX_USER:$NGINX_GROUP" "$WEB_ROOT"
    fi
    
    # Test and reload nginx
    if sudo nginx -t; then
        sudo systemctl reload nginx
        success "Rollback completed successfully"
    else
        error "Rollback failed - nginx configuration is invalid"
        return 1
    fi
}

rollback_docker() {
    local backup_dir="$1"
    
    log "Restoring Docker configuration..."
    
    if [[ -d "$backup_dir/config" ]]; then
        cp -r "$backup_dir/config/"* "${PROJECT_ROOT}/config/"
    fi
    
    if [[ -d "$backup_dir/html" ]]; then
        cp -r "$backup_dir/html/"* "${PROJECT_ROOT}/html/"
    fi
    
    if [[ -f "$backup_dir/.env" ]]; then
        cp "$backup_dir/.env" "$ENV_FILE"
    fi
    
    # Restart containers
    docker-compose restart nginx-server
    success "Docker rollback completed successfully"
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_deployment_files() {
    log "🔍 Validating deployment files..."
    
    DEPLOY_NGINX_CONFIG=false
    DEPLOY_WEB_FILES=false
    
    # Check for nginx configuration
    if [[ -d "nginx-config" ]] || [[ -d "${PROJECT_ROOT}/config/nginx" ]]; then
        DEPLOY_NGINX_CONFIG=true
        info "Found nginx configuration files"
    fi
    
    # Check for web files
    if [[ -d "html" ]] || [[ -d "public" ]] || [[ -d "${PROJECT_ROOT}/html" ]]; then
        DEPLOY_WEB_FILES=true
        info "Found web files to deploy"
    fi
    
    if [[ "$DEPLOY_NGINX_CONFIG" == false ]] && [[ "$DEPLOY_WEB_FILES" == false ]]; then
        warning "No files to deploy found"
        exit 0
    fi
}

test_nginx_configuration() {
    if [[ "$DEPLOY_NGINX_CONFIG" != true ]]; then
        return 0
    fi
    
    log "🧪 Testing nginx configuration..."
    
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            test_bare_metal_nginx_config
            ;;
        "docker")
            test_docker_nginx_config
            ;;
    esac
}

test_bare_metal_nginx_config() {
    local temp_dir="/tmp/nginx-deploy-$TIMESTAMP"
    mkdir -p "$temp_dir"
    
    # Copy current nginx config to temp directory
    cp -r "$NGINX_CONFIG_PATH/"* "$temp_dir/"
    
    # Apply new configuration to temp directory
    apply_config_to_directory "$temp_dir"
    
    # Test the configuration
    if sudo nginx -t -c "$temp_dir/nginx.conf"; then
        success "Nginx configuration test passed"
    else
        error "Nginx configuration test failed"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    rm -rf "$temp_dir"
}

test_docker_nginx_config() {
    # For Docker, we'll test when the container starts
    log "Docker nginx configuration will be tested during container startup"
}

apply_config_to_directory() {
    local target_dir="$1"
    
    # Apply new configuration to target directory
    if [[ -d "nginx-config/conf.d" ]]; then
        cp -r nginx-config/conf.d/* "$target_dir/conf.d/" 2>/dev/null || true
    fi
    
    if [[ -d "nginx-config/includes" ]]; then
        mkdir -p "$target_dir/includes"
        cp -r nginx-config/includes/* "$target_dir/includes/" 2>/dev/null || true
    fi
    
    if [[ -f "nginx-config/nginx.conf" ]]; then
        cp nginx-config/nginx.conf "$target_dir/nginx.conf"
    fi
    
    # Replace domain placeholders
    replace_placeholders_in_directory "$target_dir"
}

replace_placeholders_in_directory() {
    local target_dir="$1"
    
    find "$target_dir" -name "*.conf" -type f -exec sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" {} \; 2>/dev/null || true
    find "$target_dir" -name "*.conf" -type f -exec sed -i "s/7gram\.xyz/$DOMAIN/g" {} \; 2>/dev/null || true
}

# =============================================================================
# DEPLOYMENT FUNCTIONS
# =============================================================================

deploy_configuration() {
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            deploy_bare_metal
            ;;
        "docker")
            deploy_docker
            ;;
        *)
            error "Unknown deployment type: $DEPLOYMENT_TYPE"
            exit 1
            ;;
    esac
}

deploy_bare_metal() {
    deploy_bare_metal_nginx_config
    deploy_bare_metal_web_files
    reload_bare_metal_nginx
}

deploy_bare_metal_nginx_config() {
    if [[ "$DEPLOY_NGINX_CONFIG" != true ]]; then
        return 0
    fi
    
    log "🔧 Deploying nginx configuration..."
    
    # Deploy conf.d files
    if [[ -d "nginx-config/conf.d" ]]; then
        log "Deploying conf.d files..."
        sudo mkdir -p "$NGINX_CONFIG_PATH/conf.d"
        sudo cp -r nginx-config/conf.d/* "$NGINX_CONFIG_PATH/conf.d/"
        success "conf.d files deployed"
    fi
    
    # Deploy include files
    if [[ -d "nginx-config/includes" ]]; then
        log "Deploying include files..."
        sudo mkdir -p "$NGINX_CONFIG_PATH/includes"
        sudo cp -r nginx-config/includes/* "$NGINX_CONFIG_PATH/includes/"
        success "Include files deployed"
    fi
    
    # Deploy main nginx.conf
    if [[ -f "nginx-config/nginx.conf" ]]; then
        log "Deploying main nginx.conf..."
        sudo cp nginx-config/nginx.conf "$NGINX_CONFIG_PATH/nginx.conf"
        success "nginx.conf deployed"
    fi
    
    # Replace domain placeholders in deployed config
    log "Updating domain placeholders..."
    sudo find "$NGINX_CONFIG_PATH" -name "*.conf" -type f -exec sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" {} \; 2>/dev/null || true
    sudo find "$NGINX_CONFIG_PATH" -name "*.conf" -type f -exec sed -i "s/7gram\.xyz/$DOMAIN/g" {} \; 2>/dev/null || true
    
    # Test final configuration
    log "Testing deployed nginx configuration..."
    if sudo nginx -t; then
        success "Deployed nginx configuration is valid"
    else
        error "Deployed nginx configuration is invalid"
        rollback "$BACKUP_DIR"
        exit 1
    fi
}

deploy_bare_metal_web_files() {
    if [[ "$DEPLOY_WEB_FILES" != true ]]; then
        return 0
    fi
    
    log "📄 Deploying web files..."
    
    # Ensure web root exists
    sudo mkdir -p "$WEB_ROOT"
    
    # Deploy HTML files
    if [[ -d "html" ]]; then
        log "Deploying files from html/ directory..."
        sudo cp -r html/* "$WEB_ROOT/"
    fi
    
    if [[ -d "public" ]]; then
        log "Deploying files from public/ directory..."
        sudo cp -r public/* "$WEB_ROOT/"
    fi
    
    # Update placeholders in HTML files
    log "Updating placeholders in web files..."
    sudo find "$WEB_ROOT" -name "*.html" -type f -exec sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" {} \; 2>/dev/null || true
    sudo find "$WEB_ROOT" -name "*.html" -type f -exec sed -i "s/7gram\.xyz/$DOMAIN/g" {} \; 2>/dev/null || true
    
    # Set proper permissions
    log "Setting file permissions..."
    sudo chown -R "$NGINX_USER:$NGINX_GROUP" "$WEB_ROOT"
    sudo chmod -R 755 "$WEB_ROOT"
    sudo find "$WEB_ROOT" -type f -exec chmod 644 {} \;
    
    success "Web files deployed and permissions set"
}

reload_bare_metal_nginx() {
    log "🔄 Reloading nginx..."
    
    # Final configuration test
    if sudo nginx -t; then
        log "Configuration test passed, reloading nginx..."
        
        if sudo systemctl reload nginx; then
            success "Nginx reloaded successfully"
        else
            error "Nginx reload failed"
            rollback "$BACKUP_DIR"
            exit 1
        fi
    else
        error "Final nginx configuration test failed"
        rollback "$BACKUP_DIR"
        exit 1
    fi
    
    # Verify nginx is running
    if sudo systemctl is-active --quiet nginx; then
        success "Nginx is running"
    else
        error "Nginx is not running after reload"
        rollback "$BACKUP_DIR"
        exit 1
    fi
}

deploy_docker() {
    check_docker_prerequisites
    create_docker_directories
    deploy_docker_stack
}

check_docker_prerequisites() {
    log "Checking Docker prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check environment file
    if [[ ! -f "$ENV_FILE" ]]; then
        if [[ -f "${ENV_FILE}.example" ]]; then
            warning "No .env file found, copying from .env.example"
            cp "${ENV_FILE}.example" "$ENV_FILE"
            warning "Please edit .env file with your configuration"
            exit 1
        else
            error "No .env file found"
            exit 1
        fi
    fi
    
    success "Docker prerequisites checked"
}

create_docker_directories() {
    log "Creating required directories..."
    
    local dirs=(
        "config/nginx/conf.d"
        "config/nginx/includes"
        "config/nginx/error-pages"
        "html"
        "assets"
        "monitoring/prometheus"
        "monitoring/grafana/provisioning/dashboards"
        "monitoring/grafana/provisioning/datasources"
        "logs/nginx"
        "logs/letsencrypt"
        "backups"
        "data/certbot/certs"
        "data/certbot/www"
        "data/nginx/ssl"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "${PROJECT_ROOT}/${dir}"
    done
    
    success "Directories created"
}

deploy_docker_stack() {
    local profile="${1:-}"
    log "Deploying Docker stack${profile:+ with profile: $profile}..."
    
    cd "$PROJECT_ROOT"
    
    # Pull latest images
    log "Pulling latest images..."
    if [[ -n "$profile" ]]; then
        docker-compose --profile "$profile" pull
    else
        docker-compose pull
    fi
    
    # Start services
    log "Starting services..."
    if [[ -n "$profile" ]]; then
        docker-compose --profile "$profile" up -d
    else
        docker-compose up -d
    fi
    
    # Wait for services to be healthy
    log "Waiting for services to be healthy..."
    sleep 10
    
    # Check service status
    docker-compose ps
    
    success "Docker stack deployed successfully"
}

# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================

perform_health_checks() {
    log "🏥 Performing health checks..."
    
    # Wait a moment for services to fully start
    sleep 3
    
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            perform_bare_metal_health_checks
            ;;
        "docker")
            perform_docker_health_checks
            ;;
    esac
}

perform_bare_metal_health_checks() {
    # Test main site
    if curl -f -s -m 10 http://localhost/health > /dev/null 2>&1; then
        success "Main site health check passed"
    elif curl -f -s -m 10 http://localhost/ > /dev/null 2>&1; then
        success "Main site is accessible"
    else
        warning "Main site health check failed"
    fi
    
    # Test SSL if certificates exist
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        log "Testing HTTPS access..."
        if curl -f -s -k -m 10 https://localhost/ > /dev/null 2>&1; then
            success "HTTPS site is accessible"
        else
            warning "HTTPS site health check failed"
        fi
    fi
    
    # Test key subdomains
    test_subdomains
}

perform_docker_health_checks() {
    # Check Docker container health
    if docker-compose ps | grep -q "Up"; then
        success "Docker containers are running"
    else
        warning "Some Docker containers may not be running"
    fi
    
    # Test main site through Docker
    if docker exec nginx-server wget --quiet --tries=1 --spider http://localhost/health 2>/dev/null; then
        success "Docker nginx health check passed"
    elif docker exec nginx-server wget --quiet --tries=1 --spider http://localhost/ 2>/dev/null; then
        success "Docker nginx is accessible"
    else
        warning "Docker nginx health check failed"
    fi
}

test_subdomains() {
    for subdomain in nginx auth plex jellyfin; do
        if curl -f -s -m 5 "http://$subdomain.$DOMAIN/health" > /dev/null 2>&1; then
            info "$subdomain subdomain is accessible"
        elif curl -f -s -m 5 "http://$subdomain.$DOMAIN/" > /dev/null 2>&1; then
            info "$subdomain subdomain is accessible"
        fi
    done
}

# =============================================================================
# SUMMARY AND CLEANUP
# =============================================================================

show_deployment_summary() {
    echo ""
    echo "=============================================="
    success "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY"
    echo "=============================================="
    
    log "📊 Deployment Summary:"
    echo "  • Type: $DEPLOYMENT_TYPE"
    echo "  • Timestamp: $TIMESTAMP"
    echo "  • Backup: $BACKUP_DIR"
    echo "  • Domain: $DOMAIN"
    
    if [[ "$DEPLOY_NGINX_CONFIG" == true ]]; then
        echo "  • ✅ Nginx configuration deployed"
    fi
    
    if [[ "$DEPLOY_WEB_FILES" == true ]]; then
        echo "  • ✅ Web files deployed"
    fi
    
    echo "  • ✅ Services reloaded successfully"
    echo "  • ✅ Health checks completed"
    
    show_access_urls
    show_management_commands
    
    success "Deployment completed at $(date)"
}

show_access_urls() {
    echo ""
    log "🌐 Access URLs:"
    echo "  • Main site: https://$DOMAIN/"
    echo "  • Health check: https://$DOMAIN/health"
    
    # Get Tailscale IP if available
    if command -v tailscale &> /dev/null; then
        local tailscale_ip
        tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "Not available")
        if [[ "$tailscale_ip" != "Not available" ]]; then
            echo "  • Tailscale: http://$tailscale_ip/"
        fi
    fi
}

show_management_commands() {
    echo ""
    log "🛠️ Management Commands:"
    
    case "$DEPLOYMENT_TYPE" in
        "bare-metal")
            echo "  • Check status: systemctl status nginx"
            echo "  • Test config: nginx -t"
            echo "  • View logs: journalctl -u nginx -f"
            echo "  • Rollback: $0 rollback $BACKUP_DIR"
            ;;
        "docker")
            echo "  • Check status: docker-compose ps"
            echo "  • View logs: docker-compose logs -f"
            echo "  • Restart: docker-compose restart"
            echo "  • Rollback: $0 rollback $BACKUP_DIR"
            ;;
    esac
}

cleanup_deployment_files() {
    log "🧹 Cleaning up deployment files..."
    
    # Remove deployment files (they've been processed)
    rm -rf nginx-config html public 2>/dev/null || true
    
    success "Cleanup completed"
}

# =============================================================================
# ERROR HANDLING
# =============================================================================

cleanup_on_exit() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        error "Deployment failed with exit code $exit_code"
        
        if [[ -n "$BACKUP_DIR" ]] && [[ -d "$BACKUP_DIR" ]]; then
            warning "Attempting automatic rollback..."
            rollback "$BACKUP_DIR" || error "Automatic rollback failed"
        fi
    fi
    
    # Clean up temporary files
    rm -rf /tmp/nginx-deploy-* 2>/dev/null || true
    
    exit $exit_code
}

trap cleanup_on_exit EXIT

# =============================================================================
# COMMAND HANDLERS
# =============================================================================

handle_rollback_command() {
    if [[ -n "$2" ]] && [[ -d "$2" ]]; then
        rollback "$2"
    else
        error "Usage: $0 rollback <backup_directory>"
        echo "Available backups:"
        ls -la "$BACKUP_PATH" 2>/dev/null || echo "No backups found"
        exit 1
    fi
}

handle_docker_commands() {
    local command="$1"
    shift
    
    case "$command" in
        "logs") docker-compose logs --tail="${1:-100}" -f "${2:-}" ;;
        "status") docker-compose ps ;;
        "backup") docker-compose run --rm backup ;;
        "ssl-status") 
            docker exec nginx-server sh -c '
                if [ -f /etc/letsencrypt/live/*/fullchain.pem ]; then
                    for cert in /etc/letsencrypt/live/*/fullchain.pem; do
                        domain=$(basename $(dirname "$cert"))
                        echo "Domain: $domain"
                        openssl x509 -in "$cert" -noout -dates
                        echo ""
                    done
                else
                    echo "No SSL certificates found"
                fi
            '
            ;;
        "stop") docker-compose down ;;
        "destroy") 
            warning "This will remove all data!"
            read -p "Are you sure? (yes/no): " confirm
            if [[ "$confirm" == "yes" ]]; then
                docker-compose down -v
            fi
            ;;
        *) error "Unknown Docker command: $command" ;;
    esac
}

# =============================================================================
# MAIN FUNCTION
# =============================================================================

main() {
    load_config
    detect_deployment_type
    
    # Handle special commands
    if [[ $# -gt 0 ]]; then
        case "$1" in
            "rollback")
                handle_rollback_command "$@"
                exit 0
                ;;
            "logs"|"status"|"backup"|"ssl-status"|"stop"|"destroy")
                if [[ "$DEPLOYMENT_TYPE" == "docker" ]]; then
                    handle_docker_commands "$@"
                    exit 0
                else
                    error "Command '$1' is only available for Docker deployments"
                    exit 1
                fi
                ;;
        esac
    fi
    
    # Standard deployment flow
    init_deployment
    
    # Change to deployment directory for bare metal
    if [[ "$DEPLOYMENT_TYPE" == "bare-metal" ]]; then
        if [[ ! -d "$DEPLOY_PATH" ]]; then
            error "Deployment directory not found: $DEPLOY_PATH"
            exit 1
        fi
        cd "$DEPLOY_PATH"
    fi
    
    # Main deployment steps
    create_backup
    validate_deployment_files
    test_nginx_configuration
    deploy_configuration
    perform_health_checks
    show_deployment_summary
    cleanup_deployment_files
}

# Execute main function
main "$@"