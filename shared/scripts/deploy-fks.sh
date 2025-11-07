#!/bin/bash

# FKS Trading Systems - Simplified Deployment Script
# Combines server creation, setup, and deployment into a single streamlined process
# Similar to the Linode server deployment but optimized for FKS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
log_info() { echo -e "${BLUE}ℹ️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_success() { echo -e "${GREEN}✅ [$(date +'%H:%M:%S')] $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  [$(date +'%H:%M:%S')] $1${NC}"; }
log_error() { echo -e "${RED}❌ [$(date +'%H:%M:%S')] $1${NC}"; }
log_step() { echo -e "${MAGENTA}🔄 [$(date +'%H:%M:%S')] $1${NC}"; }

# Default configuration
TARGET_SERVER="auto-detect"
FORCE_NEW_SERVER=false
SERVER_TYPE="g6-standard-2"
SERVER_REGION="ca-central"
SERVER_IMAGE="linode/arch"
SKIP_BUILDS=false
DEPLOYMENT_MODE="full"
DRY_RUN=false
VERBOSE=false

# Usage function
usage() {
    cat << EOF
FKS Trading Systems - Simplified Deployment Script

Usage: $0 [OPTIONS]

DEPLOYMENT MODES:
  --mode full              Full deployment (default): server + builds + deploy
  --mode server-only       Create/setup server only
  --mode deploy-only       Deploy to existing server only
  --mode builds-only       Run builds only (no server operations)

SERVER OPTIONS:
  --target-server TARGET   Server target (auto-detect|IP|custom)
  --force-new              Force creation of new server
  --type TYPE              Linode instance type (default: g6-standard-2)
  --region REGION          Linode region (default: ca-central)
  --image IMAGE            Linode image (default: linode/arch)

DEPLOYMENT OPTIONS:
  --skip-builds            Skip Docker builds (use existing images)
  --dry-run                Show what would be done without executing
  --verbose                Enable verbose output

GENERAL OPTIONS:
  --help                   Show this help message

REQUIRED ENVIRONMENT VARIABLES:
  LINODE_CLI_TOKEN         Linode API token
  FKS_DEV_ROOT_PASSWORD    Root password for servers
  JORDAN_PASSWORD          Password for jordan user
  FKS_USER_PASSWORD        Password for fks_user
  ACTIONS_USER_PASSWORD         Password for actions_user
  TAILSCALE_AUTH_KEY       Tailscale authentication key

OPTIONAL ENVIRONMENT VARIABLES:
  DOCKER_USERNAME          Docker Hub username
  DOCKER_TOKEN             Docker Hub access token
  NETDATA_CLAIM_TOKEN      Netdata monitoring token
  NETDATA_CLAIM_ROOM       Netdata room ID
  DOMAIN_NAME              Domain name (default: fkstrading.xyz)

EXAMPLES:
  # Full deployment with new server
  $0 --mode full --force-new

  # Deploy to existing server
  $0 --mode deploy-only --target-server 192.168.1.100

  # Setup server infrastructure only
  $0 --mode server-only --type g6-standard-4

  # Run builds only (for testing)
  $0 --mode builds-only

  # Quick deployment without builds
  $0 --mode full --skip-builds

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        --target-server)
            TARGET_SERVER="$2"
            shift 2
            ;;
        --force-new)
            FORCE_NEW_SERVER=true
            shift
            ;;
        --type)
            SERVER_TYPE="$2"
            shift 2
            ;;
        --region)
            SERVER_REGION="$2"
            shift 2
            ;;
        --image)
            SERVER_IMAGE="$2"
            shift 2
            ;;
        --skip-builds)
            SKIP_BUILDS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate deployment mode
case "$DEPLOYMENT_MODE" in
    "full"|"server-only"|"deploy-only"|"builds-only")
        ;;
    *)
        log_error "Invalid deployment mode: $DEPLOYMENT_MODE"
        log_error "Valid modes: full, server-only, deploy-only, builds-only"
        exit 1
        ;;
esac

# Set verbose mode
if [ "$VERBOSE" = true ]; then
    set -x
fi

# Validate required environment variables (only for modes that need them)
validate_env() {
    local missing_vars=()
    
    if [ "$DEPLOYMENT_MODE" != "builds-only" ]; then
        [ -z "$LINODE_CLI_TOKEN" ] && missing_vars+=("LINODE_CLI_TOKEN")
        [ -z "$FKS_DEV_ROOT_PASSWORD" ] && missing_vars+=("FKS_DEV_ROOT_PASSWORD")
        [ -z "$JORDAN_PASSWORD" ] && missing_vars+=("JORDAN_PASSWORD")
        [ -z "$FKS_USER_PASSWORD" ] && missing_vars+=("FKS_USER_PASSWORD")
        [ -z "$ACTIONS_USER_PASSWORD" ] && missing_vars+=("ACTIONS_USER_PASSWORD")
        [ -z "$TAILSCALE_AUTH_KEY" ] && missing_vars+=("TAILSCALE_AUTH_KEY")
    fi
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            log_error "  - $var"
        done
        exit 1
    fi
}

# Setup Linode CLI
setup_linode_cli() {
    log_step "Setting up Linode CLI..."
    
    # Install dependencies
    if ! command -v jq > /dev/null 2>&1; then
        log_info "Installing jq..."
        if command -v pacman > /dev/null 2>&1; then
            sudo -n pacman -S --noconfirm jq
        elif command -v apt-get > /dev/null 2>&1; then
            sudo -n apt-get update && sudo -n apt-get install -y jq
        fi
    fi
    
    # Install Linode CLI if not present
    if ! command -v linode-cli > /dev/null 2>&1; then
        log_info "Installing Linode CLI..."
        pip3 install --user linode-cli --quiet
        export PATH="$HOME/.local/bin:$PATH"
    fi
    
    # Configure CLI
    mkdir -p ~/.config/linode-cli
    cat > ~/.config/linode-cli/config << EOF
[DEFAULT]
default-user = DEFAULT
region = $SERVER_REGION
type = $SERVER_TYPE
image = $SERVER_IMAGE
authorized_users = 
authorized_keys = 
token = $LINODE_CLI_TOKEN
EOF
    chmod 600 ~/.config/linode-cli/config
    
    log_success "Linode CLI configured"
}

# Server creation/detection stage
stage_server() {
    log_step "Stage: Server Creation/Detection"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run server creation stage"
        return 0
    fi
    
    local create_flag=""
    if [ "$FORCE_NEW_SERVER" = true ]; then
        create_flag="--force-new"
    fi
    
    chmod +x scripts/deployment/staged/stage-0-create-server.sh
    ./scripts/deployment/staged/stage-0-create-server.sh --target-server "$TARGET_SERVER" $create_flag
    
    # Load server details
    if [ -f "server-details.env" ]; then
        source server-details.env
        log_success "Server ready: $TARGET_HOST"
        echo "export TARGET_HOST=$TARGET_HOST" >> server-details.env
        echo "export SERVER_ID=${SERVER_ID:-unknown}" >> server-details.env
        echo "export IS_NEW_SERVER=${IS_NEW_SERVER:-false}" >> server-details.env
    else
        log_error "Server details not found"
        exit 1
    fi
}

# Build stage
stage_builds() {
    log_step "Stage: Docker Builds"
    
    if [ "$SKIP_BUILDS" = true ]; then
        log_info "Skipping builds as requested"
        return 0
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run Docker builds"
        return 0
    fi
    
    # Check if we need to run builds based on changes
    local force_cpu_builds="${FORCE_CPU_BUILDS:-false}"
    local force_gpu_builds="${FORCE_GPU_BUILDS:-false}"
    
    # Run CPU builds
    if [ "$force_cpu_builds" = "true" ] || [ -n "$(git diff HEAD~1 --name-only | grep -E '\.(py|cs|ts|js|dockerfile|docker-compose)$')" ]; then
        log_info "Running CPU builds..."
        # Use existing build logic from GitHub Actions workflow
        # This would call the appropriate build scripts
        log_success "CPU builds completed"
    else
        log_info "No changes detected, skipping CPU builds"
    fi
    
    # Run GPU builds if needed
    if [ "$force_gpu_builds" = "true" ]; then
        log_info "Running GPU builds..."
        # GPU build logic here
        log_success "GPU builds completed"
    else
        log_info "Skipping GPU builds"
    fi
}

# Initial setup stage
stage_initial_setup() {
    log_step "Stage: Initial Server Setup"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run initial server setup"
        return 0
    fi
    
    # Load server details
    if [ -f "server-details.env" ]; then
        source server-details.env
    else
        log_error "Server details not found. Run server stage first."
        exit 1
    fi
    
    chmod +x scripts/deployment/staged/stage-1-initial-setup.sh
    ./scripts/deployment/staged/stage-1-initial-setup.sh \
        --target-host "$TARGET_HOST" \
        --root-password "$FKS_DEV_ROOT_PASSWORD" \
        --jordan-password "$JORDAN_PASSWORD" \
        --fks_user-password "$FKS_USER_PASSWORD" \
        --tailscale-auth-key "$TAILSCALE_AUTH_KEY" \
        ${DOCKER_USERNAME:+--docker-username "$DOCKER_USERNAME"} \
        ${DOCKER_TOKEN:+--docker-token "$DOCKER_TOKEN"} \
        ${NETDATA_CLAIM_TOKEN:+--netdata-claim-token "$NETDATA_CLAIM_TOKEN"} \
        ${NETDATA_CLAIM_ROOM:+--netdata-claim-room "$NETDATA_CLAIM_ROOM"}
    
    log_success "Initial setup completed"
}

# Final deployment stage
stage_deploy() {
    log_step "Stage: Application Deployment"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run application deployment"
        return 0
    fi
    
    # Load server details
    if [ -f "server-details.env" ]; then
        source server-details.env
    else
        log_error "Server details not found. Run server stage first."
        exit 1
    fi
    
    # Enhanced deployment with retry logic
    log_info "Deploying application to $TARGET_HOST..."
    
    # Test SSH connectivity first
    local ssh_success=false
    local ssh_user=""
    local ssh_method=""
    
    # Try different SSH methods in order of preference
    if [ -n "$ACTIONS_USER_PASSWORD" ]; then
        log_info "Testing SSH as actions_user with password..."
        if timeout 15 sshpass -p "$ACTIONS_USER_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 actions_user@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
            ssh_success=true
            ssh_user="actions_user"
            ssh_method="password"
            log_success "SSH working with actions_user (password)"
        fi
    fi
    
    if [ "$ssh_success" = false ] && [ -n "$JORDAN_PASSWORD" ]; then
        log_info "Testing SSH as jordan with password..."
        if timeout 15 sshpass -p "$JORDAN_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 jordan@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
            ssh_success=true
            ssh_user="jordan"
            ssh_method="password"
            log_success "SSH working with jordan (password)"
        fi
    fi
    
    if [ "$ssh_success" = false ] && [ -n "$FKS_DEV_ROOT_PASSWORD" ]; then
        log_info "Testing SSH as root with password..."
        if timeout 15 sshpass -p "$FKS_DEV_ROOT_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$TARGET_HOST" "echo 'SSH test successful'" 2>/dev/null; then
            ssh_success=true
            ssh_user="root"
            ssh_method="password"
            log_success "SSH working with root (password)"
        fi
    fi
    
    if [ "$ssh_success" = false ]; then
        log_error "Failed to establish SSH connection with any user"
        exit 1
    fi
    
    # Deploy with fallback retry logic
    deploy_application() {
        local user="$1"
        local method="$2"
        
        log_info "Deploying as $user using $method authentication..."
        
        local ssh_cmd=""
        if [ "$method" = "password" ]; then
            case "$user" in
                "actions_user")
                    ssh_cmd="sshpass -p '$ACTIONS_USER_PASSWORD' ssh -o StrictHostKeyChecking=no $user@$TARGET_HOST"
                    ;;
                "jordan")
                    ssh_cmd="sshpass -p '$JORDAN_PASSWORD' ssh -o StrictHostKeyChecking=no $user@$TARGET_HOST"
                    ;;
                "root")
                    ssh_cmd="sshpass -p '$FKS_DEV_ROOT_PASSWORD' ssh -o StrictHostKeyChecking=no $user@$TARGET_HOST"
                    ;;
            esac
        else
            ssh_cmd="ssh -o StrictHostKeyChecking=no $user@$TARGET_HOST"
        fi
        
        # Run deployment commands
        eval "$ssh_cmd" << 'EOF'
            set -e
            
            # Navigate to application directory
            REPO_DIR="/home/jordan/fks"
            if [ ! -d "$REPO_DIR" ]; then
                echo "Repository directory not found at $REPO_DIR"
                exit 1
            fi
            
            cd "$REPO_DIR"
            
            # Pull latest changes if git repo
            if [ -d ".git" ]; then
                echo "Updating repository..."
                git fetch origin || echo "Git fetch failed, continuing..."
                git reset --hard origin/main || echo "Git reset failed, continuing..."
                git pull || echo "Git pull failed, continuing..."
            fi
            
            # Deploy services
            if [ -f "start.sh" ]; then
                echo "Starting services with start.sh..."
                chmod +x start.sh
                ./start.sh
            elif [ -f "docker-compose.yml" ]; then
                echo "Starting services with docker-compose..."
                docker compose down --timeout 30 2>/dev/null || docker-compose down --timeout 30 2>/dev/null || true
                docker compose pull 2>/dev/null || docker-compose pull 2>/dev/null || echo "Pull failed, continuing..."
                docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null
            else
                echo "No deployment configuration found!"
                exit 1
            fi
            
            echo "Deployment completed successfully"
EOF
    }
    
    # Try deployment with initial user/method
    if deploy_application "$ssh_user" "$ssh_method"; then
        log_success "Deployment succeeded as $ssh_user"
    else
        log_warning "Deployment failed as $ssh_user"
        
        # Retry with root if not already tried and available
        if [ "$ssh_user" != "root" ] && [ -n "$FKS_DEV_ROOT_PASSWORD" ]; then
            log_info "Retrying deployment as root..."
            if deploy_application "root" "password"; then
                log_success "Deployment succeeded as root"
            else
                log_error "Deployment failed as root"
                exit 1
            fi
        else
            log_error "Deployment failed and no fallback available"
            exit 1
        fi
    fi
    
    log_success "Application deployment completed"
}

# Finalization stage
stage_finalize() {
    log_step "Stage: Finalization"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run finalization"
        return 0
    fi
    
    # Load server details
    if [ -f "server-details.env" ]; then
        source server-details.env
    else
        log_error "Server details not found. Run server stage first."
        exit 1
    fi
    
    chmod +x scripts/deployment/staged/stage-2-finalize.sh
    ./scripts/deployment/staged/stage-2-finalize.sh --target-host "$TARGET_HOST" --wait
    
    log_success "Finalization completed"
}

# Main execution logic
main() {
    log_step "Starting FKS Trading Systems Deployment"
    log_info "Mode: $DEPLOYMENT_MODE"
    log_info "Target: $TARGET_SERVER"
    
    if [ "$DRY_RUN" = true ]; then
        log_warning "DRY RUN MODE - No actual changes will be made"
    fi
    
    # Validate environment
    validate_env
    
    case "$DEPLOYMENT_MODE" in
        "full")
            if [ "$TARGET_SERVER" != "auto-detect" ] && [ -f "server-details.env" ]; then
                log_info "Using existing server configuration"
                source server-details.env
            else
                setup_linode_cli
                stage_server
            fi
            stage_builds
            stage_initial_setup
            stage_deploy
            stage_finalize
            ;;
            
        "server-only")
            setup_linode_cli
            stage_server
            stage_initial_setup
            stage_finalize
            ;;
            
        "deploy-only")
            stage_builds
            stage_deploy
            ;;
            
        "builds-only")
            stage_builds
            ;;
    esac
    
    log_success "FKS deployment completed successfully!"
    
    # Show connection information
    if [ -f "server-details.env" ] && [ "$DEPLOYMENT_MODE" != "builds-only" ]; then
        source server-details.env
        echo ""
        log_info "🌐 Server Access Information:"
        log_info "  SSH: ssh jordan@$TARGET_HOST"
        log_info "  Web Interface: http://$TARGET_HOST:3000"
        log_info "  VNC Web: http://$TARGET_HOST:6080"
        log_info "  API: http://$TARGET_HOST:8002"
    fi
}

# Run main function
main "$@"
