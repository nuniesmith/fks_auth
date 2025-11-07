#!/bin/bash

# FKS NinjaTrader Development Environment Startup
# Quick startup script for NinjaTrader development workflow

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
warning() { echo -e "${YELLOW}⚠️${NC} $1"; }

print_header() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         FKS NinjaTrader Setup        ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
    echo ""
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if we're in the ninja source directory
    if [[ ! -f "FKS.sln" ]]; then
        warning "Not in ninja source directory. Looking for src/ninja..."
        if [[ -d "src/ninja" ]]; then
            cd src/ninja
            log "Changed to src/ninja directory"
        else
            error "❌ FKS.sln not found. Please run from ninja source directory."
            exit 1
        fi
    fi
    
    # Check .NET SDK
    if command -v dotnet >/dev/null 2>&1; then
        success ".NET SDK found: $(dotnet --version)"
    else
        warning ".NET SDK not found - required for building"
    fi
    
    success "Prerequisites check completed"
}

show_menu() {
    echo ""
    echo "Available actions:"
    echo "1. 🔨 Build FKS project"
    echo "2. 📦 Create NT8 package"
    echo "3. 🚀 Deploy to NinjaTrader"
    echo "4. 🔍 Verify package"
    echo "5. 🩺 Health check"
    echo "6. 🛠️ Complete build & deploy workflow"
    echo "7. 🆘 Exit"
    echo ""
    read -p "Choose an action (1-7): " choice
}

build_project() {
    log "Building FKS project..."
    if [[ -f "../../scripts/ninja/windows/build.ps1" ]]; then
        success "Found build script, switching to PowerShell..."
        powershell.exe -ExecutionPolicy Bypass -File "../../scripts/ninja/windows/build.ps1" -Clean -Package
    else
        log "Using dotnet CLI..."
        dotnet build src/FKS.csproj --configuration Release
    fi
}

create_package() {
    log "Creating NT8 package..."
    if [[ -f "../../scripts/ninja/windows/enhanced-package.ps1" ]]; then
        powershell.exe -ExecutionPolicy Bypass -File "../../scripts/ninja/windows/enhanced-package.ps1"
    else
        warning "Package script not found. Run from repository root."
    fi
}

deploy_to_nt() {
    log "Deploying to NinjaTrader..."
    if [[ -f "../../scripts/ninja/windows/deploy-strategy.ps1" ]]; then
        powershell.exe -ExecutionPolicy Bypass -File "../../scripts/ninja/windows/deploy-strategy.ps1"
    else
        warning "Deploy script not found. Run from repository root."
    fi
}

verify_package() {
    log "Verifying package..."
    if [[ -f "../../scripts/ninja/windows/verify-package.ps1" ]]; then
        powershell.exe -ExecutionPolicy Bypass -File "../../scripts/ninja/windows/verify-package.ps1"
    else
        warning "Verify script not found. Run from repository root."
    fi
}

health_check() {
    log "Running health check..."
    if [[ -f "../../scripts/ninja/windows/health-check.ps1" ]]; then
        powershell.exe -ExecutionPolicy Bypass -File "../../scripts/ninja/windows/health-check.ps1"
    else
        warning "Health check script not found. Run from repository root."
    fi
}

complete_workflow() {
    log "Running complete build & deploy workflow..."
    build_project
    echo ""
    create_package
    echo ""
    verify_package
    echo ""
    deploy_to_nt
    echo ""
    success "Complete workflow finished!"
}

# Main execution
print_header

check_prerequisites

while true; do
    show_menu
    
    case $choice in
        1)
            build_project
            ;;
        2)
            create_package
            ;;
        3)
            deploy_to_nt
            ;;
        4)
            verify_package
            ;;
        5)
            health_check
            ;;
        6)
            complete_workflow
            ;;
        7)
            log "Goodbye!"
            exit 0
            ;;
        *)
            warning "Invalid choice. Please select 1-7."
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
done
