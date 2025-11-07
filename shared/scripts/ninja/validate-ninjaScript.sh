#!/bin/bash

# NinjaScript Validation Script
# Validates that NinjaScript files follow proper conventions before packaging

set -e

# Colors for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log() { echo -e "[$(date '+%H:%M:%S')] $1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
warning() { echo -e "${YELLOW}⚠️${NC} $1"; }
error() { echo -e "${RED}❌${NC} $1"; }

# Project paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NINJA_SRC_DIR="$PROJECT_ROOT/src/ninja/src"

log "Validating NinjaScript files in: $NINJA_SRC_DIR"

validate_indicators() {
    local error_count=0
    
    log "=== Validating Indicators ==="
    
    if [[ ! -d "$NINJA_SRC_DIR/Indicators" ]]; then
        warning "No Indicators directory found"
        return 0
    fi
    
    for file in "$NINJA_SRC_DIR/Indicators"/*.cs; do
        if [[ ! -f "$file" ]]; then
            continue
        fi
        
        local filename=$(basename "$file" .cs)
        log "Checking $filename..."
        
        # Check namespace
        if ! grep -q "namespace NinjaTrader.NinjaScript.Indicators" "$file"; then
            error "$filename: Missing or incorrect namespace declaration"
            ((error_count++))
        fi
        
        # Check class inheritance
        if ! grep -q "class $filename.*: .*Indicator" "$file"; then
            error "$filename: Class must inherit from Indicator"
            ((error_count++))
        fi
        
        # Check for proper region usage (NinjaTrader convention)
        if ! grep -q "#region" "$file"; then
            warning "$filename: Consider using #region for better code organization"
        fi
        
        success "$filename: Basic validation passed"
    done
    
    return $error_count
}

validate_strategies() {
    local error_count=0
    
    log "=== Validating Strategies ==="
    
    if [[ ! -d "$NINJA_SRC_DIR/Strategies" ]]; then
        warning "No Strategies directory found"
        return 0
    fi
    
    for file in "$NINJA_SRC_DIR/Strategies"/*.cs; do
        if [[ ! -f "$file" ]]; then
            continue
        fi
        
        local filename=$(basename "$file" .cs)
        log "Checking $filename..."
        
        # Check namespace
        if ! grep -q "namespace NinjaTrader.NinjaScript.Strategies" "$file"; then
            error "$filename: Missing or incorrect namespace declaration"
            ((error_count++))
        fi
        
        # Check class inheritance
        if ! grep -q "class $filename.*: .*Strategy" "$file"; then
            error "$filename: Class must inherit from Strategy"
            ((error_count++))
        fi
        
        success "$filename: Basic validation passed"
    done
    
    return $error_count
}

validate_addons() {
    local error_count=0
    
    log "=== Validating AddOns ==="
    
    if [[ ! -d "$NINJA_SRC_DIR/AddOns" ]]; then
        warning "No AddOns directory found"
        return 0
    fi
    
    for file in "$NINJA_SRC_DIR/AddOns"/*.cs; do
        if [[ ! -f "$file" ]]; then
            continue
        fi
        
        local filename=$(basename "$file" .cs)
        log "Checking $filename..."
        
        # Check namespace
        if ! grep -q "namespace NinjaTrader.NinjaScript.AddOns" "$file"; then
            error "$filename: Missing or incorrect namespace declaration"
            ((error_count++))
        fi
        
        # AddOns should NOT inherit from NinjaScript components
        if grep -q ": Indicator\|: Strategy\|: DrawingTool" "$file"; then
            error "$filename: AddOns should not inherit from NinjaScript components"
            ((error_count++))
        fi
        
        success "$filename: Basic validation passed"
    done
    
    return $error_count
}

validate_manifest() {
    log "=== Validating Manifest ==="
    
    local manifest_file="$PROJECT_ROOT/src/ninja/manifest.xml"
    
    if [[ ! -f "$manifest_file" ]]; then
        error "manifest.xml not found at $manifest_file"
        return 1
    fi
    
    # Check for common issues
    if grep -q "NinjaTrader.NinjaScript.AddOns" "$manifest_file" | grep -q "ExportedType"; then
        error "Manifest should NOT export AddOns as ExportedTypes"
        return 1
    fi
    
    success "Manifest validation passed"
    return 0
}

validate_project_file() {
    log "=== Validating Project File ==="
    
    local project_file="$NINJA_SRC_DIR/FKS.csproj"
    
    if [[ ! -f "$project_file" ]]; then
        error "FKS.csproj not found at $project_file"
        return 1
    fi
    
    # Check for problematic dependencies
    if grep -q "<Private>true</Private>" "$project_file" && grep -q "System\.\(Memory\|ValueTuple\|Numerics\.Vectors\)" "$project_file"; then
        warning "NuGet packages should have <Private>false</Private> to avoid conflicts"
    fi
    
    success "Project file validation passed"
    return 0
}

# Main validation
main() {
    log "Starting NinjaScript validation..."
    
    local total_errors=0
    
    validate_indicators
    total_errors=$((total_errors + $?))
    
    validate_strategies  
    total_errors=$((total_errors + $?))
    
    validate_addons
    total_errors=$((total_errors + $?))
    
    validate_manifest
    total_errors=$((total_errors + $?))
    
    validate_project_file
    total_errors=$((total_errors + $?))
    
    echo ""
    if [[ $total_errors -eq 0 ]]; then
        success "All validations passed! Ready for packaging."
        exit 0
    else
        error "Found $total_errors validation errors. Fix these before packaging."
        exit 1
    fi
}

main "$@"
