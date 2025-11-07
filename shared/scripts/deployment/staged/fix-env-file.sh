#!/bin/bash

# fix-env-file.sh - Automatically fix common environment file formatting issues
# 
# This script fixes common issues in environment files, particularly:
# - Unquoted SSH keys that contain spaces
# - Unquoted values with special characters
# - Basic syntax validation
#
# Usage: fix-env-file.sh <env-file>

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $1${NC}" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 <env-file>

Automatically fix common environment file formatting issues:
- Quote SSH keys that contain spaces
- Quote values with special characters
- Validate syntax after fixing
- Create backup before making changes

Example:
  $0 deployment.env

The script will:
1. Create a backup (.bak extension)
2. Fix unquoted SSH keys and other values
3. Validate the fixed file
4. Report what was changed

EOF
}

# Validate environment file after fixing
validate_env_file() {
    local env_file="$1"
    
    # Test syntax by trying to source it safely
    if (set -a; source "$env_file"; set +a) 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Fix unquoted SSH keys and other values
fix_env_file() {
    local env_file="$1"
    local temp_file="${env_file}.tmp"
    local changes_made=0
    
    log "Processing environment file: $env_file"
    
    # Read the file line by line and fix issues
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines and comments
        if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
            echo "$line"
            continue
        fi
        
        # Check if this is a variable assignment
        if [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]]; then
            var_name="${line%%=*}"
            var_value="${line#*=}"
            
            # Check if value is already quoted (and properly closed)
            if [[ "$var_value" =~ ^\".*\"$ ]] || [[ "$var_value" =~ ^\'.*\'$ ]]; then
                # Already quoted, keep as is
                echo "$line"
            elif [[ "$var_value" =~ ^\" ]]; then
                # Starts with quote - likely intended to be quoted but may be multi-line
                # Skip auto-quoting for these cases
                echo "$line"
            else
                # Check if value contains SSH key pattern or spaces that need quoting
                if [[ "$var_value" =~ ssh-[a-z0-9] ]] || [[ "$var_value" =~ [[:space:]] ]] || [[ "$var_value" =~ [\$\`\\] ]]; then
                    # Escape any existing quotes in the value
                    escaped_value="${var_value//\"/\\\"}"
                    echo "${var_name}=\"${escaped_value}\""
                    changes_made=1
                    warn "Fixed unquoted value for $var_name" >&2
                else
                    # Keep as is if no special characters
                    echo "$line"
                fi
            fi
        else
            # Not a variable assignment, keep as is
            echo "$line"
        fi
    done < "$env_file" > "$temp_file"
    
    if [ $changes_made -eq 1 ]; then
        # Replace original with fixed version
        mv "$temp_file" "$env_file"
        success "Applied fixes to $env_file"
        return 0
    else
        # No changes needed
        rm -f "$temp_file"
        log "No changes needed in $env_file"
        return 1
    fi
}

# Main function
main() {
    if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_usage
        exit 0
    fi
    
    local env_file="$1"
    
    # Check if file exists
    if [ ! -f "$env_file" ]; then
        error "Environment file not found: $env_file"
        exit 1
    fi
    
    # Check if file is readable
    if [ ! -r "$env_file" ]; then
        error "Cannot read environment file: $env_file"
        exit 1
    fi
    
    # Create backup
    local backup_file="${env_file}.bak"
    cp "$env_file" "$backup_file"
    log "Created backup: $backup_file"
    
    # Check initial syntax
    log "Checking initial file syntax..."
    if validate_env_file "$env_file"; then
        log "File syntax is already valid"
        initial_valid=true
    else
        warn "File has syntax issues, attempting to fix..."
        initial_valid=false
    fi
    
    # Attempt to fix the file
    if fix_env_file "$env_file"; then
        log "Changes were made to the file"
    else
        if [ "$initial_valid" = true ]; then
            log "File was already properly formatted"
        else
            log "No automatic fixes could be applied"
        fi
    fi
    
    # Validate the result
    log "Validating fixed file..."
    if validate_env_file "$env_file"; then
        success "Environment file is now valid: $env_file"
        
        # Show what changed (if anything)
        if [ -f "$backup_file" ]; then
            if ! diff -q "$backup_file" "$env_file" >/dev/null 2>&1; then
                log "Changes made:"
                diff "$backup_file" "$env_file" | head -20 || true
            fi
        fi
        
        exit 0
    else
        error "Failed to fix environment file syntax"
        error "Please check the file manually for syntax errors"
        error "Backup saved as: $backup_file"
        exit 1
    fi
}

# Run main function
main "$@"
