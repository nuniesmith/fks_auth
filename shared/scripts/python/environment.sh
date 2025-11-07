#!/bin/bash
# filepath: scripts/python/environment.sh
# FKS Trading Systems - Python Environment Management

# Prevent multiple sourcing and direct execution
if [[ "${FKS_PYTHON_ENVIRONMENT_LOADED:-}" == "1" ]]; then
    return 0
fi

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

readonly FKS_PYTHON_ENVIRONMENT_LOADED=1
readonly PYTHON_ENV_MODULE_VERSION="3.0.0"

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"

# Configuration with defaults
readonly PYTHON_MIN_VERSION="${FKS_PYTHON_MIN_VERSION:-3.8}"
readonly CONDA_ENV_NAME="${FKS_CONDA_ENV:-fks_env}"
readonly VENV_PATH="${FKS_VENV_PATH:-$HOME/.venv/fks_env}"
readonly PYTHON_ENV_TYPE="${FKS_PYTHON_ENV_TYPE:-auto}"
readonly PYTHON_SCRIPTS_DIR="${PYTHON_SCRIPTS_DIR:-./scripts/python}"

# Global state
DETECTED_ENV_TYPE=""
PYTHON_EXECUTABLE=""
ENV_STATUS=""

# =============================================================================
# Core Environment Detection
# =============================================================================

# Main initialization function
init_python_environment() {
    log_info "🐍 Initializing Python environment..."
    
    if ! _check_python_availability; then
        log_error "❌ Python requirements not met"
        _show_python_installation_guide
        return 1
    fi
    
    _detect_environment_type
    
    case "$DETECTED_ENV_TYPE" in
        "conda") _setup_conda_environment ;;
        "venv") _setup_venv_environment ;;
        "system") _setup_system_environment ;;
        *) 
            log_error "❌ Failed to detect suitable Python environment"
            return 1
            ;;
    esac
    
    _verify_environment_setup
}

# Detect the best environment type to use
_detect_environment_type() {
    log_debug "🔍 Detecting Python environment type..."
    
    case "$PYTHON_ENV_TYPE" in
        "conda"|"venv"|"system")
            DETECTED_ENV_TYPE="$PYTHON_ENV_TYPE"
            log_debug "Using configured environment type: $DETECTED_ENV_TYPE"
            ;;
        "auto")
            _auto_detect_environment
            ;;
        *)
            log_error "Invalid environment type: $PYTHON_ENV_TYPE"
            return 1
            ;;
    esac
}

# Auto-detect best available environment
_auto_detect_environment() {
    if _check_conda_available; then
        DETECTED_ENV_TYPE="conda"
        log_debug "Auto-detected: conda"
    elif _check_venv_capability; then
        DETECTED_ENV_TYPE="venv"
        log_debug "Auto-detected: venv"
    else
        DETECTED_ENV_TYPE="system"
        log_debug "Auto-detected: system python"
    fi
}

# Check if Python meets minimum requirements
_check_python_availability() {
    local python_cmd python_version
    
    # Find suitable Python executable
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            python_version=$($cmd --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+')
            if _version_meets_minimum "$python_version" "$PYTHON_MIN_VERSION"; then
                PYTHON_EXECUTABLE="$cmd"
                log_debug "✅ Found suitable Python: $cmd ($python_version)"
                return 0
            fi
        fi
    done
    
    log_debug "❌ No suitable Python found (minimum: $PYTHON_MIN_VERSION)"
    return 1
}

# Version comparison helper
_version_meets_minimum() {
    local current="$1" minimum="$2"
    local -a current_parts minimum_parts
    
    IFS='.' read -ra current_parts <<< "$current"
    IFS='.' read -ra minimum_parts <<< "$minimum"
    
    for i in {0..1}; do
        local curr_part="${current_parts[i]:-0}"
        local min_part="${minimum_parts[i]:-0}"
        
        if (( curr_part > min_part )); then
            return 0
        elif (( curr_part < min_part )); then
            return 1
        fi
    done
    
    return 0  # Equal versions
}

# =============================================================================
# Conda Environment Management
# =============================================================================

_check_conda_available() {
    if command -v conda >/dev/null 2>&1; then
        return 0
    fi
    
    # Check common conda installation paths
    local conda_paths=(
        "$HOME/miniconda3/etc/profile.d/conda.sh"
        "$HOME/anaconda3/etc/profile.d/conda.sh"
        "/opt/conda/etc/profile.d/conda.sh"
    )
    
    for conda_path in "${conda_paths[@]}"; do
        if [[ -f "$conda_path" ]]; then
            source "$conda_path"
            command -v conda >/dev/null 2>&1 && return 0
        fi
    done
    
    return 1
}

_setup_conda_environment() {
    log_info "🐍 Setting up Conda environment: $CONDA_ENV_NAME"
    
    if ! _check_conda_available; then
        log_error "❌ Conda not available"
        _show_conda_installation_guide
        return 1
    fi
    
    _init_conda_shell
    
    if _conda_env_exists "$CONDA_ENV_NAME"; then
        log_info "✅ Environment '$CONDA_ENV_NAME' exists"
        if _ask_yes_no "Update existing environment?" "n"; then
            _update_conda_environment
        fi
    else
        _create_conda_environment
    fi
    
    ENV_STATUS="conda:$CONDA_ENV_NAME"
    _show_conda_activation_info
}

_init_conda_shell() {
    if ! conda info >/dev/null 2>&1; then
        eval "$(conda shell.bash hook)" 2>/dev/null || true
    fi
}

_conda_env_exists() {
    conda env list | grep -q "^$1 "
}

_create_conda_environment() {
    log_info "📦 Creating Conda environment: $CONDA_ENV_NAME"
    
    if conda create -n "$CONDA_ENV_NAME" python=3.9 -y; then
        log_success "✅ Created environment: $CONDA_ENV_NAME"
        _install_conda_packages
    else
        log_error "❌ Failed to create environment"
        return 1
    fi
}

_update_conda_environment() {
    log_info "🔄 Updating Conda environment: $CONDA_ENV_NAME"
    
    if [[ -f "environment.yml" ]]; then
        conda env update -n "$CONDA_ENV_NAME" -f environment.yml
    else
        conda update -n "$CONDA_ENV_NAME" --all -y
    fi
}

_install_conda_packages() {
    local packages=(
        "pip" "numpy" "pandas" "pyyaml" "requests"
    )
    
    log_info "📦 Installing basic packages..."
    conda install -n "$CONDA_ENV_NAME" "${packages[@]}" -y
    
    # Install from requirements if available
    if [[ -f "requirements.txt" ]]; then
        log_info "💡 Remember to activate environment and run: pip install -r requirements.txt"
    fi
}

# =============================================================================
# Virtual Environment Management
# =============================================================================

_check_venv_capability() {
    $PYTHON_EXECUTABLE -m venv --help >/dev/null 2>&1
}

_setup_venv_environment() {
    log_info "🐍 Setting up virtual environment: $VENV_PATH"
    
    if ! _check_venv_capability; then
        log_error "❌ Virtual environment module not available"
        _show_venv_installation_guide
        return 1
    fi
    
    if [[ -d "$VENV_PATH" ]] && _venv_is_valid "$VENV_PATH"; then
        log_info "✅ Virtual environment exists"
        if _ask_yes_no "Recreate virtual environment?" "n"; then
            _recreate_venv_environment
        fi
    else
        _create_venv_environment
    fi
    
    ENV_STATUS="venv:$VENV_PATH"
    _show_venv_activation_info
}

_venv_is_valid() {
    local venv_path="$1"
    [[ -f "$venv_path/bin/activate" ]] || [[ -f "$venv_path/Scripts/activate" ]]
}

_create_venv_environment() {
    log_info "📦 Creating virtual environment: $VENV_PATH"
    
    # Create parent directory if needed
    mkdir -p "$(dirname "$VENV_PATH")"
    
    if $PYTHON_EXECUTABLE -m venv "$VENV_PATH"; then
        log_success "✅ Created virtual environment"
        _setup_venv_packages
    else
        log_error "❌ Failed to create virtual environment"
        return 1
    fi
}

_recreate_venv_environment() {
    log_info "🔄 Recreating virtual environment"
    rm -rf "$VENV_PATH"
    _create_venv_environment
}

_setup_venv_packages() {
    local pip_cmd
    pip_cmd=$(_get_venv_pip_command)
    
    if [[ -n "$pip_cmd" ]]; then
        log_info "⬆️  Upgrading pip..."
        "$pip_cmd" install --upgrade pip
        
        if [[ -f "requirements.txt" ]]; then
            log_info "📦 Installing requirements..."
            "$pip_cmd" install -r requirements.txt
        fi
    fi
}

_get_venv_pip_command() {
    if [[ -f "$VENV_PATH/bin/pip" ]]; then
        echo "$VENV_PATH/bin/pip"
    elif [[ -f "$VENV_PATH/Scripts/pip.exe" ]]; then
        echo "$VENV_PATH/Scripts/pip.exe"
    fi
}

# =============================================================================
# System Python Management
# =============================================================================

_setup_system_environment() {
    log_info "🐍 Using system Python"
    
    local python_version python_path
    python_version=$($PYTHON_EXECUTABLE --version 2>&1)
    python_path=$(which "$PYTHON_EXECUTABLE")
    
    log_info "Version: $python_version"
    log_info "Location: $python_path"
    
    if ! $PYTHON_EXECUTABLE -m pip --version >/dev/null 2>&1; then
        log_error "❌ pip not available"
        _show_pip_installation_guide
        return 1
    fi
    
    _warn_system_python_usage
    
    if [[ -f "requirements.txt" ]] && _ask_yes_no "Install requirements with --user?" "n"; then
        _install_system_requirements
    fi
    
    ENV_STATUS="system:$python_path"
}

_warn_system_python_usage() {
    log_warn "⚠️  Using system Python - consider using a virtual environment"
    cat << EOF
💡 Benefits of virtual environments:
  • Isolated package installations
  • No conflicts with system packages
  • Easy environment recreation
  • Better project reproducibility
EOF
}

_install_system_requirements() {
    log_info "📦 Installing requirements for system Python..."
    if $PYTHON_EXECUTABLE -m pip install -r requirements.txt --user; then
        log_success "✅ Requirements installed (user site-packages)"
    else
        log_error "❌ Failed to install requirements"
        return 1
    fi
}

# =============================================================================
# Environment Verification and Status
# =============================================================================

_verify_environment_setup() {
    log_info "🧪 Verifying environment setup..."
    
    case "$DETECTED_ENV_TYPE" in
        "conda")
            _verify_conda_environment
            ;;
        "venv")
            _verify_venv_environment
            ;;
        "system")
            _verify_system_environment
            ;;
    esac
}

_verify_conda_environment() {
    if conda env list | grep -q "^$CONDA_ENV_NAME "; then
        log_success "✅ Conda environment verified: $CONDA_ENV_NAME"
        return 0
    else
        log_error "❌ Conda environment verification failed"
        return 1
    fi
}

_verify_venv_environment() {
    if _venv_is_valid "$VENV_PATH"; then
        log_success "✅ Virtual environment verified: $VENV_PATH"
        return 0
    else
        log_error "❌ Virtual environment verification failed"
        return 1
    fi
}

_verify_system_environment() {
    if command -v "$PYTHON_EXECUTABLE" >/dev/null 2>&1; then
        log_success "✅ System Python verified: $PYTHON_EXECUTABLE"
        return 0
    else
        log_error "❌ System Python verification failed"
        return 1
    fi
}

# Environment status and information
check_python_environment_status() {
    log_info "🐍 Python Environment Status"
    
    echo ""
    echo "${YELLOW}Current Status:${NC} ${ENV_STATUS:-Not initialized}"
    echo "${YELLOW}Python Executable:${NC} ${PYTHON_EXECUTABLE:-Not detected}"
    echo "${YELLOW}Environment Type:${NC} ${DETECTED_ENV_TYPE:-Not detected}"
    
    if [[ -n "$PYTHON_EXECUTABLE" ]]; then
        echo "${YELLOW}Python Version:${NC} $($PYTHON_EXECUTABLE --version 2>&1)"
        
        # Show active environment info
        _show_active_environment_info
        
        # Show package count
        _show_package_info
        
        # Check requirements status
        _check_requirements_status
    fi
}

_show_active_environment_info() {
    echo ""
    echo "${YELLOW}Active Environment:${NC}"
    
    if [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
        echo "  Conda: $CONDA_DEFAULT_ENV"
    elif [[ -n "${VIRTUAL_ENV:-}" ]]; then
        echo "  Virtual Env: $VIRTUAL_ENV"
    else
        echo "  System Python (no virtual environment active)"
    fi
}

_show_package_info() {
    if $PYTHON_EXECUTABLE -m pip list >/dev/null 2>&1; then
        local package_count
        package_count=$($PYTHON_EXECUTABLE -m pip list 2>/dev/null | tail -n +3 | wc -l)
        echo "${YELLOW}Installed Packages:${NC} $package_count"
    fi
}

_check_requirements_status() {
    if [[ ! -f "requirements.txt" ]]; then
        return 0
    fi
    
    echo ""
    echo "${YELLOW}Requirements Status:${NC}"
    
    local total missing=0
    total=$(grep -c "^[a-zA-Z]" requirements.txt 2>/dev/null || echo "0")
    echo "  Total requirements: $total"
    
    if (( total > 0 )); then
        while IFS= read -r line; do
            [[ $line =~ ^[[:space:]]*# ]] || [[ -z "${line// }" ]] && continue
            
            local package_name
            package_name=$(echo "$line" | sed 's/[>=<~!].*//' | tr -d '[:space:]')
            
            if [[ -n "$package_name" ]] && ! $PYTHON_EXECUTABLE -m pip show "$package_name" >/dev/null 2>&1; then
                ((missing++))
            fi
        done < requirements.txt
        
        echo "  Missing packages: $missing"
    fi
}

# =============================================================================
# Utility Functions
# =============================================================================

_ask_yes_no() {
    local question="$1" default="$2"
    local prompt response
    
    case "$default" in
        "y"|"Y") prompt="[Y/n]" ;;
        "n"|"N") prompt="[y/N]" ;;
        *) prompt="[y/n]" ;;
    esac
    
    echo -n "$question $prompt: "
    read -r response
    
    [[ -z "$response" ]] && response="$default"
    
    case "$response" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# Generate activation scripts
generate_activation_script() {
    local script_name="activate_fks_env.sh"
    
    log_info "📝 Generating activation script: $script_name"
    
    cat > "$script_name" << EOF
#!/bin/bash
# FKS Trading Systems - Environment Activation Script
# Generated: $(date)

set -euo pipefail

echo "🐍 Activating FKS Python Environment..."

EOF
    
    case "$DETECTED_ENV_TYPE" in
        "conda")
            cat >> "$script_name" << 'EOF'
# Initialize and activate conda
if command -v conda >/dev/null 2>&1; then
    eval "$(conda shell.bash hook)" 2>/dev/null || true
    conda activate '$CONDA_ENV_NAME'
    echo "✅ Activated conda environment: $CONDA_DEFAULT_ENV"
else
    echo "❌ Conda not available"
    exit 1
fi
EOF
            ;;
        "venv")
            cat >> "$script_name" << EOF
# Activate virtual environment
if [[ -f "$VENV_PATH/bin/activate" ]]; then
    source "$VENV_PATH/bin/activate"
    echo "✅ Activated virtual environment: $VENV_PATH"
else
    echo "❌ Virtual environment not found: $VENV_PATH"
    exit 1
fi
EOF
            ;;
        "system")
            cat >> "$script_name" << 'EOF'
# Setup system Python environment
export PYTHONUSERBASE="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
echo "✅ Configured system Python environment"
EOF
            ;;
    esac
    
    cat >> "$script_name" << 'EOF'

# Set Python path for project
export PYTHONPATH="$(pwd)/src:${PYTHONPATH:-}"

echo "Environment ready! Python: $(python --version)"
EOF
    
    chmod +x "$script_name"
    log_success "✅ Activation script created: $script_name"
}

# =============================================================================
# Installation Guides
# =============================================================================

_show_python_installation_guide() {
    cat << EOF
${YELLOW}Python Installation Guide:${NC}

${GREEN}Ubuntu/Debian:${NC}
  sudo apt update && sudo apt install python3 python3-pip python3-venv

${GREEN}CentOS/RHEL/Fedora:${NC}
  sudo dnf install python3 python3-pip

${GREEN}macOS:${NC}
  brew install python3

${GREEN}Windows:${NC}
  Download from: https://www.python.org/downloads/

${YELLOW}Verify:${NC} python3 --version && python3 -m pip --version
EOF
}

_show_conda_installation_guide() {
    cat << EOF
${YELLOW}Conda Installation Guide:${NC}

${GREEN}Miniconda (Recommended):${NC}
  curl -O https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
  bash Miniconda3-latest-Linux-x86_64.sh

${YELLOW}Verify:${NC} conda --version
EOF
}

_show_venv_installation_guide() {
    cat << EOF
${YELLOW}Virtual Environment Installation:${NC}

${GREEN}Ubuntu/Debian:${NC}
  sudo apt install python3-venv

${YELLOW}Verify:${NC} python3 -m venv --help
EOF
}

_show_pip_installation_guide() {
    cat << EOF
${YELLOW}pip Installation Guide:${NC}

${GREEN}Most systems:${NC}
  python3 -m ensurepip --upgrade

${GREEN}Ubuntu/Debian:${NC}
  sudo apt install python3-pip

${YELLOW}Verify:${NC} python3 -m pip --version
EOF
}

# =============================================================================
# Activation Info Display
# =============================================================================

_show_conda_activation_info() {
    cat << EOF

${YELLOW}💡 Conda Environment Usage:${NC}
  Activate:   ${GREEN}conda activate $CONDA_ENV_NAME${NC}
  Deactivate: ${GREEN}conda deactivate${NC}
  Remove:     ${GREEN}conda env remove -n $CONDA_ENV_NAME${NC}

EOF
}

_show_venv_activation_info() {
    local activate_cmd
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        activate_cmd="$VENV_PATH\\Scripts\\activate"
    else
        activate_cmd="source $VENV_PATH/bin/activate"
    fi
    
    cat << EOF

${YELLOW}💡 Virtual Environment Usage:${NC}
  Activate:   ${GREEN}$activate_cmd${NC}
  Deactivate: ${GREEN}deactivate${NC}
  Remove:     ${GREEN}rm -rf $VENV_PATH${NC}

EOF
}

# Export main functions
export -f init_python_environment check_python_environment_status generate_activation_script

log_debug "📦 Loaded Python environment module (v$PYTHON_ENV_MODULE_VERSION)"