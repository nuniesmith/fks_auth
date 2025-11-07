#!/bin/bash
# filepath: fks/scripts/core/validation.sh
# FKS Trading Systems - System Validation Functions

# Prevent multiple sourcing
[[ -n "${FKS_CORE_VALIDATION_LOADED:-}" ]] && return 0
readonly FKS_CORE_VALIDATION_LOADED=1

# Module metadata
readonly VALIDATION_MODULE_VERSION="3.0.1"
readonly VALIDATION_MODULE_LOADED="$(date +%s)"

# Get script directory (avoid readonly conflicts)
if [[ -z "${VALIDATION_SCRIPT_DIR:-}" ]]; then
    readonly VALIDATION_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Source dependencies with fallback
if [[ -f "$VALIDATION_SCRIPT_DIR/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$VALIDATION_SCRIPT_DIR/logging.sh"
elif [[ -f "$(dirname "$VALIDATION_SCRIPT_DIR")/core/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$(dirname "$VALIDATION_SCRIPT_DIR")/core/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[INFO] $1"; }
    log_warn() { echo "[WARN] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo "[DEBUG] $1" >&2; }
    log_success() { echo "[SUCCESS] $1"; }
    start_timer() { eval "TIMER_$1_START=\$(date +%s)"; }
    stop_timer() { 
        local name=$1
        local start_var="TIMER_${name}_START"
        local start_time=${!start_var:-$(date +%s)}
        echo $(($(date +%s) - start_time))
    }
fi

# Validation configuration with mode-specific adjustments
declare -A VALIDATION_CONFIG=(
    [MIN_MEMORY_GB]=2
    [RECOMMENDED_MEMORY_GB]=8
    [MIN_DISK_GB]=5
    [RECOMMENDED_DISK_GB]=20
    [MIN_CPU_CORES]=1
    [RECOMMENDED_CPU_CORES]=4
    [NETWORK_TIMEOUT]=5
    [VALIDATION_TIMEOUT]=30
)

# Adjust requirements based on mode
_adjust_validation_config() {
    case "${FKS_MODE:-development}" in
        "server"|"production")
            VALIDATION_CONFIG[MIN_MEMORY_GB]=4
            VALIDATION_CONFIG[RECOMMENDED_MEMORY_GB]=16
            VALIDATION_CONFIG[MIN_DISK_GB]=10
            VALIDATION_CONFIG[RECOMMENDED_DISK_GB]=50
            VALIDATION_CONFIG[MIN_CPU_CORES]=2
            VALIDATION_CONFIG[RECOMMENDED_CPU_CORES]=8
            ;;
        "development"|*)
            # Keep default values for development
            ;;
    esac
}

# Validation results storage
declare -A VALIDATION_RESULTS=()
declare -A VALIDATION_ERRORS=()
declare -A VALIDATION_WARNINGS=()

# =============================================================================
# Main Validation Functions
# =============================================================================

# Main system validation entry point
validate_system_requirements() {
    log_info "🔍 Validating system requirements for ${FKS_MODE:-unknown} mode..."
    start_timer "validation"
    
    # Initialize validation state
    _init_validation_state
    _adjust_validation_config
    
    # Run validation checks
    local validators=(
        "_validate_core_system"
        "_validate_software_tools"
        "_validate_configuration"
        "_validate_environment"
    )
    
    local total_errors=0
    local total_warnings=0
    
    for validator in "${validators[@]}"; do
        log_debug "Running validator: $validator"
        if ! $validator; then
            ((total_errors++))
        fi
        local current_warnings
        current_warnings=$(_count_warnings)
        log_debug "Current warnings count: $current_warnings"
        total_warnings=$current_warnings
    done
    
    # Generate final report
    local validation_time
    validation_time=$(stop_timer "validation")
    _generate_final_report "$total_errors" "$total_warnings" "$validation_time"
    
    return $(( total_errors > 0 ? 1 : 0 ))
}

# Quick validation for fast checks
quick_validate() {
    log_info "⚡ Quick system validation"
    
    local checks=(
        "_check_os_compatibility"
        "_check_disk_space"
        "_check_essential_tools"
        "_check_main_script"
    )
    
    local issues=0
    echo "Essential Requirements:"
    
    for check in "${checks[@]}"; do
        if ! $check; then
            ((issues++))
        fi
    done
    
    echo ""
    if [[ $issues -eq 0 ]]; then
        log_success "✅ Quick validation passed"
        return 0
    else
        log_error "❌ Quick validation failed ($issues issues)"
        return 1
    fi
}

# =============================================================================
# Core System Validation
# =============================================================================

_validate_core_system() {
    log_debug "Validating core system components..."
    
    local validators=(
        "_validate_operating_system"
        "_validate_hardware_requirements"
        "_validate_disk_space"
        "_validate_network_connectivity"
    )
    
    local errors=0
    for validator in "${validators[@]}"; do
        if ! $validator; then
            ((errors++))
        fi
    done
    
    return $errors
}

_validate_operating_system() {
    log_debug "Validating operating system..."
    
    local os_name os_version
    os_name=$(uname -s)
    os_version=$(uname -r)
    
    VALIDATION_RESULTS["os_name"]="$os_name"
    VALIDATION_RESULTS["os_version"]="$os_version"
    
    case "$os_name" in
        "Linux"|"Darwin")
            log_debug "✅ Supported OS detected: $os_name $os_version"
            
            # Additional Linux distribution detection
            if [[ "$os_name" == "Linux" ]]; then
                if [[ -f /etc/os-release ]]; then
                    local distro
                    distro=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d'"' -f2)
                    VALIDATION_RESULTS["os_distribution"]="$distro"
                    log_debug "Linux distribution: $distro"
                fi
            fi
            return 0
            ;;
        "CYGWIN"*|"MINGW"*|"MSYS"*)
            log_warn "⚠️  Windows environment detected: $os_name"
            VALIDATION_WARNINGS["os_compatibility"]="Windows environments may have compatibility issues"
            return 0
            ;;
        *)
            log_error "❌ Unsupported operating system: $os_name"
            VALIDATION_ERRORS["os_unsupported"]="Operating system $os_name is not supported"
            return 1
            ;;
    esac
}

_validate_hardware_requirements() {
    log_debug "Validating hardware requirements..."
    
    local issues=0
    _validate_memory || ((issues++))
    _validate_cpu || ((issues++))
    _validate_gpu  # GPU is optional, don't count as error
    
    return $issues
}

_validate_memory() {
    local total_mem_gb=0
    
    if command -v free >/dev/null 2>&1; then
        # Linux
        total_mem_gb=$(free -g | awk '/^Mem:/ {print $2}')
        if [[ $total_mem_gb -eq 0 ]]; then
            # Handle systems with less than 1GB
            local total_mem_mb
            total_mem_mb=$(free -m | awk '/^Mem:/ {print $2}')
            total_mem_gb=$(( (total_mem_mb + 512) / 1024 ))  # Round up
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v sysctl >/dev/null 2>&1; then
            local mem_bytes
            mem_bytes=$(sysctl -n hw.memsize)
            total_mem_gb=$(( mem_bytes / 1024 / 1024 / 1024 ))
        fi
    else
        log_warn "⚠️  Cannot determine memory capacity on this system"
        VALIDATION_WARNINGS["memory_unknown"]="Unable to determine system memory"
        return 1
    fi
    
    VALIDATION_RESULTS["memory_gb"]="$total_mem_gb"
    
    if [[ $total_mem_gb -lt ${VALIDATION_CONFIG[MIN_MEMORY_GB]} ]]; then
        log_error "❌ Insufficient memory: ${total_mem_gb}GB (minimum: ${VALIDATION_CONFIG[MIN_MEMORY_GB]}GB)"
        VALIDATION_ERRORS["memory_insufficient"]="System has ${total_mem_gb}GB memory, minimum ${VALIDATION_CONFIG[MIN_MEMORY_GB]}GB required"
        return 1
    elif [[ $total_mem_gb -lt ${VALIDATION_CONFIG[RECOMMENDED_MEMORY_GB]} ]]; then
        log_warn "⚠️  Limited memory: ${total_mem_gb}GB (recommended: ${VALIDATION_CONFIG[RECOMMENDED_MEMORY_GB]}GB+)"
        VALIDATION_WARNINGS["memory_limited"]="System has ${total_mem_gb}GB memory, ${VALIDATION_CONFIG[RECOMMENDED_MEMORY_GB]}GB+ recommended for optimal performance"
        return 0
    else
        log_debug "✅ Sufficient memory: ${total_mem_gb}GB"
        return 0
    fi
}

_validate_cpu() {
    local cpu_count
    
    if command -v nproc >/dev/null 2>&1; then
        cpu_count=$(nproc)
    elif [[ -f /proc/cpuinfo ]]; then
        cpu_count=$(grep -c ^processor /proc/cpuinfo)
    elif [[ "$OSTYPE" == "darwin"* ]] && command -v sysctl >/dev/null 2>&1; then
        cpu_count=$(sysctl -n hw.ncpu 2>/dev/null)
    else
        cpu_count="unknown"
    fi
    
    VALIDATION_RESULTS["cpu_cores"]="$cpu_count"
    
    if [[ "$cpu_count" == "unknown" ]]; then
        log_warn "⚠️  Cannot determine CPU information"
        VALIDATION_WARNINGS["cpu_unknown"]="Unable to determine CPU information"
        return 1
    fi
    
    if [[ $cpu_count -lt ${VALIDATION_CONFIG[MIN_CPU_CORES]} ]]; then
        log_error "❌ Insufficient CPU cores: $cpu_count (minimum: ${VALIDATION_CONFIG[MIN_CPU_CORES]})"
        VALIDATION_ERRORS["cpu_insufficient"]="System has $cpu_count CPU cores, minimum ${VALIDATION_CONFIG[MIN_CPU_CORES]} required"
        return 1
    elif [[ $cpu_count -lt ${VALIDATION_CONFIG[RECOMMENDED_CPU_CORES]} ]]; then
        log_warn "⚠️  Limited CPU cores: $cpu_count (recommended: ${VALIDATION_CONFIG[RECOMMENDED_CPU_CORES]}+)"
        VALIDATION_WARNINGS["cpu_limited"]="System has $cpu_count CPU cores, ${VALIDATION_CONFIG[RECOMMENDED_CPU_CORES]}+ recommended"
        return 0
    else
        log_debug "✅ Sufficient CPU cores: $cpu_count"
        return 0
    fi
}

_validate_gpu() {
    if command -v nvidia-smi >/dev/null 2>&1; then
        if nvidia-smi >/dev/null 2>&1; then
            local gpu_info
            gpu_info=$(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)
            log_debug "✅ NVIDIA GPU detected: $gpu_info"
            VALIDATION_RESULTS["gpu_available"]="nvidia"
            VALIDATION_RESULTS["gpu_name"]="$gpu_info"
        else
            log_warn "⚠️  NVIDIA GPU detected but drivers may not be working properly"
            VALIDATION_WARNINGS["gpu_driver"]="NVIDIA GPU detected but drivers may not be functioning correctly"
            VALIDATION_RESULTS["gpu_available"]="nvidia_error"
        fi
    else
        log_debug "ℹ️  No NVIDIA GPU detected (CPU-only mode available)"
        VALIDATION_RESULTS["gpu_available"]="none"
    fi
    return 0  # GPU is optional
}

_validate_disk_space() {
    log_debug "Validating disk space..."
    
    local current_dir_space current_dir_gb
    if command -v df >/dev/null 2>&1; then
        current_dir_space=$(df . 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
        current_dir_gb=$((current_dir_space / 1024 / 1024))
    else
        log_warn "⚠️  Cannot determine disk space"
        VALIDATION_WARNINGS["disk_unknown"]="Unable to determine available disk space"
        return 1
    fi
    
    VALIDATION_RESULTS["disk_space_gb"]="$current_dir_gb"
    
    if [[ $current_dir_gb -lt ${VALIDATION_CONFIG[MIN_DISK_GB]} ]]; then
        log_error "❌ Insufficient disk space: ${current_dir_gb}GB (minimum: ${VALIDATION_CONFIG[MIN_DISK_GB]}GB)"
        VALIDATION_ERRORS["disk_insufficient"]="Only ${current_dir_gb}GB available, minimum ${VALIDATION_CONFIG[MIN_DISK_GB]}GB required"
        return 1
    elif [[ $current_dir_gb -lt ${VALIDATION_CONFIG[RECOMMENDED_DISK_GB]} ]]; then
        log_warn "⚠️  Limited disk space: ${current_dir_gb}GB (recommended: ${VALIDATION_CONFIG[RECOMMENDED_DISK_GB]}GB+)"
        VALIDATION_WARNINGS["disk_limited"]="Only ${current_dir_gb}GB available, ${VALIDATION_CONFIG[RECOMMENDED_DISK_GB]}GB+ recommended"
    else
        log_debug "✅ Sufficient disk space: ${current_dir_gb}GB"
    fi
    
    return 0
}

_validate_network_connectivity() {
    log_debug "Validating network connectivity..."
    
    local timeout="${VALIDATION_CONFIG[NETWORK_TIMEOUT]}"
    
    # Test basic connectivity with multiple approaches
    if command -v ping >/dev/null 2>&1; then
        if ping -c 1 -W "$timeout" 8.8.8.8 >/dev/null 2>&1; then
            log_debug "✅ Internet connectivity available"
            VALIDATION_RESULTS["internet_connectivity"]="available"
        else
            log_debug "ℹ️  Internet connectivity test failed (may be behind firewall)"
            VALIDATION_RESULTS["internet_connectivity"]="limited"
        fi
    elif command -v curl >/dev/null 2>&1; then
        if curl -s --max-time "$timeout" http://httpbin.org/ip >/dev/null 2>&1; then
            log_debug "✅ Internet connectivity available (via curl)"
            VALIDATION_RESULTS["internet_connectivity"]="available"
        else
            log_debug "ℹ️  Internet connectivity test failed"
            VALIDATION_RESULTS["internet_connectivity"]="limited"
        fi
    else
        log_debug "ℹ️  Cannot test network connectivity (no ping or curl available)"
        VALIDATION_RESULTS["internet_connectivity"]="unknown"
    fi
    
    return 0  # Network issues are not critical for basic operation
}

# =============================================================================
# Software Tools Validation
# =============================================================================

_validate_software_tools() {
    log_debug "Validating software tools..."
    
    local errors=0
    _validate_essential_tools || ((errors++))
    _validate_optional_tools  # Don't count optional tools as errors
    
    return $errors
}

_validate_essential_tools() {
    log_debug "Checking essential tools..."
    
    local essential_tools=("bash" "grep" "awk" "sed" "mkdir" "rm" "cp" "mv")
    local errors=0
    
    for tool in "${essential_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_debug "✅ $tool available"
            VALIDATION_RESULTS["tool_$tool"]="available"
        else
            log_error "❌ Essential tool missing: $tool"
            VALIDATION_ERRORS["tool_missing_$tool"]="Essential tool $tool is not available"
            ((errors++))
        fi
    done
    
    # Check for HTTP client (at least one required)
    if command -v curl >/dev/null 2>&1; then
        VALIDATION_RESULTS["http_client"]="curl"
        log_debug "✅ HTTP client: curl"
    elif command -v wget >/dev/null 2>&1; then
        VALIDATION_RESULTS["http_client"]="wget"
        log_debug "✅ HTTP client: wget"
    else
        log_warn "⚠️  No HTTP client available (curl or wget recommended)"
        VALIDATION_WARNINGS["http_client_missing"]="Neither curl nor wget is available - may limit functionality"
    fi
    
    return $errors
}

_validate_optional_tools() {
    log_debug "Checking optional tools..."
    
    local optional_tools=(
        "git:Version control"
        "yq:YAML processing"
        "jq:JSON processing"
        "bc:Math calculations"
        "docker:Container platform"
        "python3:Python runtime"
        "node:JavaScript runtime"
        "npm:Node package manager"
    )
    
    local available_tools=()
    local missing_tools=()
    
    for tool_desc in "${optional_tools[@]}"; do
        local tool="${tool_desc%%:*}"
        local desc="${tool_desc##*:}"
        
        if command -v "$tool" >/dev/null 2>&1; then
            log_debug "✅ $tool available ($desc)"
            VALIDATION_RESULTS["tool_$tool"]="available"
            available_tools+=("$tool")
        else
            log_debug "ℹ️  $tool not available ($desc)"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_debug "Optional tools not available: ${missing_tools[*]}"
    fi
    
    if [[ ${#available_tools[@]} -gt 0 ]]; then
        log_debug "Available optional tools: ${available_tools[*]}"
    fi
    
    return 0
}

# =============================================================================
# Configuration Validation
# =============================================================================

_validate_configuration() {
    log_debug "Validating configuration..."
    
    local errors=0
    _validate_file_structure || ((errors++))
    _validate_file_permissions  # Warnings only
    
    return $errors
}

_validate_file_structure() {
    log_debug "Checking file structure..."
    
    local required_dirs=("scripts")
    local optional_dirs=("config" "data" "logs" "temp")
    local errors=0
    
    # Check required directories
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_debug "✅ Required directory exists: $dir"
            VALIDATION_RESULTS["dir_$dir"]="exists"
        else
            log_error "❌ Required directory missing: $dir"
            VALIDATION_ERRORS["dir_missing_$dir"]="Required directory $dir is missing"
            ((errors++))
        fi
    done
    
    # Check optional directories
    for dir in "${optional_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_debug "✅ Optional directory exists: $dir"
            VALIDATION_RESULTS["dir_$dir"]="exists"
        else
            log_debug "ℹ️  Optional directory missing: $dir (will be created as needed)"
        fi
    done
    
    # Check main script
    local main_script="${PROJECT_ROOT:-.}/scripts/main.sh"
    if [[ -f "$main_script" ]]; then
        log_debug "✅ Main script exists"
        VALIDATION_RESULTS["main_script"]="exists"
        
        if [[ ! -x "$main_script" ]]; then
            log_warn "⚠️  Main script is not executable"
            VALIDATION_WARNINGS["main_script_permissions"]="Main script needs execute permissions"
        fi
    else
        log_error "❌ Main script missing: $main_script"
        VALIDATION_ERRORS["main_script_missing"]="Main script $main_script is missing"
        ((errors++))
    fi
    
    return $errors
}

_validate_file_permissions() {
    log_debug "Checking file permissions..."
    
    # Check if running as root
    if [[ "$EUID" -eq 0 ]]; then
        log_warn "⚠️  Running as root user"
        VALIDATION_WARNINGS["running_as_root"]="Running as root is not recommended for development mode"
    fi
    
    # Check directory write permissions
    if ! _test_directory_writable; then
        log_warn "⚠️  Current directory is not writable"
        VALIDATION_WARNINGS["directory_not_writable"]="Current directory is not writable - may cause issues"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Environment Validation
# =============================================================================

_validate_environment() {
    log_debug "Validating environment variables and settings..."
    
    _validate_environment_variables
    _validate_path_variables
    _validate_shell_environment
    
    return 0  # Environment issues are warnings only
}

_validate_environment_variables() {
    log_debug "Checking environment variables..."
    
    local important_vars=("HOME" "USER" "SHELL" "PATH")
    local missing_vars=()
    
    for var in "${important_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            log_debug "✅ $var is set"
            VALIDATION_RESULTS["env_$var"]="set"
        else
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_warn "⚠️  Missing environment variables: ${missing_vars[*]}"
        for var in "${missing_vars[@]}"; do
            VALIDATION_WARNINGS["env_missing_$var"]="Environment variable $var is not set"
        done
    fi
    
    # Check FKS-specific variables
    if [[ -n "${FKS_MODE:-}" ]]; then
        log_debug "✅ FKS_MODE is set to: $FKS_MODE"
        VALIDATION_RESULTS["fks_mode"]="$FKS_MODE"
    fi
}

_validate_path_variables() {
    log_debug "Checking PATH variables..."
    
    if [[ -z "${PATH:-}" ]]; then
        log_warn "⚠️  PATH environment variable not set"
        VALIDATION_WARNINGS["path_not_set"]="PATH environment variable is not set"
        return
    fi
    
    local path_count
    path_count=$(echo "$PATH" | tr ':' '\n' | wc -l)
    log_debug "✅ PATH is set and contains $path_count directories"
    VALIDATION_RESULTS["path_entries"]="$path_count"
}

_validate_shell_environment() {
    log_debug "Checking shell environment..."
    
    # Check shell version
    if [[ -n "${BASH_VERSION:-}" ]]; then
        local bash_major="${BASH_VERSION%%.*}"
        VALIDATION_RESULTS["bash_version"]="$BASH_VERSION"
        
        if [[ $bash_major -ge 4 ]]; then
            log_debug "✅ Bash version compatible: $BASH_VERSION"
        else
            log_warn "⚠️  Old Bash version: $BASH_VERSION (4.0+ recommended)"
            VALIDATION_WARNINGS["bash_old"]="Bash version $BASH_VERSION is old, 4.0+ recommended"
        fi
    fi
}

# =============================================================================
# Component-Specific Validation
# =============================================================================

validate_component() {
    local component="$1"
    
    log_info "🔍 Validating component: $component"
    
    case "$component" in
        "docker") _validate_docker_component ;;
        "python") _validate_python_component ;;
        "network") _validate_network_connectivity ;;
        "storage") _validate_disk_space ;;
        "permissions") _validate_file_permissions ;;
        "all") validate_system_requirements ;;
        *) 
            log_error "Unknown component: $component"
            log_info "Available components: docker, python, network, storage, permissions, all"
            return 1
            ;;
    esac
}

_validate_docker_component() {
    log_info "🐳 Validating Docker component..."
    
    local errors=0
    
    if command -v docker >/dev/null 2>&1; then
        echo "✅ Docker installed"
        local docker_version
        docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
        echo "   Version: $docker_version"
        
        if timeout 10 docker info >/dev/null 2>&1; then
            echo "✅ Docker daemon running"
            
            # Check Docker Compose
            if command -v docker-compose >/dev/null 2>&1; then
                local compose_version
                compose_version=$(docker-compose --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
                echo "✅ Docker Compose available (standalone): $compose_version"
            elif docker compose version >/dev/null 2>&1; then
                local compose_version
                compose_version=$(docker compose version --short 2>/dev/null)
                echo "✅ Docker Compose available (plugin): $compose_version"
            else
                echo "❌ Docker Compose not available"
                ((errors++))
            fi
        else
            echo "❌ Docker daemon not running or not accessible"
            echo "   Try: sudo systemctl start docker"
            ((errors++))
        fi
    else
        echo "❌ Docker not installed"
        echo "   Install Docker from: https://docs.docker.com/get-docker/"
        ((errors++))
    fi
    
    return $errors
}

_validate_python_component() {
    log_info "🐍 Validating Python component..."
    
    local warnings=0
    
    if command -v python3 >/dev/null 2>&1; then
        local python_version
        python_version=$(python3 --version 2>/dev/null | cut -d' ' -f2)
        echo "✅ Python3 installed: $python_version"
        
        # Check version compatibility (3.8+)
        if [[ -n "$python_version" ]]; then
            local major minor
            IFS='.' read -r major minor patch <<< "$python_version"
            
            if [[ $major -eq 3 ]] && [[ $minor -ge 8 ]]; then
                echo "✅ Python version compatible (3.8+ required)"
            elif [[ $major -eq 3 ]] && [[ $minor -ge 6 ]]; then
                echo "⚠️  Python version may be too old ($python_version, 3.8+ recommended)"
                ((warnings++))
            else
                echo "❌ Python version too old ($python_version, 3.8+ required)"
                return 1
            fi
        fi
        
        # Check pip
        if command -v pip3 >/dev/null 2>&1; then
            local pip_version
            pip_version=$(pip3 --version 2>/dev/null | cut -d' ' -f2)
            echo "✅ pip3 available: $pip_version"
        elif command -v pip >/dev/null 2>&1; then
            local pip_version
            pip_version=$(pip --version 2>/dev/null | cut -d' ' -f2)
            echo "✅ pip available: $pip_version"
        else
            echo "❌ pip not available"
            return 1
        fi
        
        # Check virtual environment capability
        if python3 -m venv --help >/dev/null 2>&1; then
            echo "✅ Python venv module available"
        else
            echo "⚠️  Python venv module not available"
            ((warnings++))
        fi
        
    else
        echo "❌ Python3 not installed"
        echo "   Install Python 3.8+ from: https://www.python.org/downloads/"
        return 1
    fi
    
    return $(( warnings > 0 ? 1 : 0 ))
}

# =============================================================================
# Utility Functions
# =============================================================================

_init_validation_state() {
    VALIDATION_RESULTS=()
    VALIDATION_ERRORS=()
    VALIDATION_WARNINGS=()
    log_debug "Validation state initialized"
}

_count_warnings() {
    echo "${#VALIDATION_WARNINGS[@]}"
}

_test_directory_writable() {
    local test_file=".write_test_$$"
    if touch "$test_file" 2>/dev/null; then
        rm -f "$test_file" 2>/dev/null
        return 0
    else
        return 1
    fi
}

_check_os_compatibility() {
    local os_name
    os_name=$(uname -s)
    case "$os_name" in
        "Linux"|"Darwin")
            echo "  ✅ Operating System: $os_name"
            return 0
            ;;
        *)
            echo "  ❌ Operating System: $os_name (unsupported)"
            return 1
            ;;
    esac
}

_check_disk_space() {
    local disk_gb
    disk_gb=$(df . 2>/dev/null | awk 'NR==2 {print int($4/1024/1024)}' || echo "0")
    if [[ $disk_gb -ge ${VALIDATION_CONFIG[MIN_DISK_GB]} ]]; then
        echo "  ✅ Disk Space: ${disk_gb}GB"
        return 0
    else
        echo "  ❌ Disk Space: ${disk_gb}GB (minimum ${VALIDATION_CONFIG[MIN_DISK_GB]}GB required)"
        return 1
    fi
}

_check_essential_tools() {
    local tools=("bash" "grep" "awk")
    local errors=0
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  ✅ Tool: $tool"
        else
            echo "  ❌ Tool: $tool (required)"
            ((errors++))
        fi
    done
    
    return $errors
}

_check_main_script() {
    local main_script="${PROJECT_ROOT:-.}/scripts/main.sh"
    if [[ -f "$main_script" ]]; then
        echo "  ✅ Main Script: Found"
        return 0
    else
        echo "  ❌ Main Script: Missing ($main_script)"
        return 1
    fi
}

_generate_final_report() {
    local total_errors=$1
    local total_warnings=$2
    local validation_time=$3
    
    echo ""
    log_info "📋 System Validation Report (${validation_time}s)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo "Summary: $total_errors errors, $total_warnings warnings"
    
    _show_system_info
    _show_issues "$total_errors" "$total_warnings"
    _show_recommendations "$total_errors" "$total_warnings"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ $total_errors -eq 0 ]]; then
        if [[ $total_warnings -eq 0 ]]; then
            log_success "✅ System validation passed successfully"
        else
            log_warn "⚠️  System validation passed with warnings"
        fi
    else
        log_error "❌ System validation failed"
    fi
}

_show_system_info() {
    echo ""
    echo "System Information:"
    echo "  OS: ${VALIDATION_RESULTS[os_name]:-Unknown} ${VALIDATION_RESULTS[os_version]:-}"
    [[ -n "${VALIDATION_RESULTS[os_distribution]:-}" ]] && echo "  Distribution: ${VALIDATION_RESULTS[os_distribution]}"
    echo "  Memory: ${VALIDATION_RESULTS[memory_gb]:-Unknown}GB"
    echo "  CPU Cores: ${VALIDATION_RESULTS[cpu_cores]:-Unknown}"
    echo "  Disk Space: ${VALIDATION_RESULTS[disk_space_gb]:-Unknown}GB"
    echo "  GPU: ${VALIDATION_RESULTS[gpu_available]:-none}"
    [[ -n "${VALIDATION_RESULTS[gpu_name]:-}" ]] && echo "  GPU Model: ${VALIDATION_RESULTS[gpu_name]}"
    echo "  Mode: ${FKS_MODE:-unknown}"
    echo "  Bash: ${VALIDATION_RESULTS[bash_version]:-$BASH_VERSION}"
}

_show_issues() {
    local total_errors=$1
    local total_warnings=$2
    
    if [[ $total_errors -gt 0 ]]; then
        echo ""
        echo "❌ ERRORS (must be fixed):"
        for error_key in "${!VALIDATION_ERRORS[@]}"; do
            echo "  • ${VALIDATION_ERRORS[$error_key]}"
        done
    fi
    
    if [[ $total_warnings -gt 0 ]]; then
        echo ""
        echo "⚠️  WARNINGS (recommended to fix):"
        local count=0
        for warning_key in "${!VALIDATION_WARNINGS[@]}"; do
            if [[ $count -lt 5 ]]; then  # Limit to first 5 warnings
                echo "  • ${VALIDATION_WARNINGS[$warning_key]}"
                ((count++))
            fi
        done
        
        if [[ ${#VALIDATION_WARNINGS[@]} -gt 5 ]]; then
            echo "  ... and $((${#VALIDATION_WARNINGS[@]} - 5)) more warnings"
        fi
    fi
}

_show_recommendations() {
    local total_errors=$1
    local total_warnings=$2
    
    echo ""
    echo "Recommendations:"
    
    if [[ $total_errors -gt 0 ]]; then
        echo "  🔴 Fix critical errors before proceeding"
        echo "  💡 Run './run.sh validate fix' to attempt automatic fixes"
    elif [[ $total_warnings -gt 0 ]]; then
        echo "  🟡 Consider addressing warnings for optimal performance"
        if [[ "${VALIDATION_RESULTS[memory_gb]:-0}" -lt "${VALIDATION_CONFIG[RECOMMENDED_MEMORY_GB]}" ]]; then
            echo "  💾 Consider upgrading RAM for better performance"
        fi
        if [[ "${VALIDATION_RESULTS[cpu_cores]:-0}" -lt "${VALIDATION_CONFIG[RECOMMENDED_CPU_CORES]}" ]]; then
            echo "  🖥️  Consider upgrading CPU for better performance"
        fi
    else
        echo "  ✅ System is ready for FKS Trading Systems!"
        echo "  🚀 You can proceed with confidence"
    fi
}

# =============================================================================
# Interactive Functions
# =============================================================================

fix_validation_issues() {
    log_info "🔧 Attempting to fix common validation issues..."
    
    local fixes_applied=0
    
    # Fix script permissions
    local main_script="${PROJECT_ROOT:-.}/scripts/main.sh"
    if [[ -f "$main_script" ]] && [[ ! -x "$main_script" ]]; then
        log_info "Fixing main script permissions..."
        if chmod +x "$main_script" 2>/dev/null; then
            log_success "✅ Fixed main script permissions"
            ((fixes_applied++))
        else
            log_warn "⚠️  Could not fix main script permissions"
        fi
    fi
    
    # Create missing directories
    local required_dirs=("logs" "data" "config" "temp")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_info "Creating directory: $dir"
            if mkdir -p "$dir" 2>/dev/null; then
                log_success "✅ Created directory: $dir"
                ((fixes_applied++))
            else
                log_warn "⚠️  Could not create directory: $dir"
            fi
        fi
    done
    
    # Set up basic configuration if missing
    if [[ ! -f "config/app.yml" ]] && [[ -d "config" ]]; then
        log_info "Creating basic configuration file..."
        cat > config/app.yml << 'EOF'
# FKS Trading Systems Configuration
app:
  name: "FKS Trading Systems"
  version: "3.0.0"
  mode: "development"

system:
  log_level: "INFO"
  debug: false
EOF
        if [[ -f "config/app.yml" ]]; then
            log_success "✅ Created basic configuration"
            ((fixes_applied++))
        fi
    fi
    
    echo ""
    if [[ $fixes_applied -gt 0 ]]; then
        log_success "✅ Applied $fixes_applied automatic fixes"
        log_info "Run validation again to check if issues were resolved"
    else
        log_info "No automatic fixes were needed or possible"
    fi
    
    return $fixes_applied
}

# Export functions for external use
export -f validate_system_requirements quick_validate validate_component fix_validation_issues

# Main execution guard
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ This script should be sourced, not executed directly"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

log_debug "📦 Loaded validation module (v$VALIDATION_MODULE_VERSION)"