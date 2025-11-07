#!/bin/bash
# filepath: fks/scripts/core/environment.sh
# FKS Trading Systems - Environment Detection Functions

# Prevent multiple sourcing
[[ -n "${FKS_CORE_ENVIRONMENT_LOADED:-}" ]] && return 0
readonly FKS_CORE_ENVIRONMENT_LOADED=1

# Module metadata
readonly ENVIRONMENT_MODULE_VERSION="3.1.0"
readonly DETECTION_TIMEOUT=15  # Reduced timeout
readonly CACHE_DURATION=300    # 5 minutes

# Get script directory (avoid readonly conflicts)
if [[ -z "${ENVIRONMENT_SCRIPT_DIR:-}" ]]; then
    readonly ENVIRONMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Source dependencies with fallback
if [[ -f "$ENVIRONMENT_SCRIPT_DIR/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$ENVIRONMENT_SCRIPT_DIR/logging.sh"
elif [[ -f "$(dirname "$ENVIRONMENT_SCRIPT_DIR")/core/logging.sh" ]]; then
    # shellcheck disable=SC1090
    source "$(dirname "$ENVIRONMENT_SCRIPT_DIR")/core/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[INFO] $1"; }
    log_warn() { echo "[WARN] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo "[DEBUG] $1" >&2; }
    log_success() { echo "[SUCCESS] $1"; }
fi

# Environment detection results
declare -A ENVIRONMENT_INFO
declare -A CAPABILITY_FLAGS
declare -g LAST_DETECTION_TIME=0
declare -g DETECTION_IN_PROGRESS=0

# Detection configuration - functions exist, no timeout needed
declare -Ar DETECTION_MODULES=(
    ["os"]="detect_operating_system"
    ["hardware"]="detect_hardware_capabilities"
    ["software"]="detect_software_environment"
    ["container"]="detect_container_environment"
    ["network"]="detect_network_environment"
    ["development"]="detect_development_environment"
)

# Initialize environment detection with caching
init_environment_detection() {
    local current_time
    current_time=$(date +%s)
    
    # Prevent concurrent detection
    if [[ $DETECTION_IN_PROGRESS -eq 1 ]]; then
        log_debug "Environment detection already in progress, waiting..."
        return 0
    fi
    
    # Check if cache is still valid
    if [[ $((current_time - LAST_DETECTION_TIME)) -lt $CACHE_DURATION ]]; then
        log_debug "Using cached environment detection results"
        return 0
    fi
    
    log_debug "Initializing environment detection..."
    DETECTION_IN_PROGRESS=1
    
    # Clear previous results
    ENVIRONMENT_INFO=()
    CAPABILITY_FLAGS=()
    
    # Run detection modules - call functions directly (no timeout needed)
    for module in "${!DETECTION_MODULES[@]}"; do
        local func="${DETECTION_MODULES[$module]}"
        if declare -F "$func" >/dev/null 2>&1; then
            log_debug "Running detection module: $module"
            if ! "$func"; then
                log_warn "Detection module '$module' failed"
            fi
        else
            log_warn "Detection function '$func' not found"
        fi
    done
    
    LAST_DETECTION_TIME=$current_time
    DETECTION_IN_PROGRESS=0
    log_debug "Environment detection completed"
}

# Operating system detection
detect_operating_system() {
    local os_info
    os_info=$(uname -srm 2>/dev/null || echo "Unknown Unknown Unknown")
    read -r os_name os_version architecture <<< "$os_info"
    
    ENVIRONMENT_INFO["os_name"]="$os_name"
    ENVIRONMENT_INFO["os_version"]="$os_version"
    ENVIRONMENT_INFO["architecture"]="$architecture"
    
    case "$os_name" in
        "Linux")
            ENVIRONMENT_INFO["os_family"]="linux"
            _detect_linux_distribution
            CAPABILITY_FLAGS["linux"]="yes"
            ;;
        "Darwin")
            ENVIRONMENT_INFO["os_family"]="macos"
            _detect_macos_version
            CAPABILITY_FLAGS["macos"]="yes"
            ;;
        "CYGWIN"*|"MINGW"*|"MSYS"*)
            ENVIRONMENT_INFO["os_family"]="windows"
            ENVIRONMENT_INFO["os_distribution"]="windows_subsystem"
            CAPABILITY_FLAGS["windows_subsystem"]="yes"
            ;;
        *)
            ENVIRONMENT_INFO["os_family"]="unknown"
            log_warn "Unknown operating system: $os_name"
            ;;
    esac
    
    return 0
}

# Linux distribution detection (private function)
_detect_linux_distribution() {
    if [[ -f /etc/os-release ]]; then
        # Modern method
        local id="" version_id="" pretty_name=""
        while IFS='=' read -r key value; do
            case "$key" in
                ID) id="${value//\"/}" ;;
                VERSION_ID) version_id="${value//\"/}" ;;
                PRETTY_NAME) pretty_name="${value//\"/}" ;;
            esac
        done < /etc/os-release
        
        ENVIRONMENT_INFO["os_distribution"]="${id:-unknown}"
        ENVIRONMENT_INFO["os_distribution_version"]="${version_id:-unknown}"
        ENVIRONMENT_INFO["os_distribution_name"]="${pretty_name:-unknown}"
        
    elif [[ -f /etc/redhat-release ]]; then
        ENVIRONMENT_INFO["os_distribution"]="redhat"
        ENVIRONMENT_INFO["os_distribution_name"]=$(cat /etc/redhat-release 2>/dev/null)
        
    elif [[ -f /etc/debian_version ]]; then
        ENVIRONMENT_INFO["os_distribution"]="debian"
        ENVIRONMENT_INFO["os_distribution_version"]=$(cat /etc/debian_version 2>/dev/null)
        
    elif [[ -f /etc/lsb-release ]]; then
        # Fallback for older Ubuntu/LSB systems
        local distrib_id="" distrib_release=""
        while IFS='=' read -r key value; do
            case "$key" in
                DISTRIB_ID) distrib_id="${value//\"/}" ;;
                DISTRIB_RELEASE) distrib_release="${value//\"/}" ;;
            esac
        done < /etc/lsb-release
        
        ENVIRONMENT_INFO["os_distribution"]="${distrib_id,,}"
        ENVIRONMENT_INFO["os_distribution_version"]="$distrib_release"
    else
        ENVIRONMENT_INFO["os_distribution"]="unknown"
    fi
}

# macOS version detection (private function)
_detect_macos_version() {
    if command -v sw_vers >/dev/null 2>&1; then
        local product_version product_name
        product_version=$(sw_vers -productVersion 2>/dev/null)
        product_name=$(sw_vers -productName 2>/dev/null)
        
        ENVIRONMENT_INFO["os_distribution"]="macos"
        ENVIRONMENT_INFO["os_distribution_version"]="$product_version"
        ENVIRONMENT_INFO["os_distribution_name"]="$product_name $product_version"
    fi
}

# Hardware capabilities detection
detect_hardware_capabilities() {
    _detect_memory
    _detect_cpu
    _detect_gpu_capabilities
    _detect_storage_capabilities
    return 0
}

# Memory detection (private function)
_detect_memory() {
    local mem_gb=0
    
    case "${ENVIRONMENT_INFO[os_family]:-unknown}" in
        "linux")
            if [[ -f /proc/meminfo ]]; then
                local mem_total_kb
                mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
                if [[ -n "$mem_total_kb" && "$mem_total_kb" -gt 0 ]]; then
                    mem_gb=$((mem_total_kb / 1024 / 1024))
                    # Handle systems with less than 1GB
                    [[ $mem_gb -eq 0 ]] && mem_gb=1
                fi
            fi
            ;;
        "macos")
            if command -v sysctl >/dev/null 2>&1; then
                local mem_bytes
                mem_bytes=$(sysctl -n hw.memsize 2>/dev/null)
                if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
                    mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
                fi
            fi
            ;;
        *)
            # Try free command as fallback
            if command -v free >/dev/null 2>&1; then
                local mem_total_mb
                mem_total_mb=$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}')
                if [[ -n "$mem_total_mb" && "$mem_total_mb" -gt 0 ]]; then
                    mem_gb=$(( (mem_total_mb + 512) / 1024 ))  # Round up
                fi
            fi
            ;;
    esac
    
    ENVIRONMENT_INFO["memory_total_gb"]="$mem_gb"
    
    # Set capability flags based on memory
    if [[ $mem_gb -ge 8 ]]; then
        CAPABILITY_FLAGS["high_memory"]="yes"
    elif [[ $mem_gb -ge 4 ]]; then
        CAPABILITY_FLAGS["adequate_memory"]="yes"
    else
        CAPABILITY_FLAGS["low_memory"]="yes"
    fi
}

# CPU detection (private function)
_detect_cpu() {
    local cpu_cores=0
    local cpu_model="unknown"
    
    case "${ENVIRONMENT_INFO[os_family]:-unknown}" in
        "linux")
            # Try nproc first (most reliable)
            if command -v nproc >/dev/null 2>&1; then
                cpu_cores=$(nproc 2>/dev/null)
            elif [[ -f /proc/cpuinfo ]]; then
                cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "0")
                cpu_model=$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
            fi
            ;;
        "macos")
            if command -v sysctl >/dev/null 2>&1; then
                cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "0")
                cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
            fi
            ;;
        *)
            # Try to get CPU info from other sources
            if command -v nproc >/dev/null 2>&1; then
                cpu_cores=$(nproc 2>/dev/null || echo "0")
            fi
            ;;
    esac
    
    ENVIRONMENT_INFO["cpu_cores"]="${cpu_cores:-0}"
    ENVIRONMENT_INFO["cpu_model"]="${cpu_model:-unknown}"
    
    # Set capability flags based on CPU
    if [[ ${cpu_cores:-0} -ge 8 ]]; then
        CAPABILITY_FLAGS["high_cpu"]="yes"
    elif [[ ${cpu_cores:-0} -ge 4 ]]; then
        CAPABILITY_FLAGS["adequate_cpu"]="yes"
    elif [[ ${cpu_cores:-0} -ge 2 ]]; then
        CAPABILITY_FLAGS["dual_core"]="yes"
    else
        CAPABILITY_FLAGS["single_core"]="yes"
    fi
}

# GPU capabilities detection
_detect_gpu_capabilities() {
    # Initialize GPU flags
    CAPABILITY_FLAGS["nvidia_gpu"]="not_available"
    CAPABILITY_FLAGS["amd_gpu"]="not_available"
    CAPABILITY_FLAGS["intel_gpu"]="not_available"
    
    # NVIDIA GPU detection
    if command -v nvidia-smi >/dev/null 2>&1; then
        if timeout 5 nvidia-smi >/dev/null 2>&1; then
            CAPABILITY_FLAGS["nvidia_gpu"]="available"
            
            local gpu_count gpu_primary
            gpu_count=$(nvidia-smi --list-gpus 2>/dev/null | wc -l)
            gpu_primary=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
            
            ENVIRONMENT_INFO["nvidia_gpu_count"]="${gpu_count:-0}"
            ENVIRONMENT_INFO["nvidia_gpu_primary"]="${gpu_primary:-unknown}"
            
            # Check CUDA
            if command -v nvcc >/dev/null 2>&1; then
                CAPABILITY_FLAGS["cuda"]="available"
                ENVIRONMENT_INFO["cuda_version"]=$(nvcc --version 2>/dev/null | grep "release" | awk '{print $6}' | cut -d',' -f1)
            fi
        else
            log_debug "NVIDIA GPU tools found but not functional"
        fi
    fi
    
    # AMD and Intel GPU detection (Linux only for now)
    if [[ "${ENVIRONMENT_INFO[os_family]:-unknown}" == "linux" ]] && command -v lspci >/dev/null 2>&1; then
        local gpu_info
        gpu_info=$(lspci 2>/dev/null | grep -i "vga\|3d\|display" || echo "")
        
        if [[ -n "$gpu_info" ]]; then
            if grep -qi "amd\|radeon\|ati" <<< "$gpu_info"; then
                CAPABILITY_FLAGS["amd_gpu"]="detected"
                ENVIRONMENT_INFO["amd_gpu_info"]=$(grep -i "amd\|radeon\|ati" <<< "$gpu_info" | head -1)
            fi
            
            if grep -qi "intel.*graphics\|intel.*display" <<< "$gpu_info"; then
                CAPABILITY_FLAGS["intel_gpu"]="detected"
                ENVIRONMENT_INFO["intel_gpu_info"]=$(grep -i "intel.*graphics\|intel.*display" <<< "$gpu_info" | head -1)
            fi
        fi
    fi
}

# Storage capabilities detection
_detect_storage_capabilities() {
    local available_gb=0
    local total_gb=0
    
    # Get available space
    if command -v df >/dev/null 2>&1; then
        local df_output
        df_output=$(df . 2>/dev/null | awk 'NR==2 {print $4, $2}')
        if [[ -n "$df_output" ]]; then
            local available_kb total_kb
            read -r available_kb total_kb <<< "$df_output"
            available_gb=$((available_kb / 1024 / 1024))
            total_gb=$((total_kb / 1024 / 1024))
        fi
    fi
    
    ENVIRONMENT_INFO["disk_available_gb"]="$available_gb"
    ENVIRONMENT_INFO["disk_total_gb"]="$total_gb"
    
    # Storage type detection (Linux only)
    if [[ "${ENVIRONMENT_INFO[os_family]:-unknown}" == "linux" ]]; then
        local storage_type="unknown"
        local root_device
        
        # Get root device
        root_device=$(df / 2>/dev/null | awk 'NR==2 {print $1}' | sed 's/[0-9]*$//' | sed 's|/dev/||')
        
        if [[ -n "$root_device" ]]; then
            local rotational_file="/sys/block/$root_device/queue/rotational"
            if [[ -f "$rotational_file" ]]; then
                case "$(cat "$rotational_file" 2>/dev/null)" in
                    "0") storage_type="ssd" ;;
                    "1") storage_type="hdd" ;;
                esac
            fi
        fi
        
        ENVIRONMENT_INFO["storage_type"]="$storage_type"
        CAPABILITY_FLAGS["storage_${storage_type}"]="yes"
    fi
    
    # Set storage capacity flags
    if [[ $available_gb -ge 50 ]]; then
        CAPABILITY_FLAGS["ample_storage"]="yes"
    elif [[ $available_gb -ge 20 ]]; then
        CAPABILITY_FLAGS["adequate_storage"]="yes"
    else
        CAPABILITY_FLAGS["limited_storage"]="yes"
    fi
}

# Software environment detection
detect_software_environment() {
    _detect_package_managers
    _detect_development_tools
    _detect_runtime_environments
    _detect_virtualization_environment
    return 0
}

# Package manager detection
_detect_package_managers() {
    local -ar package_managers=("apt" "yum" "dnf" "pacman" "brew" "zypper" "apk" "pkg")
    
    ENVIRONMENT_INFO["available_package_managers"]=""
    
    for pm in "${package_managers[@]}"; do
        if command -v "$pm" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["package_manager_$pm"]="available"
            
            # Set primary package manager (first one found)
            if [[ -z "${ENVIRONMENT_INFO[primary_package_manager]:-}" ]]; then
                ENVIRONMENT_INFO["primary_package_manager"]="$pm"
            fi
            
            # Build list of available package managers
            if [[ -z "${ENVIRONMENT_INFO[available_package_managers]}" ]]; then
                ENVIRONMENT_INFO["available_package_managers"]="$pm"
            else
                ENVIRONMENT_INFO["available_package_managers"]="${ENVIRONMENT_INFO[available_package_managers]}, $pm"
            fi
        else
            CAPABILITY_FLAGS["package_manager_$pm"]="not_available"
        fi
    done
}

# Development tools detection
_detect_development_tools() {
    local -ar dev_tools=("git" "curl" "wget" "nano" "vim" "emacs" "code" "make" "gcc" "clang" "ssh" "rsync")
    
    ENVIRONMENT_INFO["available_dev_tools"]=""
    local available_count=0
    
    for tool in "${dev_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["dev_tool_$tool"]="available"
            ((available_count++))
            
            # Get version info for important tools
            case "$tool" in
                "git") 
                    ENVIRONMENT_INFO["git_version"]=$(git --version 2>/dev/null | awk '{print $3}') 
                    ;;
                "gcc") 
                    ENVIRONMENT_INFO["gcc_version"]=$(gcc --version 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1) 
                    ;;
                "make")
                    ENVIRONMENT_INFO["make_version"]=$(make --version 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+' | head -1)
                    ;;
            esac
            
            # Build list of available tools
            if [[ -z "${ENVIRONMENT_INFO[available_dev_tools]}" ]]; then
                ENVIRONMENT_INFO["available_dev_tools"]="$tool"
            else
                ENVIRONMENT_INFO["available_dev_tools"]="${ENVIRONMENT_INFO[available_dev_tools]}, $tool"
            fi
        else
            CAPABILITY_FLAGS["dev_tool_$tool"]="not_available"
        fi
    done
    
    ENVIRONMENT_INFO["dev_tools_count"]="$available_count"
    
    # Set development environment capability
    if [[ $available_count -ge 8 ]]; then
        CAPABILITY_FLAGS["rich_dev_environment"]="yes"
    elif [[ $available_count -ge 5 ]]; then
        CAPABILITY_FLAGS["adequate_dev_environment"]="yes"
    else
        CAPABILITY_FLAGS["minimal_dev_environment"]="yes"
    fi
}

# Runtime environments detection
_detect_runtime_environments() {
    _detect_python_environment
    _detect_other_runtimes
}

# Python environment detection
_detect_python_environment() {
    # Python 3 detection
    if command -v python3 >/dev/null 2>&1; then
        CAPABILITY_FLAGS["python3"]="available"
        local py_version py_path
        py_version=$(python3 --version 2>/dev/null | awk '{print $2}')
        py_path=$(command -v python3)
        
        ENVIRONMENT_INFO["python3_version"]="$py_version"
        ENVIRONMENT_INFO["python3_path"]="$py_path"
        
        # Version compatibility check (3.8+)
        if [[ -n "$py_version" ]]; then
            local major minor patch
            IFS='.' read -r major minor patch <<< "$py_version"
            if [[ $major -eq 3 ]] && [[ $minor -ge 8 ]]; then
                CAPABILITY_FLAGS["python3_compatible"]="yes"
            else
                CAPABILITY_FLAGS["python3_compatible"]="no"
            fi
        fi
        
        # Check for Python 2 (legacy)
        if command -v python2 >/dev/null 2>&1; then
            ENVIRONMENT_INFO["python2_version"]=$(python2 --version 2>&1 | awk '{print $2}')
            CAPABILITY_FLAGS["python2"]="available"
        fi
    else
        CAPABILITY_FLAGS["python3"]="not_available"
        CAPABILITY_FLAGS["python3_compatible"]="no"
    fi
    
    # Package managers
    local -ar py_pkg_managers=("pip3" "pip" "conda" "pipenv" "poetry")
    for pkg_mgr in "${py_pkg_managers[@]}"; do
        if command -v "$pkg_mgr" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["$pkg_mgr"]="available"
            
            case "$pkg_mgr" in
                "pip3"|"pip")
                    ENVIRONMENT_INFO["${pkg_mgr}_version"]=$($pkg_mgr --version 2>/dev/null | awk '{print $2}')
                    ;;
                "conda")
                    ENVIRONMENT_INFO["conda_version"]=$(conda --version 2>/dev/null | awk '{print $2}')
                    ;;
                "pipenv")
                    ENVIRONMENT_INFO["pipenv_version"]=$(pipenv --version 2>/dev/null | awk '{print $3}')
                    ;;
                "poetry")
                    ENVIRONMENT_INFO["poetry_version"]=$(poetry --version 2>/dev/null | awk '{print $3}')
                    ;;
            esac
        else
            CAPABILITY_FLAGS["$pkg_mgr"]="not_available"
        fi
    done
    
    # Environment detection
    if [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
        CAPABILITY_FLAGS["conda_env_active"]="yes"
        ENVIRONMENT_INFO["conda_active_env"]="$CONDA_DEFAULT_ENV"
    else
        CAPABILITY_FLAGS["conda_env_active"]="no"
    fi
    
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        CAPABILITY_FLAGS["venv_active"]="yes"
        ENVIRONMENT_INFO["venv_path"]="$VIRTUAL_ENV"
        ENVIRONMENT_INFO["venv_name"]=$(basename "$VIRTUAL_ENV")
    else
        CAPABILITY_FLAGS["venv_active"]="no"
    fi
}

# Other runtime environments detection
_detect_other_runtimes() {
    local -A runtimes=(
        ["node"]="nodejs"
        ["java"]="java"
        ["go"]="golang"
        ["rustc"]="rust"
        ["ruby"]="ruby"
        ["php"]="php"
    )
    
    for cmd in "${!runtimes[@]}"; do
        local runtime="${runtimes[$cmd]}"
        if command -v "$cmd" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["$runtime"]="available"
            
            case "$cmd" in
                "node") 
                    ENVIRONMENT_INFO["nodejs_version"]=$(node --version 2>/dev/null | sed 's/^v//')
                    # Check npm
                    if command -v npm >/dev/null 2>&1; then
                        CAPABILITY_FLAGS["npm"]="available"
                        ENVIRONMENT_INFO["npm_version"]=$(npm --version 2>/dev/null)
                    fi
                    ;;
                "java") 
                    ENVIRONMENT_INFO["java_version"]=$(java -version 2>&1 | head -1 | cut -d'"' -f2)
                    ;;
                "go") 
                    ENVIRONMENT_INFO["go_version"]=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
                    ;;
                "rustc") 
                    ENVIRONMENT_INFO["rust_version"]=$(rustc --version 2>/dev/null | awk '{print $2}')
                    ;;
                "ruby")
                    ENVIRONMENT_INFO["ruby_version"]=$(ruby --version 2>/dev/null | awk '{print $2}')
                    ;;
                "php")
                    ENVIRONMENT_INFO["php_version"]=$(php --version 2>/dev/null | head -1 | awk '{print $2}')
                    ;;
            esac
        else
            CAPABILITY_FLAGS["$runtime"]="not_available"
        fi
    done
}

# Virtualization environment detection
_detect_virtualization_environment() {
    # Initialize flags
    CAPABILITY_FLAGS["running_in_container"]="no"
    CAPABILITY_FLAGS["running_in_vm"]="no"
    CAPABILITY_FLAGS["running_in_wsl"]="no"
    
    # Container detection
    if [[ -f /.dockerenv ]]; then
        CAPABILITY_FLAGS["running_in_container"]="yes"
        ENVIRONMENT_INFO["container_type"]="docker"
    elif [[ -f /run/.containerenv ]]; then
        CAPABILITY_FLAGS["running_in_container"]="yes"
        ENVIRONMENT_INFO["container_type"]="podman"
    elif [[ -f /proc/1/cgroup ]] && grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
        CAPABILITY_FLAGS["running_in_container"]="yes"
        
        if grep -q "docker" /proc/1/cgroup 2>/dev/null; then
            ENVIRONMENT_INFO["container_type"]="docker"
        elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
            ENVIRONMENT_INFO["container_type"]="lxc"
        elif grep -q "kubepods" /proc/1/cgroup 2>/dev/null; then
            ENVIRONMENT_INFO["container_type"]="kubernetes"
        fi
    fi
    
    # VM detection
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt_type
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [[ "$virt_type" != "none" ]]; then
            CAPABILITY_FLAGS["running_in_vm"]="yes"
            ENVIRONMENT_INFO["vm_type"]="$virt_type"
        fi
    elif [[ -f /sys/hypervisor/uuid ]] && [[ "$(head -c 3 /sys/hypervisor/uuid 2>/dev/null)" == "ec2" ]]; then
        CAPABILITY_FLAGS["running_in_vm"]="yes"
        ENVIRONMENT_INFO["vm_type"]="aws-ec2"
    elif [[ -f /proc/version ]] && grep -q "Microsoft\|WSL" /proc/version; then
        # WSL detection moved here for better organization
        CAPABILITY_FLAGS["running_in_wsl"]="yes"
        if grep -q "WSL2" /proc/version; then
            ENVIRONMENT_INFO["wsl_version"]="2"
        else
            ENVIRONMENT_INFO["wsl_version"]="1"
        fi
    fi
    
    # Cloud provider detection
    _detect_cloud_provider
}

# Cloud provider detection (helper function)
_detect_cloud_provider() {
    # AWS detection
    if [[ -f /sys/hypervisor/uuid ]] && [[ "$(head -c 3 /sys/hypervisor/uuid 2>/dev/null)" == "ec2" ]]; then
        CAPABILITY_FLAGS["cloud_provider_aws"]="yes"
        ENVIRONMENT_INFO["cloud_provider"]="aws"
    elif command -v curl >/dev/null 2>&1 && timeout 2 curl -s -m 1 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        CAPABILITY_FLAGS["cloud_provider_aws"]="yes"
        ENVIRONMENT_INFO["cloud_provider"]="aws"
    # Google Cloud detection
    elif command -v curl >/dev/null 2>&1 && timeout 2 curl -s -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ >/dev/null 2>&1; then
        CAPABILITY_FLAGS["cloud_provider_gcp"]="yes"
        ENVIRONMENT_INFO["cloud_provider"]="gcp"
    # Azure detection
    elif command -v curl >/dev/null 2>&1 && timeout 2 curl -s -m 1 -H "Metadata: true" http://169.254.169.254/metadata/instance/ >/dev/null 2>&1; then
        CAPABILITY_FLAGS["cloud_provider_azure"]="yes"
        ENVIRONMENT_INFO["cloud_provider"]="azure"
    else
        CAPABILITY_FLAGS["cloud_provider_none"]="yes"
        ENVIRONMENT_INFO["cloud_provider"]="none"
    fi
}

# Container environment detection
detect_container_environment() {
    # Docker detection
    if command -v docker >/dev/null 2>&1; then
        CAPABILITY_FLAGS["docker"]="available"
        local docker_version
        docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
        ENVIRONMENT_INFO["docker_version"]="$docker_version"
        
        # Test daemon connectivity with timeout
        if timeout 5 docker info >/dev/null 2>&1; then
            CAPABILITY_FLAGS["docker_daemon"]="running"
            
            # Get additional Docker info
            local docker_info
            docker_info=$(timeout 5 docker system info --format "{{.ServerVersion}};{{.NCPU}};{{.MemTotal}}" 2>/dev/null)
            if [[ -n "$docker_info" ]]; then
                IFS=';' read -r server_version server_cpu server_mem <<< "$docker_info"
                ENVIRONMENT_INFO["docker_server_version"]="$server_version"
                ENVIRONMENT_INFO["docker_server_cpu"]="$server_cpu"
                ENVIRONMENT_INFO["docker_server_memory"]="$((server_mem / 1024 / 1024 / 1024))GB"
            fi
        else
            CAPABILITY_FLAGS["docker_daemon"]="not_running"
        fi
    else
        CAPABILITY_FLAGS["docker"]="not_available"
    fi
    
    # Docker Compose detection
    if command -v docker-compose >/dev/null 2>&1; then
        CAPABILITY_FLAGS["docker_compose"]="available"
        local compose_version
        compose_version=$(docker-compose --version 2>/dev/null | awk '{print $3}' | tr -d ',')
        ENVIRONMENT_INFO["docker_compose_version"]="$compose_version"
        ENVIRONMENT_INFO["docker_compose_type"]="standalone"
    elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        CAPABILITY_FLAGS["docker_compose"]="available"
        local compose_version
        compose_version=$(docker compose version --short 2>/dev/null)
        ENVIRONMENT_INFO["docker_compose_version"]="$compose_version"
        ENVIRONMENT_INFO["docker_compose_type"]="plugin"
    else
        CAPABILITY_FLAGS["docker_compose"]="not_available"
    fi
    
    # Other container tools
    local -ar container_tools=("podman" "kubectl" "helm" "skaffold")
    for tool in "${container_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["$tool"]="available"
            
            case "$tool" in
                "podman")
                    ENVIRONMENT_INFO["podman_version"]=$(podman --version 2>/dev/null | awk '{print $3}')
                    ;;
                "kubectl")
                    ENVIRONMENT_INFO["kubectl_version"]=$(kubectl version --client --short 2>/dev/null | awk '{print $3}' | sed 's/v//')
                    ;;
                "helm")
                    ENVIRONMENT_INFO["helm_version"]=$(helm version --short 2>/dev/null | sed 's/v//')
                    ;;
            esac
        else
            CAPABILITY_FLAGS["$tool"]="not_available"
        fi
    done
    
    return 0
}

# Network environment detection
detect_network_environment() {
    # Basic connectivity test with timeout and fallback
    local connectivity_available=false
    
    # Test with ping first (most reliable)
    if command -v ping >/dev/null 2>&1; then
        if timeout 3 ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then
            connectivity_available=true
        elif timeout 3 ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then
            connectivity_available=true
        fi
    fi
    
    # Fallback to curl if ping fails
    if [[ "$connectivity_available" == false ]] && command -v curl >/dev/null 2>&1; then
        if timeout 3 curl -s --max-time 2 http://httpbin.org/ip >/dev/null 2>&1; then
            connectivity_available=true
        fi
    fi
    
    if [[ "$connectivity_available" == true ]]; then
        CAPABILITY_FLAGS["internet_connectivity"]="available"
    else
        CAPABILITY_FLAGS["internet_connectivity"]="not_available"
    fi
    
    # DNS resolution test
    if command -v nslookup >/dev/null 2>&1; then
        if timeout 3 nslookup google.com >/dev/null 2>&1; then
            CAPABILITY_FLAGS["dns_resolution"]="working"
        else
            CAPABILITY_FLAGS["dns_resolution"]="not_working"
        fi
    elif command -v host >/dev/null 2>&1; then
        if timeout 3 host google.com >/dev/null 2>&1; then
            CAPABILITY_FLAGS["dns_resolution"]="working"
        else
            CAPABILITY_FLAGS["dns_resolution"]="not_working"
        fi
    elif [[ "$connectivity_available" == true ]]; then
        # If we have connectivity, assume DNS is working
        CAPABILITY_FLAGS["dns_resolution"]="working"
    else
        CAPABILITY_FLAGS["dns_resolution"]="not_working"
    fi
    
    # Proxy detection
    local proxy_vars=("HTTP_PROXY" "http_proxy" "HTTPS_PROXY" "https_proxy" "ALL_PROXY" "all_proxy")
    local proxy_configured=false
    
    for proxy_var in "${proxy_vars[@]}"; do
        if [[ -n "${!proxy_var:-}" ]]; then
            proxy_configured=true
            ENVIRONMENT_INFO["proxy_${proxy_var,,}"]="${!proxy_var}"
        fi
    done
    
    if [[ "$proxy_configured" == true ]]; then
        CAPABILITY_FLAGS["proxy_configured"]="yes"
    else
        CAPABILITY_FLAGS["proxy_configured"]="no"
    fi
    
    # Network interface detection (Linux/macOS)
    if command -v ip >/dev/null 2>&1; then
        local interfaces
        interfaces=$(ip link show 2>/dev/null | grep -E "^[0-9]+" | awk -F': ' '{print $2}' | grep -v lo | head -5 | tr '\n' ', ' | sed 's/,$//')
        ENVIRONMENT_INFO["network_interfaces"]="$interfaces"
    elif command -v ifconfig >/dev/null 2>&1; then
        local interfaces
        interfaces=$(ifconfig 2>/dev/null | grep -E "^[a-zA-Z]" | awk '{print $1}' | grep -v lo | head -5 | tr '\n' ', ' | sed 's/,$//')
        ENVIRONMENT_INFO["network_interfaces"]="$interfaces"
    fi
    
    return 0
}

# Development environment detection
detect_development_environment() {
    # Terminal information
    ENVIRONMENT_INFO["terminal_type"]="${TERM:-unknown}"
    ENVIRONMENT_INFO["shell"]="${SHELL:-unknown}"
    ENVIRONMENT_INFO["shell_name"]=$(basename "${SHELL:-bash}")
    ENVIRONMENT_INFO["user"]="${USER:-${USERNAME:-unknown}}"
    ENVIRONMENT_INFO["home"]="${HOME:-unknown}"
    
    # Terminal capabilities
    case "${TERM:-}" in
        *256color*|*-256|xterm-256color) 
            CAPABILITY_FLAGS["terminal_256_color"]="yes" 
            ;;
        *) 
            CAPABILITY_FLAGS["terminal_256_color"]="no" 
            ;;
    esac
    
    if [[ "${TERM:-}" =~ truecolor ]] || [[ "${COLORTERM:-}" =~ (truecolor|24bit) ]]; then
        CAPABILITY_FLAGS["terminal_truecolor"]="yes"
    else
        CAPABILITY_FLAGS["terminal_truecolor"]="no"
    fi
    
    # SSH session detection
    if [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]] || [[ "${TERM:-}" =~ screen.* ]]; then
        CAPABILITY_FLAGS["ssh_session"]="yes"
        ENVIRONMENT_INFO["ssh_connection"]="${SSH_CONNECTION:-${SSH_CLIENT:-yes}}"
    else
        CAPABILITY_FLAGS["ssh_session"]="no"
    fi
    
    # Git repository detection
    if [[ -d ".git" ]] && command -v git >/dev/null 2>&1; then
        CAPABILITY_FLAGS["git_repository"]="yes"
        
        local git_branch git_status git_remote
        git_branch=$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
        git_status=$(git status --porcelain 2>/dev/null | wc -l || echo "unknown")
        git_remote=$(git remote -v 2>/dev/null | head -1 | awk '{print $2}' || echo "none")
        
        ENVIRONMENT_INFO["git_branch"]="$git_branch"
        ENVIRONMENT_INFO["git_status"]="$git_status"
        ENVIRONMENT_INFO["git_remote"]="$git_remote"
        
        # Check if repo is clean
        if [[ "$git_status" == "0" ]]; then
            CAPABILITY_FLAGS["git_repo_clean"]="yes"
        else
            CAPABILITY_FLAGS["git_repo_clean"]="no"
        fi
    else
        CAPABILITY_FLAGS["git_repository"]="no"
    fi
    
    # IDE/Editor detection
    local -ar editors=("code" "vim" "nvim" "emacs" "nano" "subl")
    ENVIRONMENT_INFO["available_editors"]=""
    
    for editor in "${editors[@]}"; do
        if command -v "$editor" >/dev/null 2>&1; then
            CAPABILITY_FLAGS["editor_$editor"]="available"
            
            if [[ -z "${ENVIRONMENT_INFO[available_editors]}" ]]; then
                ENVIRONMENT_INFO["available_editors"]="$editor"
            else
                ENVIRONMENT_INFO["available_editors"]="${ENVIRONMENT_INFO[available_editors]}, $editor"
            fi
        fi
    done
    
    return 0
}

# Utility functions
get_environment_capability() {
    local key="$1"
    echo "${CAPABILITY_FLAGS[$key]:-unknown}"
}

get_environment_info() {
    local key="$1"
    echo "${ENVIRONMENT_INFO[$key]:-unknown}"
}

has_capability() {
    local capability="$1"
    [[ "${CAPABILITY_FLAGS[$capability]:-}" =~ ^(available|yes|working|running)$ ]]
}

# Requirement checking with improved logic
check_requirements() {
    local requirements=("$@")
    local missing_requirements=()
    local warnings=()
    
    log_debug "Checking requirements: ${requirements[*]}"
    
    for requirement in "${requirements[@]}"; do
        case "$requirement" in
            "docker")
                if ! (has_capability "docker" && has_capability "docker_daemon"); then
                    missing_requirements+=("docker with running daemon")
                fi
                ;;
            "python"|"python3")
                if ! (has_capability "python3" && has_capability "python3_compatible"); then
                    missing_requirements+=("python 3.8+")
                fi
                ;;
            "gpu"|"nvidia")
                if ! has_capability "nvidia_gpu"; then
                    missing_requirements+=("NVIDIA GPU")
                fi
                ;;
            "network"|"internet")
                if ! has_capability "internet_connectivity"; then
                    missing_requirements+=("internet connectivity")
                fi
                ;;
            "memory_8gb")
                if ! has_capability "high_memory"; then
                    warnings+=("8GB+ RAM recommended")
                fi
                ;;
            "cpu_4core")
                if ! has_capability "adequate_cpu"; then
                    warnings+=("4+ CPU cores recommended")
                fi
                ;;
            *)
                if ! has_capability "$requirement"; then
                    missing_requirements+=("$requirement")
                fi
                ;;
        esac
    done
    
    # Report warnings
    if [[ ${#warnings[@]} -gt 0 ]]; then
        log_warn "Performance warnings: ${warnings[*]}"
    fi
    
    # Report missing requirements
    if [[ ${#missing_requirements[@]} -eq 0 ]]; then
        log_debug "All requirements satisfied"
        return 0
    else
        log_error "Missing requirements: ${missing_requirements[*]}"
        return 1
    fi
}

# Environment summary with color support
show_environment_summary() {
    # Color definitions (with fallbacks)
    local WHITE='\033[1;37m' CYAN='\033[0;36m' YELLOW='\033[0;33m' NC='\033[0m'
    
    # Disable colors if not supported
    if [[ "${CAPABILITY_FLAGS[terminal_256_color]:-no}" == "no" ]]; then
        WHITE="" CYAN="" YELLOW="" NC=""
    fi
    
    cat << EOF

${WHITE}🌍 Environment Detection Summary${NC}
${CYAN}═══════════════════════════════${NC}

${YELLOW}System Information:${NC}
  OS: ${ENVIRONMENT_INFO[os_distribution_name]:-${ENVIRONMENT_INFO[os_name]} ${ENVIRONMENT_INFO[os_version]}}
  Architecture: ${ENVIRONMENT_INFO[architecture]:-unknown}
  Memory: ${ENVIRONMENT_INFO[memory_total_gb]:-unknown}GB
  CPU: ${ENVIRONMENT_INFO[cpu_cores]:-unknown} cores
  Storage: ${ENVIRONMENT_INFO[disk_available_gb]:-unknown}GB available (${ENVIRONMENT_INFO[storage_type]:-unknown})

${YELLOW}Development Environment:${NC}
$(has_capability "python3" && echo "  ✅ Python ${ENVIRONMENT_INFO[python3_version]:-unknown} (compatible: $(get_environment_capability python3_compatible))" || echo "  ❌ Python 3.8+ not available")
$(has_capability "docker" && echo "  ✅ Docker ${ENVIRONMENT_INFO[docker_version]:-unknown} (daemon: $(get_environment_capability docker_daemon))" || echo "  ❌ Docker not available")
$(has_capability "git_repository" && echo "  ✅ Git repository (branch: ${ENVIRONMENT_INFO[git_branch]:-unknown}, clean: $(get_environment_capability git_repo_clean))" || echo "  ℹ️  Not in a git repository")

${YELLOW}Hardware Capabilities:${NC}
$(has_capability "nvidia_gpu" && echo "  ✅ NVIDIA GPU: ${ENVIRONMENT_INFO[nvidia_gpu_primary]:-detected}" || echo "  ℹ️  No NVIDIA GPU (CPU-only mode)")
$(has_capability "high_memory" && echo "  ✅ High memory system" || (has_capability "adequate_memory" && echo "  ⚠️  Adequate memory" || echo "  ⚠️  Limited memory"))

${YELLOW}Network & Connectivity:${NC}
$(has_capability "internet_connectivity" && echo "  ✅ Internet connectivity" || echo "  ❌ No internet connectivity")
$(has_capability "dns_resolution" && echo "  ✅ DNS resolution working" || echo "  ❌ DNS resolution issues")
$(has_capability "proxy_configured" && echo "  ℹ️  Proxy configured" || echo "  ℹ️  No proxy configured")

${YELLOW}Runtime Environment:${NC}
$(has_capability "conda_env_active" && echo "  ✅ Conda environment: ${ENVIRONMENT_INFO[conda_active_env]}" || echo "  ℹ️  No active conda environment")
$(has_capability "venv_active" && echo "  ✅ Virtual environment: ${ENVIRONMENT_INFO[venv_name]}" || echo "  ℹ️  No active virtual environment")
$(has_capability "running_in_container" && echo "  ✅ Running in container: ${ENVIRONMENT_INFO[container_type]}" || echo "  ℹ️  Running on host system")

EOF
}

# Advanced debugging function
show_detailed_environment() {
    echo "🔍 Detailed Environment Information"
    echo "=================================="
    
    echo ""
    echo "📊 Capability Flags:"
    for key in $(printf '%s\n' "${!CAPABILITY_FLAGS[@]}" | sort); do
        printf "  %-30s: %s\n" "$key" "${CAPABILITY_FLAGS[$key]}"
    done
    
    echo ""
    echo "📋 Environment Info:"
    for key in $(printf '%s\n' "${!ENVIRONMENT_INFO[@]}" | sort); do
        printf "  %-30s: %s\n" "$key" "${ENVIRONMENT_INFO[$key]}"
    done
}

# Export functions for external use
export -f init_environment_detection get_environment_capability get_environment_info
export -f has_capability show_environment_summary check_requirements show_detailed_environment

# Auto-initialize on first load
if [[ -z "${FKS_ENVIRONMENT_DETECTED:-}" ]]; then
    export FKS_ENVIRONMENT_DETECTED=1
    init_environment_detection &  # Run in background to avoid blocking
fi

log_debug "📦 Loaded environment detection module (v$ENVIRONMENT_MODULE_VERSION)"