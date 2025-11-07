#!/bin/bash
# entrypoint-runtime.sh - Enhanced runtime dispatcher for FKS services
# UPDATED: Fixed logging permissions and improved error handling
set -euo pipefail

# =====================================================
# LOGGING AND UTILITIES
# =====================================================

# Enhanced logging with color support
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' NC=''
fi

# Initialize logging before any log calls
LOGS_DIR="${APP_DIR:-/app}/logs"
SERVICE_NAME="${SERVICE_NAME:-${SERVICE_TYPE:-app}}"

# Create logs directory if it doesn't exist and we have permissions
if [[ ! -d "$LOGS_DIR" ]] && mkdir -p "$LOGS_DIR" 2>/dev/null; then
    chmod 755 "$LOGS_DIR" 2>/dev/null || true
fi

# Set log file path - fallback to stderr if no write permission
if [[ -w "$LOGS_DIR" ]] || touch "${LOGS_DIR}/${SERVICE_NAME}.log" 2>/dev/null; then
    export LOG_FILE="${LOGS_DIR}/${SERVICE_NAME}.log"
    # Ensure log file is writable
    touch "$LOG_FILE" 2>/dev/null || export LOG_FILE="/dev/stderr"
else
    export LOG_FILE="/dev/stderr"
fi

# Enhanced logging functions with fallback
log_info() { 
    local msg="$(date -Iseconds) - [INFO] $1"
    echo -e "${GREEN}${msg}${NC}"
    if [[ "$LOG_FILE" != "/dev/stderr" ]]; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_warn() { 
    local msg="$(date -Iseconds) - [WARN] $1"
    echo -e "${YELLOW}${msg}${NC}" >&2
    if [[ "$LOG_FILE" != "/dev/stderr" ]]; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_error() { 
    local msg="$(date -Iseconds) - [ERROR] $1"
    echo -e "${RED}${msg}${NC}" >&2
    if [[ "$LOG_FILE" != "/dev/stderr" ]]; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local msg="$(date -Iseconds) - [DEBUG] $1"
        echo -e "${CYAN}${msg}${NC}"
        if [[ "$LOG_FILE" != "/dev/stderr" ]]; then
            echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
        fi
    fi
}

log_section() {
    local msg="===== $1: $2 ====="
    echo -e "\n${BLUE}${msg}${NC}"
    if [[ "$LOG_FILE" != "/dev/stderr" ]]; then
        echo -e "\n$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Utility functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

validate_file() {
    local file="$1"
    [[ -f "$file" && -r "$file" ]]
}

validate_executable() {
    local file="$1"
    [[ -f "$file" && -x "$file" ]]
}

validate_directory() {
    local dir="$1"
    [[ -d "$dir" && -r "$dir" ]]
}

# =====================================================
# ENVIRONMENT SETUP
# =====================================================

# Core configuration with validation
SERVICE_TYPE="${SERVICE_TYPE:-app}"
SERVICE_RUNTIME="${SERVICE_RUNTIME:-python}"
SERVICE_NAME="${SERVICE_NAME:-${SERVICE_TYPE}}"
SERVICE_PORT="${SERVICE_PORT:-8000}"
APP_DIR="${APP_DIR:-/app}"
APP_ENV="${APP_ENV:-development}"
APP_LOG_LEVEL="${APP_LOG_LEVEL:-INFO}"

# Validate essential environment
if [[ -z "$SERVICE_TYPE" || -z "$SERVICE_RUNTIME" ]]; then
    log_error "Missing required environment variables: SERVICE_TYPE, SERVICE_RUNTIME"
    exit 1
fi

# Enable debug mode if needed
if [[ "$APP_LOG_LEVEL" == "DEBUG" ]]; then
    export DEBUG="true"
fi

# Validate application directory
if ! validate_directory "$APP_DIR"; then
    log_error "Application directory not found or not readable: $APP_DIR"
    exit 1
fi

log_section "STARTUP" "FKS Enhanced Runtime Dispatcher v1.0"
log_info "Service: ${BLUE}${SERVICE_NAME}${NC} (type: ${SERVICE_TYPE}, runtime: ${SERVICE_RUNTIME})"
log_info "Environment: ${APP_ENV}, Log Level: ${APP_LOG_LEVEL}"
log_info "Application Directory: ${APP_DIR}"
log_info "Log File: ${LOG_FILE}"

# =====================================================
# ENVIRONMENT VALIDATION
# =====================================================

validate_environment() {
    log_section "VALIDATION" "Environment and Dependencies Check"
    
    # Check basic directories
    local required_dirs=("$APP_DIR" "${APP_DIR}/src")
    for dir in "${required_dirs[@]}"; do
        if validate_directory "$dir"; then
            log_debug "✓ Directory exists: $dir"
        else
            log_warn "⚠ Directory missing: $dir"
        fi
    done
    
    # Check Python environment for Python services
    if [[ "$SERVICE_RUNTIME" == "python" || "$SERVICE_RUNTIME" == "hybrid" ]]; then
        log_debug "Validating Python environment..."
        
        # Check virtual environment
        if [[ -d "/opt/venv" ]]; then
            log_debug "✓ Virtual environment found: /opt/venv"
            if [[ -f "/opt/venv/bin/python" ]]; then
                log_debug "✓ Python executable found in venv"
            else
                log_warn "⚠ Python executable not found in venv"
            fi
        else
            log_warn "⚠ Virtual environment not found at /opt/venv"
        fi
        
        # Check Python availability
        if command_exists python3; then
            log_debug "✓ Python3 available: $(python3 --version 2>&1)"
        elif command_exists python; then
            log_debug "✓ Python available: $(python --version 2>&1)"
        else
            log_error "❌ No Python interpreter found"
            return 1
        fi
    fi
    
    # Check Rust environment for Rust services
    if [[ "$SERVICE_RUNTIME" == "rust" ]]; then
        log_debug "Validating Rust environment..."
        
        # Check for Rust binaries
        local rust_bin_dirs=("${APP_DIR}/bin" "${APP_DIR}/bin/network" "${APP_DIR}/bin/execution")
        local rust_binaries_found=false
        
        for bin_dir in "${rust_bin_dirs[@]}"; do
            if validate_directory "$bin_dir" && [[ -n "$(find "$bin_dir" -type f -executable 2>/dev/null)" ]]; then
                log_debug "✓ Rust binaries found in: $bin_dir"
                rust_binaries_found=true
            fi
        done
        
        if [[ "$rust_binaries_found" == "false" ]]; then
            log_warn "⚠ No Rust binaries found in expected locations"
        fi
    fi
    
    # Check Node.js environment for Node services
    if [[ "$SERVICE_RUNTIME" == "node" ]]; then
        log_debug "Validating Node.js environment..."
        
        # Check Node.js availability
        if command_exists node; then
            log_debug "✓ Node.js available: $(node --version 2>&1)"
        else
            log_error "❌ No Node.js interpreter found"
            return 1
        fi
        
        # Check npm availability
        if command_exists npm; then
            log_debug "✓ npm available: $(npm --version 2>&1)"
        else
            log_warn "⚠ npm not found"
        fi
        
        # Check for package.json
        if [[ -f "${APP_DIR}/package.json" ]]; then
            log_debug "✓ package.json found"
        else
            log_warn "⚠ package.json not found in ${APP_DIR}"
        fi
        
        # Check for node_modules
        if [[ -d "${APP_DIR}/node_modules" ]]; then
            log_debug "✓ node_modules directory found"
        else
            log_warn "⚠ node_modules directory not found"
        fi
    fi
    
    # Check .NET environment for .NET services
    if [[ "$SERVICE_RUNTIME" == "dotnet" ]]; then
        log_debug "Validating .NET environment..."
        
        # Check .NET availability
        if command_exists dotnet; then
            log_debug "✓ .NET available: $(dotnet --version 2>&1)"
        else
            log_error "❌ No .NET runtime found"
            return 1
        fi
        
        # Check for .csproj files
        local csproj_files=($(find "${APP_DIR}" -name "*.csproj" 2>/dev/null | head -5))
        if [[ ${#csproj_files[@]} -gt 0 ]]; then
            log_debug "✓ .NET project files found: ${#csproj_files[@]} files"
        else
            log_warn "⚠ No .csproj files found in ${APP_DIR}"
        fi
    fi
    
    log_debug "Environment validation completed"
}

# =====================================================
# ENTRYPOINT DISCOVERY AND EXECUTION
# =====================================================

# Define entrypoint search order with priorities
ENTRYPOINT_STRATEGIES=(
    "enhanced_startup"
    "runtime_specific" 
    "unified_main"
    "node_app"
    "dotnet_app"
    "direct_binary"
    "service_specific"
    "emergency_fallback"
)

# Strategy 1: Enhanced startup script (highest priority)
try_enhanced_startup() {
    local enhanced_startup="${APP_DIR}/start_service.sh"
    
    if validate_executable "$enhanced_startup"; then
        log_info "✅ Using enhanced startup script with robust service discovery"
        log_debug "Executing: $enhanced_startup $*"
        cd "$APP_DIR" || return 1
        exec "$enhanced_startup" "$@"
    fi
    
    return 1
}

# Strategy 2: Runtime-specific entrypoints
try_runtime_specific() {
    local runtime_script=""
    
    case "${SERVICE_RUNTIME}" in
        python|hybrid)
            # Try multiple naming conventions
            local python_scripts=(
                "${APP_DIR}/scripts/docker/entrypoint-python.sh"
                "${APP_DIR}/scripts/docker/entrypoint-python.sh"
                "${APP_DIR}/entrypoint-python.sh"
            )
            
            for script in "${python_scripts[@]}"; do
                if validate_executable "$script"; then
                    runtime_script="$script"
                    break
                fi
            done
            ;;
        rust)
            # Try multiple naming conventions
            local rust_scripts=(
                "${APP_DIR}/scripts/docker/entrypoint-rust.sh"
                "${APP_DIR}/scripts/docker/entrypoint-rust.sh"
                "${APP_DIR}/entrypoint-rust.sh"
            )
            
            for script in "${rust_scripts[@]}"; do
                if validate_executable "$script"; then
                    runtime_script="$script"
                    break
                fi
            done
            ;;
        node)
            # Try multiple naming conventions for Node.js
            local node_scripts=(
                "${APP_DIR}/scripts/docker/entrypoint_node.sh"
                "${APP_DIR}/scripts/docker/entrypoint-node.sh"
                "${APP_DIR}/entrypoint_node.sh"
            )
            
            for script in "${node_scripts[@]}"; do
                if validate_executable "$script"; then
                    runtime_script="$script"
                    break
                fi
            done
            ;;
        dotnet)
            # Try multiple naming conventions for .NET
            local dotnet_scripts=(
                "${APP_DIR}/scripts/docker/entrypoint_dotnet.sh"
                "${APP_DIR}/scripts/docker/entrypoint-dotnet.sh"
                "${APP_DIR}/entrypoint_dotnet.sh"
            )
            
            for script in "${dotnet_scripts[@]}"; do
                if validate_executable "$script"; then
                    runtime_script="$script"
                    break
                fi
            done
            ;;
        *)
            log_debug "No specific entrypoint for runtime: ${SERVICE_RUNTIME}"
            return 1
            ;;
    esac
    
    if [[ -n "$runtime_script" ]] && validate_executable "$runtime_script"; then
        log_info "🔄 Using runtime-specific entrypoint: $(basename "$runtime_script")"
        log_debug "Executing: $runtime_script $*"
        cd "$APP_DIR" || return 1
        exec "$runtime_script" "$@"
    fi
    
    return 1
}

# Strategy 3: Unified main.py dispatcher
try_unified_main() {
    if [[ "$SERVICE_RUNTIME" != "python" && "$SERVICE_RUNTIME" != "hybrid" ]]; then
        return 1
    fi
    
    # Setup Python environment
    export PYTHONPATH="${APP_DIR}/src:${APP_DIR}:${PYTHONPATH:-}"
    export PYTHONUNBUFFERED=1
    export PATH="/opt/venv/bin:${PATH}"
    
    # Activate virtual environment
    if [[ -d "/opt/venv" && -f "/opt/venv/bin/activate" ]]; then
        source "/opt/venv/bin/activate"
        log_debug "Activated virtual environment"
    fi
    
    # Try main.py locations
    local main_locations=(
        "${APP_DIR}/src/main.py"
        "${APP_DIR}/main.py"
        "${APP_DIR}/src/services/main.py"
    )
    
    for main_file in "${main_locations[@]}"; do
        if validate_file "$main_file"; then
            local main_dir
            main_dir="$(dirname "$main_file")"
            cd "$main_dir" || continue
            
            log_info "📦 Using unified main.py dispatcher: $main_file"
            log_debug "Working directory: $main_dir"
            log_debug "Executing: python $(basename "$main_file") service ${SERVICE_TYPE} $*"
            exec python "$(basename "$main_file")" service "${SERVICE_TYPE}" "$@"
        fi
    done
    
    return 1
}

# Strategy 3.1: Node.js application execution
try_node_app() {
    if [[ "$SERVICE_RUNTIME" != "node" ]]; then
        return 1
    fi
    
    # Setup Node.js environment
    export NODE_ENV="${APP_ENV:-development}"
    export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=512}"
    
    cd "$APP_DIR" || return 1
    
    # Try to run npm start if package.json exists
    if [[ -f "${APP_DIR}/package.json" ]]; then
        log_info "📦 Found package.json, trying npm start"
        if npm start 2>/dev/null; then
            return 0
        fi
    fi
    
    # Try common Node.js entry points
    local node_entry_points=(
        "${APP_DIR}/src/index.js"
        "${APP_DIR}/index.js"
        "${APP_DIR}/src/app.js"
        "${APP_DIR}/app.js"
        "${APP_DIR}/src/server.js"
        "${APP_DIR}/server.js"
        "${APP_DIR}/src/main.js"
        "${APP_DIR}/main.js"
    )
    
    for entry_point in "${node_entry_points[@]}"; do
        if validate_file "$entry_point"; then
            local entry_dir
            entry_dir="$(dirname "$entry_point")"
            cd "$entry_dir" || continue
            
            log_info "🚀 Starting Node.js application: $entry_point"
            log_debug "Working directory: $entry_dir"
            log_debug "Executing: node $(basename "$entry_point") $*"
            exec node "$(basename "$entry_point")" "$@"
        fi
    done
    
    return 1
}

# Strategy 3.2: .NET application execution
try_dotnet_app() {
    if [[ "$SERVICE_RUNTIME" != "dotnet" ]]; then
        return 1
    fi
    
    # Setup .NET environment
    export DOTNET_ENVIRONMENT="${APP_ENV:-Development}"
    export ASPNETCORE_ENVIRONMENT="${APP_ENV:-Development}"
    export DOTNET_CLI_TELEMETRY_OPTOUT=1
    
    cd "$APP_DIR" || return 1
    
    # Try to find and run .csproj files
    local csproj_files=($(find "${APP_DIR}" -name "*.csproj" 2>/dev/null))
    
    for csproj in "${csproj_files[@]}"; do
        local csproj_dir
        csproj_dir="$(dirname "$csproj")"
        cd "$csproj_dir" || continue
        
        log_info "🔷 Running .NET project: $csproj"
        log_debug "Working directory: $csproj_dir"
        log_debug "Executing: dotnet run --project $(basename "$csproj") $*"
        exec dotnet run --project "$(basename "$csproj")" "$@"
    done
    
    # Try to find DLL files to run
    local dll_files=($(find "${APP_DIR}" -name "*.dll" -path "*/bin/*" 2>/dev/null | head -5))
    
    for dll in "${dll_files[@]}"; do
        if [[ -f "$dll" ]]; then
            local dll_dir
            dll_dir="$(dirname "$dll")"
            cd "$dll_dir" || continue
            
            log_info "🔷 Running .NET assembly: $dll"
            log_debug "Working directory: $dll_dir"
            log_debug "Executing: dotnet $(basename "$dll") $*"
            exec dotnet "$(basename "$dll")" "$@"
        fi
    done
    
    return 1
}

# Strategy 4: Direct binary execution (for Rust services)
try_direct_binary() {
    if [[ "$SERVICE_RUNTIME" != "rust" ]]; then
        return 1
    fi
    
    # Setup Rust environment
    export RUST_LOG="${APP_LOG_LEVEL,,}"
    export RUST_BACKTRACE=1
    
    # Define binary search paths
    local binary_paths=(
        "${APP_DIR}/bin/${SERVICE_TYPE}"
        "${APP_DIR}/bin/network/${SERVICE_TYPE}"
        "${APP_DIR}/bin/execution/${SERVICE_TYPE}"
        "${APP_DIR}/bin/connector/${SERVICE_TYPE}"
        "${APP_DIR}/bin/${SERVICE_TYPE}-service"
        "${APP_DIR}/bin/fks_${SERVICE_TYPE}"
    )
    
    for binary_path in "${binary_paths[@]}"; do
        if validate_executable "$binary_path"; then
            log_info "🎯 Executing Rust binary: $binary_path"
            log_debug "Executing: $binary_path $*"
            cd "$APP_DIR" || return 1
            exec "$binary_path" "$@"
        fi
    done
    
    return 1
}

# Strategy 5: Service-specific module execution
try_service_specific() {
    if [[ "$SERVICE_RUNTIME" != "python" && "$SERVICE_RUNTIME" != "hybrid" ]]; then
        return 1
    fi
    
    # Setup Python environment
    export PYTHONPATH="${APP_DIR}/src:${APP_DIR}:${PYTHONPATH:-}"
    export PYTHONUNBUFFERED=1
    export PATH="/opt/venv/bin:${PATH}"
    
    # Activate virtual environment
    if [[ -d "/opt/venv" && -f "/opt/venv/bin/activate" ]]; then
        source "/opt/venv/bin/activate"
        log_debug "Activated virtual environment"
    fi
    
    # Try service-specific module locations
    local service_modules=(
        "${APP_DIR}/src/services/${SERVICE_TYPE}/main.py"
        "${APP_DIR}/src/services/${SERVICE_TYPE}/__main__.py"
        "${APP_DIR}/src/${SERVICE_TYPE}/main.py"
        "${APP_DIR}/src/${SERVICE_TYPE}/__main__.py"
    )
    
    for module_file in "${service_modules[@]}"; do
        if validate_file "$module_file"; then
            local module_dir
            module_dir="$(dirname "$module_file")"
            cd "$module_dir" || continue
            
            log_info "🎯 Using service-specific module: $module_file"
            log_debug "Working directory: $module_dir"
            log_debug "Executing: python $(basename "$module_file") $*"
            exec python "$(basename "$module_file")" "$@"
        fi
    done
    
    # Try running as module
    local python_modules=(
        "services.${SERVICE_TYPE}"
        "${SERVICE_TYPE}.main"
        "${SERVICE_TYPE}"
    )
    
    cd "${APP_DIR}/src" || return 1
    
    for module in "${python_modules[@]}"; do
        if python -c "import ${module}" 2>/dev/null; then
            log_info "🎯 Running Python module: $module"
            log_debug "Executing: python -m $module $*"
            exec python -m "$module" "$@"
        fi
    done
    
    return 1
}

# Strategy 6: Emergency fallback
try_emergency_fallback() {
    log_warn "🆘 Using emergency fallback service"
    
    case "${SERVICE_RUNTIME}" in
        python|hybrid)
            # Setup Python environment
            export PYTHONPATH="${APP_DIR}/src:${APP_DIR}:${PYTHONPATH:-}"
            [[ -d "/opt/venv" && -f "/opt/venv/bin/activate" ]] && source "/opt/venv/bin/activate"
            
            log_info "Starting emergency Python HTTP server on port ${SERVICE_PORT}"
            cd "$APP_DIR" || exit 1
            exec python -c "
import sys, time, os, socket
sys.path.insert(0, '${APP_DIR}/src')
sys.path.insert(0, '${APP_DIR}')

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def emergency_server():
    try:
        from flask import Flask, jsonify
        app = Flask('${SERVICE_TYPE}-emergency')
        
        @app.route('/')
        def root():
            return jsonify({
                'service': '${SERVICE_TYPE}',
                'status': 'emergency_mode',
                'message': 'Service running in emergency fallback mode'
            })
        
        @app.route('/health')
        def health():
            return jsonify({
                'status': 'emergency',
                'service': '${SERVICE_TYPE}',
                'runtime': '${SERVICE_RUNTIME}',
                'message': 'Emergency fallback mode - limited functionality'
            })
        
        @app.route('/info')
        def info():
            return jsonify({
                'service': '${SERVICE_TYPE}',
                'runtime': '${SERVICE_RUNTIME}',
                'type': 'emergency_fallback',
                'environment': '${APP_ENV}',
                'working_dir': os.getcwd(),
                'python_version': sys.version,
                'python_path': sys.path[:5]
            })
        
        print('🚨 Emergency HTTP server starting on port ${SERVICE_PORT}')
        app.run(host='0.0.0.0', port=${SERVICE_PORT}, debug=False)
        
    except ImportError as e:
        print(f'Flask not available: {e}')
        print('🔄 Running basic keep-alive loop')
        while True:
            print(f'Emergency fallback for ${SERVICE_TYPE} - $(date)')
            time.sleep(30)
    except Exception as e:
        print(f'Emergency fallback error: {e}')
        sys.exit(1)
"
            ;;
        rust)
            log_error "No Rust binary found and no emergency fallback available"
            log_error "Available files in ${APP_DIR}/bin:"
            find "${APP_DIR}/bin" -type f 2>/dev/null | head -10 || log_error "No files found in bin directory"
            exit 1
            ;;
        node)
            log_info "Starting emergency Node.js server on port ${SERVICE_PORT}"
            cd "$APP_DIR" || exit 1
            
            # Try to start a basic Express server if available, otherwise use built-in http
            exec node -e "
const http = require('http');
const path = require('path');
const fs = require('fs');

const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    
    if (req.url === '/') {
        res.writeHead(200);
        res.end(JSON.stringify({
            service: '${SERVICE_TYPE}',
            status: 'emergency_mode',
            message: 'Service running in emergency fallback mode'
        }));
    } else if (req.url === '/health') {
        res.writeHead(200);
        res.end(JSON.stringify({
            status: 'emergency',
            service: '${SERVICE_TYPE}',
            runtime: '${SERVICE_RUNTIME}',
            message: 'Emergency fallback mode - limited functionality'
        }));
    } else if (req.url === '/info') {
        res.writeHead(200);
        res.end(JSON.stringify({
            service: '${SERVICE_TYPE}',
            runtime: '${SERVICE_RUNTIME}',
            type: 'emergency_fallback',
            environment: '${APP_ENV}',
            working_dir: process.cwd(),
            node_version: process.version,
            platform: process.platform
        }));
    } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Not found' }));
    }
});

console.log('🚨 Emergency Node.js HTTP server starting on port ${SERVICE_PORT}');
server.listen(${SERVICE_PORT}, '0.0.0.0', () => {
    console.log('✅ Emergency server running on port ${SERVICE_PORT}');
});

server.on('error', (err) => {
    console.error('Emergency server error:', err);
    process.exit(1);
});
"
            ;;
        dotnet)
            log_info "Starting emergency .NET server on port ${SERVICE_PORT}"
            cd "$APP_DIR" || exit 1
            
            # Try to find and run a .NET executable or create a minimal web server
            if command_exists dotnet; then
                exec dotnet -c "
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

class Program 
{
    static async Task Main(string[] args)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add(\"http://0.0.0.0:${SERVICE_PORT}/\");
        
        try 
        {
            listener.Start();
            Console.WriteLine(\"🚨 Emergency .NET HTTP server starting on port ${SERVICE_PORT}\");
            
            while (true)
            {
                var context = await listener.GetContextAsync();
                var request = context.Request;
                var response = context.Response;
                
                string responseString = \"\";
                
                switch (request.Url.AbsolutePath)
                {
                    case \"/\":
                        responseString = \"{\\\"service\\\":\\\"${SERVICE_TYPE}\\\",\\\"status\\\":\\\"emergency_mode\\\",\\\"message\\\":\\\"Service running in emergency fallback mode\\\"}\";
                        break;
                    case \"/health\":
                        responseString = \"{\\\"status\\\":\\\"emergency\\\",\\\"service\\\":\\\"${SERVICE_TYPE}\\\",\\\"runtime\\\":\\\"${SERVICE_RUNTIME}\\\",\\\"message\\\":\\\"Emergency fallback mode - limited functionality\\\"}\";
                        break;
                    case \"/info\":
                        responseString = \$\"{\\\"service\\\":\\\"${SERVICE_TYPE}\\\",\\\"runtime\\\":\\\"${SERVICE_RUNTIME}\\\",\\\"type\\\":\\\"emergency_fallback\\\",\\\"environment\\\":\\\"${APP_ENV}\\\",\\\"dotnet_version\\\":\\\"{Environment.Version}\\\"}\";
                        break;
                    default:
                        response.StatusCode = 404;
                        responseString = \"{\\\"error\\\":\\\"Not found\\\"}\";
                        break;
                }
                
                response.ContentType = \"application/json\";
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(\$\"Emergency server error: {ex.Message}\");
            Environment.Exit(1);
        }
    }
}
"
            else
                log_error "No .NET runtime found and no emergency fallback available"
                exit 1
            fi
            ;;
        *)
            log_error "Unknown runtime: ${SERVICE_RUNTIME}"
            exit 1
            ;;
    esac
}

# =====================================================
# SIGNAL HANDLING
# =====================================================

# Graceful shutdown handler
cleanup() {
    local exit_code=$?
    log_info "Received shutdown signal, cleaning up..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    log_info "Cleanup completed, exiting with code $exit_code"
    exit $exit_code
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

# =====================================================
# MAIN EXECUTION LOGIC
# =====================================================

# Validate environment first
if ! validate_environment; then
    log_error "Environment validation failed"
    exit 1
fi

log_section "DISCOVERY" "Attempting service discovery strategies"

# Try each strategy in order
for strategy in "${ENTRYPOINT_STRATEGIES[@]}"; do
    log_debug "Trying strategy: $strategy"
    
    case "$strategy" in
        enhanced_startup)
            if try_enhanced_startup "$@"; then exit 0; fi
            ;;
        runtime_specific)
            if try_runtime_specific "$@"; then exit 0; fi
            ;;
        unified_main)
            if try_unified_main "$@"; then exit 0; fi
            ;;
        node_app)
            if try_node_app "$@"; then exit 0; fi
            ;;
        dotnet_app)
            if try_dotnet_app "$@"; then exit 0; fi
            ;;
        direct_binary)
            if try_direct_binary "$@"; then exit 0; fi
            ;;
        service_specific)
            if try_service_specific "$@"; then exit 0; fi
            ;;
        emergency_fallback)
            try_emergency_fallback "$@"
            exit 0
            ;;
    esac
done

# Should never reach here
log_error "All service discovery strategies failed"
log_error "Available files in ${APP_DIR}:"
find "${APP_DIR}" -maxdepth 2 -type f -name "*.py" -o -name "*.sh" 2>/dev/null | head -20 || true
exit 1