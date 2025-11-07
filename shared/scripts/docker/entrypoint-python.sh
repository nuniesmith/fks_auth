#!/bin/bash
# entrypoint-python.sh - Enhanced Python entrypoint
set -euo pipefail

# Basic logging
log_info() { echo -e "\033[0;32m[INFO]\033[0m $(date -Iseconds) - $1"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m $(date -Iseconds) - $1" >&2; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $(date -Iseconds) - $1" >&2; }
log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo -e "\033[0;36m[DEBUG]\033[0m $(date -Iseconds) - $1"; }

# Import common functions if available
if [[ -f "/app/scripts/docker/common.sh" ]]; then
    source "/app/scripts/docker/common.sh"
fi

# Environment setup with validation
SERVICE_TYPE="${SERVICE_TYPE:-app}"
SERVICE_PORT="${SERVICE_PORT:-8000}"
APP_LOG_LEVEL="${APP_LOG_LEVEL:-INFO}"
APP_DIR="${APP_DIR:-/app}"
# Prefer new layout at /app/src/python, but keep /app/src for backward-compat
SRC_DIR="${SRC_DIR:-${APP_DIR}/src/python}"
ALT_SRC_DIR="${ALT_SRC_DIR:-${APP_DIR}/src}"
PYTHON_SRC_DIR="${SRC_DIR}"

# Enable debug if needed
[[ "$APP_LOG_LEVEL" == "DEBUG" ]] && export DEBUG="true"

log_info "🐍 Starting Python service: ${SERVICE_TYPE}"

# Setup Python environment with src/python priority and legacy src as fallback
export PYTHONPATH="${PYTHON_SRC_DIR}:${ALT_SRC_DIR}:${APP_DIR}:${PYTHONPATH:-}"
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PATH="/opt/venv/bin:${PATH}"

# Virtual environment activation with validation
venv_activated=false
VENV_PATHS=("/opt/venv" "${APP_DIR}/venv" "${APP_DIR}/.venv")

for venv_path in "${VENV_PATHS[@]}"; do
    if [[ -d "$venv_path" && -f "$venv_path/bin/activate" ]]; then
        source "$venv_path/bin/activate"
        log_info "✅ Activated virtual environment: $venv_path"
        venv_activated=true
        break
    fi
done

if [[ "$venv_activated" == "false" ]]; then
    log_warn "⚠️ No virtual environment found, using system Python"
fi

# Verify Python installation
if ! python --version >/dev/null 2>&1; then
    log_error "❌ Python not available"
    exit 1
fi

log_debug "Python version: $(python --version)"
log_debug "Python path: $PYTHONPATH"
log_debug "Python source directory: $PYTHON_SRC_DIR"
log_debug "Legacy source directory: $ALT_SRC_DIR"

# Service discovery with enhanced main.py dispatcher
change_to_directory() {
    local target_dir="$1"
    if [[ -d "$target_dir" ]]; then
        cd "$target_dir" || {
            log_error "Failed to change to directory: $target_dir"
            return 1
        }
        log_debug "Changed to directory: $target_dir"
        return 0
    fi
    return 1
}

# Enhanced service discovery
log_debug "Starting service discovery for: $SERVICE_TYPE"

if [[ -f "${PYTHON_SRC_DIR}/main.py" ]]; then
    if change_to_directory "$PYTHON_SRC_DIR"; then
        log_info "📦 Using enhanced main.py dispatcher from src/python"
        log_debug "Executing: python main.py service ${SERVICE_TYPE} $*"
        exec python main.py service "${SERVICE_TYPE}" "$@"
    fi
fi

# Strategy 2: Main.py from legacy src
if [[ -f "${ALT_SRC_DIR}/main.py" ]]; then
    if change_to_directory "$ALT_SRC_DIR"; then
        log_info "📦 Using enhanced main.py dispatcher from src (legacy)"
        log_debug "Executing: python main.py service ${SERVICE_TYPE} $*"
        exec python main.py service "${SERVICE_TYPE}" "$@"
    fi
fi

# Strategy 3: Main.py from app root
if [[ -f "${APP_DIR}/main.py" ]]; then
    if change_to_directory "$APP_DIR"; then
        log_info "📦 Using main.py from app root"
        log_debug "Executing: python main.py service ${SERVICE_TYPE} $*"
        exec python main.py service "${SERVICE_TYPE}" "$@"
    fi
fi

# Strategy 4: Service-specific module discovery (updated for src/python structure)
SERVICE_MODULE_PATHS=(
    "${PYTHON_SRC_DIR}/services/${SERVICE_TYPE}/main.py"
    "${PYTHON_SRC_DIR}/${SERVICE_TYPE}/main.py"
    "${ALT_SRC_DIR}/services/${SERVICE_TYPE}/main.py"
    "${ALT_SRC_DIR}/${SERVICE_TYPE}/main.py"
    "${APP_DIR}/services/${SERVICE_TYPE}/main.py"
)

for module_path in "${SERVICE_MODULE_PATHS[@]}"; do
    if [[ -f "$module_path" ]]; then
        log_info "🎯 Found service module: $module_path"
        if change_to_directory "$PYTHON_SRC_DIR" || change_to_directory "$ALT_SRC_DIR"; then
            local base_dir
            if [[ "$module_path" == "${PYTHON_SRC_DIR}"* ]]; then
                base_dir="$PYTHON_SRC_DIR"
            elif [[ "$module_path" == "${ALT_SRC_DIR}"* ]]; then
                base_dir="$ALT_SRC_DIR"
            else
                base_dir=""
            fi
            # Convert file path to module path relative to detected base_dir
            if [[ -n "$base_dir" ]]; then
                relative_path="${module_path#${base_dir}/}"
                module_name="${relative_path%.py}"
                module_name="${module_name//\//.}"
                
                log_debug "Executing: python -m $module_name $*"
                exec python -m "$module_name" "$@"
            else
                # For paths outside PYTHON_SRC_DIR, execute directly
                module_dir="$(dirname "$module_path")"
                if change_to_directory "$module_dir"; then
                    log_debug "Executing: python main.py $*"
                    exec python main.py "$@"
                fi
            fi
        fi
    fi
done

# Strategy 5: Try using framework service template (attempt from both src/python and legacy src)
if change_to_directory "$PYTHON_SRC_DIR"; then
    log_info "🔧 Trying framework service template"
    if python -c "from framework.services.template import start_template_service" 2>/dev/null; then
        log_info "✅ Using framework service template"
        exec python -c "
import sys
sys.path.insert(0, '${PYTHON_SRC_DIR}')
sys.path.insert(0, '${ALT_SRC_DIR}')
sys.path.insert(0, '${APP_DIR}')
from framework.services.template import start_template_service
start_template_service('${SERVICE_TYPE}', ${SERVICE_PORT})
"
    else
        log_debug "Framework service template not available from ${PYTHON_SRC_DIR}"
    fi
fi

# Strategy 6: Try framework from legacy src directory
if change_to_directory "$ALT_SRC_DIR"; then
    log_info "🔧 Trying framework service template from src"
    if python -c "from framework.services.template import start_template_service" 2>/dev/null; then
        log_info "✅ Using framework service template"
        exec python -c "
import sys
sys.path.insert(0, '${PYTHON_SRC_DIR}')
sys.path.insert(0, '${ALT_SRC_DIR}')
sys.path.insert(0, '${APP_DIR}')
from framework.services.template import start_template_service
start_template_service('${SERVICE_TYPE}', ${SERVICE_PORT})
"
    fi
fi

# Strategy 7: Direct Python module execution (if PYTHON_MODULE is set) - MOVED TO LOWER PRIORITY
if [[ -n "${PYTHON_MODULE:-}" && "${PYTHON_MODULE}" != "main" ]]; then
    log_info "🔧 Using explicit Python module: ${PYTHON_MODULE}"
    if change_to_directory "$PYTHON_SRC_DIR"; then
        if [[ "$PYTHON_MODULE" == *":"* ]]; then
            MODULE_PATH="${PYTHON_MODULE%:*}"
            FUNCTION_NAME="${PYTHON_MODULE#*:}"
            log_debug "Executing: python -m ${MODULE_PATH} ${FUNCTION_NAME} $*"
            exec python -m "${MODULE_PATH}" "${FUNCTION_NAME}" "$@"
        else
            log_debug "Executing: python -m ${PYTHON_MODULE} $*"
            exec python -m "${PYTHON_MODULE}" "$@"
        fi
    fi
fi

# Error reporting
log_error "❌ No Python service handler found for: ${SERVICE_TYPE}"
log_info "Searched locations:"
log_info "  - ${PYTHON_SRC_DIR}/main.py"
log_info "  - ${SRC_DIR}/main.py"
log_info "  - ${APP_DIR}/main.py"
for path in "${SERVICE_MODULE_PATHS[@]}"; do
    log_info "  - $path"
done

# List what's actually available
log_info "Available files in ${PYTHON_SRC_DIR}:"
find "${PYTHON_SRC_DIR}" -name "*.py" -type f 2>/dev/null | head -10 || log_warn "No Python files found in python directory"

log_info "Available files in ${ALT_SRC_DIR}:"
find "${ALT_SRC_DIR}" -name "*.py" -type f 2>/dev/null | head -10 || log_warn "No Python files found in legacy src directory"

# Emergency fallback
log_warn "🆘 Using emergency Python fallback"
if change_to_directory "$PYTHON_SRC_DIR" || change_to_directory "$ALT_SRC_DIR"; then
    exec python -c "
import sys, time, traceback
sys.path.insert(0, '${PYTHON_SRC_DIR}')
sys.path.insert(0, '${ALT_SRC_DIR}')
sys.path.insert(0, '${APP_DIR}')

print('🚨 Emergency Python fallback for service: ${SERVICE_TYPE}')
print('Available sys.path:', sys.path[:4])
print('Working directory:', '$(pwd)')

try:
    # Try to import and use service template
    from framework.services.template import start_template_service
    print('✅ Found service template, starting...')
    start_template_service('${SERVICE_TYPE}', ${SERVICE_PORT})
except ImportError as e:
    print(f'⚠️ Service template not available: {e}')
    try:
        # Try basic Flask server
        from flask import Flask, jsonify
        app = Flask('${SERVICE_TYPE}-emergency')
        
        @app.route('/health')
        def health():
            return jsonify({'status': 'emergency', 'service': '${SERVICE_TYPE}'})
        
        @app.route('/info')
        def info():
            return jsonify({
                'service': '${SERVICE_TYPE}',
                'status': 'emergency_fallback',
                'working_dir': '$(pwd)',
                'python_src_dir': '${PYTHON_SRC_DIR}',
                'message': 'No main.py found, using emergency mode'
            })
        
        print('🌐 Starting emergency Flask server on port ${SERVICE_PORT}')
        app.run(host='0.0.0.0', port=${SERVICE_PORT})
    except ImportError:
        print('🔄 Flask not available, running basic loop')
        while True:
            print(f'Emergency fallback for ${SERVICE_TYPE} - sleeping...')
            time.sleep(60)
except Exception as e:
    print(f'❌ Emergency fallback failed: {e}')
    traceback.print_exc()
    sys.exit(1)
"
fi

exit 1