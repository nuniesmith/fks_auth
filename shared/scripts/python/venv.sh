#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# CONFIGURATION & GLOBAL VARIABLES
###############################################################################

LOG_DIR="/tmp/utils"
LOG_FILE="${LOG_DIR}/utils.log"
# The sudo password is no longer needed since we re-run as root.
COMPOSE_FILE="./docker-compose.yml"
VENV_DIR="/home/${USER}/.venv"
REQUIREMENTS_FILE="/home/${USER}/code/repos/fks/requirements.txt"
PACKAGE_CACHE="/home/${USER}/packages"
PYTHON_VERSION="/usr/bin/python"  # Default Python version

DEBUG=false  # Enable verbose debugging if needed
[[ "$DEBUG" == "true" ]] && set -x

NON_INTERACTIVE=false  # Default mode is interactive

while getopts "yV:" opt; do
  case "$opt" in
    y) NON_INTERACTIVE=true ;;
    V) PYTHON_VERSION="$OPTARG" ;;
    *) echo "Usage: $(basename "$0") [-y] [-V python_version]"; exit 1 ;;
  esac
done
shift "$((OPTIND-1))"

mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
trap 'log_info "Script interrupted."; exit 130' INT
trap 'log_info "Script terminated."; exit 143' TERM

###############################################################################
# LOGGING & UTILITIES
###############################################################################

log_info() { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"; }
log_warn() { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2 | tee -a "$LOG_FILE"; }

confirm() {
    if [[ "$NON_INTERACTIVE" == true ]]; then
        echo "$1 [y/N]: y (auto-confirmed)"
        return 0
    else
        read -r -p "$1 [y/N]: " response
        [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
    fi
}

###############################################################################
# SETUP PYTHON VIRTUAL ENVIRONMENT
###############################################################################

setup_python_venv() {
    # Check if the specified Python version is available
    if ! command -v "${PYTHON_VERSION}" &>/dev/null; then
        log_error "Python version ${PYTHON_VERSION} is not installed or not found in PATH."
        exit 1
    fi

    # Install system dependencies for venv if using APT (Debian/Ubuntu)
    if command -v apt &>/dev/null; then
        if ! dpkg -s python3-venv &>/dev/null; then
            log_info "Installing python3-venv..."
            apt update && apt install -y python3-venv
        fi
    fi

    # Delete the existing virtual environment if it exists
    if [[ -d "$VENV_DIR" ]]; then
        log_info "Deleting existing virtual environment at '$VENV_DIR'..."
        rm -rf "$VENV_DIR"
    fi

    # Create the virtual environment
    log_info "Creating a new virtual environment at '$VENV_DIR'..."
    "${PYTHON_VERSION}" -m venv "$VENV_DIR"

    # Activate the virtual environment
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    log_info "Virtual environment activated."

    # Update pip
    log_info "Updating pip..."
    pip install --upgrade pip

    # Prepare the package cache directory
    mkdir -p "$PACKAGE_CACHE"

    # Download packages from requirements.txt into the cache
    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        log_info "Downloading packages to '$PACKAGE_CACHE'..."
        pip download -r "$REQUIREMENTS_FILE" -d "$PACKAGE_CACHE"
        log_info "Download complete."
    else
        log_warn "No requirements.txt found. Skipping package download."
    fi

    # Install packages from the cached files
    if [[ -d "$PACKAGE_CACHE" && -n "$(ls -A "$PACKAGE_CACHE")" ]]; then
        log_info "Installing packages from '$PACKAGE_CACHE'..."
        pip install --no-index --find-links="$PACKAGE_CACHE" -r "$REQUIREMENTS_FILE"
        log_info "Packages installed successfully."
    else
        log_warn "No cached packages found. Skipping package installation."
    fi

    log_info "Python virtual environment setup complete."
}

# Call the function if you want to run it directly:
setup_python_venv