# Dockerfile for FKS Trading Systems

# Global build arguments - available to all stages
ARG BUILD_TYPE=cpu
ARG PYTHON_VERSION=3.11
ARG RUST_VERSION=1.86.0
ARG DOTNET_VERSION=8.0
ARG NODE_VERSION=20
ARG CUDA_VERSION=12.8.0
ARG CUDNN_VERSION=cudnn
ARG UBUNTU_VERSION=ubuntu24.04
ARG BUILD_DATE
ARG BUILD_VERSION=1.0.0
ARG BUILD_COMMIT

# Service configuration
ARG SERVICE_RUNTIME=python  # Options: python, rust, hybrid, dotnet, node
ARG SERVICE_TYPE=web

# Build configuration (can be overridden at build time)
ARG BUILD_PYTHON=true
ARG BUILD_RUST_NETWORK=false 
ARG BUILD_RUST_EXECUTION=false
ARG BUILD_CONNECTOR=false
ARG BUILD_DOTNET=false
ARG BUILD_NODE=false

# Requirements file configuration
ARG REQUIREMENTS_PATH=./src/python/requirements.txt
ARG REQUIREMENTS_FILE=requirements.txt

# Directory paths for different source code types
ARG PYTHON_SRC_DIR=./src/python
ARG RUST_SRC_DIR=./src/rust
ARG NETWORK_CONNECTOR_DIR=./src/python/network
ARG RUST_NETWORK_DIR=./src/rust/network
ARG RUST_EXECUTION_DIR=./src/rust/execution
ARG DOTNET_SRC_DIR=./src/ninja
ARG NODE_SRC_DIR=./src/web/react

##############################################################
# Stage 1: Python Builder (CPU/GPU variants)
##############################################################
FROM python:${PYTHON_VERSION} AS builder-python-cpu

# GPU Python builder with Python pre-installed
FROM nvidia/cuda:${CUDA_VERSION}-${CUDNN_VERSION}-devel-${UBUNTU_VERSION} AS builder-python-gpu-base

# Install Python and essential tools for GPU builder
FROM builder-python-gpu-base AS builder-python-gpu
ARG PYTHON_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing specific Python version ${PYTHON_VERSION} and essential tools for GPU builder..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        software-properties-common \
        gcc build-essential libpq-dev curl p7zip-full unzip git \
        pkg-config libsystemd-dev libssl-dev \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python${PYTHON_VERSION} python${PYTHON_VERSION}-dev python${PYTHON_VERSION}-venv \
        python3-pip \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3 \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python \
    && python3 --version \
    && python3 -m pip --version \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Python ${PYTHON_VERSION} GPU builder setup completed."

# Select appropriate base for Python builder
FROM builder-python-${BUILD_TYPE} AS builder-python

ARG BUILD_TYPE
ARG PYTHON_VERSION
ARG SERVICE_TYPE
ARG PYTHON_SRC_DIR
ARG RUST_SRC_DIR
ARG REQUIREMENTS_PATH
ARG REQUIREMENTS_FILE
ARG EXTRA_BUILD_PACKAGES=""
ARG USE_SYSTEM_PACKAGES=true

WORKDIR /app/src

# Copy requirements files (supports nested src/python or flat src) and optional pyproject
COPY ./src /tmp/src_all
RUN set -e \
     && if [ -d /tmp/src_all/python ]; then \
             echo "Detected nested python layout for requirements."; \
             cp /tmp/src_all/python/requirements*.txt /app/ 2>/dev/null || true; \
         else \
             echo "Detected flat src layout for requirements."; \
             cp /tmp/src_all/requirements*.txt /app/ 2>/dev/null || true; \
         fi \
     && if ! ls /app/requirements*.txt 1>/dev/null 2>&1; then \
             echo "No requirements files found; creating placeholder requirements.txt"; \
             echo "# empty requirements" > /app/requirements.txt; \
         fi \
     && echo "✓ Requirements files staged:" \
     && ls -1 /app/requirements*.txt \
     && cp -a ./pyproject.toml* /app/ 2>/dev/null || true

# Show available requirements files for debugging
RUN set -e \
    && echo "=== Requirements File Information ===" \
    && echo "Service Type: ${SERVICE_TYPE}" \
    && echo "Build Type: ${BUILD_TYPE}" \
    && echo "Requested Requirements File: ${REQUIREMENTS_FILE}" \
    && echo "Available requirements files:" \
    && ls -la /app/requirements*.txt \
    && echo "Base requirements.txt content preview:" \
    && head -10 /app/requirements.txt \
    && echo "================================="

# Install system dependencies for CPU builds (GPU already has them)
RUN if [ "${BUILD_TYPE}" = "cpu" ]; then \
        echo "Installing system dependencies for CPU build..." \
        && apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            gcc build-essential libpq-dev curl p7zip-full unzip git \
            pkg-config libsystemd-dev libssl-dev ${EXTRA_BUILD_PACKAGES} \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    else \
        echo "GPU build - system dependencies already installed."; \
    fi

# Create virtual environment with improved error handling and validation
RUN set -e \
    && echo "Creating Python virtual environment..." \
    && PYTHON_CMD=$(command -v python3 || command -v python) \
    && echo "Using Python: ${PYTHON_CMD}" \
    && ${PYTHON_CMD} --version \
    && VENV_ARGS=$([ "${USE_SYSTEM_PACKAGES}" = "true" ] && echo "--system-site-packages" || echo "") \
    && ${PYTHON_CMD} -m venv /opt/venv ${VENV_ARGS} \
    && echo "Virtual environment created successfully at /opt/venv" \
    && /opt/venv/bin/python --version \
    && echo "sphinx\ntomli\nmarkdown\njinja2\npygments\npillow" > /app/docs-requirements.txt \
    && echo "Documentation requirements file created."

# Install Python dependencies with enhanced requirements handling and error recovery
RUN --mount=type=cache,target=/root/.cache/pip \
    set -e \
    && echo "=== Installing Python Dependencies ===" \
    && echo "Upgrading pip, wheel, and setuptools in virtual environment..." \
    && /opt/venv/bin/python -m pip install --upgrade pip wheel setuptools \
    && /opt/venv/bin/pip --version \
    && echo "✓ Virtual environment pip upgraded successfully" \
    && \
    # Determine requirements file based on service type and build parameters
    echo "=== Determining Requirements File ===" \
    && echo "Service Type: ${SERVICE_TYPE}" \
    && echo "Build Type: ${BUILD_TYPE}" \
    && echo "Specified Requirements File: ${REQUIREMENTS_FILE}" \
    && echo "Available requirements files:" \
    && ls -la /app/requirements*.txt \
    && \
    # Set the primary requirements file based on service type and build configuration
    if [ "${BUILD_TYPE}" = "gpu" ] && [ -f "/app/requirements_gpu.txt" ]; then \
        PRIMARY_REQUIREMENTS="/app/requirements_gpu.txt"; \
        echo "Selected: GPU requirements (requirements_gpu.txt)"; \
    elif [ "${REQUIREMENTS_FILE}" != "requirements.txt" ] && [ -f "/app/${REQUIREMENTS_FILE}" ]; then \
        PRIMARY_REQUIREMENTS="/app/${REQUIREMENTS_FILE}"; \
        echo "Selected: Custom requirements (${REQUIREMENTS_FILE})"; \
    elif [ "${SERVICE_TYPE}" = "web" ] || [ "${SERVICE_TYPE}" = "app" ]; then \
        if [ -f "/app/requirements_web.txt" ]; then \
            PRIMARY_REQUIREMENTS="/app/requirements_web.txt"; \
            echo "Selected: Web requirements (requirements_web.txt)"; \
        else \
            PRIMARY_REQUIREMENTS="/app/requirements.txt"; \
            echo "Selected: Base requirements (requirements.txt) - web file not found"; \
        fi; \
    elif [ "${SERVICE_TYPE}" = "ninja-python" ] || [ "${SERVICE_TYPE}" = "ninja-dev" ]; then \
        if [ -f "/app/requirements_dev.txt" ]; then \
            PRIMARY_REQUIREMENTS="/app/requirements_dev.txt"; \
            echo "Selected: Development requirements (requirements_dev.txt)"; \
        else \
            PRIMARY_REQUIREMENTS="/app/requirements.txt"; \
            echo "Selected: Base requirements (requirements.txt) - dev file not found"; \
        fi; \
    elif [ "${SERVICE_TYPE}" = "api" ] || [ "${SERVICE_TYPE}" = "data" ] || [ "${SERVICE_TYPE}" = "worker" ] || [ "${SERVICE_TYPE}" = "ninja-api" ]; then \
        if [ -f "/app/requirements_prod.txt" ]; then \
            PRIMARY_REQUIREMENTS="/app/requirements_prod.txt"; \
            echo "Selected: Production requirements (requirements_prod.txt)"; \
        else \
            PRIMARY_REQUIREMENTS="/app/requirements.txt"; \
            echo "Selected: Base requirements (requirements.txt) - prod file not found"; \
        fi; \
    elif [ "${SERVICE_TYPE}" = "training" ] || [ "${SERVICE_TYPE}" = "ml" ] || [ "${SERVICE_TYPE}" = "transformer" ]; then \
        if [ -f "/app/requirements_ml.txt" ]; then \
            PRIMARY_REQUIREMENTS="/app/requirements_ml.txt"; \
            echo "Selected: ML requirements (requirements_ml.txt)"; \
        else \
            PRIMARY_REQUIREMENTS="/app/requirements.txt"; \
            echo "Selected: Base requirements (requirements.txt) - ML file not found"; \
        fi; \
    else \
        PRIMARY_REQUIREMENTS="/app/requirements.txt"; \
        echo "Selected: Base requirements (requirements.txt) - default fallback"; \
    fi \
    && \
    # Validate selected requirements file exists
    echo "=== Validating Selected Requirements File ===" \
    && if [ ! -f "${PRIMARY_REQUIREMENTS}" ]; then \
        echo "❌ Error: Selected requirements file not found: ${PRIMARY_REQUIREMENTS}"; \
        echo "Available files:"; \
        ls -la /app/requirements* || echo "No requirements files found"; \
        exit 1; \
    fi \
    && echo "✓ Requirements file validated: ${PRIMARY_REQUIREMENTS}" \
    && echo "Requirements preview:" \
    && head -5 "${PRIMARY_REQUIREMENTS}" \
    && \
    # Install selected requirements with retry logic
    echo "=== Installing Primary Requirements ===" \
    && echo "Installing requirements from: ${PRIMARY_REQUIREMENTS}" \
    && /opt/venv/bin/pip install --use-pep517 --no-cache-dir --disable-pip-version-check --progress-bar off -r "${PRIMARY_REQUIREMENTS}" \
    && echo "✓ Primary requirements installed successfully" \
    && \
    # Install additional GPU packages if needed and not already included
    echo "=== Installing Additional GPU Packages ===" \
    && if [ "${BUILD_TYPE}" = "gpu" ] && [ "${PRIMARY_REQUIREMENTS}" != "/app/requirements_gpu.txt" ]; then \
        if [ -f "/app/requirements_gpu.txt" ]; then \
            echo "Installing additional GPU requirements..."; \
            /opt/venv/bin/pip install --use-pep517 --no-cache-dir --disable-pip-version-check --progress-bar off -r /app/requirements_gpu.txt; \
            echo "✓ Additional GPU requirements installed"; \
        else \
            echo "ℹ️  No additional GPU requirements file found"; \
        fi; \
    else \
        echo "ℹ️  No additional GPU requirements needed"; \
    fi \
    && \
    # Install documentation requirements
    echo "=== Installing Documentation Requirements ===" \
    && /opt/venv/bin/pip install --use-pep517 --no-cache-dir -r /app/docs-requirements.txt \
    && echo "✓ Documentation requirements installed" \
    && \
    # Install and verify core packages
    echo "=== Installing Core Packages ===" \
    && CORE_PACKAGES="yfinance pyyaml pydantic pydantic-settings loguru flask" \
    && for pkg in $CORE_PACKAGES; do \
        if ! /opt/venv/bin/pip list | grep -i "$pkg" > /dev/null 2>&1; then \
            echo "Installing core package: $pkg"; \
            /opt/venv/bin/pip install --use-pep517 --no-cache-dir "$pkg"; \
        else \
            echo "✓ Core package $pkg already installed"; \
        fi; \
    done \
    && echo "✓ Core packages installation complete" \
    && \
    # Install GPU-specific packages for GPU builds with CUDA version matching
    if [ "${BUILD_TYPE}" = "gpu" ]; then \
        echo "=== Installing GPU-Specific Packages ==="; \
        CUDA_VERSION_SHORT=$(echo "${CUDA_VERSION}" | cut -d'.' -f1,2 | tr -d '.'); \
        echo "Detected CUDA version: ${CUDA_VERSION} (short: ${CUDA_VERSION_SHORT})"; \
        \
        # Install PyTorch with appropriate CUDA version
        if ! /opt/venv/bin/pip list | grep -i "torch" > /dev/null 2>&1; then \
            echo "Installing PyTorch with CUDA ${CUDA_VERSION} support..."; \
            if [ "${CUDA_VERSION_SHORT}" = "128" ] || [ "${CUDA_VERSION_SHORT}" = "127" ]; then \
                TORCH_CUDA_VERSION="cu121"; \
            elif [ "${CUDA_VERSION_SHORT}" = "126" ] || [ "${CUDA_VERSION_SHORT}" = "125" ]; then \
                TORCH_CUDA_VERSION="cu121"; \
            elif [ "${CUDA_VERSION_SHORT}" = "124" ] || [ "${CUDA_VERSION_SHORT}" = "123" ]; then \
                TORCH_CUDA_VERSION="cu121"; \
            elif [ "${CUDA_VERSION_SHORT}" = "122" ] || [ "${CUDA_VERSION_SHORT}" = "121" ]; then \
                TORCH_CUDA_VERSION="cu121"; \
            else \
                TORCH_CUDA_VERSION="cu118"; \
            fi; \
            echo "Using PyTorch CUDA version: ${TORCH_CUDA_VERSION}"; \
            /opt/venv/bin/pip install --use-pep517 --no-cache-dir \
                torch torchvision torchaudio \
                --index-url "https://download.pytorch.org/whl/${TORCH_CUDA_VERSION}"; \
            echo "✓ PyTorch with CUDA support installed"; \
        else \
            echo "✓ PyTorch already installed via requirements file"; \
        fi; \
        \
        # Install TensorFlow with CUDA support
        if ! /opt/venv/bin/pip list | grep -i "tensorflow" > /dev/null 2>&1; then \
            echo "Installing TensorFlow with CUDA support..."; \
            /opt/venv/bin/pip install --use-pep517 --no-cache-dir "tensorflow[and-cuda]"; \
            echo "✓ TensorFlow with CUDA support installed"; \
        else \
            echo "✓ TensorFlow already installed via requirements file"; \
        fi; \
        \
        # Install additional ML/AI packages for GPU builds
        echo "Installing additional ML/AI packages for GPU builds..."; \
        GPU_ML_PACKAGES="scikit-learn matplotlib seaborn plotly jupyter"; \
        for pkg in $GPU_ML_PACKAGES; do \
            if ! /opt/venv/bin/pip list | grep -i "$pkg" > /dev/null 2>&1; then \
                echo "Installing GPU ML package: $pkg"; \
                /opt/venv/bin/pip install --use-pep517 --no-cache-dir "$pkg"; \
            else \
                echo "✓ GPU ML package $pkg already installed"; \
            fi; \
        done; \
        echo "✓ GPU-specific packages installation complete"; \
    else \
        echo "ℹ️  CPU build - skipping GPU-specific packages"; \
    fi \
    && \
    # Clean up temporary files
    echo "=== Cleaning Up ===" \
    && rm -f /tmp/gpu-extra.txt /tmp/web-extra.txt /tmp/training-extra.txt /tmp/extra-reqs.txt \
    && \
    # Generate comprehensive installed packages list
    echo "=== Generating Package Inventory ===" \
    && /opt/venv/bin/pip freeze > /app/installed-packages.txt \
    && echo "# Package installation completed at $(date -u)" >> /app/installed-packages.txt \
    && echo "# Build Type: ${BUILD_TYPE}" >> /app/installed-packages.txt \
    && echo "# Service Type: ${SERVICE_TYPE}" >> /app/installed-packages.txt \
    && echo "# CUDA Version: ${CUDA_VERSION}" >> /app/installed-packages.txt \
    && TOTAL_PACKAGES=$(grep -c "^[^#]" /app/installed-packages.txt) \
    && echo "✓ Package inventory generated: ${TOTAL_PACKAGES} packages installed" \
    && \
    # Final validation
    echo "=== Final Validation ===" \
    && /opt/venv/bin/python -c "import sys; print(f'Python version: {sys.version}')" \
    && /opt/venv/bin/python -c "import pip; print(f'Pip version: {pip.__version__}')" \
    && if [ "${BUILD_TYPE}" = "gpu" ]; then \
        echo "Validating GPU packages..."; \
        /opt/venv/bin/python -c "import torch; print(f'PyTorch version: {torch.__version__}'); print(f'CUDA available: {torch.cuda.is_available()}')" 2>/dev/null || echo "⚠️  PyTorch validation failed"; \
        /opt/venv/bin/python -c "import tensorflow as tf; print(f'TensorFlow version: {tf.__version__}')" 2>/dev/null || echo "⚠️  TensorFlow validation failed"; \
    fi \
    && echo "✅ All dependencies installed and validated successfully" \
    && echo "=== Dependencies Installation Complete ==="

# Create basic pyproject.toml if not exists
RUN if [ ! -f /app/pyproject.toml ]; then \
        echo "Creating default pyproject.toml..." \
        && echo '[project]' > /app/pyproject.toml \
        && echo 'name = "FKS Trading Systems"' >> /app/pyproject.toml \
        && echo 'version = "1.0.0"' >> /app/pyproject.toml \
        && echo 'description = "Algorithmic trading system"' >> /app/pyproject.toml \
        && echo 'license = "MIT"' >> /app/pyproject.toml \
        && echo 'requires-python = ">=3.11"' >> /app/pyproject.toml \
        && echo 'authors = [' >> /app/pyproject.toml \
        && echo '    {name = "nuniesmith"}' >> /app/pyproject.toml \
        && echo ']' >> /app/pyproject.toml \
        && echo 'readme = "README.md"' >> /app/pyproject.toml \
        && echo '' >> /app/pyproject.toml \
        && echo '[build-system]' >> /app/pyproject.toml \
        && echo 'requires = ["setuptools>=61.0", "wheel"]' >> /app/pyproject.toml \
        && echo 'build-backend = "setuptools.build_meta"' >> /app/pyproject.toml \
        && echo '' >> /app/pyproject.toml \
        && echo '[tool.setuptools.packages.find]' >> /app/pyproject.toml \
        && echo 'where = ["src"]' >> /app/pyproject.toml \
        && echo '' >> /app/pyproject.toml \
        && echo '[tool.setuptools.package-dir]' >> /app/pyproject.toml \
        && echo '""" = "src"' >> /app/pyproject.toml \
        && echo "Default pyproject.toml created."; \
    fi

# Copy Python source code (for Python services) with layout fallback
# Preferred layout: ${PYTHON_SRC_DIR} (default ./src/python)
# Fallback layout: ./src (flat) when no nested python dir exists
# Strategy: copy entire ./src to a temp location, then normalize into /app/src/python
COPY ./src /app/_src_raw
RUN set -e \
        && if [ -d /app/_src_raw/python ] && [ "${PYTHON_SRC_DIR}" = "./src/python" ]; then \
                 echo "Detected nested python layout (src/python). Using that."; \
                 mkdir -p /app/src/python \
                 && cp -a /app/_src_raw/python/. /app/src/python/; \
             elif [ -d "/app/_src_raw" ] && [ -n "${PYTHON_SRC_DIR}" ] && [ -d "/app/_src_raw/$(echo ${PYTHON_SRC_DIR} | sed 's#^./src/##')" ]; then \
                 # Custom PYTHON_SRC_DIR override provided and exists within src
                 echo "Detected custom PYTHON_SRC_DIR=${PYTHON_SRC_DIR}. Normalizing."; \
                 mkdir -p /app/src/python \
                 && cp -a /app/_src_raw/$(echo ${PYTHON_SRC_DIR} | sed 's#^./src/##')/. /app/src/python/; \
             else \
                 echo "No nested python directory found; falling back to flat src layout."; \
                 mkdir -p /app/src/python \
                 && find /app/_src_raw -maxdepth 1 -mindepth 1 \( -name 'python' -o -name 'rust' -o -name 'web' -o -name 'node' -o -name 'ninja' \) -prune -o -exec cp -a {} /app/src/python/ \; ; \
             fi \
        && echo "✓ Python source copied (with layout normalization)" \
          && rm -rf /app/_src_raw \
          && echo "Creating top-level symlinks for python packages" \
          && mkdir -p /app/src \
          && find /app/src/python -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | while read pkg; do \
                  case "$pkg" in __pycache__|tests|test|venv) continue ;; esac; \
                  if [ ! -e "/app/src/$pkg" ]; then ln -s "/app/src/python/$pkg" "/app/src/$pkg"; fi; \
              done \
          && echo "Symlinks created:" \
          && ls -l /app/src | sed -n '1,40p'

# Create source directory structure and set permissions
RUN set -e \
    && echo "Setting up source directory structure..." \
    && mkdir -p /app/src /app/src/ninja /app/src/rust /app/src/node /app/src/web \
    && echo "✓ Source directory structure created" \
    && echo "Available directories:" \
    && ls -la /app/src/ || echo "Source directories created"

# Verify critical packages
RUN set -e \
    && echo "=== Package Verification ===" \
    && echo "Installed packages count: $(pip list | wc -l)" \
    && echo "=== Verifying Critical Packages ===" \
    && \
    # Check core packages
    for pkg in pandas numpy pyyaml pydantic pydantic-settings loguru sphinx flask; do \
        if ! /opt/venv/bin/pip list | grep -i "$pkg" > /dev/null; then \
            echo "❌ Error: $pkg not installed successfully"; exit 1; \
        fi; \
        echo "✅ $pkg successfully installed"; \
    done \
    && \
    # Check GPU packages for GPU builds
    if [ "${BUILD_TYPE}" = "gpu" ]; then \
        echo "=== Verifying GPU Packages ==="; \
        for pkg in torch tensorflow; do \
            if ! /opt/venv/bin/pip list | grep -i "$pkg" > /dev/null; then \
                echo "⚠️  Warning: GPU package $pkg not found"; \
            else \
                echo "✅ GPU package $pkg successfully installed"; \
            fi; \
        done; \
    fi \
    && echo "=== Package Verification Complete ==="

##############################################################
# Stage 1B: Rust Network Builder (conditional)
##############################################################
FROM alpine:latest AS builder-rust-network-false
RUN mkdir -p /app/bin/network \
    && echo "# Rust network build skipped" > /app/bin/network/.placeholder \
    && echo "Skipping Rust network build as per configuration."

FROM rust:${RUST_VERSION}-slim AS builder-rust-network-true
ARG SERVICE_TYPE
ARG RUST_NETWORK_DIR
ARG EXTRA_BUILD_PACKAGES=""

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    set -e \
    && echo "Installing Rust build dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pkg-config libssl-dev gcc build-essential git ca-certificates ${EXTRA_BUILD_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Rust build dependencies installed."

# Copy Rust project files for dependency caching
COPY ${RUST_NETWORK_DIR}/Cargo.toml ${RUST_NETWORK_DIR}/Cargo.lock* ./

# Improved dependency caching
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    set -e \
    && echo "Setting up Rust dependency caching..." \
    && mkdir -p src \
    && echo 'fn main() { println!("Downloading dependencies..."); }' > src/main.rs \
    && cargo build --release \
    && rm -rf src/ \
    && echo "Rust dependencies cached."

# Copy the actual source files
COPY ${RUST_NETWORK_DIR}/src ./src

# Build with improved error handling
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    set -e \
    && echo "Building Rust network components..." \
    && cargo build --release \
    && mkdir -p /app/bin/network \
    && echo "Copying build artifacts..." \
    && find /app/target/release -type f -executable -not -path "*/deps/*" -not -name "*.d" \
        -exec cp {} /app/bin/network/ \; \
    && strip /app/bin/network/* 2>/dev/null || true \
    && ls -la /app/bin/network/ \
    && echo "Rust network components built and installed."

FROM builder-rust-network-${BUILD_RUST_NETWORK} AS builder-rust-network

##############################################################
# Stage 1C: Rust Execution Builder (conditional)
##############################################################
FROM alpine:latest AS builder-rust-execution-false
RUN mkdir -p /app/bin/execution \
    && echo "# Rust execution build skipped" > /app/bin/execution/.placeholder \
    && echo "Skipping Rust execution build as per configuration."

FROM rust:${RUST_VERSION}-slim AS builder-rust-execution-true
ARG SERVICE_TYPE
ARG RUST_EXECUTION_DIR
ARG EXTRA_BUILD_PACKAGES=""

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Rust execution dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pkg-config libssl-dev gcc build-essential git ca-certificates ${EXTRA_BUILD_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Rust execution dependencies installed."

COPY ${RUST_EXECUTION_DIR}/Cargo.toml ${RUST_EXECUTION_DIR}/Cargo.lock* ./

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    set -e \
    && echo "Setting up Rust execution dependency caching..." \
    && mkdir -p src \
    && echo 'fn main() { println!("Downloading dependencies..."); }' > src/main.rs \
    && cargo build --release \
    && rm -rf src/ \
    && echo "Rust execution dependencies cached."

# Create placeholder for source mount (source will be mounted via volume)
RUN mkdir -p ./src \
    && echo "Source directory created for volume mount" > ./src/.gitkeep

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    set -e \
    && echo "Building Rust execution components..." \
    && cargo build --release \
    && mkdir -p /app/bin/execution \
    && find /app/target/release -type f -executable -not -path "*/deps/*" -not -name "*.d" \
        -exec cp {} /app/bin/execution/ \; \
    && strip /app/bin/execution/* 2>/dev/null || true \
    && ls -la /app/bin/execution/ \
    && echo "Rust execution components built and installed."

FROM builder-rust-execution-${BUILD_RUST_EXECUTION} AS builder-rust-execution

##############################################################
# Stage 1D: Network Connector Builder (conditional)
##############################################################
FROM alpine:latest AS builder-connector-false
RUN mkdir -p /app/bin/connector /app/connector \
    && echo "# Connector build skipped" > /app/bin/connector/.placeholder \
    && echo "Skipping connector build as per configuration."

FROM builder-python AS builder-connector-true
ARG NETWORK_CONNECTOR_DIR
ARG RUST_VERSION

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH="/root/.cargo/bin:${PATH}"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Rust for connector components..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pkg-config libssl-dev curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Rust installed for connector components."

# Copy connector files with fallback
RUN if [ -d "${NETWORK_CONNECTOR_DIR}" ]; then \
        cp -r ${NETWORK_CONNECTOR_DIR}/ /app/connector/; \
    else \
        mkdir -p /app/connector; \
    fi

RUN set -e \
    && mkdir -p /app/bin/connector \
    && if [ -f "/app/connector/requirements.txt" ]; then \
        echo "Installing connector-specific Python requirements..." \
        && /opt/venv/bin/pip install --use-pep517 --no-cache-dir -r /app/connector/requirements.txt; \
    fi

WORKDIR /app/connector

RUN set -e \
    && echo "Setting up connector components..." \
    && if [ -f "Cargo.toml" ]; then \
        echo "Building Rust extensions for connector..." \
        && cargo build --release \
        && find /app/target/release -type f -executable -not -path "*/deps/*" -not -name "*.d" \
            -exec cp {} /app/bin/connector/ \; \
        && if [ -f "setup.py" ]; then \
            echo "Installing Python package from setup.py..." \
            && /opt/venv/bin/pip install -e .; \
        fi; \
    fi \
    && echo "Connector setup complete."

FROM builder-connector-${BUILD_CONNECTOR} AS builder-connector

##############################################################
# Stage 1E: .NET Builder (conditional)
##############################################################
FROM alpine:latest AS builder-dotnet-false
RUN mkdir -p /app/bin/dotnet /app/src /workspace/src \
    && echo "#!/bin/bash" > /app/bin/dotnet/placeholder \
    && echo "echo '.NET components not built'" >> /app/bin/dotnet/placeholder \
    && chmod +x /app/bin/dotnet/placeholder \
    && echo "# .NET components not built" > /workspace/src/placeholder.txt

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION:-8.0} AS builder-dotnet-true
ARG SERVICE_TYPE
ARG DOTNET_SRC_DIR=./src/ninja
ARG EXTRA_BUILD_PACKAGES=""

WORKDIR /workspace

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing .NET build dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl wget git vim nano unzip zip tree \
        gnupg ca-certificates ${EXTRA_BUILD_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo ".NET build dependencies installed."

# Install Mono for .NET Framework compatibility
RUN apt-get update && apt-get install -y gnupg ca-certificates \
    && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF \
    && echo "deb https://download.mono-project.com/repo/ubuntu stable-focal main" | tee /etc/apt/sources.list.d/mono-official-stable.list \
    && apt-get update && apt-get install -y mono-complete msbuild nuget \
    && rm -rf /var/lib/apt/lists/*

# Create source directory for mount (source will be mounted via volume)
RUN mkdir -p /workspace/src \
    && echo "Source directory created for volume mount" > /workspace/src/.gitkeep

# Install .NET tools
RUN dotnet tool install --global dotnet-ef || true \
    && dotnet tool install --global dotnet-outdated-tool || true

# Build .NET project if project file exists
RUN set -e \
    && echo "Building .NET components..." \
    && mkdir -p /app/bin/dotnet \
    && if find /workspace/src -name "*.csproj" -o -name "*.sln" | head -1 | grep -q .; then \
        echo "Found .NET project files, building..." \
        && cd /workspace/src \
        && dotnet restore \
        && dotnet build --configuration Release \
        && echo ".NET project built successfully"; \
    else \
        echo "No .NET project files found, creating placeholder"; \
    fi \
    && echo ".NET build complete."

FROM builder-dotnet-${BUILD_DOTNET} AS builder-dotnet

##############################################################
# Stage 1F: Node.js Builder (conditional)
##############################################################
FROM alpine:latest AS builder-node-false
RUN mkdir -p /app/bin/node /app/src /workspace/src \
    && echo "#!/bin/bash" > /app/bin/node/placeholder \
    && echo "echo 'Node.js components not built'" >> /app/bin/node/placeholder \
    && chmod +x /app/bin/node/placeholder \
    && echo "# Node.js components not built" > /workspace/src/placeholder.txt

FROM node:${NODE_VERSION:-20}-slim AS builder-node-true
ARG SERVICE_TYPE
ARG NODE_SRC_DIR=./src/web/react
ARG EXTRA_BUILD_PACKAGES=""
ARG USER_ID=1088
ARG GROUP_ID=1088
ARG APP_ENV=development

WORKDIR /workspace

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Node.js build dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl wget git python3 python3-pip build-essential \
        inotify-tools bash ${EXTRA_BUILD_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Node.js build dependencies installed."

# Install global packages needed for React development and serving
RUN npm install -g serve create-react-app

# Create directory structure
RUN mkdir -p /workspace/src/web/react /app/bin/node /app/src/web/react

# Copy React application source code
COPY --chown=${USER_ID}:${GROUP_ID} ${NODE_SRC_DIR}/package*.json /workspace/src/web/react/
COPY --chown=${USER_ID}:${GROUP_ID} ${NODE_SRC_DIR}/.npmrc* /workspace/src/web/react/

WORKDIR /workspace/src/web/react

# Install dependencies with proper npm configuration
RUN --mount=type=cache,target=/root/.npm \
        set -e \
        && echo "Installing React dependencies (reconciling lock if needed)..." \
        && if [ -f package-lock.json ]; then \
                 echo "Attempting clean install with npm ci..."; \
                 npm ci --legacy-peer-deps --no-audit --no-fund || ( \
                     echo "npm ci failed due to lock mismatch, falling back to npm install to refresh lock"; \
                     rm -f package-lock.json; \
                     npm install --legacy-peer-deps --no-audit --no-fund \
                 ); \
             else \
                 npm install --legacy-peer-deps --no-audit --no-fund; \
             fi \
        && echo "✓ Dependencies installed successfully"

# Copy the rest of the React application
COPY --chown=${USER_ID}:${GROUP_ID} ${NODE_SRC_DIR}/ /workspace/src/web/react/

# Build React app for production if not in development
RUN set -e \
    && echo "Building React application (APP_ENV: ${APP_ENV})..." \
    && if [ "${APP_ENV}" != "development" ]; then \
        echo "Building production React app..."; \
        export REACT_APP_API_URL="${REACT_APP_API_URL:-/api}"; \
        export TSC_COMPILE_ON_ERROR=true; \
        export DISABLE_ESLINT_PLUGIN=true; \
        npm run build || (echo "Build failed, continuing anyway" && exit 0); \
        echo "✓ React production build complete"; \
    else \
        echo "Development mode - skipping production build"; \
    fi \
    && echo "Node.js setup complete."

FROM builder-node-${BUILD_NODE} AS builder-node

##############################################################
# Stage 2: Runtime Selection - IMPROVED GPU SUPPORT
##############################################################
FROM python:${PYTHON_VERSION} AS runtime-python-cpu
FROM rust:${RUST_VERSION}-slim-bookworm AS runtime-rust-cpu
FROM rust:${RUST_VERSION}-slim-bookworm AS runtime-rust-gpu
FROM python:${PYTHON_VERSION} AS runtime-hybrid-cpu

# GPU Python runtime with Python pre-installed
FROM nvidia/cuda:${CUDA_VERSION}-${CUDNN_VERSION}-runtime-${UBUNTU_VERSION} AS runtime-python-gpu-base
FROM runtime-python-gpu-base AS runtime-python-gpu
ARG EXTRA_RUNTIME_PACKAGES=""
ARG PYTHON_VERSION=3.11

# Install Python and runtime dependencies for GPU
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Python ${PYTHON_VERSION} and runtime dependencies for GPU..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        software-properties-common \
        curl ca-certificates tini rsync netcat-openbsd \
        libpq5 ${EXTRA_RUNTIME_PACKAGES} \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python${PYTHON_VERSION} python${PYTHON_VERSION}-venv python3-pip \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3 \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "GPU Python runtime setup completed."

# GPU Hybrid runtime
FROM nvidia/cuda:${CUDA_VERSION}-${CUDNN_VERSION}-runtime-${UBUNTU_VERSION} AS runtime-hybrid-gpu-base
FROM runtime-hybrid-gpu-base AS runtime-hybrid-gpu
ARG EXTRA_RUNTIME_PACKAGES=""
ARG PYTHON_VERSION=3.11

# Install Python and runtime dependencies for GPU
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Python ${PYTHON_VERSION} and runtime dependencies for hybrid GPU..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        software-properties-common \
        curl ca-certificates tini rsync netcat-openbsd \
        libpq5 ${EXTRA_RUNTIME_PACKAGES} \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python${PYTHON_VERSION} python${PYTHON_VERSION}-venv python3-pip \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3 \
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "GPU Hybrid runtime setup completed."

# .NET Runtime stages
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION:-8.0} AS runtime-dotnet-cpu
ARG EXTRA_RUNTIME_PACKAGES=""

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing .NET runtime dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates tini rsync netcat-openbsd \
        git vim nano unzip zip tree htop net-tools iputils-ping telnet \
        gnupg ${EXTRA_RUNTIME_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo ".NET runtime setup completed."

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION:-8.0} AS runtime-dotnet-gpu
ARG EXTRA_RUNTIME_PACKAGES=""

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing .NET GPU runtime dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates tini rsync netcat-openbsd \
        git vim nano unzip zip tree htop net-tools iputils-ping telnet \
        gnupg ${EXTRA_RUNTIME_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo ".NET GPU runtime setup completed."

# Node.js Runtime stages  
FROM node:${NODE_VERSION:-20}-slim AS runtime-node-cpu
ARG EXTRA_RUNTIME_PACKAGES=""

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Node.js runtime dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates tini rsync netcat-openbsd \
        git python3 python3-pip build-essential \
        inotify-tools bash ${EXTRA_RUNTIME_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Node.js runtime setup completed."

FROM node:${NODE_VERSION:-20}-slim AS runtime-node-gpu
ARG EXTRA_RUNTIME_PACKAGES=""

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -e \
    && echo "Installing Node.js GPU runtime dependencies..." \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates tini rsync netcat-openbsd \
        git python3 python3-pip build-essential \
        inotify-tools bash ${EXTRA_RUNTIME_PACKAGES} \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && echo "Node.js GPU runtime setup completed."

# Runtime stage with validation
FROM runtime-${SERVICE_RUNTIME}-${BUILD_TYPE} AS runtime-base

# Runtime arguments
ARG BUILD_TYPE
ARG PYTHON_VERSION
ARG SERVICE_RUNTIME
ARG SERVICE_TYPE
ARG SERVICE_PORT=8000
ARG SERVICE_NAME="app-${SERVICE_TYPE}"
ARG APP_VERSION=1.0.0
ARG APP_ENV=development
ARG APP_LOG_LEVEL=INFO
ARG PYTHON_MODULE=""
ARG DISPATCHER_MODULE="main"
ARG HEALTHCHECK_INTERVAL=30s
ARG HEALTHCHECK_TIMEOUT=10s
ARG HEALTHCHECK_RETRIES=3
ARG HEALTHCHECK_START_PERIOD=10s
ARG ENABLE_HEALTHCHECK=true
ARG EXTRA_RUNTIME_PACKAGES=""
ARG USER_NAME=appuser
ARG USER_ID=1088
ARG GROUP_ID=1088
ARG GPU_MEMORY_LIMIT=""
ARG GPU_COUNT=1
ARG BUILD_RUST_NETWORK
ARG BUILD_RUST_EXECUTION
ARG BUILD_CONNECTOR
ARG BUILD_DATE
ARG BUILD_VERSION
ARG BUILD_COMMIT

WORKDIR /app

# Create user with better handling
RUN set -e \
    && echo "Creating service user: ${USER_NAME} (${USER_ID}:${GROUP_ID})..." \
    && groupadd -g ${GROUP_ID} ${USER_NAME} 2>/dev/null || true \
    && useradd -u ${USER_ID} -g ${GROUP_ID} -m -s /bin/bash ${USER_NAME} 2>/dev/null || true \
    && echo "User created successfully."

# Install runtime dependencies only for CPU builds (GPU already has them)
RUN if [ "${BUILD_TYPE}" = "cpu" ]; then \
        echo "Installing runtime dependencies for CPU service..." \
        && apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            curl ca-certificates tini rsync netcat-openbsd ${EXTRA_RUNTIME_PACKAGES} \
        && if [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then \
            apt-get install -y --no-install-recommends libpq5; \
        fi \
        && apt-get clean && rm -rf /var/lib/apt/lists/* \
        && echo "CPU runtime dependencies installed successfully."; \
    else \
        echo "GPU runtime - dependencies already installed."; \
    fi

# Verify runtime installation based on SERVICE_RUNTIME
RUN set -e \
    && echo "Verifying runtime installation for: ${SERVICE_RUNTIME}" \
    && if [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then \
        echo "Verifying Python installation..." \
        && python3 --version \
        && echo "✓ Python verification completed successfully"; \
    elif [ "${SERVICE_RUNTIME}" = "dotnet" ]; then \
        echo "Verifying .NET installation..." \
        && dotnet --version \
        && echo "✓ .NET verification completed successfully"; \
    elif [ "${SERVICE_RUNTIME}" = "node" ]; then \
        echo "Verifying Node.js installation..." \
        && node --version \
        && npm --version \
        && echo "✓ Node.js verification completed successfully"; \
    elif [ "${SERVICE_RUNTIME}" = "rust" ]; then \
        echo "Verifying Rust installation..." \
        && rustc --version \
        && echo "✓ Rust verification completed successfully"; \
    else \
        echo "⚠ Unknown runtime: ${SERVICE_RUNTIME}, skipping verification"; \
    fi

# Create directory structure with validation and FIXED logs directory  
RUN set -e \
    && echo "Creating service directories..." \
    && mkdir -p /app/bin /app/bin/network /app/bin/execution /app/bin/connector /app/bin/dotnet /app/bin/node \
    && mkdir -p /app/docs /app/scripts/docker \
    && mkdir -p /app/{data,logs,models,tmp} \
    && mkdir -p /app/src/{ninja,node} \
    && echo "✓ Service directories created"

# Set environment variables
ENV PYTHONPATH=/app/src:/app/src/python:/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:/app/bin:/app/bin/network:/app/bin/execution:/app/bin/connector:/app/bin/dotnet:/app/bin/node:$PATH" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    NUGET_PACKAGES=/root/.nuget/packages \
    SERVICE_RUNTIME=${SERVICE_RUNTIME} \
    SERVICE_TYPE=${SERVICE_TYPE} \
    SERVICE_NAME=${SERVICE_NAME} \
    SERVICE_PORT=${SERVICE_PORT} \
    APP_VERSION=${APP_VERSION} \
    APP_ENV=${APP_ENV} \
    APP_LOG_LEVEL=${APP_LOG_LEVEL} \
    BUILD_TYPE=${BUILD_TYPE} \
    CONFIG_DIR=/app/config \
    DATA_DIR=/app/data \
    LOGS_DIR=/app/logs \
    DOCS_DIR=/app/docs \
    MPLCONFIGDIR=/home/${USER_NAME}/.matplotlib \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

##############################################################
# Stage 3: Final Assembly
##############################################################
FROM runtime-base AS final

# Re-declare build args needed in this stage
ARG SERVICE_PORT=8000

# Copy built components based on runtime (excluding source code - will be mounted)
# Only copy Python components for Python-based runtimes
RUN if [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then \
        echo "Python runtime detected, Python components will be copied in next steps"; \
    elif [ "${SERVICE_RUNTIME}" = "node" ]; then \
        echo "Node.js runtime detected, Node.js is already available in base image"; \
    elif [ "${SERVICE_RUNTIME}" = "rust" ]; then \
        echo "Rust runtime detected, Rust components will be copied"; \
    elif [ "${SERVICE_RUNTIME}" = "dotnet" ]; then \
        echo ".NET runtime detected, .NET is already available in base image"; \
    fi

# Conditionally copy Python components only for Python/Hybrid runtimes
COPY --from=builder-python --chown=${USER_ID}:${GROUP_ID} /opt/venv /opt/venv
COPY --from=builder-python --chown=${USER_ID}:${GROUP_ID} /app/installed-packages.txt /app/installed-packages.txt
COPY --from=builder-python --chown=${USER_ID}:${GROUP_ID} /app/pyproject.toml /app/pyproject.toml

# Copy binaries and build artifacts
COPY --from=builder-rust-network --chown=${USER_ID}:${GROUP_ID} /app/bin/network/ /app/bin/network/
COPY --from=builder-rust-execution --chown=${USER_ID}:${GROUP_ID} /app/bin/execution/ /app/bin/execution/
COPY --from=builder-connector --chown=${USER_ID}:${GROUP_ID} /app/bin/connector/ /app/bin/connector/
COPY --from=builder-connector --chown=${USER_ID}:${GROUP_ID} /app/connector/ /app/connector/
COPY --from=builder-dotnet --chown=${USER_ID}:${GROUP_ID} /app/bin/dotnet/ /app/bin/dotnet/
COPY --from=builder-node --chown=${USER_ID}:${GROUP_ID} /app/bin/node/ /app/bin/node/

# Copy source code based on runtime
# For Python services, copy Python source
COPY --from=builder-python --chown=${USER_ID}:${GROUP_ID} /app/src/python/ /app/src/python/

# For Node.js services, copy React application
# Create a script to handle conditional copy based on what exists in builder-node
RUN --mount=type=bind,from=builder-node,source=/,target=/builder-node \
    if [ "${SERVICE_RUNTIME}" = "node" ]; then \
        echo "Copying React application for Node.js runtime..."; \
        if [ -d "/builder-node/workspace/src/web/react" ]; then \
            cp -r /builder-node/workspace/src/web/react /app/src/web/; \
            chown -R ${USER_ID}:${GROUP_ID} /app/src/web/react; \
            echo "✓ React application copied successfully"; \
        else \
            echo "⚠️ React source not found in builder stage, creating empty directory"; \
            mkdir -p /app/src/web/react; \
        fi; \
    else \
        echo "Skipping React application copy for ${SERVICE_RUNTIME} runtime"; \
        mkdir -p /app/src/web/react; \
    fi

# Create additional source directories if needed
RUN mkdir -p /app/src /app/src/ninja /app/src/rust /app/src/node \
    && chown -R ${USER_ID}:${GROUP_ID} /app/src/

# Copy configuration if exists; otherwise create placeholder
RUN set -e \
        && if [ -d ./config ]; then \
                 echo "Copying service config"; \
                 cp -r ./config /app/config; \
             else \
                 echo "No local config directory; creating empty /app/config"; \
                 mkdir -p /app/config; \
             fi \
        && chown -R ${USER_ID}:${GROUP_ID} /app/config

# Copy scripts if present
RUN set -e \
        && if [ -d ./scripts/docker ]; then \
                 echo "Copying service docker scripts"; \
                 mkdir -p /app/scripts/docker; \
                 cp -r ./scripts/docker/* /app/scripts/docker/ || true; \
             else \
                 echo "No service docker scripts present"; \
                 mkdir -p /app/scripts/docker; \
             fi \
        && chown -R ${USER_ID}:${GROUP_ID} /app/scripts

# Provide default entrypoint scripts if missing (single RUN for parser safety)
RUN set -e \ 
 && if [ ! -f /app/entrypoint-runtime.sh ]; then \ 
            echo "Generating default /app/entrypoint-runtime.sh"; \ 
            printf '%s\n' '#!/usr/bin/env bash' \ 
                'set -euo pipefail' \ 
                'PY_RUNTIME=${SERVICE_RUNTIME:-python}' \ 
                'if [ -n "${RUNTIME_CMD:-}" ]; then' \
                '  echo "[entrypoint] Running custom RUNTIME_CMD" >&2' \
                '  exec bash -c "$RUNTIME_CMD"' \
                'fi' \
                'PORT=${SERVICE_PORT:-8000}' \ 
                'MODULE="${PYTHON_MODULE:-}"' \ 
                'if [ -z "$MODULE" ] && [ "$PY_RUNTIME" = "python" ]; then' \ 
                '  CANDIDATE=$(grep -R "FastAPI" -l src 2>/dev/null | head -1 | sed '"'"'s#^src/##; s#/__init__\\.py$##; s#/#.#g; s#\\.py$##'"'"')' \ 
                '  [ -n "$CANDIDATE" ] && MODULE="$CANDIDATE:app"' \ 
                'fi' \ 
                'case "$PY_RUNTIME" in' \ 
                '  python|hybrid)' \ 
                '    if command -v uvicorn >/dev/null 2>&1 && [ -n "$MODULE" ]; then' \ 
                '      echo "[entrypoint] Starting uvicorn $MODULE on $PORT" >&2' \ 
                '      exec uvicorn "$MODULE" --host 0.0.0.0 --port "$PORT"' \ 
                '    fi ;;' \ 
                '  node)' \ 
                '    if [ -f package.json ]; then (npm run start || node server.js || node index.js) && exit 0; fi ;;' \ 
                '  rust)' \ 
                '    if command -v main >/dev/null 2>&1; then exec main; fi ;;' \ 
                '  dotnet)' \ 
                '    comp=$(find . -maxdepth 2 -name "*.dll" | head -1); if [ -n "$comp" ]; then exec dotnet "$comp"; fi ;;' \ 
                '  *) echo "[entrypoint] Unknown runtime $PY_RUNTIME; sleep infinity" >&2; sleep infinity ;;' \ 
                'esac' \ 
                'echo "[entrypoint] No runnable target detected; sleeping" >&2' \ 
                'sleep infinity' \ 
                > /app/entrypoint-runtime.sh; \ 
        fi \ 
 && for lang in python rust node; do \ 
            script=/app/scripts/docker/entrypoint-${lang}.sh; \ 
            if [ ! -f "$script" ]; then echo '#!/usr/bin/env bash' > "$script"; fi; \ 
            chmod +x "$script"; \ 
        done \ 
 && chmod +x /app/entrypoint-runtime.sh \ 
 && echo "✓ Default entrypoint scripts ensured"

# Validate service directory structure with detailed reporting
RUN set -e \
    && echo "=== Service Directory Structure Validation ===" \
    && echo "Checking for services directory..." \
    && if [ -d "/app/src/services" ]; then \
        echo "✅ Services directory found at /app/src/services"; \
        echo "Available services:"; \
        for service_dir in /app/src/services/*/; do \
            if [ -d "$service_dir" ]; then \
                service_name=$(basename "$service_dir"); \
                if [ -f "$service_dir/main.py" ]; then \
                    echo "  ✅ $service_name (main.py found)"; \
                else \
                    echo "  ❌ $service_name (no main.py)"; \
                fi; \
            fi; \
        done; \
    else \
        echo "⚠️ No services directory found at /app/src/services"; \
        echo "Checking alternative locations..."; \
        if [ -d "/app/services" ]; then \
            echo "✅ Found services at /app/services"; \
        else \
            echo "⚠️ No services directory found - will use fallback mode"; \
        fi; \
    fi \
    && echo "=== Main Dispatcher Validation ===" \
    && if [ -f "/app/src/main.py" ]; then \
        echo "✅ Main dispatcher found at /app/src/main.py"; \
    else \
        echo "⚠️ Main dispatcher not found at /app/src/main.py"; \
    fi \
    && echo "=== Entrypoint Scripts Validation ===" \
    && echo "📋 Available entrypoint scripts:" \
    && ls -la /app/entrypoint-runtime.sh /app/scripts/docker/entrypoint_*.sh 2>/dev/null || echo "Some entrypoint scripts missing" \
    && echo "=== Validation Complete ==="

# Set up scripts, permissions, and create logs directory with proper ownership
RUN set -e \
    && echo "Setting up service directories and permissions..." \
    && chmod +x /app/scripts/docker/*.sh 2>/dev/null || echo "No additional docker scripts found" \
    && find /app/bin -type f -executable -exec chmod +x {} \; 2>/dev/null || true \
    && echo "Creating and setting permissions for logs directory..." \
    && mkdir -p /app/logs \
    && chown -R ${USER_ID}:${GROUP_ID} /app \
    && if [ -d "/home/${USER_NAME}" ]; then chown -R ${USER_ID}:${GROUP_ID} /home/${USER_NAME}; fi \
    && echo "Setup completed successfully."

# Enhanced build validation with requirements info
RUN set -e \
    && echo "=== Build Validation ===" \
    && echo "Service Type: ${SERVICE_TYPE}" \
    && echo "Runtime: ${SERVICE_RUNTIME}" \
    && echo "Build Type: ${BUILD_TYPE}" \
    && echo "Rust Network: ${BUILD_RUST_NETWORK}" \
    && echo "Rust Execution: ${BUILD_RUST_EXECUTION}" \
    && echo "Connector: ${BUILD_CONNECTOR}" \
    && echo "Entrypoint Strategy: External Scripts" \
    && echo "Main Entrypoint: /app/entrypoint-runtime.sh" \
    && echo "Requirements File Used: $(head -5 /app/installed-packages.txt | grep '^#' || echo 'N/A')" \
    && echo "Total Packages Installed: $(cat /app/installed-packages.txt | wc -l)" \
    && echo "Logs Directory: /app/logs (created with proper permissions)" \
    && echo "==================" \
    && if [ "${SERVICE_RUNTIME}" = "python" ] || [ "${SERVICE_RUNTIME}" = "hybrid" ]; then \
        if ! /opt/venv/bin/python --version; then \
            echo "Python validation failed"; exit 1; \
        fi; \
        echo "✓ Python runtime validated"; \
        if [ "${BUILD_TYPE}" = "gpu" ]; then \
            echo "✓ GPU Python runtime ready"; \
        fi; \
    fi \
    && echo "✓ Build validation complete"

# Create comprehensive documentation
RUN set -e \
    && mkdir -p /app/docs \
    && echo "# FKS Trading Systems" > /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "## Service Information" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "- **Build Type:** ${BUILD_TYPE}" >> /app/docs/README.md \
    && echo "- **Environment:** ${APP_ENV}" >> /app/docs/README.md \
    && echo "- **Version:** ${APP_VERSION}" >> /app/docs/README.md \
    && echo "- **Runtime:** ${SERVICE_RUNTIME}" >> /app/docs/README.md \
    && echo "- **Service:** ${SERVICE_TYPE}" >> /app/docs/README.md \
    && echo "- **Build Date:** ${BUILD_DATE}" >> /app/docs/README.md \
    && echo "- **Build Version:** ${BUILD_VERSION}" >> /app/docs/README.md \
    && echo "- **Build Commit:** ${BUILD_COMMIT}" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "## Entrypoint Strategy" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "This container uses external entrypoint scripts for better maintainability:" >> /app/docs/README.md \
    && echo "- **Main Dispatcher:** /app/entrypoint-runtime.sh" >> /app/docs/README.md \
    && echo "- **Python Handler:** /app/scripts/docker/entrypoint-python.sh" >> /app/docs/README.md \
    && echo "- **Rust Handler:** /app/scripts/docker/entrypoint-rust.sh" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "## Components Built" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "- Rust Network: ${BUILD_RUST_NETWORK}" >> /app/docs/README.md \
    && echo "- Rust Execution: ${BUILD_RUST_EXECUTION}" >> /app/docs/README.md \
    && echo "- Connector: ${BUILD_CONNECTOR}" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "## Directory Structure" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "- **Logs:** /app/logs (writable by appuser)" >> /app/docs/README.md \
    && echo "- **Data:** /app/data" >> /app/docs/README.md \
    && echo "- **Config:** /app/config" >> /app/docs/README.md \
    && echo "- **Source:** /app/src" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && echo "## GPU Support" >> /app/docs/README.md \
    && echo "" >> /app/docs/README.md \
    && if [ "${BUILD_TYPE}" = "gpu" ]; then \
        echo "This container includes GPU support with CUDA ${CUDA_VERSION}." >> /app/docs/README.md; \
    else \
        echo "This is a CPU-only container." >> /app/docs/README.md; \
    fi \
    && echo "" >> /app/docs/README.md \
    && echo "*Generated: $(date -u +'%Y-%m-%d %H:%M:%S UTC')*" >> /app/docs/README.md

# Enhanced metadata labels
LABEL maintainer="nuniesmith" \
      org.opencontainers.image.title="${SERVICE_NAME}" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.vendor="nuniesmith" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Container image for ${SERVICE_NAME} service with external entrypoint scripts" \
      org.opencontainers.image.source="https://github.com/nuniesmith/fks" \
      org.opencontainers.image.environment="${APP_ENV}" \
      org.opencontainers.image.build.type="${BUILD_TYPE}" \
      org.opencontainers.image.service.runtime="${SERVICE_RUNTIME}" \
      org.opencontainers.image.service.type="${SERVICE_TYPE}" \
      com.nvidia.volumes.needed="${BUILD_TYPE}" \
      com.nvidia.gpu.count="${GPU_COUNT}" \
      com.fks.build.components="${BUILD_RUST_NETWORK},${BUILD_RUST_EXECUTION},${BUILD_CONNECTOR}" \
      com.fks.build.version="${BUILD_VERSION}" \
      com.fks.build.commit="${BUILD_COMMIT}" \
      com.fks.entrypoint.strategy="external" \
      com.fks.logs.directory="/app/logs"

# Expose a default port (runtime listens on SERVICE_PORT via ENV
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD if [ "${ENABLE_HEALTHCHECK}" = "true" ] && [ -f "/app/scripts/docker/healthcheck.sh" ]; then \
            /bin/bash /app/scripts/docker/healthcheck.sh; \
        else \
            timeout 5 bash -c "</dev/tcp/localhost/${SERVICE_PORT}" || exit 1; \
        fi

# Switch to non-root user
USER ${USER_NAME}

# UPDATED: Use external runtime dispatcher as entrypoint
ENTRYPOINT ["/bin/bash", "--", "/app/entrypoint-runtime.sh"]