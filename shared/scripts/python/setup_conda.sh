#!/bin/bash

# Setup Conda Environment for FKS Trading Systems Model
# This script removes existing .venv and creates a new conda environment

echo "Setting up Conda Environment for FKS Trading Systems Model..."
echo "=============================================================="

# Configuration
ENV_NAME="fks_env"
PYTHON_VERSION="3.11"
REQUIREMENTS_FILE="requirements.txt"

# Initialize conda for bash (required for conda activate to work in scripts)
echo "Initializing conda..."
eval "$(conda shell.bash hook)" 2>/dev/null || {
    echo "⚠️  Conda not found in PATH. Trying common conda locations..."
    if [ -f "$HOME/miniconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/miniconda3/etc/profile.d/conda.sh"
    elif [ -f "$HOME/anaconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/anaconda3/etc/profile.d/conda.sh"
    elif [ -f "/opt/conda/etc/profile.d/conda.sh" ]; then
        source "/opt/conda/etc/profile.d/conda.sh"
    else
        echo "❌ Conda installation not found. Please install conda first."
        exit 1
    fi
}

# Verify conda is available
if ! command -v conda &> /dev/null; then
    echo "❌ Conda command not available after initialization"
    exit 1
fi

echo "✅ Conda initialized: $(conda --version)"

# Step 1: Remove existing virtual environment
echo "Step 1: Cleaning up existing environments..."
if [ -d ".venv" ]; then
    echo "Removing existing .venv directory..."
    rm -rf .venv
    echo "✅ .venv removed"
else
    echo "No .venv directory found"
fi

if [ -d "venv" ]; then
    echo "Removing existing venv directory..."
    rm -rf venv
    echo "✅ venv removed"
else
    echo "No venv directory found"
fi

# Step 2: Remove conda environment if it exists
echo "Checking for existing conda environment: $ENV_NAME"
if conda env list | grep -q "^$ENV_NAME "; then
    echo "Found existing conda environment: $ENV_NAME"
    read -p "Do you want to remove and recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing conda environment: $ENV_NAME"
        conda env remove -n $ENV_NAME -y
        echo "✅ Existing conda environment removed"
    else
        echo "Keeping existing environment. Exiting..."
        exit 0
    fi
fi

# Step 3: Create new conda environment
echo "Step 2: Creating new conda environment..."
echo "Environment name: $ENV_NAME"
echo "Python version: $PYTHON_VERSION"

conda create -n $ENV_NAME python=$PYTHON_VERSION -y

if [ $? -eq 0 ]; then
    echo "✅ Conda environment created successfully"
else
    echo "❌ Failed to create conda environment"
    exit 1
fi

# Step 4: Activate the environment
echo "Step 3: Activating conda environment..."
conda activate $ENV_NAME

if [ $? -eq 0 ]; then
    echo "✅ Environment activated: $ENV_NAME"
    echo "Active environment: $CONDA_DEFAULT_ENV"
else
    echo "❌ Failed to activate environment"
    exit 1
fi

# Step 5: Update pip
echo "Step 4: Updating pip..."
python -m pip install --upgrade pip

if [ $? -eq 0 ]; then
    echo "✅ Pip updated successfully"
    pip --version
else
    echo "❌ Failed to update pip"
    exit 1
fi

# Step 6: Install PyTorch with CUDA support first
echo "Step 5: Installing PyTorch with CUDA support..."
echo "Installing PyTorch with CUDA 12.1..."

# Try conda installation first (more stable for CUDA)
echo "Attempting conda installation of PyTorch..."
conda install pytorch torchvision torchaudio pytorch-cuda=12.1 -c pytorch -c nvidia -y

if [ $? -eq 0 ]; then
    echo "✅ PyTorch with CUDA installed successfully via conda"
else
    echo "⚠️  Conda installation failed, trying pip with CUDA 12.1..."
    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
    
    if [ $? -ne 0 ]; then
        echo "⚠️  CUDA 12.1 failed, trying CUDA 11.8..."
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
        
        if [ $? -ne 0 ]; then
            echo "⚠️  All CUDA installations failed, installing CPU-only version..."
            pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
        fi
    fi
fi

# Verify PyTorch installation
echo "Verifying PyTorch installation..."
python -c "
import torch
print(f'PyTorch version: {torch.__version__}')
print(f'CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'CUDA version: {torch.version.cuda}')
    print(f'GPU count: {torch.cuda.device_count()}')
    for i in range(torch.cuda.device_count()):
        print(f'GPU {i}: {torch.cuda.get_device_name(i)}')
else:
    print('Running on CPU only')
"

# Step 7: Install requirements from file
echo "Step 6: Installing requirements from $REQUIREMENTS_FILE..."
if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Installing requirements from file (excluding PyTorch packages)..."
    # Filter out PyTorch packages from requirements.txt since we already installed them
    grep -v -E "^(torch|torchvision|torchaudio)" $REQUIREMENTS_FILE > temp_requirements.txt
    pip install -r temp_requirements.txt
    rm temp_requirements.txt
    
    if [ $? -eq 0 ]; then
        echo "✅ Requirements installed successfully"
    else
        echo "⚠️  Some requirements may have failed to install"
        echo "Installing critical packages individually..."
        
        # Install critical packages individually if requirements.txt fails
        declare -a packages=(
            "pydantic>=2.8.0"
            "PyYAML>=6.0"
            "numpy>=1.24.0"
            "pandas>=1.0.0"
            "scikit-learn>=1.3.0"
            "matplotlib>=3.7.0"
            "ta>=0.10.0"
            "yfinance>=0.2.0"
            "vaderSentiment>=3.3.0"
            "loguru>=0.7.0"
            "pandas_market_calendars>=4.0.0"
            "seaborn>=0.11.0"
            "plotly>=5.0.0"
            "jupyter>=1.0.0"
            "tqdm>=4.64.0"
            "python-dotenv>=0.19.0"
        )
        
        for package in "${packages[@]}"; do
            echo "Installing $package..."
            pip install "$package" || echo "⚠️  Failed to install $package"
        done
    fi
else
    echo "⚠️  Requirements file not found: $REQUIREMENTS_FILE"
    echo "Installing essential packages manually..."
    
    # Essential packages for the trading model
    declare -a essential_packages=(
        "pydantic>=2.8.0"
        "PyYAML>=6.0"
        "numpy>=1.24.0"
        "pandas>=1.0.0"
        "scikit-learn>=1.3.0"
        "matplotlib>=3.7.0"
        "ta>=0.10.0"
        "yfinance>=0.2.0"
        "vaderSentiment>=3.3.0"
        "loguru>=0.7.0"
        "pandas_market_calendars>=4.0.0"
        "seaborn>=0.11.0"
        "plotly>=5.0.0"
        "jupyter>=1.0.0"
        "tqdm>=4.64.0"
        "python-dotenv>=0.19.0"
    )
    
    for package in "${essential_packages[@]}"; do
        echo "Installing $package..."
        pip install "$package" || echo "⚠️  Failed to install $package"
    done
fi

# Step 8: Test installation
echo "Step 7: Testing installation..."
python -c "
import sys
import warnings
warnings.filterwarnings('ignore')

# Test imports
test_packages = {
    'torch': 'PyTorch',
    'numpy': 'NumPy', 
    'pandas': 'Pandas',
    'sklearn': 'Scikit-learn',
    'matplotlib': 'Matplotlib',
    'pydantic': 'Pydantic',
    'yaml': 'PyYAML',
    'ta': 'TA-Lib',
    'yfinance': 'YFinance',
    'vaderSentiment': 'VaderSentiment',
    'loguru': 'Loguru'
}

print('=' * 60)
print('PACKAGE INSTALLATION TEST')
print('=' * 60)
print(f'Python: {sys.version.split()[0]}')

for module, name in test_packages.items():
    try:
        imported = __import__(module)
        version = getattr(imported, '__version__', 'unknown')
        print(f'✅ {name}: {version}')
    except ImportError as e:
        print(f'❌ {name}: NOT INSTALLED ({e})')

print()
print('CUDA TEST:')
try:
    import torch
    print(f'CUDA available: {torch.cuda.is_available()}')
    if torch.cuda.is_available():
        print(f'CUDA version: {torch.version.cuda}')
        print(f'GPU count: {torch.cuda.device_count()}')
        for i in range(torch.cuda.device_count()):
            print(f'GPU {i}: {torch.cuda.get_device_name(i)}')
        
        # Test CUDA operations
        try:
            x = torch.randn(100, 100).cuda()
            y = torch.mm(x, x.T)
            print('✅ CUDA operations: PASSED')
        except Exception as e:
            print(f'❌ CUDA operations: FAILED - {e}')
    else:
        print('⚠️  CUDA not available - running on CPU')
except ImportError:
    print('❌ PyTorch not installed')
print('=' * 60)
"

# Step 9: Create activation scripts
echo "Step 8: Creating activation scripts..."

# Create activation script
cat > scripts/environment/activate_env.sh << 'EOF'
#!/bin/bash
# Activate the fks_env conda environment

# Initialize conda
eval "$(conda shell.bash hook)" 2>/dev/null || {
    if [ -f "$HOME/miniconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/miniconda3/etc/profile.d/conda.sh"
    elif [ -f "$HOME/anaconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/anaconda3/etc/profile.d/conda.sh"
    elif [ -f "/opt/conda/etc/profile.d/conda.sh" ]; then
        source "/opt/conda/etc/profile.d/conda.sh"
    fi
}

conda activate fks_env

if [ "$CONDA_DEFAULT_ENV" = "fks_env" ]; then
    echo "🚀 Conda environment 'fks_env' activated"
    echo "Python: $(which python)"
    echo "Pip: $(which pip)"
    
    python -c "
import torch
print(f'PyTorch: {torch.__version__}')
print(f'CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'GPU: {torch.cuda.get_device_name(0)}')
else:
    print('Running on CPU')
"
else
    echo "❌ Failed to activate environment"
fi
EOF

chmod +x scripts/environment/activate_env.sh

# Create deactivation script
cat > scripts/environment/deactivate_env.sh << 'EOF'
#!/bin/bash
# Deactivate conda environment
conda deactivate
echo "📴 Conda environment deactivated"
EOF

chmod +x scripts/environment/deactivate_env.sh

# Create directory structure
echo "Step 9: Creating directory structure..."
mkdir -p {models,data,logs,results,config,scripts}
echo "✅ Directories created: models, data, logs, results, config, scripts"

# Step 10: Final summary
echo ""
echo "=============================================================="
echo "🎉 SETUP COMPLETE!"
echo "=============================================================="
echo "Environment name: $ENV_NAME"
echo "Python: $(python --version 2>&1)"
echo "Location: $(which python)"
echo "Active environment: $CONDA_DEFAULT_ENV"
echo ""
echo "📋 Quick Commands:"
echo "  Activate:   source scripts/environment/activate_env.sh"
echo "  Deactivate: source scripts/environment/deactivate_env.sh" 
echo "  Test CUDA:  python -c 'import torch; print(torch.cuda.is_available())'"
echo "  Run model:  python src/main.py --config config/app_config.yaml"
echo ""
echo "🗑️  To remove environment: conda env remove -n $ENV_NAME"
echo ""
echo "📁 Directory structure created:"
echo "  models/    - for saved models"
echo "  data/      - for datasets"
echo "  logs/      - for log files"
echo "  results/   - for output results"
echo "  config/    - for configuration files"
echo "  scripts/   - for utility scripts"
echo "=============================================================="

# Show installed package summary
echo "📦 Key Package Versions:"
python -c "
packages = ['torch', 'numpy', 'pandas', 'scikit-learn', 'matplotlib', 'pydantic', 'yaml']
for pkg in packages:
    try:
        if pkg == 'yaml':
            import yaml as module
        else:
            module = __import__(pkg.replace('-', '_'))
        version = getattr(module, '__version__', 'unknown')
        print(f'  {pkg}: {version}')
    except ImportError:
        print(f'  {pkg}: NOT INSTALLED')
"

echo ""
echo "🚀 Environment is ready for use!"
echo "Run 'source scripts/environment/activate_env.sh' to start using the environment."