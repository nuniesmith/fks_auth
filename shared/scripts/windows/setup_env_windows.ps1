# Setup Conda Environment for FKS Trading Systems Model
# This script removes existing .venv and creates a new conda environment

Write-Host "Setting up Conda Environment for FKS Trading Systems Model..." -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green

# Configuration
$ENV_NAME = "transformer_gold"
$PYTHON_VERSION = "3.11"
$REQUIREMENTS_FILE = "requirements.txt"

# Step 1: Remove existing virtual environment
Write-Host "Step 1: Cleaning up existing environments..." -ForegroundColor Yellow

if (Test-Path ".venv") {
    Write-Host "Removing existing .venv directory..."
    Remove-Item -Recurse -Force ".venv"
    Write-Host "* .venv removed" -ForegroundColor Green
}
else {
    Write-Host "No .venv directory found"
}

if (Test-Path "venv") {
    Write-Host "Removing existing venv directory..."
    Remove-Item -Recurse -Force "venv"
    Write-Host "* venv removed" -ForegroundColor Green
}
else {
    Write-Host "No venv directory found"
}

# Step 2: Remove conda environment if it exists
Write-Host "Checking for existing conda environment: $ENV_NAME"
$envExists = & conda env list | Select-String "^$ENV_NAME "
if ($envExists) {
    Write-Host "Removing existing conda environment: $ENV_NAME"
    & conda env remove -n $ENV_NAME -y
    Write-Host "* Existing conda environment removed" -ForegroundColor Green
}

# Step 3: Create new conda environment
Write-Host "Step 2: Creating new conda environment..." -ForegroundColor Yellow
Write-Host "Environment name: $ENV_NAME"
Write-Host "Python version: $PYTHON_VERSION"

& conda create -n $ENV_NAME python=$PYTHON_VERSION -y

if ($LASTEXITCODE -eq 0) {
    Write-Host "* Conda environment created successfully" -ForegroundColor Green
}
else {
    Write-Host "* Failed to create conda environment" -ForegroundColor Red
    exit 1
}

# Step 4: Activate the environment
Write-Host "Step 3: Activating conda environment..." -ForegroundColor Yellow
& conda activate $ENV_NAME

if ($LASTEXITCODE -eq 0) {
    Write-Host "* Environment activated" -ForegroundColor Green
}
else {
    Write-Host "* Failed to activate environment" -ForegroundColor Red
    exit 1
}

# Step 5: Update pip
Write-Host "Step 4: Updating pip..." -ForegroundColor Yellow
& python -m pip install --upgrade pip

if ($LASTEXITCODE -eq 0) {
    Write-Host "* Pip updated successfully" -ForegroundColor Green
    & pip --version
}
else {
    Write-Host "* Failed to update pip" -ForegroundColor Red
    exit 1
}

# Step 6: Install PyTorch with CUDA support first
Write-Host "Step 5: Installing PyTorch with CUDA support..." -ForegroundColor Yellow
Write-Host "Installing PyTorch 2.7.1+ with CUDA 12.1..."

# Try conda installation first
& conda install pytorch=2.7.1 torchvision=0.22.1 pytorch-cuda=12.1 -c pytorch -c nvidia -y

if ($LASTEXITCODE -eq 0) {
    Write-Host "* PyTorch with CUDA installed successfully via conda" -ForegroundColor Green
}
else {
    Write-Host "! Conda installation failed, trying pip with CUDA 12.1..." -ForegroundColor Yellow
    & pip install torch>=2.7.1 torchvision>=0.22.1 --index-url https://download.pytorch.org/whl/cu121
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "! CUDA 12.1 failed, trying CUDA 11.8..." -ForegroundColor Yellow
        & pip install torch>=2.7.1 torchvision>=0.22.1 --index-url https://download.pytorch.org/whl/cu118
    }
}

# Verify PyTorch installation
Write-Host "Verifying PyTorch installation..."
& python -c 'import torch; print("PyTorch version: " + torch.__version__)'
& python -c 'import torch; print("CUDA available: " + str(torch.cuda.is_available()))'
& python -c 'import torch; print("CUDA version: " + str(torch.version.cuda)) if torch.cuda.is_available() else print("No CUDA")'

# Step 7: Install requirements
Write-Host "Step 6: Installing requirements..." -ForegroundColor Yellow

if (Test-Path $REQUIREMENTS_FILE) {
    Write-Host "Installing from requirements.txt..."
    & pip install -r $REQUIREMENTS_FILE
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "* Requirements installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "! Some requirements failed, installing individually..." -ForegroundColor Yellow
        # Install packages individually
        & pip install "pydantic>=2.8.0"
        & pip install "PyYAML>=6.0"
        & pip install "numpy>=2.3.0"
        & pip install "pandas>=2.3.0"
        & pip install "scikit-learn>=1.7.0"
        & pip install "matplotlib>=3.10.3"
        & pip install "ta>=0.11.0"
        & pip install "yfinance>=0.2.62"
        & pip install "vaderSentiment>=3.3.2"
        & pip install "loguru>=0.7.0"
        & pip install "pandas_market_calendars>=5.1.0"
        & pip install "hfs>=0.6.0"
        & pip install "seaborn>=0.11.0"
        & pip install "plotly>=5.0.0"
        & pip install "jupyter>=1.0.0"
        & pip install "tqdm>=4.64.0"
        & pip install "python-dotenv>=0.19.0"
    }
}
else {
    Write-Host "! Requirements file not found, installing manually..." -ForegroundColor Yellow
    # Install packages manually
    & pip install "pydantic>=2.8.0"
    & pip install "PyYAML>=6.0"
    & pip install "numpy>=2.3.0"
    & pip install "pandas>=2.3.0"
    & pip install "scikit-learn>=1.7.0"
    & pip install "matplotlib>=3.10.3"
    & pip install "ta>=0.11.0"
    & pip install "yfinance>=0.2.62"
    & pip install "vaderSentiment>=3.3.2"
    & pip install "loguru>=0.7.0"
    & pip install "pandas_market_calendars>=5.1.0"
    & pip install "hfs>=0.6.0"
    & pip install "seaborn>=0.11.0"
    & pip install "plotly>=5.0.0"
    & pip install "jupyter>=1.0.0"
    & pip install "tqdm>=4.64.0"
    & pip install "python-dotenv>=0.19.0"
}

# Step 8: Test installation
Write-Host "Step 7: Testing installation..." -ForegroundColor Yellow
Write-Host "=============================================================="
Write-Host "PACKAGE VERSIONS TEST"
Write-Host "=============================================================="
& python -c 'import sys; print("Python: " + sys.version)'
& python -c 'import torch; print("PyTorch: " + torch.__version__)'
& python -c 'import numpy; print("NumPy: " + numpy.__version__)'
& python -c 'import pandas; print("Pandas: " + pandas.__version__)'
& python -c 'import sklearn; print("Scikit-learn: " + sklearn.__version__)'
& python -c 'import matplotlib; print("Matplotlib: " + matplotlib.__version__)'
& python -c 'import pydantic; print("Pydantic: " + pydantic.__version__)'

Write-Host ""
Write-Host "CUDA TEST:"
& python -c 'import torch; print("CUDA available: " + str(torch.cuda.is_available()))'
& python -c 'import torch; print("CUDA version: " + str(torch.version.cuda)) if torch.cuda.is_available() else print("No CUDA")'
& python -c 'import torch; print("GPU count: " + str(torch.cuda.device_count())) if torch.cuda.is_available() else None'
Write-Host "=============================================================="

# Step 9: Create activation scripts
Write-Host "Step 8: Creating activation scripts..." -ForegroundColor Yellow

# Create activate_env.bat
$activateBat = @"
@echo off
call conda activate $ENV_NAME
echo Conda environment '$ENV_NAME' activated
echo Python:
where python
echo Pip:
where pip
python -c "import torch; print('PyTorch: ' + torch.__version__)"
"@
$activateBat | Out-File -FilePath "activate_env.bat" -Encoding ASCII

# Create activate_env.ps1
$activatePs1 = @"
# Activate the transformer_gold conda environment
& conda activate $ENV_NAME
Write-Host "Conda environment '$ENV_NAME' activated" -ForegroundColor Green
Write-Host "Python: " -NoNewline
& where.exe python
Write-Host "Pip: " -NoNewline  
& where.exe pip
& python -c 'import torch; print("PyTorch: " + torch.__version__)'
"@
$activatePs1 | Out-File -FilePath "activate_env.ps1" -Encoding UTF8

# Create deactivate scripts
$deactivateBat = @"
@echo off
conda deactivate
echo Conda environment deactivated
"@
$deactivateBat | Out-File -FilePath "deactivate_env.bat" -Encoding ASCII

$deactivatePs1 = @"
# Deactivate conda environment
& conda deactivate
Write-Host "Conda environment deactivated" -ForegroundColor Yellow
"@
$deactivatePs1 | Out-File -FilePath "deactivate_env.ps1" -Encoding UTF8

# Final summary
Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "SETUP COMPLETE!" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "Environment name: $ENV_NAME"
Write-Host "Python version:"
& python --version
Write-Host "Location:"
& where.exe python
Write-Host ""
Write-Host "Quick Commands:" -ForegroundColor Cyan
Write-Host "  Activate (cmd):        activate_env.bat"
Write-Host "  Activate (PowerShell): .\activate_env.ps1"
Write-Host "  Deactivate (cmd):      deactivate_env.bat" 
Write-Host "  Deactivate (PowerShell): .\deactivate_env.ps1"
Write-Host "  Test CUDA:             python cuda.py"
Write-Host "  Run model:             python src\main.py --config config\app_config.yaml"
Write-Host ""
Write-Host "To remove environment: conda env remove -n $ENV_NAME" -ForegroundColor Red
Write-Host "==============================================================" -ForegroundColor Green

# Show key package versions
Write-Host "Key Package Versions:" -ForegroundColor Cyan
& python -c 'import torch; print("  torch: " + torch.__version__)'
& python -c 'import numpy; print("  numpy: " + numpy.__version__)'
& python -c 'import pandas; print("  pandas: " + pandas.__version__)'
& python -c 'import sklearn; print("  scikit-learn: " + sklearn.__version__)'
& python -c 'import matplotlib; print("  matplotlib: " + matplotlib.__version__)'
& python -c 'import pydantic; print("  pydantic: " + pydantic.__version__)'

Write-Host ""
Write-Host "Setup completed successfully! Press any key to continue..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")