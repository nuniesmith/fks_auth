# FKS Trading Systems Model Runner
# This script runs the main trading model pipeline

Write-Host "Starting FKS Trading Systems Model..." -ForegroundColor Green
Write-Host "=================================="

# Configuration
$CONFIG_PATH = ".\config\app_config.yaml"

# Check if conda environment exists and activate it
$condaEnvs = & conda info --envs 2>$null
if ($condaEnvs -and ($condaEnvs | Select-String "transformer_gold")) {
    Write-Host "Activating conda environment: transformer_gold..." -ForegroundColor Yellow
    & conda activate transformer_gold
} else {
    # Check if virtual environment exists
    if (Test-Path "venv") {
        Write-Host "Activating virtual environment..." -ForegroundColor Yellow
        & .\venv\Scripts\Activate.ps1
    } elseif (Test-Path ".venv") {
        Write-Host "Activating virtual environment..." -ForegroundColor Yellow
        & .\.venv\Scripts\Activate.ps1
    } else {
        Write-Host "No conda or virtual environment found. Creating virtual environment..." -ForegroundColor Yellow
        & python -m venv venv
        & .\venv\Scripts\Activate.ps1
        Write-Host "Installing requirements..."
        if (Test-Path "requirements.txt") {
            & pip install -r requirements.txt
        } else {
            Write-Host "Warning: requirements.txt not found" -ForegroundColor Yellow
        }
    }
}

# Create necessary directories
Write-Host "Creating directories..."
$directories = @("models", "data", "logs", "results", "config")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
    }
}

# Check if config file exists, create default if not
if (!(Test-Path $CONFIG_PATH)) {
    Write-Host "Config file not found at $CONFIG_PATH. Creating default configuration..." -ForegroundColor Yellow
    & python -c "
from src.core.config import Config
import os
os.makedirs(os.path.dirname('$CONFIG_PATH'), exist_ok=True)
config = Config()
config.to_yaml('$CONFIG_PATH')
print('Default configuration created at $CONFIG_PATH')
"
}

# Check if CUDA is available
Write-Host "Checking CUDA availability..."
& python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"

# Set config path as environment variable for Python script
$env:CONFIG_PATH = $CONFIG_PATH

# Run the main script with config path
Write-Host "Running main training pipeline with config: $CONFIG_PATH" -ForegroundColor Cyan
& python .\src\main.py --config $CONFIG_PATH

Write-Host "==================================" -ForegroundColor Green
Write-Host "Training completed!" -ForegroundColor Green

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")