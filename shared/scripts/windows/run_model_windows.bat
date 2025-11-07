@echo off
REM FKS Trading Systems Model Runner - Windows Version
REM This script runs the main trading model pipeline using conda environment

echo Starting FKS Trading Systems Model...
echo ==================================

REM Configuration
set CONFIG_PATH=.\config\app_config.yaml
set DATA_PATH=.\data\raw_gc_data.csv
set CONDA_ENV=transformer_gold

REM Initialize conda
call conda init cmd.exe >nul 2>&1

REM Check if conda environment exists and activate it
conda env list | findstr /C:"%CONDA_ENV%" >nul
if %ERRORLEVEL% == 0 (
    echo Activating conda environment: %CONDA_ENV%
    call conda activate %CONDA_ENV%
) else (
    echo Conda environment '%CONDA_ENV%' not found. Creating it...
    call conda create -n %CONDA_ENV% python=3.11 -y
    call conda activate %CONDA_ENV%
    echo Installing requirements...
    
    REM Install PyTorch with CUDA support first
    echo Installing PyTorch with CUDA 12.1 support...
    call conda install pytorch torchvision torchaudio pytorch-cuda=12.1 -c pytorch -c nvidia -y
    
    REM Install other requirements
    if exist requirements.txt (
        pip install -r requirements.txt
    ) else (
        echo requirements.txt not found. Installing basic packages...
        pip install numpy pandas scikit-learn matplotlib seaborn
    )
)

REM Verify we're in the correct environment
echo Active conda environment: %CONDA_DEFAULT_ENV%
python -c "import sys; print('Python path:', sys.executable)"

REM Create necessary directories
echo Creating directories...
if not exist models mkdir models
if not exist data mkdir data
if not exist logs mkdir logs
if not exist results mkdir results
if not exist config mkdir config

REM Check if data file exists
if not exist "%DATA_PATH%" (
    echo Warning: Data file not found at %DATA_PATH%
    echo Please ensure your time series data is available at this location.
) else (
    echo Data file found at %DATA_PATH%
)

REM Check if config file exists, create default if not
if not exist "%CONFIG_PATH%" (
    echo Config file not found at %CONFIG_PATH%. Creating default configuration...
    python -c "from src.core.config import Config; import os; os.makedirs(os.path.dirname(r'%CONFIG_PATH%'), exist_ok=True); config = Config(); config.to_yaml(r'%CONFIG_PATH%'); print('Default configuration created at %CONFIG_PATH%')"
)

REM Check CUDA availability
echo Checking CUDA availability...
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'PyTorch version: {torch.__version__}') if torch.cuda.is_available() else print('Running on CPU only')"

REM Export paths as environment variables for Python script
set CONFIG_PATH=%CONFIG_PATH%
set DATA_PATH=%DATA_PATH%

REM Run CUDA test script if it exists
if exist scripts\cuda.py (
    echo Running CUDA test...
    python scripts\cuda.py
)

REM Run the main script with config and data paths
echo Running main training pipeline...
echo Config: %CONFIG_PATH%
echo Data: %DATA_PATH%
python .\src\main.py --config "%CONFIG_PATH%" --data "%DATA_PATH%"

echo ==================================
echo Training completed!

pause