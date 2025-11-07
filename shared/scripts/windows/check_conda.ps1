# Check for Conda Installation and Setup
Write-Host "Checking for Conda installation..." -ForegroundColor Yellow

# Check common conda installation paths
$condaPaths = @(
    "$env:USERPROFILE\miniconda3\Scripts\conda.exe",
    "$env:USERPROFILE\anaconda3\Scripts\conda.exe",
    "$env:USERPROFILE\AppData\Local\miniconda3\Scripts\conda.exe",
    "$env:USERPROFILE\AppData\Local\anaconda3\Scripts\conda.exe",
    "C:\ProgramData\miniconda3\Scripts\conda.exe",
    "C:\ProgramData\anaconda3\Scripts\conda.exe",
    "C:\miniconda3\Scripts\conda.exe",
    "C:\anaconda3\Scripts\conda.exe"
)

$foundConda = $false
$condaPath = ""

foreach ($path in $condaPaths) {
    if (Test-Path $path) {
        Write-Host "Found conda at: $path" -ForegroundColor Green
        $foundConda = $true
        $condaPath = $path
        break
    }
}

if ($foundConda) {
    Write-Host "Conda is installed but not in PATH. Setting up..." -ForegroundColor Yellow
    
    # Get the conda directory
    $condaDir = Split-Path $condaPath
    $condaBaseDir = Split-Path $condaDir
    
    Write-Host "Conda directory: $condaBaseDir"
    
    # Initialize conda for PowerShell
    Write-Host "Initializing conda for PowerShell..."
    & $condaPath init powershell
    
    Write-Host ""
    Write-Host "=== CONDA SETUP COMPLETE ===" -ForegroundColor Green
    Write-Host "Please RESTART PowerShell and run the setup script again." -ForegroundColor Yellow
    Write-Host "Or manually add conda to your PATH by running:" -ForegroundColor Cyan
    Write-Host "`$env:PATH += ';$condaDir'" -ForegroundColor White
    
} else {
    Write-Host "Conda not found in common locations." -ForegroundColor Red
    Write-Host ""
    Write-Host "=== CONDA INSTALLATION OPTIONS ===" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1: Install Miniconda (Recommended)" -ForegroundColor Cyan
    Write-Host "1. Download from: https://docs.conda.io/en/latest/miniconda.html"
    Write-Host "2. Choose 'Miniconda3 Windows 64-bit'"
    Write-Host "3. Run the installer and check 'Add to PATH'"
    Write-Host ""
    Write-Host "Option 2: Install via winget (if available)" -ForegroundColor Cyan
    Write-Host "Run: winget install Anaconda.Miniconda3"
    Write-Host ""
    Write-Host "Option 3: Install via Chocolatey (if available)" -ForegroundColor Cyan
    Write-Host "Run: choco install miniconda3"
    Write-Host ""
    Write-Host "Option 4: Use Python virtual environment instead" -ForegroundColor Cyan
    Write-Host "Run our alternative setup script that uses venv instead of conda"
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")