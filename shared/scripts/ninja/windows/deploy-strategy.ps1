# Enhanced FKS Strategy Deployment Script
# Deploys the improved strategy with comprehensive logging and trade execution tracking

Write-Host "=== FKS Enhanced Strategy Deployment ===" -ForegroundColor Green

# Set paths
$projectPath = "c:\Users\Jordan\Documents\ninja"
$sourceDll = "$projectPath\bin\Release\FKS.dll"
$targetPath = "$env:USERPROFILE\Documents\NinjaTrader 8\bin\Custom"

# Check if source DLL exists
if (-not (Test-Path $sourceDll)) {
    Write-Host "ERROR: Source DLL not found at $sourceDll" -ForegroundColor Red
    Write-Host "Please build the project first with: dotnet build src/FKS.csproj --configuration Release"
    exit 1
}

# Create target directory if it doesn't exist
if (-not (Test-Path $targetPath)) {
    New-Item -ItemType Directory -Path $targetPath -Force
    Write-Host "Created directory: $targetPath" -ForegroundColor Yellow
}

# Get file versions for comparison
$sourceFile = Get-Item $sourceDll
$targetFile = "$targetPath\FKS.dll"

Write-Host "Source DLL: $sourceDll" -ForegroundColor Cyan
Write-Host "  Size: $($sourceFile.Length) bytes"
Write-Host "  Modified: $($sourceFile.LastWriteTime)"

if (Test-Path $targetFile) {
    $existingFile = Get-Item $targetFile
    Write-Host "Existing DLL: $targetFile" -ForegroundColor Cyan
    Write-Host "  Size: $($existingFile.Length) bytes"
    Write-Host "  Modified: $($existingFile.LastWriteTime)"
    
    if ($sourceFile.LastWriteTime -le $existingFile.LastWriteTime) {
        Write-Host "WARNING: Source file is not newer than target!" -ForegroundColor Yellow
    }
}

# Copy the DLL
try {
    Copy-Item $sourceDll $targetPath -Force
    Write-Host "SUCCESS: FKS.dll copied to NinjaTrader 8" -ForegroundColor Green
    
    # Verify the copy
    $copiedFile = Get-Item "$targetPath\FKS.dll"
    Write-Host "Verified: $($copiedFile.Length) bytes copied at $($copiedFile.LastWriteTime)" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to copy DLL - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Make sure NinjaTrader 8 is closed before running this script." -ForegroundColor Yellow
    exit 1
}

# Show key improvements
Write-Host "`n=== Enhanced Features Deployed ===" -ForegroundColor Green
Write-Host "✓ Comprehensive trade execution logging" -ForegroundColor White
Write-Host "✓ Enhanced order and execution tracking" -ForegroundColor White
Write-Host "✓ Improved signal validation and ATR checks" -ForegroundColor White
Write-Host "✓ Better error handling and debugging" -ForegroundColor White
Write-Host "✓ Validated use of shared AddOns calculations" -ForegroundColor White
Write-Host "✓ More selective signal generation criteria" -ForegroundColor White
Write-Host "✓ Position size calculation logging" -ForegroundColor White

Write-Host "`n=== Next Steps ===" -ForegroundColor Yellow
Write-Host "1. Start NinjaTrader 8"
Write-Host "2. Stop any running FKS_Strategy instances"
Write-Host "3. Recompile NinjaScript (F5 or Tools > Compile NinjaScript)"
Write-Host "4. Start a new FKS_Strategy instance on your chart"
Write-Host "5. Check the Output window for enhanced debug logging"
Write-Host "6. Monitor trade executions with detailed P and L tracking"

Write-Host ""
Write-Host "Deployment completed successfully!" -ForegroundColor Green
