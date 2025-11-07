Write-Host "FKS Project Health Check" -ForegroundColor Green
Write-Host "==========================" -ForegroundColor Green

# Check C# files
Write-Host "C# Source Files:" -ForegroundColor Yellow
$csFiles = (Get-ChildItem -Path "src" -Filter "*.cs" -Recurse).Count
Write-Host "  Found files: $csFiles" -ForegroundColor White

# Check references
Write-Host "References:" -ForegroundColor Yellow
$dllFiles = if (Test-Path "references") { (Get-ChildItem -Path "references" -Filter "*.dll").Count } else { 0 }
Write-Host "  DLL files: $dllFiles" -ForegroundColor White

# Check .NET
Write-Host "Build Tools:" -ForegroundColor Yellow
try {
    $dotnetVersion = dotnet --version 2>$null
    Write-Host "  .NET SDK: Available ($dotnetVersion)" -ForegroundColor Green
} catch {
    Write-Host "  .NET SDK: Not available" -ForegroundColor Red
}

# Check packages
Write-Host "Build Packages:" -ForegroundColor Yellow
if (Test-Path "packages") {
    $packages = Get-ChildItem -Path "packages" -Filter "*.zip"
    if ($packages) {
        Write-Host "  Latest package: $($packages[-1].Name)" -ForegroundColor Green
        Write-Host "  Package size: $([math]::Round($packages[-1].Length / 1MB, 2)) MB" -ForegroundColor White
    } else {
        Write-Host "  No packages found" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No packages directory" -ForegroundColor Red
}

# Check project structure
Write-Host "Project Structure:" -ForegroundColor Yellow
$dirs = @("src/AddOns", "src/Indicators", "src/Strategies", "src/Core", "src/Features", "src/ML", "src/Shared")
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        $count = (Get-ChildItem -Path $dir -Filter "*.cs").Count
        Write-Host "  $dir`: $count files" -ForegroundColor Green
    } else {
        Write-Host "  $dir`: Missing" -ForegroundColor Red
    }
}

# Check NinjaTrader installation
Write-Host "NinjaTrader:" -ForegroundColor Yellow
$ntPath = "$env:USERPROFILE\Documents\NinjaTrader 8"
if (Test-Path $ntPath) {
    Write-Host "  Installation: Found at $ntPath" -ForegroundColor Green
    $customPath = "$ntPath\bin\Custom"
    if (Test-Path $customPath) {
        Write-Host "  Custom directory: Available" -ForegroundColor Green
        $fksDll = "$customPath\FKS.dll"
        if (Test-Path $fksDll) {
            $dllInfo = Get-Item $fksDll
            Write-Host "  FKS.dll: Deployed ($($dllInfo.LastWriteTime))" -ForegroundColor Green
        } else {
            Write-Host "  FKS.dll: Not deployed" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Custom directory: Not found" -ForegroundColor Red
    }
} else {
    Write-Host "  Installation: Not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "==========================" -ForegroundColor Green
Write-Host "Health check complete!" -ForegroundColor Green
