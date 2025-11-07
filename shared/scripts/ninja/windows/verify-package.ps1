# NinjaTrader 8 Package Verifier
# This script verifies that your package is properly formatted for NT8

param(
    [string]$PackagePath = "packages/FKS_TradingSystem.zip"
)

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Verify-Package {
    param([string]$ZipPath)
    
    if (-not (Test-Path $ZipPath)) {
        Write-Error "Package not found: $ZipPath"
        return $false
    }
    
    Write-Info "Verifying NinjaTrader 8 package: $ZipPath"
    
    try {
        # Load ZIP file
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $ZipPath))
        
        $hasManifest = $false
        $hasIndicators = $false
        $hasStrategies = $false
        $hasAddOns = $false
        $hasDLL = $false
        
        Write-Info "Package contents:"
        foreach ($entry in $zip.Entries) {
            $sizeKB = [math]::Round($entry.Length / 1024, 1)
            Write-Host "  $($entry.FullName) ($sizeKB KB)" -ForegroundColor Gray
            
            # Check for required components
            if ($entry.FullName -eq "manifest.xml") {
                $hasManifest = $true
                Write-Success "Found manifest.xml"
            }
            if ($entry.FullName -like "bin/Custom/Indicators/*" -or $entry.FullName -like "bin\Custom\Indicators\*") {
                $hasIndicators = $true
            }
            if ($entry.FullName -like "bin/Custom/Strategies/*" -or $entry.FullName -like "bin\Custom\Strategies\*") {
                $hasStrategies = $true
            }
            if ($entry.FullName -like "bin/Custom/AddOns/*" -or $entry.FullName -like "bin\Custom\AddOns\*") {
                $hasAddOns = $true
            }
            if ($entry.FullName -eq "bin/FKS.dll" -or $entry.FullName -eq "bin\FKS.dll") {
                $hasDLL = $true
                $dllSizeKB = [math]::Round($entry.Length / 1024, 1)
                Write-Success "Found compiled DLL: FKS.dll ($dllSizeKB KB)"
            }
        }
        
        # Verify manifest content
        if ($hasManifest) {
            $manifestEntry = $zip.Entries | Where-Object { $_.FullName -eq "manifest.xml" }
            $reader = [System.IO.StreamReader]::new($manifestEntry.Open())
            $manifestContent = $reader.ReadToEnd()
            $reader.Close()
            
            if ($manifestContent -like "*NinjaScriptManifest*") {
                Write-Success "Manifest has correct NinjaTrader format"
            } else {
                Write-Error "Manifest does not have correct NinjaTrader format"
            }
            
            if ($manifestContent -like "*SchemaVersion*") {
                Write-Success "Manifest has schema version"
            } else {
                Write-Warning "Manifest missing schema version"
            }
            
            if ($manifestContent -like "*FKS.dll*") {
                Write-Success "Manifest references FKS.dll"
            } else {
                Write-Warning "Manifest doesn't reference the compiled DLL"
            }
            
            if ($manifestContent -like "*AssemblyName>FKS<*") {
                Write-Success "Manifest has assembly name references"
            } else {
                Write-Warning "Manifest missing assembly name references"
            }
        }
        
        $zip.Dispose()
        
        # Summary
        Write-Info "=== VERIFICATION SUMMARY ==="
        if ($hasManifest) { Write-Success "Manifest present" } else { Write-Error "Missing manifest.xml" }
        if ($hasDLL) { Write-Success "Compiled DLL present" } else { Write-Error "Missing FKS.dll" }
        if ($hasIndicators) { Write-Success "Indicators found" } else { Write-Warning "No indicators found" }
        if ($hasStrategies) { Write-Success "Strategies found" } else { Write-Warning "No strategies found" }
        if ($hasAddOns) { Write-Success "AddOns found" } else { Write-Warning "No AddOns found" }
        
        $packageSize = (Get-Item $ZipPath).Length
        Write-Info "Package size: $packageSize bytes"
        
        if ($hasManifest -and $hasDLL -and ($hasIndicators -or $hasStrategies -or $hasAddOns)) {
            Write-Success "Package appears to be properly formatted for NinjaTrader 8"
            return $true
        } else {
            Write-Error "Package may have issues importing into NinjaTrader 8"
            if (-not $hasDLL) {
                Write-Error "Missing compiled DLL - this will cause import failures"
            }
            return $false
        }
        
    } catch {
        Write-Error "Error verifying package: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
Write-Info "=== NinjaTrader 8 Package Verifier ==="
$result = Verify-Package -ZipPath $PackagePath

if ($result) {
    Write-Info ""
    Write-Info "=== IMPORT INSTRUCTIONS ==="
    Write-Info "1. Close NinjaTrader 8 completely"
    Write-Info "2. Open NinjaTrader 8"
    Write-Info "3. Go to Tools → Import → NinjaScript Add-On"
    Write-Info "4. Select: $PackagePath"
    Write-Info "5. Click Import"
    Write-Info "6. Restart NinjaTrader 8"
    Write-Info "7. Check Indicators/Strategies lists for FKS components"
} else {
    Write-Error "Package verification failed. Check the issues above before importing."
}
