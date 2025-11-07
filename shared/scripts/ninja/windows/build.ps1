# FKS NinjaTrader 8 Build Script
# This script builds the FKS project and creates a NinjaTrader 8 package

param(
    [string]$Configuration = "Release",
    [switch]$Clean,
    [switch]$Package,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"
$Blue = "Blue"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check if dotnet is available
    try {
        $dotnetVersion = dotnet --version
        Write-Success "Found .NET SDK version: $dotnetVersion"
    } catch {
        Write-Error ".NET SDK not found. Please install .NET SDK."
        exit 1
    }
    
    # Check if project files exist
    if (-not (Test-Path "FKS.sln")) {
        Write-Error "FKS.sln not found in current directory"
        exit 1
    }
    
    if (-not (Test-Path "src/FKS.csproj")) {
        Write-Error "src/FKS.csproj not found"
        exit 1
    }
    
    # Check if NinjaTrader references exist
    $ntReferences = @(
        "references/NinjaTrader.Core.dll",
        "references/NinjaTrader.Custom.dll",
        "references/NinjaTrader.Gui.dll"
    )
    
    foreach ($ref in $ntReferences) {
        if (-not (Test-Path $ref)) {
            Write-Warning "Missing NinjaTrader reference: $ref"
        }
    }
    
    Write-Success "Prerequisites check completed"
}

function Invoke-Clean {
    Write-Info "Cleaning previous builds..."
    
    try {
        dotnet clean src/FKS.csproj -c $Configuration
        
        # Remove additional directories
        $cleanDirs = @("bin", "obj", "packages")
        foreach ($dir in $cleanDirs) {
            if (Test-Path $dir) {
                Remove-Item $dir -Recurse -Force
                Write-Info "Removed directory: $dir"
            }
        }
        
        Write-Success "Clean completed"
    } catch {
        Write-Error "Clean failed: $($_.Exception.Message)"
        exit 1
    }
}

function Invoke-Restore {
    Write-Info "Restoring NuGet packages..."
    
    try {
        dotnet restore src/FKS.csproj
        Write-Success "Package restore completed"
    } catch {
        Write-Error "Package restore failed: $($_.Exception.Message)"
        exit 1
    }
}

function Invoke-Build {
    Write-Info "Building FKS project (Configuration: $Configuration)..."
    
    try {
        $buildArgs = @(
            "build",
            "src/FKS.csproj",
            "-c", $Configuration,
            "--no-restore"
        )
        
        if ($Verbose) {
            $buildArgs += "-v", "detailed"
        }
        
        dotnet @buildArgs
        
        Write-Success "Build completed successfully"
        
        # Check if DLL was created
        $dllPath = "bin/$Configuration/FKS.dll"
        if (Test-Path $dllPath) {
            $dllInfo = Get-Item $dllPath
            Write-Success "FKS.dll created: $($dllInfo.Length) bytes"
        } else {
            Write-Warning "FKS.dll not found at expected location: $dllPath"
        }
        
    } catch {
        Write-Error "Build failed: $($_.Exception.Message)"
        exit 1
    }
}

function New-NT8Package {
    Write-Info "Creating NinjaTrader 8 package..."
    
    try {
        # Verify DLL exists first
        $dllPath = "bin/$Configuration/FKS.dll"
        if (-not (Test-Path $dllPath)) {
            Write-Error "FKS.dll not found at $dllPath. Please build first."
            return
        }
        
        # Create package directory structure
        $packageDir = "packages/temp"
        $directories = @(
            "$packageDir/bin/Custom/Indicators",
            "$packageDir/bin/Custom/Strategies", 
            "$packageDir/bin/Custom/AddOns",
            "$packageDir/bin"
        )
        
        # Clean and create directories
        if (Test-Path "packages") {
            Remove-Item "packages" -Recurse -Force
        }
        
        foreach ($dir in $directories) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        
        # Copy compiled DLL (IMPORTANT!)
        Copy-Item $dllPath "$packageDir/bin/FKS.dll" -Force
        Write-Success "Copied compiled DLL: $dllPath"
        
        # Copy PDB file if it exists (for debugging)
        $pdbPath = "bin/$Configuration/FKS.pdb"
        if (Test-Path $pdbPath) {
            Copy-Item $pdbPath "$packageDir/bin/FKS.pdb" -Force
            Write-Info "Copied debug symbols: $pdbPath"
        }
        
        # Copy source files according to NinjaTrader structure
        $fileMappings = @{
            "src/Indicators/FKS_AI.cs" = "$packageDir/bin/Custom/Indicators/FKS_AI.cs"
            "src/Indicators/FKS_AO.cs" = "$packageDir/bin/Custom/Indicators/FKS_AO.cs"
            "src/Indicators/FKS_Engine.cs" = "$packageDir/bin/Custom/Indicators/FKS_Engine.cs"
            "src/Indicators/FKS_Dashboard.cs" = "$packageDir/bin/Custom/Indicators/FKS_Dashboard.cs"
            "src/Indicators/FKS_Performance.cs" = "$packageDir/bin/Custom/Indicators/FKS_Performance.cs"
            "src/Indicators/FKS_Test.cs" = "$packageDir/bin/Custom/Indicators/FKS_Test.cs"
            "src/Strategies/FKS_Strategy.cs" = "$packageDir/bin/Custom/Strategies/FKS_Strategy.cs"
            "src/AddOns/FKS_Regime.cs" = "$packageDir/bin/Custom/AddOns/FKS_Regime.cs"
            "src/GlobalUsings.cs" = "$packageDir/bin/Custom/GlobalUsings.cs"
        }
        
        $copiedFiles = @()
        foreach ($mapping in $fileMappings.GetEnumerator()) {
            if (Test-Path $mapping.Key) {
                Copy-Item $mapping.Key $mapping.Value -Force
                Write-Info "Copied: $($mapping.Key)"
                $copiedFiles += $mapping.Value
            } else {
                Write-Warning "Source file not found: $($mapping.Key)"
            }
        }
        
        if ($copiedFiles.Count -eq 0) {
            Write-Error "No source files were copied! Package cannot be created."
            return
        }
        
        # Create proper NinjaTrader 8 manifest with assembly reference
        $manifestContent = @"
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest SchemaVersion="1.0" xmlns="http://www.ninjatrader.com/NinjaScript">
  <Assemblies>
    <Assembly>
      <FullName>FKS, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null</FullName>
      <ExportedTypes>
        <ExportedType>NinjaTrader.NinjaScript.AddOns.FKS_Regime</ExportedType>
        <ExportedType>NinjaTrader.NinjaScript.Indicators.FKS_AI</ExportedType>
        <ExportedType>NinjaTrader.NinjaScript.Indicators.FKS_Test</ExportedType>
        <ExportedType>NinjaTrader.NinjaScript.Strategies.FKS_Strategy</ExportedType>
      </ExportedTypes>
    </Assembly>
  </Assemblies>
  <NinjaScriptCollection>
    <AddOns>
      <AddOn>
        <TypeName>FKS_Regime</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.AddOns.FKS_Regime</FullTypeName>
      </AddOn>
    </AddOns>
    <Indicators>
      <Indicator>
        <TypeName>FKS_AI</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Indicators.FKS_AI</FullTypeName>
      </Indicator>
      <Indicator>
        <TypeName>FKS_Test</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Indicators.FKS_Test</FullTypeName>
      </Indicator>
    </Indicators>
    <Strategies>
      <Strategy>
        <TypeName>FKS_Strategy</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Strategies.FKS_Strategy</FullTypeName>
      </Strategy>
    </Strategies>
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>FKS.dll</n>
      <Path>bin</Path>
    </File>
    <File>
      <n>AddOns\FKS_Regime.cs</n>
      <Path>bin\Custom\AddOns</Path>
    </File>
    <File>
      <n>Indicators\FKS_AI.cs</n>
      <Path>bin\Custom\Indicators</Path>
    </File>
    <File>
      <n>Indicators\FKS_Test.cs</n>
      <Path>bin\Custom\Indicators</Path>
    </File>
    <File>
      <n>Strategies\FKS_Strategy.cs</n>
      <Path>bin\Custom\Strategies</Path>
    </File>
    <File>
      <n>GlobalUsings.cs</n>
      <Path>bin\Custom</Path>
    </File>
  </Files>
</NinjaScriptManifest>
"@
        
        # Write manifest to package
        $manifestContent | Out-File -FilePath "$packageDir/manifest.xml" -Encoding UTF8
        Write-Info "Created NinjaTrader 8 manifest.xml with assembly reference"
        
        # Create ZIP archive with proper naming
        $zipName = "packages/FKS_TradingSystem_v1.0.0.zip"
        if (Test-Path $zipName) {
            Remove-Item $zipName -Force
        }
        
        # Compress with PowerShell (compatible method)
        Compress-Archive -Path "$packageDir/*" -DestinationPath $zipName -Force
        
        # Cleanup temp directory
        Remove-Item $packageDir -Recurse -Force
        
        Write-Success "Package created: $zipName"
        
        # Verify and show package contents
        if (Test-Path $zipName) {
            $zipSize = (Get-Item $zipName).Length
            Write-Success "Package size: $zipSize bytes"
            
            # Show ZIP contents
            Write-Info "Package contents:"
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $zipName))
            $zip.Entries | Sort-Object FullName | ForEach-Object {
                $sizeKB = [math]::Round($_.Length / 1024, 1)
                Write-Host "  $($_.FullName) ($sizeKB KB)" -ForegroundColor Gray
            }
            $zip.Dispose()
            
            # Verify DLL is included
            $dllIncluded = $false
            $zip2 = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $zipName))
            foreach ($entry in $zip2.Entries) {
                # Check for DLL with either forward or backward slashes
                if ($entry.FullName -eq "bin/FKS.dll" -or $entry.FullName -eq "bin\FKS.dll") {
                    $dllIncluded = $true
                    $dllSizeKB = [math]::Round($entry.Length / 1024, 1)
                    Write-Success "FKS.dll included in package ($dllSizeKB KB)"
                    break
                }
            }
            $zip2.Dispose()
            
            if (-not $dllIncluded) {
                Write-Error "FKS.dll NOT found in package!"
            }
        }
        
    } catch {
        Write-Error "Package creation failed: $($_.Exception.Message)"
        Write-Error "Stack trace: $($_.ScriptStackTrace)"
        exit 1
    }
}

function Show-Summary {
    Write-Info "=== BUILD SUMMARY ==="
    
    if (Test-Path "bin/$Configuration/FKS.dll") {
        $dll = Get-Item "bin/$Configuration/FKS.dll"
        Write-Success "FKS.dll: $($dll.Length) bytes, Modified: $($dll.LastWriteTime)"
    }
    
    if (Test-Path "packages/FKS_TradingSystem_v1.0.0.zip") {
        $zip = Get-Item "packages/FKS_TradingSystem_v1.0.0.zip"
        Write-Success "NT8 Package: $($zip.Length) bytes"
    }
    
    Write-Info "Build completed successfully!"
    Write-Info "Next steps:"
    Write-Info "1. Import packages/FKS_TradingSystem_v1.0.0.zip into NinjaTrader 8"
    Write-Info "2. Restart NinjaTrader 8"
    Write-Info "3. Check Tools -> Import -> NinjaScript Add-On"
}

# Main execution
try {
    Write-Info "=== FKS NinjaTrader 8 Build Script ==="
    Write-Info "Configuration: $Configuration"
    
    Test-Prerequisites
    
    if ($Clean) {
        Invoke-Clean
    }
    
    Invoke-Restore
    Invoke-Build
    
    if ($Package) {
        New-NT8Package
    }
    
    Show-Summary
    
} catch {
    Write-Error "Build script failed: $($_.Exception.Message)"
    exit 1
}
