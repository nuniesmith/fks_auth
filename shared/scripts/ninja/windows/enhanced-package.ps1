# Enhanced-NT8-Package.ps1 - Packages full FKS trading system

param(
    [string]$PackageName = "FKS_TradingSystem_Full",
    [string]$Version = "1.0.0"
)

Write-Host "📦 Creating Full FKS Trading Systems Package" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green

# Step 1: Build DLL with all components
Write-Host "`n1️⃣ Building complete DLL..." -ForegroundColor Yellow
Remove-Item "bin", "src\bin", "src\obj" -Recurse -Force -ErrorAction SilentlyContinue

$buildResult = dotnet build "src\FKS.csproj" --configuration Release --output "bin\Release" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ❌ Build failed:" -ForegroundColor Red
    Write-Host $buildResult -ForegroundColor Gray
    exit 1
}

$dllPath = "bin\Release\FKS.dll"
if (!(Test-Path $dllPath)) {
    Write-Host "   ❌ DLL not found at $dllPath" -ForegroundColor Red
    exit 1
}

$dllSize = [math]::Round((Get-Item $dllPath).Length / 1KB, 1)
Write-Host "   ✅ DLL built successfully ($dllSize KB)" -ForegroundColor Green

# Step 2: Create comprehensive package structure
Write-Host "`n2️⃣ Creating package structure..." -ForegroundColor Yellow
$packageDir = "NT8_Package_Full"
Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue

# Create all directories
$dirs = @(
    $packageDir,
    "$packageDir\bin",
    "$packageDir\bin\Custom",
    "$packageDir\bin\Custom\Indicators",
    "$packageDir\bin\Custom\Strategies", 
    "$packageDir\bin\Custom\AddOns"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Step 3: Create Info.xml
Write-Host "`n3️⃣ Creating Info.xml..." -ForegroundColor Yellow
$infoXml = '<?xml version="1.0" encoding="utf-8"?>
<NinjaTrader>
  <Export>
    <Version>8.1.2.1</Version>
  </Export>
</NinjaTrader>'

$infoXml | Out-File "$packageDir\Info.xml" -Encoding UTF8

# Step 4: Copy DLL
Write-Host "`n4️⃣ Copying DLL..." -ForegroundColor Yellow
Copy-Item $dllPath "$packageDir\bin\FKS.dll" -Force

# Step 5: Copy all source files with detailed logging
Write-Host "`n5️⃣ Copying source files..." -ForegroundColor Yellow

# Copy indicators
Write-Host "   📊 Indicators:" -ForegroundColor Cyan
$indicatorFiles = Get-ChildItem "src\Indicators\*.cs" -ErrorAction SilentlyContinue
$indicatorCount = 0
foreach ($file in $indicatorFiles) {
    Copy-Item $file.FullName "$packageDir\bin\Custom\Indicators\" -Force
    $indicatorCount++
    Write-Host "     ✅ $($file.Name)" -ForegroundColor Green
}
Write-Host "     Total indicators: $indicatorCount" -ForegroundColor Gray

# Copy strategies  
Write-Host "   📈 Strategies:" -ForegroundColor Cyan
$strategyFiles = Get-ChildItem "src\Strategies\*.cs" -ErrorAction SilentlyContinue
$strategyCount = 0
foreach ($file in $strategyFiles) {
    Copy-Item $file.FullName "$packageDir\bin\Custom\Strategies\" -Force
    $strategyCount++
    Write-Host "     ✅ $($file.Name)" -ForegroundColor Green
}
Write-Host "     Total strategies: $strategyCount" -ForegroundColor Gray

# Copy addons
Write-Host "   🔧 AddOns:" -ForegroundColor Cyan
$addonFiles = Get-ChildItem "src\AddOns\*.cs" -ErrorAction SilentlyContinue  
$addonCount = 0
foreach ($file in $addonFiles) {
    Copy-Item $file.FullName "$packageDir\bin\Custom\AddOns\" -Force
    $addonCount++
    Write-Host "     ✅ $($file.Name)" -ForegroundColor Green
}
Write-Host "     Total addons: $addonCount" -ForegroundColor Gray

# Step 6: Create comprehensive manifest.xml
Write-Host "`n6️⃣ Creating comprehensive manifest.xml..." -ForegroundColor Yellow

# Build exported types list
$exportedTypes = @()
foreach ($file in $indicatorFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $exportedTypes += "        <ExportedType>NinjaTrader.NinjaScript.Indicators.$className</ExportedType>"
}
foreach ($file in $strategyFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $exportedTypes += "        <ExportedType>NinjaTrader.NinjaScript.Strategies.$className</ExportedType>"
}
foreach ($file in $addonFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $exportedTypes += "        <ExportedType>NinjaTrader.NinjaScript.AddOns.$className</ExportedType>"
}

# Build indicator collection
$indicatorCollection = @()
foreach ($file in $indicatorFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $indicatorCollection += @"
      <Indicator>
        <TypeName>$className</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Indicators.$className</FullTypeName>
      </Indicator>
"@
}

# Build strategy collection
$strategyCollection = @()
foreach ($file in $strategyFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $strategyCollection += @"
      <Strategy>
        <TypeName>$className</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Strategies.$className</FullTypeName>
      </Strategy>
"@
}

# Build addon collection
$addonCollection = @()
foreach ($file in $addonFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $addonCollection += @"
      <AddOn>
        <TypeName>$className</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.AddOns.$className</FullTypeName>
      </AddOn>
"@
}

# Build files list
$filesList = @()
$filesList += @"
    <File>
      <n>FKS.dll</n>
      <Path>bin</Path>
    </File>
"@

foreach ($file in $indicatorFiles) {
    $filesList += @"
    <File>
      <n>Indicators\$($file.Name)</n>
      <Path>bin\Custom\Indicators</Path>
    </File>
"@
}

foreach ($file in $strategyFiles) {
    $filesList += @"
    <File>
      <n>Strategies\$($file.Name)</n>
      <Path>bin\Custom\Strategies</Path>
    </File>
"@
}

foreach ($file in $addonFiles) {
    $filesList += @"
    <File>
      <n>AddOns\$($file.Name)</n>
      <Path>bin\Custom\AddOns</Path>
    </File>
"@
}

# Create the complete manifest
$manifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest SchemaVersion="1.0" xmlns="http://www.ninjatrader.com/NinjaScript">
  <Assemblies>
    <Assembly>
      <FullName>FKS, Version=$Version.0, Culture=neutral, PublicKeyToken=null</FullName>
      <ExportedTypes>
$($exportedTypes -join "`n")
      </ExportedTypes>
    </Assembly>
  </Assemblies>
  <NinjaScriptCollection>
    <Indicators>
$($indicatorCollection -join "`n")
    </Indicators>
    <Strategies>
$($strategyCollection -join "`n")
    </Strategies>
    <AddOns>
$($addonCollection -join "`n")
    </AddOns>
  </NinjaScriptCollection>
  <Files>
$($filesList -join "`n")
  </Files>
</NinjaScriptManifest>
"@

$manifestXml | Out-File "$packageDir\manifest.xml" -Encoding UTF8

# Step 7: Show comprehensive package contents
Write-Host "`n7️⃣ Package contents summary:" -ForegroundColor Yellow
Write-Host "   📊 Indicators: $indicatorCount files" -ForegroundColor Cyan
Write-Host "   📈 Strategies: $strategyCount files" -ForegroundColor Cyan  
Write-Host "   🔧 AddOns: $addonCount files" -ForegroundColor Cyan
Write-Host "   💾 DLL: FKS.dll ($dllSize KB)" -ForegroundColor Cyan
Write-Host "   📄 Metadata: Info.xml, manifest.xml" -ForegroundColor Cyan

$totalFiles = $indicatorCount + $strategyCount + $addonCount + 3  # +3 for DLL, Info.xml, manifest.xml
Write-Host "   📦 Total files in package: $totalFiles" -ForegroundColor Gray

# Step 8: Create ZIP package
Write-Host "`n8️⃣ Creating ZIP package..." -ForegroundColor Yellow
$zipPath = "${PackageName}_v${Version}.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($packageDir, $zipPath)

$zipSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
Write-Host "   ✅ Package created: $zipPath ($zipSize KB)" -ForegroundColor Green

# Step 9: Verify ZIP contents
Write-Host "`n9️⃣ Verifying ZIP structure..." -ForegroundColor Yellow
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
$zipEntryCount = $zip.Entries.Count
Write-Host "   📦 ZIP contains $zipEntryCount entries" -ForegroundColor Gray

# Show key files
foreach ($entry in $zip.Entries | Where-Object { $_.Name -match '\.(xml|dll|cs)$' } | Sort-Object FullName) {
    $entrySize = [math]::Round($entry.Length / 1KB, 1)
    Write-Host "   📄 $($entry.FullName) ($entrySize KB)" -ForegroundColor Gray
}
$zip.Dispose()

# Cleanup temp directory
Remove-Item $packageDir -Recurse -Force

Write-Host "`n🎉 FULL PACKAGE CREATED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host "Package: $zipPath" -ForegroundColor Yellow
Write-Host "Size: $zipSize KB" -ForegroundColor Yellow
Write-Host "Components: $indicatorCount indicators, $strategyCount strategies, $addonCount addons" -ForegroundColor Yellow

Write-Host "`n📋 Import Instructions:" -ForegroundColor Cyan
Write-Host "1. ⚠️  CLOSE NinjaTrader 8 completely first!" -ForegroundColor Red
Write-Host "2. Open NinjaTrader 8" -ForegroundColor White
Write-Host "3. Tools → Import → NinjaScript Add-On" -ForegroundColor White
Write-Host "4. Select: $zipPath" -ForegroundColor White
Write-Host "5. Click Import" -ForegroundColor White
Write-Host "6. Restart NinjaTrader 8" -ForegroundColor White

Write-Host "`n🎯 After Import - Available Components:" -ForegroundColor Cyan
Write-Host "📊 Indicators:" -ForegroundColor Yellow
foreach ($file in $indicatorFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    Write-Host "   • $className" -ForegroundColor Gray
}
Write-Host "📈 Strategies:" -ForegroundColor Yellow  
foreach ($file in $strategyFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    Write-Host "   • $className" -ForegroundColor Gray
}
Write-Host "🔧 AddOns:" -ForegroundColor Yellow
foreach ($file in $addonFiles) {
    $className = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    Write-Host "   • $className" -ForegroundColor Gray
}
