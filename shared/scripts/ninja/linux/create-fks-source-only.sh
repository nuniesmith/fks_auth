#!/bin/bash

# Create a source-code-only package for FKS that imports as source
# This avoids the cross-platform DLL compatibility issue entirely

echo "Creating FKS source-code-only package..."

# Create a temporary directory
mkdir -p /tmp/fks_source_only
cd /tmp/fks_source_only

# Create the proper NinjaTrader package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Copy all source files from the FKS project
echo "Copying source files..."

# Copy indicators
cp /home/ordan/fks/src/ninja/src/Indicators/*.cs package/bin/Custom/Indicators/
echo "Copied $(ls /home/ordan/fks/src/ninja/src/Indicators/*.cs | wc -l) indicator files"

# Copy strategies  
cp /home/ordan/fks/src/ninja/src/Strategies/*.cs package/bin/Custom/Strategies/
echo "Copied $(ls /home/ordan/fks/src/ninja/src/Strategies/*.cs | wc -l) strategy files"

# Copy AddOns
cp /home/ordan/fks/src/ninja/src/AddOns/*.cs package/bin/Custom/AddOns/
echo "Copied $(ls /home/ordan/fks/src/ninja/src/AddOns/*.cs | wc -l) addon files"

# Copy GlobalUsings if it exists
if [ -f "/home/ordan/fks/src/ninja/src/GlobalUsings.cs" ]; then
    cp /home/ordan/fks/src/ninja/src/GlobalUsings.cs package/bin/Custom/
    echo "Copied GlobalUsings.cs"
fi

# Create proper manifest.xml at ROOT level - NO DLL references
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
    <Indicator>FKS_Dashboard</Indicator>
    <Indicator>FKS_AO</Indicator>
    <Indicator>FKS_AI</Indicator>
    <Indicator>FKS_PythonBridge</Indicator>
    <Strategy>FKS_Strategy</Strategy>
  </ExportedTypes>
  <NinjaScriptCollection>
    <n>FKS Trading Systems (Source)</n>
    <Version>1.0.0</Version>
    <Vendor>FKS Team</Vendor>
    <Description>FKS Trading Systems - Source Code Import</Description>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create proper Info.xml at ROOT level
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>FKS Trading Systems Source</n>
  <Version>1.0.0</Version>
  <Vendor>FKS Team</Vendor>
  <Description>FKS Trading Systems imported as source code to avoid cross-platform DLL issues</Description>
</NinjaScriptInfo>
EOF

echo "Created manifest and info files"

cd package
zip -r FKS_SourceOnly_Package.zip .

echo "✅ FKS source-only package created"
echo "Package structure (NO DLL - pure source):"
echo "  manifest.xml         <- Manifest at ROOT (no DLL references)"
echo "  Info.xml            <- Info at ROOT"
echo "  bin/Custom/Indicators/   <- All indicator source files"
echo "  bin/Custom/Strategies/   <- All strategy source files"  
echo "  bin/Custom/AddOns/       <- All addon source files"

mv FKS_SourceOnly_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/FKS_SourceOnly_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l FKS_SourceOnly_Package.zip | head -20

echo ""
echo "✅ This package contains ONLY source code, no DLLs"
echo "✅ Should import successfully and compile on Windows"
echo "✅ Avoids cross-platform compatibility issues entirely"
