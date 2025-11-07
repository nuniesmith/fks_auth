#!/bin/bash

# Create FKS package using the OLD SourceCodeCollection manifest format
echo "Creating FKS package with OLD SourceCodeCollection format..."

# Create a temporary directory
mkdir -p /tmp/fks_old_full
cd /tmp/fks_old_full

# Create the proper NinjaTrader package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

echo "Copying FKS source files..."

# Copy all FKS source files
cp /home/ordan/fks/src/ninja/src/Indicators/*.cs package/bin/Custom/Indicators/
cp /home/ordan/fks/src/ninja/src/Strategies/*.cs package/bin/Custom/Strategies/
cp /home/ordan/fks/src/ninja/src/AddOns/*.cs package/bin/Custom/AddOns/

# Copy GlobalUsings if it exists
if [ -f "/home/ordan/fks/src/ninja/src/GlobalUsings.cs" ]; then
    cp /home/ordan/fks/src/ninja/src/GlobalUsings.cs package/bin/Custom/
    echo "Copied GlobalUsings.cs"
fi

echo "Copied $(ls package/bin/Custom/Indicators/*.cs | wc -l) indicator files"
echo "Copied $(ls package/bin/Custom/Strategies/*.cs | wc -l) strategy files"
echo "Copied $(ls package/bin/Custom/AddOns/*.cs | wc -l) addon files"

# Create manifest using the OLD SourceCodeCollection format
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
    <SourceCodeCollection>
      <Indicators>
        <NinjaScriptInfo>
          <FileName>FKS_Dashboard.cs</FileName>
          <n>FKS_Dashboard</n>
          <DisplayName>FKS Info Dashboard</DisplayName>
        </NinjaScriptInfo>
        <NinjaScriptInfo>
          <FileName>FKS_AO.cs</FileName>
          <n>FKS_AO</n>
          <DisplayName>FKS Awesome Oscillator</DisplayName>
        </NinjaScriptInfo>
        <NinjaScriptInfo>
          <FileName>FKS_AI.cs</FileName>
          <n>FKS_AI</n>
          <DisplayName>FKS AI Indicator</DisplayName>
        </NinjaScriptInfo>
        <NinjaScriptInfo>
          <FileName>FKS_PythonBridge.cs</FileName>
          <n>FKS_PythonBridge</n>
          <DisplayName>FKS Python Bridge</DisplayName>
        </NinjaScriptInfo>
      </Indicators>
      <Strategies>
        <NinjaScriptInfo>
          <FileName>FKS_Strategy.cs</FileName>
          <n>FKS_Strategy</n>
          <DisplayName>FKS Trading Strategy</DisplayName>
        </NinjaScriptInfo>
      </Strategies>
    </SourceCodeCollection>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create Info.xml with the old format
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>FKS Trading Systems (Old Format)</n>
  <Version>1.0.0</Version>
  <Vendor>FKS Trading</Vendor>
  <Description>FKS Trading Systems using SourceCodeCollection manifest format</Description>
</NinjaScriptInfo>
EOF

echo "Created OLD format package files with SourceCodeCollection"

cd package
zip -r FKS_OldFormat_Package.zip .

echo "✅ FKS Old Format package created with SourceCodeCollection structure"
echo "Package contains:"
echo "  - manifest.xml with <SourceCodeCollection> format (OLD STYLE)"
echo "  - All FKS indicators, strategies, and addons as source"
echo "  - Detailed <NinjaScriptInfo> entries for each component"
echo "  - Info.xml with <n> tags"

mv FKS_OldFormat_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/FKS_OldFormat_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l FKS_OldFormat_Package.zip | head -15

echo ""
echo "✅ This uses the OLD SourceCodeCollection manifest format!"
echo "✅ Based on older scripts found in the workspace"
echo "✅ This format may work better with NinjaTrader 8 import"
