#!/bin/bash

# Create a package with BOTH DLL and source code using OLD manifest format
echo "Creating package with DLL + source code using OLD manifest format..."

# Create a temporary directory
mkdir -p /tmp/fks_old_with_dll
cd /tmp/fks_old_with_dll

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

# Copy the DLL to ROOT level (required for NT8 import) AND to bin folder
echo "Adding FKS.dll to package..."
if [ -f "/home/ordan/fks/bin/Release/FKS.dll" ]; then
    # DLL at ROOT level (required for NT8)
    cp /home/ordan/fks/bin/Release/FKS.dll package/FKS.dll
    # DLL in bin folder (standard location)
    cp /home/ordan/fks/bin/Release/FKS.dll package/bin/FKS.dll
    echo "✅ Added FKS.dll to package (root + bin)"
else
    echo "❌ FKS.dll not found, building first..."
    cd /home/ordan/fks/src/ninja/src
    dotnet build -c Release
    if [ -f "/home/ordan/fks/bin/Release/FKS.dll" ]; then
        cd /tmp/fks_old_with_dll
        cp /home/ordan/fks/bin/Release/FKS.dll package/FKS.dll
        cp /home/ordan/fks/bin/Release/FKS.dll package/bin/FKS.dll
        echo "✅ Built and added FKS.dll to package"
    else
        echo "❌ Failed to build FKS.dll"
        exit 1
    fi
fi

# Create manifest using OLD SourceCodeCollection format WITH DLL reference
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
    <Files>
      <File>
        <n>FKS.dll</n>
        <Path>bin</Path>
      </File>
    </Files>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create Info.xml
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>FKS Trading Systems (DLL + Source)</n>
  <Version>1.0.0</Version>
  <Vendor>FKS Trading</Vendor>
  <Description>FKS Trading Systems with DLL and source code using old manifest format</Description>
</NinjaScriptInfo>
EOF

echo "Created OLD format package files with DLL + source"

cd package
zip -r FKS_OldFormat_WithDLL_Package.zip .

echo "✅ FKS Old Format + DLL package created"
echo "Package contains:"
echo "  - FKS.dll at ROOT level (required for NT8)"
echo "  - FKS.dll in bin/ folder"
echo "  - All FKS source code in bin/Custom/ folders"
echo "  - OLD SourceCodeCollection manifest format"
echo "  - <Files> section referencing the DLL"

mv FKS_OldFormat_WithDLL_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/FKS_OldFormat_WithDLL_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l FKS_OldFormat_WithDLL_Package.zip | head -20

echo ""
echo "✅ This package includes BOTH:"
echo "  - Custom FKS.dll (with AddOn classes)"
echo "  - Source code (for NinjaScript components)" 
echo "  - OLD manifest format with SourceCodeCollection"
echo "  - DLL reference in <Files> section"
