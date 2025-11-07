#!/bin/bash

# Create a corrected FKS package with AdditionalReferences.txt
echo "Creating FKS package with proper AdditionalReferences.txt..."

# Create a temporary directory
mkdir -p /tmp/fks_with_references
cd /tmp/fks_with_references

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
        cd /tmp/fks_with_references
        cp /home/ordan/fks/bin/Release/FKS.dll package/FKS.dll
        cp /home/ordan/fks/bin/Release/FKS.dll package/bin/FKS.dll
        echo "✅ Built and added FKS.dll to package"
    else
        echo "❌ Failed to build FKS.dll"
        exit 1
    fi
fi

# CREATE THE CRITICAL AdditionalReferences.txt FILE
echo "Creating AdditionalReferences.txt..."
cat > package/AdditionalReferences.txt << 'EOF'
FKS
EOF

echo "✅ Created AdditionalReferences.txt with FKS reference"

# Create proper manifest.xml using current format (since old format also failed)
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
    <n>FKS Trading Systems (With References)</n>
    <Version>1.0.0</Version>
    <Vendor>FKS Trading</Vendor>
    <Description>FKS Trading Systems with proper AdditionalReferences.txt</Description>
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>FKS.dll</n>
      <Path>bin</Path>
    </File>
  </Files>
</NinjaScriptManifest>
EOF

# Create Info.xml
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>FKS Trading Systems (With References)</n>
  <Version>1.0.0</Version>
  <Vendor>FKS Trading</Vendor>
  <Description>FKS Trading Systems with proper AdditionalReferences.txt file</Description>
</NinjaScriptInfo>
EOF

echo "Created package files with AdditionalReferences.txt"

cd package
zip -r FKS_WithReferences_Package.zip .

echo "✅ FKS package with AdditionalReferences.txt created"
echo "Package contains:"
echo "  - FKS.dll at ROOT level (required for NT8)"
echo "  - AdditionalReferences.txt at ROOT level (CRITICAL!)"
echo "  - FKS.dll in bin/ folder"
echo "  - All FKS source code in bin/Custom/ folders"
echo "  - Proper manifest.xml and Info.xml"

mv FKS_WithReferences_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/FKS_WithReferences_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l FKS_WithReferences_Package.zip | head -15

echo ""
echo "🎯 KEY DIFFERENCE: This package includes AdditionalReferences.txt"
echo "✅ According to NinjaTrader forum, this is REQUIRED for custom DLLs"
echo "✅ This was the missing piece causing import failures!"
