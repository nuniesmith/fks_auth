#!/bin/bash

echo "Creating FKS package with proper NinjaScript structure..."

# Create package structure without DLL in root
BUILD_DIR="/tmp/fks_proper_structure"
mkdir -p "$BUILD_DIR/bin/Custom"/{Indicators,Strategies,AddOns}

cd /home/ordan/fks/src/ninja/src

echo "Copying source files only..."

# Copy source files
cp Indicators/FKS_Dashboard.cs "$BUILD_DIR/bin/Custom/Indicators/"
cp Strategies/FKS_Strategy.cs "$BUILD_DIR/bin/Custom/Strategies/"
cp AddOns/*.cs "$BUILD_DIR/bin/Custom/AddOns/"

# Create manifest that only exports source code, no precompiled assemblies
cat > "$BUILD_DIR/manifest.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
    <SourceCodeCollection>
      <Indicators>
        <NinjaScriptInfo>
          <FileName>FKS_Dashboard.cs</FileName>
          <Name>FKS_Dashboard</Name>
          <DisplayName>FKS Info</DisplayName>
        </NinjaScriptInfo>
      </Indicators>
      <Strategies>
        <NinjaScriptInfo>
          <FileName>FKS_Strategy.cs</FileName>
          <Name>FKS_Strategy</Name>
          <DisplayName>FKS Strategy</DisplayName>
        </NinjaScriptInfo>
      </Strategies>
    </SourceCodeCollection>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create Info.xml
cat > "$BUILD_DIR/Info.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <Name>FKS Trading Systems</Name>
  <Version>1.0.0</Version>
  <Vendor>FKS Trading</Vendor>
  <Description>FKS Trading Systems - Source Code Only</Description>
</NinjaScriptInfo>
EOF

cd "$BUILD_DIR"
zip -r FKS_SourceCode_v1.0.0.zip .

mv FKS_SourceCode_v1.0.0.zip /home/ordan/fks/

echo "✅ Source-code-only package created: FKS_SourceCode_v1.0.0.zip"
echo "This package contains NO precompiled DLL"
echo "NinjaTrader will compile everything itself"

ls -la /home/ordan/fks/FKS_SourceCode_v1.0.0.zip
