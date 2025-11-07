#!/bin/bash

# Create a source-only package (no precompiled DLL)
# This lets NinjaTrader compile everything itself with proper dependencies

echo "Creating source-only FKS package..."

BUILD_DIR="/tmp/fks_source_only"
mkdir -p "$BUILD_DIR"/{bin/Custom/Indicators,bin/Custom/Strategies,bin/Custom/AddOns}

cd /home/ordan/fks/src/ninja/src

echo "Copying source files..."

# Copy only the essential source files
cp Indicators/FKS_Dashboard.cs "$BUILD_DIR/bin/Custom/Indicators/"

# Create a minimal manifest that exports no DLLs, only source
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
    </SourceCodeCollection>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create Info.xml
cat > "$BUILD_DIR/Info.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <Name>FKS Source Only</Name>
  <Version>1.0.0</Version>
  <Vendor>FKS Trading</Vendor>
</NinjaScriptInfo>
EOF

cd "$BUILD_DIR"
zip -r FKS_SourceOnly_v1.0.0.zip .

mv FKS_SourceOnly_v1.0.0.zip /home/ordan/fks/

echo "✅ Source-only package created: FKS_SourceOnly_v1.0.0.zip"
echo "This package contains NO precompiled DLL - only source files"
echo "NinjaTrader will compile everything itself with proper dependencies"

ls -la /home/ordan/fks/FKS_SourceOnly_v1.0.0.zip
