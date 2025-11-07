#!/bin/bash

# Create an absolutely empty package to test the import mechanism itself
echo "Creating empty test package to isolate import issue..."

# Create a temporary directory
mkdir -p /tmp/fks_empty_test
cd /tmp/fks_empty_test

# Create the proper NinjaTrader package structure with NO content
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Create minimal manifest.xml with NO exports
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
    <n>Empty Test Package</n>
    <Version>1.0.0</Version>
    <Vendor>Test</Vendor>
    <Description>Empty package to test import mechanism</Description>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create minimal Info.xml
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>Empty Test Package</n>
  <Version>1.0.0</Version>
  <Vendor>Test</Vendor>
  <Description>Empty package to test import mechanism</Description>
</NinjaScriptInfo>
EOF

echo "Created empty package files"

cd package
zip -r Empty_Test_Package.zip .

echo "✅ Empty test package created"
echo "Package contains:"
echo "  - manifest.xml (no exports)"
echo "  - Info.xml"
echo "  - Empty bin/Custom/ folder structure"
echo "  - NO code files"
echo "  - NO DLLs"

mv Empty_Test_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Empty_Test_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Empty_Test_Package.zip

echo ""
echo "✅ If this empty package also fails, the issue is with:"
echo "  - Package structure"
echo "  - XML format"
echo "  - NinjaTrader installation/configuration"
echo "  - File permissions or Windows security"
