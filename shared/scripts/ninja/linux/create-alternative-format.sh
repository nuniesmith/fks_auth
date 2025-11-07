#!/bin/bash

# Create test package with alternative XML structure
echo "Creating test package with alternative XML format..."

# Create a temporary directory
mkdir -p /tmp/fks_alt_format
cd /tmp/fks_alt_format

# Create the proper NinjaTrader package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Create alternative manifest.xml format (closer to what I've seen in commercial packages)
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <ExportedTypes />
  <NinjaScriptCollection>
    <Name>Alternative Format Test</Name>
    <Version>1.0.0.0</Version>
    <Vendor>Test Vendor</Vendor>
    <Description>Testing alternative XML format</Description>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create alternative Info.xml format
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Name>Alternative Format Test</Name>
  <Version>1.0.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Testing alternative XML format for NinjaTrader import</Description>
</NinjaScriptInfo>
EOF

echo "Created alternative format package files"

cd package
zip -r Alternative_Format_Package.zip .

echo "✅ Alternative format test package created"
echo "Package contains alternative XML structure with:"
echo "  - XML schema namespaces"
echo "  - <Name> instead of <n>"
echo "  - Version format: 1.0.0.0"
echo "  - Self-closing <ExportedTypes />"

mv Alternative_Format_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Alternative_Format_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Alternative_Format_Package.zip

echo ""
echo "✅ This tests different XML formatting approaches"
