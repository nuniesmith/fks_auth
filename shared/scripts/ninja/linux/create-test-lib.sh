#!/bin/bash

# Create a completely isolated test with PROPER NinjaTrader package structure:
# - DLL at root level
# - manifest.xml at root level  
# - Info.xml at root level
# - Source files in bin/Custom/ folder structure

echo "Creating ultra-minimal test package with proper NT8 structure..."

# Create a temporary directory
mkdir -p /tmp/fks_test
cd /tmp/fks_test

# Create a minimal C# library with no NinjaScript dependencies
cat > TestLib.cs << 'EOF'
using System;

namespace TestNamespace
{
    public static class TestUtility
    {
        public static string GetMessage()
        {
            return "Hello from test library";
        }
    }
}
EOF

# Create project file for .NET Framework 4.8 (same as NT8)
cat > TestLib.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <OutputType>Library</OutputType>
    <AssemblyName>TestLib</AssemblyName>
  </PropertyGroup>
</Project>
EOF

# Build the test library
echo "Building test library..."
dotnet build -c Release

# Check the correct .NET 4.8 output path
DLL_PATH=""
if [ -f "bin/Release/net48/TestLib.dll" ]; then
    DLL_PATH="bin/Release/net48/TestLib.dll"
elif [ -f "bin/Release/TestLib.dll" ]; then
    DLL_PATH="bin/Release/TestLib.dll"
fi

if [ -n "$DLL_PATH" ] && [ -f "$DLL_PATH" ]; then
    echo "✅ Test library built successfully"
    echo "Size: $(ls -lh $DLL_PATH | awk '{print $5}')"
    
    # Create proper NinjaTrader package structure
    mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}
    
    # Copy DLL to ROOT level (required for NT8 import)
    cp "$DLL_PATH" package/TestLib.dll
    
    # Also copy to bin folder (standard location)
    cp "$DLL_PATH" package/bin/TestLib.dll
    
    # Create proper manifest.xml at ROOT level
    cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>TestLib.dll</n>
      <Path>bin</Path>
    </File>
  </Files>
</NinjaScriptManifest>
EOF

    # Create proper Info.xml at ROOT level
    cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <Name>TestLib Package</Name>
  <Version>1.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Minimal test library for NT8 import testing</Description>
</NinjaScriptInfo>
EOF
    
    cd package
    zip -r TestLib_Package.zip .
    
    echo "✅ Test package created: TestLib_Package.zip"
    echo "Package structure:"
    echo "  TestLib.dll          <- DLL at ROOT (required for NT8)"
    echo "  manifest.xml         <- Manifest at ROOT"
    echo "  Info.xml            <- Info at ROOT"
    echo "  bin/TestLib.dll     <- DLL in bin folder"
    echo "  bin/Custom/         <- Empty folders for source files"
    echo ""
    echo "This follows EXACT NinjaTrader package requirements:"
    echo "- DLL at root level for import"
    echo "- Proper manifest and info files"
    echo "- Standard folder structure"
    
    mv TestLib_Package.zip /home/ordan/fks/
    echo "Package saved to: /home/ordan/fks/TestLib_Package.zip"
    
    # Show file verification
    echo ""
    echo "Package contents verification:"
    cd /home/ordan/fks
    unzip -l TestLib_Package.zip
    
else
    echo "❌ Failed to build test library"
    echo "Searched for DLL in:"
    echo "  bin/Release/net48/TestLib.dll"
    echo "  bin/Release/TestLib.dll"
    echo ""
    echo "Available files:"
    find . -name "*.dll" -o -name "*.exe" 2>/dev/null || echo "  No DLL files found"
fi
