#!/bin/bash

# Create a test package that might be more Windows-compatible
echo "Creating Windows-compatible test package..."

# Create a temporary directory
mkdir -p /tmp/fks_windows_test
cd /tmp/fks_windows_test

# Create a minimal C# library optimized for Windows compatibility
cat > TestLib.cs << 'EOF'
using System;

namespace TestNamespace
{
    public static class TestUtility
    {
        public static string GetMessage()
        {
            return "Hello from Windows-compatible test library";
        }
        
        public static string GetFrameworkVersion()
        {
            return "NET Framework 4.8";
        }
    }
}
EOF

# Create project file with explicit Windows compatibility settings
cat > TestLib.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <OutputType>Library</OutputType>
    <AssemblyName>TestLib</AssemblyName>
    <UseWindowsForms>false</UseWindowsForms>
    <UseWPF>false</UseWPF>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <Deterministic>false</Deterministic>
    <DebugType>portable</DebugType>
    <Optimize>true</Optimize>
    <RuntimeIdentifier>win-x86</RuntimeIdentifier>
    <SelfContained>false</SelfContained>
  </PropertyGroup>
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|AnyCPU'">
    <DefineConstants>TRACE</DefineConstants>
    <Optimize>true</Optimize>
  </PropertyGroup>
  
  <ItemGroup>
    <Reference Include="System" />
    <Reference Include="System.Core" />
  </ItemGroup>
</Project>
EOF

# Build with specific settings for Windows compatibility
echo "Building Windows-compatible test library..."
dotnet restore --runtime win-x86
dotnet build -c Release --runtime win-x86 --no-self-contained

# Find the built DLL
DLL_PATH=""
if [ -f "bin/Release/net48/win-x86/TestLib.dll" ]; then
    DLL_PATH="bin/Release/net48/win-x86/TestLib.dll"
elif [ -f "bin/Release/net48/TestLib.dll" ]; then
    DLL_PATH="bin/Release/net48/TestLib.dll"
fi

if [ -n "$DLL_PATH" ] && [ -f "$DLL_PATH" ]; then
    echo "✅ Windows-compatible test library built successfully"
    echo "Size: $(ls -lh $DLL_PATH | awk '{print $5}')"
    echo "File type: $(file $DLL_PATH)"
    
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
  <n>TestLib Windows Compatible</n>
  <Version>1.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Windows-compatible test library for NT8 import testing</Description>
</NinjaScriptInfo>
EOF
    
    cd package
    zip -r TestLib_Windows_Package.zip .
    
    echo "✅ Windows-compatible test package created"
    echo "Package structure:"
    echo "  TestLib.dll          <- DLL at ROOT (Windows-compatible)"
    echo "  manifest.xml         <- Manifest at ROOT"
    echo "  Info.xml            <- Info at ROOT"
    echo "  bin/TestLib.dll     <- DLL in bin folder"
    echo "  bin/Custom/         <- Empty folders for source files"
    
    mv TestLib_Windows_Package.zip /home/ordan/fks/
    echo "Package saved to: /home/ordan/fks/TestLib_Windows_Package.zip"
    
    # Show file verification
    echo ""
    echo "Package contents verification:"
    cd /home/ordan/fks
    unzip -l TestLib_Windows_Package.zip
    
else
    echo "❌ Failed to build Windows-compatible test library"
    echo "Searched for DLL in:"
    echo "  bin/Release/net48/win-x86/TestLib.dll"
    echo "  bin/Release/net48/TestLib.dll"
    echo ""
    echo "Available files:"
    find . -name "*.dll" -o -name "*.exe" 2>/dev/null || echo "  No DLL files found"
fi
