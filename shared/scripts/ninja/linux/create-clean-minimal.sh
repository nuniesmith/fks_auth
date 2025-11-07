#!/bin/bash

echo "Creating radically simplified FKS package..."

# Create a minimal source tree with only essential classes
mkdir -p /tmp/fks_minimal/{AddOns,Indicators}

# Create ultra-minimal core classes (internal only)
cat > /tmp/fks_minimal/AddOns/FKS_Core_Minimal.cs << 'EOF'
using System;
using NinjaTrader.NinjaScript;

namespace NinjaTrader.NinjaScript.AddOns
{
    internal static class FKS_Minimal
    {
        internal static string GetVersion() => "1.0.0";
    }
}
EOF

# Create a standalone indicator with no external dependencies
cat > /tmp/fks_minimal/Indicators/FKS_Simple.cs << 'EOF'
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using NinjaTrader.NinjaScript;
using NinjaTrader.NinjaScript.Indicators;

namespace NinjaTrader.NinjaScript.Indicators
{
    public class FKS_Simple : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = "Simple FKS test indicator";
                Name = "FKS_Simple";
                Calculate = Calculate.OnBarClose;
            }
        }

        protected override void OnBarUpdate()
        {
            // Do nothing - just a test
        }
    }
}
EOF

# Create project file
cat > /tmp/fks_minimal/FKS_Minimal.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <OutputType>Library</OutputType>
    <AssemblyName>FKS_Minimal</AssemblyName>
    <RootNamespace>NinjaTrader.NinjaScript</RootNamespace>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
  </PropertyGroup>

  <ItemGroup>
    <Reference Include="NinjaTrader.Core">
      <HintPath>/home/ordan/fks/src/ninja/references/NinjaTrader.Core.dll</HintPath>
      <Private>false</Private>
    </Reference>
    <Reference Include="NinjaTrader.Custom">
      <HintPath>/home/ordan/fks/src/ninja/references/NinjaTrader.Custom.dll</HintPath>
      <Private>false</Private>
    </Reference>
  </ItemGroup>
</Project>
EOF

cd /tmp/fks_minimal

echo "Building minimal project..."
dotnet build -c Release

if [ -f "bin/Release/net48/FKS_Minimal.dll" ]; then
    echo "✅ Minimal DLL built successfully"
    
    # Create package
    mkdir -p package/bin/Custom/{Indicators,AddOns}
    cp bin/Release/net48/FKS_Minimal.dll package/bin/
    cp Indicators/FKS_Simple.cs package/bin/Custom/Indicators/
    cp AddOns/FKS_Core_Minimal.cs package/bin/Custom/AddOns/
    
    # Create manifest
    cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
    <SourceCodeCollection>
      <Indicators>
        <NinjaScriptInfo>
          <FileName>FKS_Simple.cs</FileName>
          <Name>FKS_Simple</Name>
          <DisplayName>FKS Simple</DisplayName>
        </NinjaScriptInfo>
      </Indicators>
    </SourceCodeCollection>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF
    
    cd package
    zip -r FKS_Minimal_Clean.zip .
    mv FKS_Minimal_Clean.zip /home/ordan/fks/
    
    echo "✅ Clean minimal package created: /home/ordan/fks/FKS_Minimal_Clean.zip"
    echo "This contains only a simple indicator and minimal internal utilities"
else
    echo "❌ Failed to build minimal project"
fi
