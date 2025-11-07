#!/bin/bash

# Create a minimal test package with AdditionalReferences.txt
echo "Creating minimal test with AdditionalReferences.txt..."

# Create a temporary directory
mkdir -p /tmp/fks_minimal_with_refs
cd /tmp/fks_minimal_with_refs

# First, create and build a minimal test DLL
cat > TestUtils.cs << 'EOF'
using System;

namespace FKS.TestUtils
{
    public static class SimpleUtility
    {
        public static string GetMessage()
        {
            return "Hello from test utility DLL with AdditionalReferences";
        }
        
        public static double Calculate(double value)
        {
            return value * 2.0;
        }
    }
}
EOF

# Create project file for the test DLL
cat > TestUtils.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <OutputType>Library</OutputType>
    <AssemblyName>TestUtils</AssemblyName>
  </PropertyGroup>
</Project>
EOF

echo "Building test DLL..."
dotnet build -c Release

# Create package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Copy the test DLL to package
if [ -f "bin/Release/net48/TestUtils.dll" ]; then
    # DLL at ROOT level (required for NT8)
    cp bin/Release/net48/TestUtils.dll package/TestUtils.dll
    # DLL in bin folder (standard location)  
    cp bin/Release/net48/TestUtils.dll package/bin/TestUtils.dll
    echo "✅ Added TestUtils.dll to package"
else
    echo "❌ Failed to build TestUtils.dll"
    exit 1
fi

# CREATE THE CRITICAL AdditionalReferences.txt FILE
echo "Creating AdditionalReferences.txt..."
cat > package/AdditionalReferences.txt << 'EOF'
TestUtils
EOF

echo "✅ Created AdditionalReferences.txt with TestUtils reference"

# Create a simple test indicator that uses the DLL
cat > package/bin/Custom/Indicators/TestWithReferences.cs << 'EOF'
#region Using declarations
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Windows.Media;
using NinjaTrader.NinjaScript;
using NinjaTrader.NinjaScript.Indicators;
using FKS.TestUtils;
#endregion

namespace NinjaTrader.NinjaScript.Indicators
{
    public class TestWithReferences : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"Test indicator with AdditionalReferences.txt";
                Name = "TestWithReferences";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                DisplayInDataBox = true;
                DrawOnPricePanel = false;
                DrawHorizontalGridLines = true;
                DrawVerticalGridLines = true;
                PaintPriceMarkers = true;
                ScaleJustification = NinjaTrader.Gui.Chart.ScaleJustification.Right;
                IsSuspendedWhileInactive = true;
                
                AddPlot(Brushes.Purple, "TestPlot");
            }
        }

        protected override void OnBarUpdate()
        {
            // Use the utility from our DLL
            Value[0] = SimpleUtility.Calculate(Close[0]);
        }
    }
}

#region NinjaScript generated code. Neither change nor remove.

namespace NinjaTrader.NinjaScript.Indicators
{
    public partial class Indicator : NinjaTrader.Gui.NinjaScript.IndicatorRenderBase
    {
        private TestWithReferences[] cacheTestWithReferences;
        public TestWithReferences TestWithReferences()
        {
            return TestWithReferences(Input);
        }

        public TestWithReferences TestWithReferences(ISeries<double> input)
        {
            if (cacheTestWithReferences != null)
                for (int idx = 0; idx < cacheTestWithReferences.Length; idx++)
                    if (cacheTestWithReferences[idx] != null && cacheTestWithReferences[idx].EqualsInput(input))
                        return cacheTestWithReferences[idx];

            return CacheIndicator<TestWithReferences>(new TestWithReferences(), input, ref cacheTestWithReferences);
        }
    }
}

namespace NinjaTrader.NinjaScript.MarketAnalyzerColumns
{
    public partial class MarketAnalyzerColumn : MarketAnalyzerColumnBase
    {
        public Indicators.TestWithReferences TestWithReferences()
        {
            return indicator.TestWithReferences(Input);
        }

        public Indicators.TestWithReferences TestWithReferences(ISeries<double> input )
        {
            return indicator.TestWithReferences(input);
        }
    }
}

namespace NinjaTrader.NinjaScript.Strategies
{
    public partial class Strategy : NinjaTrader.Gui.NinjaScript.StrategyRenderBase
    {
        public Indicators.TestWithReferences TestWithReferences()
        {
            return indicator.TestWithReferences(Input);
        }

        public Indicators.TestWithReferences TestWithReferences(ISeries<double> input )
        {
            return indicator.TestWithReferences(input);
        }
    }
}

#endregion
EOF

# Create proper manifest.xml
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
    <Indicator>TestWithReferences</Indicator>
  </ExportedTypes>
  <NinjaScriptCollection>
    <n>Test With References</n>
    <Version>1.0.0</Version>
    <Vendor>Test Vendor</Vendor>
    <Description>Test package with AdditionalReferences.txt file</Description>
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>TestUtils.dll</n>
      <Path>bin</Path>
    </File>
  </Files>
</NinjaScriptManifest>
EOF

# Create Info.xml
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>Test With References</n>
  <Version>1.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Minimal test with AdditionalReferences.txt for DLL</Description>
</NinjaScriptInfo>
EOF

echo "Created minimal test package with AdditionalReferences.txt"

cd package
zip -r Test_WithReferences_Package.zip .

echo "✅ Minimal test package with AdditionalReferences.txt created"
echo "Package contains:"
echo "  - TestUtils.dll at ROOT level"
echo "  - AdditionalReferences.txt at ROOT level (CRITICAL!)"
echo "  - TestUtils.dll in bin/ folder"
echo "  - One indicator using the DLL"
echo "  - Standard manifest format"

mv Test_WithReferences_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Test_WithReferences_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Test_WithReferences_Package.zip

echo ""
echo "🎯 This is the TEST to prove AdditionalReferences.txt fixes the issue!"
echo "✅ If this imports successfully, we've found the solution"
