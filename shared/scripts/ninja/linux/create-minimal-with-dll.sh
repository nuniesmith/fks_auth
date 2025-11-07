#!/bin/bash

# Create a minimal test package with BOTH a simple DLL and source code
echo "Creating minimal test with DLL + source using OLD format..."

# Create a temporary directory
mkdir -p /tmp/fks_minimal_with_dll
cd /tmp/fks_minimal_with_dll

# First, create and build a minimal test DLL with a utility class
cat > TestUtils.cs << 'EOF'
using System;

namespace FKS.TestUtils
{
    public static class SimpleUtility
    {
        public static string GetMessage()
        {
            return "Hello from test utility DLL";
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

# Create a simple test indicator that uses the DLL
cat > package/bin/Custom/Indicators/TestWithDLL.cs << 'EOF'
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
    public class TestWithDLL : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"Test indicator that uses external DLL";
                Name = "TestWithDLL";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                DisplayInDataBox = true;
                DrawOnPricePanel = false;
                DrawHorizontalGridLines = true;
                DrawVerticalGridLines = true;
                PaintPriceMarkers = true;
                ScaleJustification = NinjaTrader.Gui.Chart.ScaleJustification.Right;
                IsSuspendedWhileInactive = true;
                
                AddPlot(Brushes.Green, "TestPlot");
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
        private TestWithDLL[] cacheTestWithDLL;
        public TestWithDLL TestWithDLL()
        {
            return TestWithDLL(Input);
        }

        public TestWithDLL TestWithDLL(ISeries<double> input)
        {
            if (cacheTestWithDLL != null)
                for (int idx = 0; idx < cacheTestWithDLL.Length; idx++)
                    if (cacheTestWithDLL[idx] != null && cacheTestWithDLL[idx].EqualsInput(input))
                        return cacheTestWithDLL[idx];

            return CacheIndicator<TestWithDLL>(new TestWithDLL(), input, ref cacheTestWithDLL);
        }
    }
}

namespace NinjaTrader.NinjaScript.MarketAnalyzerColumns
{
    public partial class MarketAnalyzerColumn : MarketAnalyzerColumnBase
    {
        public Indicators.TestWithDLL TestWithDLL()
        {
            return indicator.TestWithDLL(Input);
        }

        public Indicators.TestWithDLL TestWithDLL(ISeries<double> input )
        {
            return indicator.TestWithDLL(input);
        }
    }
}

namespace NinjaTrader.NinjaScript.Strategies
{
    public partial class Strategy : NinjaTrader.Gui.NinjaScript.StrategyRenderBase
    {
        public Indicators.TestWithDLL TestWithDLL()
        {
            return indicator.TestWithDLL(Input);
        }

        public Indicators.TestWithDLL TestWithDLL(ISeries<double> input )
        {
            return indicator.TestWithDLL(input);
        }
    }
}

#endregion
EOF

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
          <FileName>TestWithDLL.cs</FileName>
          <n>TestWithDLL</n>
          <DisplayName>Test Indicator With DLL</DisplayName>
        </NinjaScriptInfo>
      </Indicators>
    </SourceCodeCollection>
    <Files>
      <File>
        <n>TestUtils.dll</n>
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
  <n>Minimal Test With DLL</n>
  <Version>1.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Minimal test package with DLL dependency and old manifest format</Description>
</NinjaScriptInfo>
EOF

echo "Created minimal test package with DLL + source"

cd package
zip -r Minimal_WithDLL_Package.zip .

echo "✅ Minimal test package with DLL created"
echo "Package contains:"
echo "  - TestUtils.dll at ROOT level"
echo "  - TestUtils.dll in bin/ folder"
echo "  - One indicator using the DLL"
echo "  - OLD SourceCodeCollection manifest format"
echo "  - <Files> section referencing the DLL"

mv Minimal_WithDLL_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Minimal_WithDLL_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Minimal_WithDLL_Package.zip

echo ""
echo "✅ This minimal test includes:"
echo "  - Simple DLL with utility class"
echo "  - Indicator that uses the DLL" 
echo "  - OLD manifest format"
echo "  - Should work if DLL + old format is the solution"
