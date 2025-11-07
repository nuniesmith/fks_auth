#!/bin/bash

# Create a test package using the OLD manifest format with SourceCodeCollection
echo "Creating test package with OLD manifest format..."

# Create a temporary directory
mkdir -p /tmp/fks_old_format
cd /tmp/fks_old_format

# Create the proper NinjaTrader package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Create a simple test indicator
cat > package/bin/Custom/Indicators/TestIndicatorOld.cs << 'EOF'
#region Using declarations
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Windows.Media;
using NinjaTrader.NinjaScript;
using NinjaTrader.NinjaScript.Indicators;
#endregion

namespace NinjaTrader.NinjaScript.Indicators
{
    public class TestIndicatorOld : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"Test indicator with old manifest format";
                Name = "TestIndicatorOld";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                DisplayInDataBox = true;
                DrawOnPricePanel = false;
                DrawHorizontalGridLines = true;
                DrawVerticalGridLines = true;
                PaintPriceMarkers = true;
                ScaleJustification = NinjaTrader.Gui.Chart.ScaleJustification.Right;
                IsSuspendedWhileInactive = true;
                
                AddPlot(Brushes.Blue, "TestPlot");
            }
        }

        protected override void OnBarUpdate()
        {
            Value[0] = Close[0];
        }
    }
}

#region NinjaScript generated code. Neither change nor remove.

namespace NinjaTrader.NinjaScript.Indicators
{
    public partial class Indicator : NinjaTrader.Gui.NinjaScript.IndicatorRenderBase
    {
        private TestIndicatorOld[] cacheTestIndicatorOld;
        public TestIndicatorOld TestIndicatorOld()
        {
            return TestIndicatorOld(Input);
        }

        public TestIndicatorOld TestIndicatorOld(ISeries<double> input)
        {
            if (cacheTestIndicatorOld != null)
                for (int idx = 0; idx < cacheTestIndicatorOld.Length; idx++)
                    if (cacheTestIndicatorOld[idx] != null && cacheTestIndicatorOld[idx].EqualsInput(input))
                        return cacheTestIndicatorOld[idx];

            return CacheIndicator<TestIndicatorOld>(new TestIndicatorOld(), input, ref cacheTestIndicatorOld);
        }
    }
}

namespace NinjaTrader.NinjaScript.MarketAnalyzerColumns
{
    public partial class MarketAnalyzerColumn : MarketAnalyzerColumnBase
    {
        public Indicators.TestIndicatorOld TestIndicatorOld()
        {
            return indicator.TestIndicatorOld(Input);
        }

        public Indicators.TestIndicatorOld TestIndicatorOld(ISeries<double> input )
        {
            return indicator.TestIndicatorOld(input);
        }
    }
}

namespace NinjaTrader.NinjaScript.Strategies
{
    public partial class Strategy : NinjaTrader.Gui.NinjaScript.StrategyRenderBase
    {
        public Indicators.TestIndicatorOld TestIndicatorOld()
        {
            return indicator.TestIndicatorOld(Input);
        }

        public Indicators.TestIndicatorOld TestIndicatorOld(ISeries<double> input )
        {
            return indicator.TestIndicatorOld(input);
        }
    }
}

#endregion
EOF

# Create manifest using the OLD SourceCodeCollection format
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
  </ExportedTypes>
  <NinjaScriptCollection>
    <SourceCodeCollection>
      <Indicators>
        <NinjaScriptInfo>
          <FileName>TestIndicatorOld.cs</FileName>
          <n>TestIndicatorOld</n>
          <DisplayName>Test Indicator Old Format</DisplayName>
        </NinjaScriptInfo>
      </Indicators>
    </SourceCodeCollection>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create Info.xml with the old format
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>Test Old Format Package</n>
  <Version>1.0.0</Version>
  <Vendor>Test Vendor</Vendor>
  <Description>Testing old SourceCodeCollection manifest format</Description>
</NinjaScriptInfo>
EOF

echo "Created OLD format package files"

cd package
zip -r Old_Format_Package.zip .

echo "✅ Old format test package created with SourceCodeCollection structure"
echo "Package contains:"
echo "  - manifest.xml with <SourceCodeCollection> format"
echo "  - Info.xml with <n> tags"
echo "  - One test indicator"
echo "  - Source code structure"

mv Old_Format_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Old_Format_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Old_Format_Package.zip

echo ""
echo "✅ This uses the OLD manifest format that might work better!"
echo "✅ Based on found older script with different XML structure"
