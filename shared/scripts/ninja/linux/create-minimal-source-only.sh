#!/bin/bash

# Create an absolutely minimal source-only package with just one simple indicator
echo "Creating ultra-minimal source-only package..."

# Create a temporary directory
mkdir -p /tmp/fks_minimal_source
cd /tmp/fks_minimal_source

# Create the proper NinjaTrader package structure
mkdir -p package/bin/Custom/{Indicators,Strategies,AddOns}

# Create a single, ultra-simple indicator with NO dependencies
cat > package/bin/Custom/Indicators/TestIndicator.cs << 'EOF'
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
    public class TestIndicator : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"Ultra simple test indicator";
                Name = "TestIndicator";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                DisplayInDataBox = true;
                DrawOnPricePanel = false;
                DrawHorizontalGridLines = true;
                DrawVerticalGridLines = true;
                PaintPriceMarkers = true;
                ScaleJustification = NinjaTrader.Gui.Chart.ScaleJustification.Right;
                IsSuspendedWhileInactive = true;
                
                AddPlot(Brushes.Orange, "TestPlot");
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
        private TestIndicator[] cacheTestIndicator;
        public TestIndicator TestIndicator()
        {
            return TestIndicator(Input);
        }

        public TestIndicator TestIndicator(ISeries<double> input)
        {
            if (cacheTestIndicator != null)
                for (int idx = 0; idx < cacheTestIndicator.Length; idx++)
                    if (cacheTestIndicator[idx] != null && cacheTestIndicator[idx].EqualsInput(input))
                        return cacheTestIndicator[idx];

            return CacheIndicator<TestIndicator>(new TestIndicator(), input, ref cacheTestIndicator);
        }
    }
}

namespace NinjaTrader.NinjaScript.MarketAnalyzerColumns
{
    public partial class MarketAnalyzerColumn : MarketAnalyzerColumnBase
    {
        public Indicators.TestIndicator TestIndicator()
        {
            return indicator.TestIndicator(Input);
        }

        public Indicators.TestIndicator TestIndicator(ISeries<double> input )
        {
            return indicator.TestIndicator(input);
        }
    }
}

namespace NinjaTrader.NinjaScript.Strategies
{
    public partial class Strategy : NinjaTrader.Gui.NinjaScript.StrategyRenderBase
    {
        public Indicators.TestIndicator TestIndicator()
        {
            return indicator.TestIndicator(Input);
        }

        public Indicators.TestIndicator TestIndicator(ISeries<double> input )
        {
            return indicator.TestIndicator(input);
        }
    }
}

#endregion
EOF

# Create proper manifest.xml at ROOT level - ONLY the test indicator
cat > package/manifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest>
  <ExportedTypes>
    <Indicator>TestIndicator</Indicator>
  </ExportedTypes>
  <NinjaScriptCollection>
    <n>Minimal Test Package</n>
    <Version>1.0.0</Version>
    <Vendor>Test</Vendor>
    <Description>Ultra minimal test indicator for debugging import issues</Description>
  </NinjaScriptCollection>
</NinjaScriptManifest>
EOF

# Create proper Info.xml at ROOT level
cat > package/Info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptInfo>
  <n>Minimal Test Package</n>
  <Version>1.0.0</Version>
  <Vendor>Test</Vendor>
  <Description>Ultra minimal test package with one simple indicator</Description>
</NinjaScriptInfo>
EOF

echo "Created ultra-minimal package files"

cd package
zip -r Minimal_SourceOnly_Package.zip .

echo "✅ Ultra-minimal source-only package created"
echo "Package structure:"
echo "  manifest.xml                    <- Manifest at ROOT"
echo "  Info.xml                       <- Info at ROOT" 
echo "  bin/Custom/Indicators/TestIndicator.cs  <- ONE simple indicator"

mv Minimal_SourceOnly_Package.zip /home/ordan/fks/
echo "Package saved to: /home/ordan/fks/Minimal_SourceOnly_Package.zip"

# Show file verification
echo ""
echo "Package contents verification:"
cd /home/ordan/fks
unzip -l Minimal_SourceOnly_Package.zip

echo ""
echo "✅ This package contains:"
echo "  - ONE ultra-simple indicator with no dependencies"
echo "  - Standard NinjaScript structure"
echo "  - Proper manifest and info files"
echo "  - NO custom AddOns or complex code"
