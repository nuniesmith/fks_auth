#!/bin/bash

# Script to identify potential type loading conflicts in FKS assembly
# This helps diagnose why NinjaTrader expects ChartStyle, DrawingTool, and BarsType

echo "=== FKS Assembly Type Loading Diagnostic ==="
echo "Analyzing potential causes for NinjaTrader type loading errors..."
echo

# Check for suspicious class names and patterns
echo "1. Checking for suspicious class names..."
cd /home/ordan/fks/src/ninja/src

echo "Classes with 'Chart' in name:"
grep -r "class.*Chart" . --include="*.cs" || echo "  None found"

echo "Classes with 'Style' in name:"
grep -r "class.*Style" . --include="*.cs" || echo "  None found"

echo "Classes with 'Drawing' in name:"
grep -r "class.*Drawing" . --include="*.cs" || echo "  None found"

echo "Classes with 'Tool' in name:"
grep -r "class.*Tool" . --include="*.cs" || echo "  None found"

echo "Classes with 'Bars' in name:"
grep -r "class.*Bars" . --include="*.cs" || echo "  None found"

echo
echo "2. Checking for suspicious inheritance patterns..."

echo "Classes inheriting from types with 'Chart' in name:"
grep -r ": .*Chart" . --include="*.cs" || echo "  None found"

echo "Classes inheriting from types with 'Drawing' in name:"
grep -r ": .*Drawing" . --include="*.cs" || echo "  None found"

echo "Classes inheriting from types with 'Bars' in name:"
grep -r ": .*Bars" . --include="*.cs" || echo "  None found"

echo
echo "3. Checking for suspicious using statements..."

echo "Using statements with ChartStyles:"
grep -r "using.*ChartStyles" . --include="*.cs" || echo "  None found"

echo "Using statements with DrawingTools:"
grep -r "using.*DrawingTools" . --include="*.cs" || echo "  None found"

echo "Using statements with Data (might include BarsType):"
grep -r "using.*NinjaTrader.Data" . --include="*.cs" || echo "  None found"

echo
echo "4. Checking for problematic attribute usage..."

echo "NinjaScriptProperty attributes (might affect type scanning):"
grep -r "NinjaScriptProperty" . --include="*.cs" || echo "  None found"

echo "TypeConverter attributes:"
grep -r "TypeConverter" . --include="*.cs" || echo "  None found"

echo
echo "5. Checking public class count by namespace..."

echo "AddOns namespace public classes:"
grep -r "public class" AddOns/ --include="*.cs" | wc -l

echo "Total public classes in project:"
grep -r "public class" . --include="*.cs" | wc -l

echo
echo "6. Assembly analysis complete."
echo "Look for patterns that might confuse NinjaTrader's type scanner."
