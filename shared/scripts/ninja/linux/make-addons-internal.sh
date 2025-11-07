#!/bin/bash

# Script to change all public utility classes to internal in AddOns folder
# This prevents NinjaTrader's type scanner from seeing them as potential NinjaScript types

cd /home/ordan/fks/src/ninja/src/AddOns

echo "Making all utility classes internal to hide from NinjaTrader's type scanner..."

# Change public class to internal class
for file in *.cs; do
    echo "Processing $file..."
    sed -i 's/public class /internal class /g' "$file"
    sed -i 's/public sealed class /internal sealed class /g' "$file"
    sed -i 's/public abstract class /internal abstract class /g' "$file"
done

echo "Done. All utility classes in AddOns are now internal."
