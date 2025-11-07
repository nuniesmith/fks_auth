#!/bin/bash

# Create a minimal test package to isolate the type loading issue

set -e

# Colors for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

PACKAGE_NAME="FKS_Minimal"
VERSION="1.0.0"
BUILD_CONFIG="Release"

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
error() { echo -e "${RED}❌${NC} $1"; exit 1; }

log "Creating minimal test package..."

# Use existing build
PROJECT_ROOT="/home/ordan/fks"
BUILD_OUTPUT_DIR="$PROJECT_ROOT/bin/$BUILD_CONFIG"

if [[ ! -f "$BUILD_OUTPUT_DIR/FKS.dll" ]]; then
    error "FKS.dll not found. Run the main build script first."
fi

# Create minimal package
PACKAGE_DIR="NT8_Package_${PACKAGE_NAME}"
rm -rf "$PACKAGE_DIR" 2>/dev/null || true

mkdir -p "$PACKAGE_DIR/bin"
mkdir -p "$PACKAGE_DIR/bin/Custom/Indicators"

# Copy only the DLL and one simple indicator
cp "$BUILD_OUTPUT_DIR/FKS.dll" "$PACKAGE_DIR/bin/FKS.dll"
cp "$PROJECT_ROOT/src/ninja/src/Indicators/FKS_Dashboard.cs" "$PACKAGE_DIR/bin/Custom/Indicators/"

# Create minimal Info.xml
cat > "$PACKAGE_DIR/Info.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaTrader>
  <Export>
    <Version>8.1.2.1</Version>
  </Export>
</NinjaTrader>
EOF

# Create minimal manifest.xml with ONLY the one indicator
cat > "$PACKAGE_DIR/manifest.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest SchemaVersion="1.0" xmlns="http://www.ninjatrader.com/NinjaScript">
  <Assemblies>
    <Assembly>
      <FullName>FKS, Version=${VERSION}.0, Culture=neutral, PublicKeyToken=null</FullName>
      <ExportedTypes>
        <ExportedType>NinjaTrader.NinjaScript.Indicators.FKS_Dashboard</ExportedType>
      </ExportedTypes>
    </Assembly>
  </Assemblies>
  <NinjaScriptCollection>
    <Indicators>
      <Indicator>
        <TypeName>FKS_Dashboard</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Indicators.FKS_Dashboard</FullTypeName>
      </Indicator>
    </Indicators>
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>FKS.dll</n>
      <Path>bin</Path>
    </File>
    <File>
      <n>Indicators\\FKS_Dashboard.cs</n>
      <Path>bin\\Custom\\Indicators</Path>
    </File>
  </Files>
</NinjaScriptManifest>
EOF

# Create ZIP
ZIP_NAME="${PACKAGE_NAME}_v${VERSION}.zip"
rm -f "$ZIP_NAME" 2>/dev/null || true

cd "$PACKAGE_DIR"
cp bin/FKS.dll ./FKS.dll
zip -r "../$ZIP_NAME" . -q
cd ..

rm -rf "$PACKAGE_DIR"

success "Minimal test package created: $ZIP_NAME"
log "This package contains ONLY:"
log "  - FKS.dll (compiled assembly)"
log "  - FKS_Dashboard.cs (single indicator)"
log "  - Minimal manifest with no AddOn exports"
log ""
log "Test this package to see if the type loading errors persist."
log "If they do, the issue is in the compiled assembly itself."
