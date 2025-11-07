#!/bin/bash

# FKS NinjaTrader 8 Build and Package Script for Linux
# Complete pipeline to build and package the FKS trading system

set -e

# Colors for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

# Configuration
PACKAGE_NAME="${1:-FKS_TradingSystem}"
VERSION="${2:-1.0.0}"
BUILD_CONFIG="Release"

# Dynamic project root detection
detect_project_root() {
    local current_dir="$(pwd)"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Try multiple approaches to find project root
    local potential_roots=(
        "$script_dir/../../../"           # From scripts/ninja/linux/ go up to project root
        "$current_dir"                    # Current directory
        "$current_dir/../"                # One level up
        "$current_dir/../../"             # Two levels up
    )
    
    for root in "${potential_roots[@]}"; do
        local abs_root="$(cd "$root" 2>/dev/null && pwd)" || continue
        
        # Check for project indicators
        if [[ -f "$abs_root/src/ninja/src/FKS.csproj" ]] || 
           [[ -f "$abs_root/FKS.sln" ]] || 
           [[ -f "$abs_root/src/ninja/FKS.sln" ]]; then
            echo "$abs_root"
            return 0
        fi
    done
    
    # Fallback: assume current directory
    echo "$(pwd)"
}

# Set project paths
PROJECT_ROOT="$(detect_project_root)"
NINJA_SRC_DIR="$PROJECT_ROOT/src/ninja"

# Determine the actual project file location
find_project_file() {
    local potential_files=(
        "$NINJA_SRC_DIR/src/FKS.csproj"
        "$NINJA_SRC_DIR/FKS.csproj"
        "$PROJECT_ROOT/src/FKS.csproj"
        "$PROJECT_ROOT/FKS.csproj"
    )
    
    for file in "${potential_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo "$file"
            return 0
        fi
    done
    
    return 1
}

PROJECT_FILE="$(find_project_file)"

# Check if project file was found
if [[ -z "$PROJECT_FILE" ]]; then
    error "Could not find FKS.csproj file. Searched in:
    - $NINJA_SRC_DIR/src/FKS.csproj
    - $NINJA_SRC_DIR/FKS.csproj  
    - $PROJECT_ROOT/src/FKS.csproj
    - $PROJECT_ROOT/FKS.csproj"
fi

log "Found project file: $PROJECT_FILE"

# Functions
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
warning() { echo -e "${YELLOW}⚠️${NC} $1"; }
error() { echo -e "${RED}❌${NC} $1"; exit 1; }

print_header() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    FKS NinjaTrader 8 Build Pipeline (Linux)  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

debug_project_structure() {
    if [[ "${DEBUG:-}" == "1" ]]; then
        log "=== DEBUG: Project Structure ==="
        log "Script location: $(dirname "${BASH_SOURCE[0]}")"
        log "Current directory: $(pwd)"
        log "Project root: $PROJECT_ROOT"
        log "Ninja source dir: $NINJA_SRC_DIR"
        log "Project file: $PROJECT_FILE"
        echo ""
        log "Project root contents:"
        ls -la "$PROJECT_ROOT" 2>/dev/null | head -10 || echo "  (not accessible)"
        echo ""
        log "Ninja source contents:"
        ls -la "$NINJA_SRC_DIR" 2>/dev/null | head -10 || echo "  (not accessible)"
        echo ""
        log "=== END DEBUG ==="
    fi
}

check_prerequisites() {
    log "Checking prerequisites..."
    log "Project root detected: $PROJECT_ROOT"
    log "Ninja source directory: $NINJA_SRC_DIR"
    
    # Check .NET SDK
    if ! command -v dotnet &> /dev/null; then
        error ".NET SDK not found. Please install .NET SDK 6.0+"
    fi
    
    local dotnet_version=$(dotnet --version)
    success ".NET SDK found: $dotnet_version"
    
    # Check project files
    if [[ -z "$PROJECT_FILE" ]] || [[ ! -f "$PROJECT_FILE" ]]; then
        error "Project file not found. Looked for FKS.csproj in:
  - $NINJA_SRC_DIR/src/FKS.csproj
  - $NINJA_SRC_DIR/FKS.csproj
  - $PROJECT_ROOT/src/FKS.csproj
  - $PROJECT_ROOT/FKS.csproj"
    fi
    
    success "Project file found: $PROJECT_FILE"
    
    # Check for zip command
    if ! command -v zip &> /dev/null; then
        error "zip command not found. Please install: sudo apt-get install zip"
    fi
    
    success "Prerequisites check completed"
}

clean_build_artifacts() {
    log "Cleaning previous build artifacts..."
    
    # Get project directory from project file
    local project_dir="$(dirname "$PROJECT_FILE")"
    
    # Clean directories
    local dirs_to_clean=(
        "$project_dir/bin"
        "$project_dir/obj"
        "$PROJECT_ROOT/bin"
        "$PROJECT_ROOT/obj"
        "$PROJECT_ROOT/packages"
    )
    
    for dir in "${dirs_to_clean[@]}"; do
        if [[ -d "$dir" ]]; then
            log "Cleaning $dir"
            rm -rf "$dir"
        fi
    done
    
    # Clean package directories and zip files in current directory
    rm -rf NT8_Package_* 2>/dev/null || true
    rm -f *.zip 2>/dev/null || true
    
    success "Clean completed"
}

build_project() {
    log "Building FKS project..."
    log "Using project file: $PROJECT_FILE"
    
    # Create build output directory
    local build_output_dir="$PROJECT_ROOT/bin/$BUILD_CONFIG"
    mkdir -p "$build_output_dir"
    
    # Restore packages
    log "Restoring NuGet packages..."
    if ! dotnet restore "$PROJECT_FILE"; then
        error "Package restore failed"
    fi
    success "Package restore completed"
    
    # Build project
    log "Building project (Configuration: $BUILD_CONFIG)..."
    if ! dotnet build "$PROJECT_FILE" --configuration "$BUILD_CONFIG" --output "$build_output_dir"; then
        error "Build failed"
    fi
    
    # Verify DLL exists
    local dll_path="$build_output_dir/FKS.dll"
    if [[ ! -f "$dll_path" ]]; then
        error "FKS.dll not found at $dll_path"
    fi
    
    local dll_size=$(du -h "$dll_path" | cut -f1)
    success "Build completed - FKS.dll created ($dll_size)"
}

create_package_structure() {
    local package_dir="NT8_Package_${PACKAGE_NAME}"
    
    # Clean and create directories
    rm -rf "$package_dir" 2>/dev/null || true
    
    mkdir -p "$package_dir"
    mkdir -p "$package_dir/bin"
    mkdir -p "$package_dir/bin/Custom"
    mkdir -p "$package_dir/bin/Custom/Indicators"
    mkdir -p "$package_dir/bin/Custom/Strategies"
    mkdir -p "$package_dir/bin/Custom/AddOns"
    
    # Return the package directory name (without color codes)
    printf "%s" "$package_dir"
}

copy_dll_to_package() {
    local package_dir=$1
    log "Copying compiled DLL..."
    
    local build_output_dir="$PROJECT_ROOT/bin/$BUILD_CONFIG"
    
    # Copy ONLY the main FKS.dll - exclude NuGet package DLLs that cause conflicts
    cp "$DLL_PATH" "$package_dir/FKS.dll"
    log "DLL copied to package root"
    
    # Also copy DLL to bin folder (standard location)
    cp "$DLL_PATH" "$package_dir/bin/FKS.dll"
    
    # CREATE CRITICAL AdditionalReferences.txt file
    log "Creating AdditionalReferences.txt..."
    cat > "$package_dir/AdditionalReferences.txt" << EOF
FKS
EOF
    success "AdditionalReferences.txt created (REQUIRED for custom DLLs)"
    
    # Copy PDB file if it exists
    if [ -f "$PDB_PATH" ]; then
        cp "$PDB_PATH" "$package_dir/bin/"
        log "Copied debug symbols"
    fi
    
    # Copy XML documentation if it exists
    local xml_path="${DLL_PATH%.dll}.xml"
    if [ -f "$xml_path" ]; then
        cp "$xml_path" "$package_dir/bin/"
        log "Copied XML documentation"
    fi
    
    # IMPORTANT: Do NOT copy NuGet package DLLs as they conflict with NT8's runtime
    # Specifically avoid: System.Buffers.dll, System.Memory.dll, System.Numerics.Vectors.dll, 
    # System.Runtime.CompilerServices.Unsafe.dll, System.ValueTuple.dll
    
    success "DLL copied to package (excluding conflicting dependencies)"
}

copy_source_files() {
    local package_dir=$1
    
    local indicator_count=0
    local strategy_count=0
    local addon_count=0
    
    # Get project directory from project file
    local project_dir="$(dirname "$PROJECT_FILE")"
    
    # Define potential source directories
    local source_dirs=(
        "$project_dir"           # Same directory as project file
        "$NINJA_SRC_DIR/src"     # Standard ninja src structure
        "$NINJA_SRC_DIR"         # Ninja directory itself
    )
    
    # Copy indicators
    for src_dir in "${source_dirs[@]}"; do
        if [[ -d "$src_dir/Indicators" ]]; then
            for file in "$src_dir/Indicators"/*.cs; do
                if [[ -f "$file" ]]; then
                    cp "$file" "$package_dir/bin/Custom/Indicators/"
                    ((indicator_count++))
                fi
            done
            break  # Use first found directory
        fi
    done
    
    # Copy strategies
    for src_dir in "${source_dirs[@]}"; do
        if [[ -d "$src_dir/Strategies" ]]; then
            for file in "$src_dir/Strategies"/*.cs; do
                if [[ -f "$file" ]]; then
                    cp "$file" "$package_dir/bin/Custom/Strategies/"
                    ((strategy_count++))
                fi
            done
            break  # Use first found directory
        fi
    done
    
    # Copy addons
    for src_dir in "${source_dirs[@]}"; do
        if [[ -d "$src_dir/AddOns" ]]; then
            for file in "$src_dir/AddOns"/*.cs; do
                if [[ -f "$file" ]]; then
                    cp "$file" "$package_dir/bin/Custom/AddOns/"
                    ((addon_count++))
                fi
            done
            break  # Use first found directory
        fi
    done
    
    # Copy GlobalUsings if exists
    for src_dir in "${source_dirs[@]}"; do
        if [[ -f "$src_dir/GlobalUsings.cs" ]]; then
            cp "$src_dir/GlobalUsings.cs" "$package_dir/bin/Custom/"
            break  # Use first found file
        fi
    done
    
    # Return counts without color codes or logging
    printf "%d:%d:%d" "$indicator_count" "$strategy_count" "$addon_count"
}

create_info_xml() {
    local package_dir=$1
    log "Creating Info.xml..."
    
    cat > "$package_dir/Info.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<NinjaTrader>
  <Export>
    <Version>8.1.2.1</Version>
  </Export>
</NinjaTrader>
EOF
    
    success "Info.xml created"
}

create_manifest_xml() {
    local package_dir=$1
    log "Creating manifest.xml..."
    
    # Get list of components
    local indicators=()
    local strategies=()
    local addons=()
    
    # Scan for indicators
    if [[ -d "$package_dir/bin/Custom/Indicators" ]]; then
        for file in "$package_dir"/bin/Custom/Indicators/*.cs; do
            if [[ -f "$file" ]]; then
                local class_name=$(basename "$file" .cs)
                indicators+=("$class_name")
            fi
        done
    fi
    
    # Scan for strategies
    if [[ -d "$package_dir/bin/Custom/Strategies" ]]; then
        for file in "$package_dir"/bin/Custom/Strategies/*.cs; do
            if [[ -f "$file" ]]; then
                local class_name=$(basename "$file" .cs)
                strategies+=("$class_name")
            fi
        done
    fi
    
    # Scan for addons
    if [[ -d "$package_dir/bin/Custom/AddOns" ]]; then
        for file in "$package_dir"/bin/Custom/AddOns/*.cs; do
            if [[ -f "$file" ]]; then
                local class_name=$(basename "$file" .cs)
                addons+=("$class_name")
            fi
        done
    fi
    
    # Start building manifest
    cat > "$package_dir/manifest.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<NinjaScriptManifest SchemaVersion="1.0" xmlns="http://www.ninjatrader.com/NinjaScript">
  <Assemblies>
    <Assembly>
      <FullName>FKS, Version=${VERSION}.0, Culture=neutral, PublicKeyToken=null</FullName>
      <ExportedTypes>
EOF
    
    # Add exported types (Only Indicators and Strategies - NOT AddOns)
    for indicator in "${indicators[@]}"; do
        echo "        <ExportedType>NinjaTrader.NinjaScript.Indicators.$indicator</ExportedType>" >> "$package_dir/manifest.xml"
    done
    for strategy in "${strategies[@]}"; do
        echo "        <ExportedType>NinjaTrader.NinjaScript.Strategies.$strategy</ExportedType>" >> "$package_dir/manifest.xml"
    done
    # CRITICAL: AddOns are utility classes and must NOT be exported as NinjaScript components
    
    cat >> "$package_dir/manifest.xml" << EOF
      </ExportedTypes>
    </Assembly>
  </Assemblies>
  <NinjaScriptCollection>
EOF
    
    # Add indicators collection
    if [[ ${#indicators[@]} -gt 0 ]]; then
        echo "    <Indicators>" >> "$package_dir/manifest.xml"
        for indicator in "${indicators[@]}"; do
            cat >> "$package_dir/manifest.xml" << EOF
      <Indicator>
        <TypeName>$indicator</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Indicators.$indicator</FullTypeName>
      </Indicator>
EOF
        done
        echo "    </Indicators>" >> "$package_dir/manifest.xml"
    fi
    
    # Add strategies collection
    if [[ ${#strategies[@]} -gt 0 ]]; then
        echo "    <Strategies>" >> "$package_dir/manifest.xml"
        for strategy in "${strategies[@]}"; do
            cat >> "$package_dir/manifest.xml" << EOF
      <Strategy>
        <TypeName>$strategy</TypeName>
        <AssemblyName>FKS</AssemblyName>
        <FullTypeName>NinjaTrader.NinjaScript.Strategies.$strategy</FullTypeName>
      </Strategy>
EOF
        done
        echo "    </Strategies>" >> "$package_dir/manifest.xml"
    fi
    
    # Note: AddOns are utility classes and should NOT be listed as NinjaScript components
    
    # Add files section
    cat >> "$package_dir/manifest.xml" << EOF
  </NinjaScriptCollection>
  <Files>
    <File>
      <n>FKS.dll</n>
      <Path>bin</Path>
    </File>
EOF
    
    # Add source files
    for indicator in "${indicators[@]}"; do
        cat >> "$package_dir/manifest.xml" << EOF
    <File>
      <n>Indicators\\$indicator.cs</n>
      <Path>bin\\Custom\\Indicators</Path>
    </File>
EOF
    done
    
    for strategy in "${strategies[@]}"; do
        cat >> "$package_dir/manifest.xml" << EOF
    <File>
      <n>Strategies\\$strategy.cs</n>
      <Path>bin\\Custom\\Strategies</Path>
    </File>
EOF
    done
    
    # Note: AddOn files are included in the package but not listed in manifest
    # since they are utility classes, not NinjaScript components
    
    # Close manifest
    cat >> "$package_dir/manifest.xml" << EOF
  </Files>
</NinjaScriptManifest>
EOF
    
    success "manifest.xml created with ${#indicators[@]} indicators, ${#strategies[@]} strategies, ${#addons[@]} addons"
}

create_zip_package() {
    local package_dir=$1
    local zip_name="${PACKAGE_NAME}_v${VERSION}.zip"
    
    # Remove existing zip if present
    if [[ -f "$zip_name" ]]; then
        rm -f "$zip_name"
    fi
    
    # Create zip with FKS.dll at root level as requested
    cd "$package_dir"
    
    # Copy DLL to root for the special requirement
    cp bin/FKS.dll ./FKS.dll
    
    # Create zip with all contents
    zip -r "../$zip_name" . -q
    
    cd ..
    
    # Verify zip was created
    if [[ ! -f "$zip_name" ]]; then
        return 1
    fi
    
    # Clean up temp directory
    rm -rf "$package_dir"
    
    # Return zip name without color codes or logging
    printf "%s" "$zip_name"
}

verify_package() {
    local zip_file=$1
    log "Verifying package contents..."
    
    # List contents
    log "Package contents:"
    unzip -l "$zip_file" | grep -E "\.(dll|xml|cs)$" | while read -r line; do
        echo "  $line"
    done
    
    # Check for required files
    local has_dll=$(unzip -l "$zip_file" | grep -c "FKS.dll" || true)
    local has_manifest=$(unzip -l "$zip_file" | grep -c "manifest.xml" || true)
    local has_info=$(unzip -l "$zip_file" | grep -c "Info.xml" || true)
    
    if [[ $has_dll -gt 0 ]] && [[ $has_manifest -gt 0 ]] && [[ $has_info -gt 0 ]]; then
        success "Package verification passed"
        
        # Check if DLL is at root level
        if unzip -l "$zip_file" | grep -q "^[[:space:]]*[0-9]*[[:space:]]*[0-9-]*[[:space:]]*[0-9:]*[[:space:]]*FKS.dll$"; then
            success "FKS.dll is at root level as requested"
        fi
    else
        error "Package verification failed - missing required files"
    fi
}

show_summary() {
    local zip_file=$1
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           BUILD SUCCESSFUL! 🎉               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    
    success "Package: $zip_file"
    success "Ready for import into NinjaTrader 8"
    
    echo ""
    log "Import Instructions:"
    echo "  1. Transfer $zip_file to your Windows machine"
    echo "  2. Close NinjaTrader 8 completely"
    echo "  3. Open NinjaTrader 8"
    echo "  4. Go to Tools → Import → NinjaScript Add-On"
    echo "  5. Select the ZIP file"
    echo "  6. Click Import"
    echo "  7. Restart NinjaTrader 8"
    
    echo ""
    log "Components will be available in:"
    echo "  • Indicators list (FKS_* indicators)"
    echo "  • Strategies list (FKS_Strategy)"
    echo "  • AddOns (FKS_Regime)"
}

# Main execution
main() {
    print_header
    
    # Show debug info if requested
    debug_project_structure
    
    check_prerequisites
    clean_build_artifacts
    build_project
    
    log "Creating NT8 package structure..."
    local package_dir=$(create_package_structure)
    copy_dll_to_package "$package_dir"
    
    log "Copying source files..."
    local counts=$(copy_source_files "$package_dir")
    IFS=':' read -r indicator_count strategy_count addon_count <<< "$counts"
    success "Copied $indicator_count indicators, $strategy_count strategies, $addon_count addons"
    
    create_info_xml "$package_dir"
    create_manifest_xml "$package_dir"
    
    log "Creating ZIP package..."
    local zip_file=$(create_zip_package "$package_dir")
    if [[ -z "$zip_file" ]]; then
        error "Failed to create ZIP package"
    fi
    
    local zip_size=$(du -h "$zip_file" | cut -f1)
    success "Package created: $zip_file ($zip_size)"
    
    verify_package "$zip_file"
    show_summary "$zip_file"
}

# Run main function
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << EOF
FKS NinjaTrader 8 Build and Package Script

Usage: $0 [PACKAGE_NAME] [VERSION]

Parameters:
  PACKAGE_NAME    Name of the package (default: FKS_TradingSystem)
  VERSION         Version number (default: 1.0.0)

Environment Variables:
  DEBUG=1         Enable debug output to show project structure detection

Examples:
  $0                           # Use defaults
  $0 MyTradingSystem 1.0.0     # Custom name and version
  DEBUG=1 $0                   # Enable debug output

The script automatically detects the project root and structure.
It will look for FKS.csproj in multiple locations relative to the script.
EOF
    exit 0
fi

main "$@"