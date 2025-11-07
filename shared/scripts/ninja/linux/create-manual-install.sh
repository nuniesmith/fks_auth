#!/bin/bash

# Create a simple manual installation script
echo "Creating manual installation guide..."

cat > manual_install_guide.txt << 'EOF'
# Manual Installation Guide for FKS Trading Systems

Since NinjaTrader 8 package imports are failing, try manual installation:

## Step 1: Extract Files Manually

1. Extract FKS_TradingSystem_v1.0.0.zip to a temporary folder
2. You should see:
   - FKS.dll (main library)
   - bin/Custom/Indicators/*.cs (indicator source files)
   - bin/Custom/Strategies/*.cs (strategy source files)  
   - bin/Custom/AddOns/*.cs (addon source files)

## Step 2: Manual File Copy

1. Close NinjaTrader 8 completely
2. Navigate to your NinjaTrader 8 documents folder:
   %USERPROFILE%\Documents\NinjaTrader 8\

3. Copy files to these locations:

   A) Copy FKS.dll to:
      %USERPROFILE%\Documents\NinjaTrader 8\bin\

   B) Copy all .cs files maintaining folder structure:
      - Copy Indicators/*.cs to: %USERPROFILE%\Documents\NinjaTrader 8\bin\Custom\Indicators\
      - Copy Strategies/*.cs to: %USERPROFILE%\Documents\NinjaTrader 8\bin\Custom\Strategies\
      - Copy AddOns/*.cs to: %USERPROFILE%\Documents\NinjaTrader 8\bin\Custom\AddOns\

## Step 3: Restart and Compile

1. Start NinjaTrader 8
2. Open Tools → NinjaScript Editor
3. Press F5 to compile all scripts
4. Check Output window for any compilation errors
5. If successful, indicators should appear in Indicators list

## Expected Components After Installation

- Indicators: FKS_Dashboard, FKS_AO, FKS_AI, FKS_PythonBridge
- Strategies: FKS_Strategy  
- AddOns: FKS_Core, FKS_Calculations, FKS_Market, FKS_Signals, FKS_Infrastructure

## Troubleshooting Manual Installation

If compilation fails:
1. Check that FKS.dll is in the bin folder
2. Verify all .cs files are in correct subdirectories
3. Look for missing using statements or dependencies
4. Check NinjaScript Editor output for specific errors

This manual method bypasses the package import system entirely.
EOF

echo "✅ Manual installation guide created: manual_install_guide.txt"

# Also create a batch file for Windows to automate the manual copy process
cat > manual_install.bat << 'EOF'
@echo off
echo FKS Trading Systems - Manual Installation Script
echo.

set "NT8_DIR=%USERPROFILE%\Documents\NinjaTrader 8"
set "EXTRACT_DIR=%~dp0extracted"

echo Checking NinjaTrader 8 directory...
if not exist "%NT8_DIR%" (
    echo ERROR: NinjaTrader 8 directory not found at %NT8_DIR%
    echo Please verify NinjaTrader 8 is installed.
    pause
    exit /b 1
)

echo NinjaTrader 8 found at: %NT8_DIR%
echo.

echo Please extract FKS_TradingSystem_v1.0.0.zip to: %EXTRACT_DIR%
echo Then run this script again.
echo.
pause

if not exist "%EXTRACT_DIR%" (
    echo ERROR: Extracted files not found at %EXTRACT_DIR%
    echo Please extract the ZIP file first.
    pause
    exit /b 1
)

echo Copying FKS.dll to bin folder...
copy "%EXTRACT_DIR%\FKS.dll" "%NT8_DIR%\bin\" /Y

echo Creating Custom directories...
mkdir "%NT8_DIR%\bin\Custom\Indicators" 2>nul
mkdir "%NT8_DIR%\bin\Custom\Strategies" 2>nul  
mkdir "%NT8_DIR%\bin\Custom\AddOns" 2>nul

echo Copying source files...
xcopy "%EXTRACT_DIR%\bin\Custom\Indicators\*" "%NT8_DIR%\bin\Custom\Indicators\" /Y /S
xcopy "%EXTRACT_DIR%\bin\Custom\Strategies\*" "%NT8_DIR%\bin\Custom\Strategies\" /Y /S
xcopy "%EXTRACT_DIR%\bin\Custom\AddOns\*" "%NT8_DIR%\bin\Custom\AddOns\" /Y /S

echo.
echo ✅ Manual installation complete!
echo.
echo Next steps:
echo 1. Start NinjaTrader 8
echo 2. Open Tools → NinjaScript Editor  
echo 3. Press F5 to compile
echo 4. Check for FKS components in the lists
echo.
pause
EOF

echo "✅ Windows batch file created: manual_install.bat"

mv manual_install_guide.txt /home/ordan/fks/
mv manual_install.bat /home/ordan/fks/

echo ""
echo "📋 Created manual installation files:"
echo "  - manual_install_guide.txt (detailed instructions)"
echo "  - manual_install.bat (Windows automation script)"
echo ""
echo "💡 Since all package imports are failing, manual installation"
echo "   bypasses the NT8 import system entirely and may work."
