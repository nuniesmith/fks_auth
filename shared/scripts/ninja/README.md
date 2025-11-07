# 🥷 FKS NinjaTrader Scripts

This directory contains all scripts related to NinjaTrader 8 development, building, packaging, and deployment for the FKS Trading Systems.

## 📁 Directory Structure

```
scripts/ninja/
├── README.md                    # This file
├── linux/                      # Linux/WSL scripts
│   ├── troubleshoot.sh         # SSH and deployment troubleshooting
│   ├── start-api-servers.sh    # Start development API services
│   └── stop-api-servers.sh     # Stop development API services
└── windows/                    # Windows PowerShell scripts
    ├── build.ps1               # Complete build and package script
    ├── enhanced-package.ps1     # Advanced packaging with verification
    ├── deploy-strategy.ps1      # Deploy built DLL to NinjaTrader
    ├── verify-package.ps1       # Verify NT8 package structure
    └── start-api-servers.ps1    # Start development services (Windows)
```

## 🔧 Windows PowerShell Scripts

### `build.ps1` - Main Build Script
**Purpose**: Complete build pipeline for FKS NinjaTrader components
**Usage**:
```powershell
# Basic build
.\build.ps1

# Clean and build
.\build.ps1 -Clean

# Build and create package
.\build.ps1 -Package

# Clean, build, and package with verbose output
.\build.ps1 -Clean -Package -Verbose
```

**Features**:
- ✅ Prerequisites checking (.NET SDK, project files)
- 🧹 Clean previous builds
- 📦 NuGet package restoration
- 🔨 Project compilation
- 📋 Package creation for NinjaTrader 8
- ✨ Comprehensive manifest generation

### `enhanced-package.ps1` - Advanced Packaging
**Purpose**: Creates comprehensive NinjaTrader 8 packages with full verification
**Usage**:
```powershell
.\enhanced-package.ps1
.\enhanced-package.ps1 -PackageName "FKS_Custom" -Version "1.0.0"
```

**Features**:
- 🏗️ Auto-discovery of all indicators, strategies, and addons
- 📄 Dynamic manifest generation
- 📊 Package content verification
- 🎯 Import instructions and component listing

### `deploy-strategy.ps1` - Quick Deployment
**Purpose**: Deploy built DLL directly to NinjaTrader 8 for development
**Usage**:
```powershell
.\deploy-strategy.ps1
```

**Features**:
- 🚀 Fast deployment to NT8 directory
- 📋 File version comparison
- ✅ Deployment verification
- 🎯 Next steps guidance

### `verify-package.ps1` - Package Verification
**Purpose**: Validate NT8 package structure before import
**Usage**:
```powershell
.\verify-package.ps1
.\verify-package.ps1 -PackagePath "my-package.zip"
```

**Features**:
- 🔍 Package structure validation
- 📄 Manifest content verification
- 💾 DLL presence checking
- 📊 Component inventory

### `start-api-servers.ps1` - Development Services
**Purpose**: Start development API services for testing
**Usage**:
```powershell
.\start-api-servers.ps1
```

## 🐧 Linux/WSL Scripts

### `troubleshoot.sh` - System Troubleshooting
**Purpose**: Diagnose and fix deployment issues on Linux servers
**Usage**:
```bash
# Show current state
./troubleshoot.sh diagnose

# Fix SSH permissions
./troubleshoot.sh fix-ssh

# Regenerate SSH keys
./troubleshoot.sh regen-keys

# Test GitHub connection
./troubleshoot.sh test-github

# Complete fix sequence
./troubleshoot.sh full-fix
```

**Features**:
- 🔍 System state diagnosis
- 🔑 SSH key management
- 🔧 Permission fixing
- 🐙 GitHub connectivity testing
- 🚀 Service restart capabilities

### `start-api-servers.sh` & `stop-api-servers.sh`
**Purpose**: Manage development API services
**Usage**:
```bash
# Start services
./start-api-servers.sh

# Stop services  
./stop-api-servers.sh
```

**Features**:
- 🚀 Python API server management
- 🖥️ VS Code proxy handling
- 📊 Health checking
- 🛑 Clean shutdown

## 🎯 Common Workflows

### 1. **Development Build & Test**
```powershell
# Windows
.\build.ps1 -Clean -Package
.\verify-package.ps1
.\deploy-strategy.ps1
```

### 2. **Production Package Creation**
```powershell
# Windows
.\enhanced-package.ps1 -PackageName "FKS_TradingSystem_v2" -Version "1.0.0"
.\verify-package.ps1 -PackagePath "FKS_TradingSystem_v2_v1.0.0.zip"
```

### 3. **Linux Server Troubleshooting**
```bash
# Linux/WSL
./troubleshoot.sh diagnose
./troubleshoot.sh full-fix
```

### 4. **Development Environment Setup**
```bash
# Linux/WSL
./start-api-servers.sh

# Windows
.\start-api-servers.ps1
```

## 📋 Prerequisites

### Windows Scripts
- **PowerShell 5.1+** or **PowerShell Core 7+**
- **.NET SDK 6.0+** (for building)
- **NinjaTrader 8** (for deployment)
- **Visual Studio Build Tools** (recommended)

### Linux Scripts  
- **Bash 4.0+**
- **Git** (for repository operations)
- **SSH client** (for key management)
- **curl** (for health checking)
- **lsof** (for port checking)

## 🔐 Security Notes

- **SSH keys** are generated with Ed25519 encryption
- **File permissions** are automatically secured (600/644)
- **GitHub authentication** uses SSH key-based auth only
- **Service PIDs** are tracked for clean shutdown

## 🐛 Troubleshooting

### Common Issues

1. **Build Failures**
   ```powershell
   # Check .NET SDK installation
   dotnet --version
   
   # Verify project structure
   Test-Path "src/FKS.csproj"
   ```

2. **Package Import Failures**
   ```powershell
   # Verify package structure
   .\verify-package.ps1 -PackagePath "your-package.zip"
   ```

3. **SSH Connection Issues**
   ```bash
   # Run full troubleshooting
   ./troubleshoot.sh full-fix
   ```

4. **Service Port Conflicts**
   ```bash
   # Check what's using the port
   lsof -i :8002
   
   # Stop conflicting services
   ./stop-api-servers.sh
   ```

## 📚 Additional Resources

- **NinjaTrader 8 Documentation**: [ninjatrader.com/docs](https://ninjatrader.com/docs)
- **.NET CLI Reference**: [docs.microsoft.com](https://docs.microsoft.com/en-us/dotnet/core/tools/)
- **PowerShell Documentation**: [docs.microsoft.com](https://docs.microsoft.com/en-us/powershell/)

## 🤝 Contributing

When adding new scripts:
1. Follow the existing naming conventions
2. Include comprehensive error handling
3. Add usage examples to this README
4. Test on both Windows and Linux where applicable
5. Include security considerations for any authentication

## 📝 Change Log

- **v1.0.0** - Initial ninja scripts organization
- Merged from `scripts copy/` directory
- Added comprehensive documentation
- Standardized error handling and logging
