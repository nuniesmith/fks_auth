const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const docsRouter = require('/workspace/src/web/api/routes/docs');

const app = express();
const PORT = 4000;

app.use(cors());
app.use(express.json());

// Documentation route
app.use('/api/docs', docsRouter);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        workspace: '/workspace',
        project: 'FKS NinjaTrader Development'
    });
});

// FKS Trading Systems Services API
app.get('/api/services', (req, res) => {
    const fksServices = [
        {
            id: 'ninja-trader',
            name: 'NinjaTrader Platform',
            icon: '📊',
            description: 'Professional trading platform for futures and forex',
            url: 'https://ninjatrader.com',
            category: 'Trading Platforms',
            status: 'active'
        },
        {
            id: 'fks_addon',
            name: 'FKS Trading Addon',
            icon: '⚡',
            description: 'Custom FKS trading algorithms and strategies',
            url: '/build',
            category: 'Trading Tools',
            status: 'development'
        },
        {
            id: 'market-data',
            name: 'Market Data Feed',
            icon: '📈',
            description: 'Real-time market data and analytics',
            url: '/api/market-data',
            category: 'Data Services',
            status: 'active'
        },
        {
            id: 'backtesting',
            name: 'Strategy Backtesting',
            icon: '🔄',
            description: 'Historical strategy performance analysis',
            url: '/api/backtest',
            category: 'Analysis Tools',
            status: 'active'
        },
        {
            id: 'portfolio-mgmt',
            name: 'Portfolio Management',
            icon: '💼',
            description: 'Track and manage trading portfolios',
            url: '/api/portfolio',
            category: 'Trading Tools',
            status: 'active'
        },
        {
            id: 'risk-management',
            name: 'Risk Management',
            icon: '🛡️',
            description: 'Risk assessment and management tools',
            url: '/api/risk',
            category: 'Risk Tools',
            status: 'active'
        },
        {
            id: 'trade-journal',
            name: 'Trade Journal',
            icon: '📝',
            description: 'Track and analyze trading performance',
            url: '/api/journal',
            category: 'Analysis Tools',
            status: 'active'
        },
        {
            id: 'alerts',
            name: 'Trading Alerts',
            icon: '🔔',
            description: 'Real-time trading signals and notifications',
            url: '/api/alerts',
            category: 'Notifications',
            status: 'active'
        },
        {
            id: 'documentation',
            name: 'FKS Documentation',
            icon: '📚',
            description: 'API documentation and trading guides',
            url: '/docs',
            category: 'Documentation',
            status: 'active'
        },
        {
            id: 'system-health',
            name: 'System Health',
            icon: '🏥',
            description: 'Monitor FKS system status and performance',
            url: '/api/health',
            category: 'System Monitoring',
            status: 'active'
        }
    ];
    
    res.json(fksServices);
});

// Get services by category
app.get('/api/services/category/:category', (req, res) => {
    const category = req.params.category;
    const fksServices = [
        // Same services array as above
    ];
    
    const filteredServices = fksServices.filter(service => 
        service.category.toLowerCase().includes(category.toLowerCase())
    );
    
    res.json(filteredServices);
});

// Trading system status endpoint
app.get('/api/trading-status', (req, res) => {
    res.json({
        status: 'operational',
        timestamp: new Date().toISOString(),
        markets: {
            futures: 'open',
            forex: 'open',
            stocks: 'closed'
        },
        fks_addon: {
            status: 'running',
            version: '1.0.0',
            last_build: new Date().toISOString()
        },
        performance: {
            cpu: '15%',
            memory: '2.1GB',
            uptime: '24h 15m'
        }
    });
});

// Build project endpoint - updated for your SDK-style project
app.post('/api/build', (req, res) => {
    console.log('Build request received');
    
    // Clean previous builds first
    const cleanCommand = 'cd /workspace/src && dotnet clean FKS.csproj -c Release';
    
    exec(cleanCommand, (cleanError) => {
        if (cleanError) {
            console.log('Clean warning (non-critical):', cleanError.message);
        }
        
        // Main build command
        const buildCommand = 'cd /workspace/src && dotnet build FKS.csproj -c Release --verbosity normal';
        
        exec(buildCommand, { 
            maxBuffer: 2 * 1024 * 1024, // 2MB buffer
            timeout: 120000 // 2 minute timeout
        }, (error, stdout, stderr) => {
            const buildOutput = {
                success: !error,
                stdout: stdout || '',
                stderr: stderr || '',
                timestamp: new Date().toISOString()
            };
            
            if (error) {
                console.error('Build error:', error.message);
                buildOutput.error = error.message;
                buildOutput.message = 'Build failed - check output for details';
                
                // Try to provide helpful error analysis
                if (stderr.includes('CS0234')) {
                    buildOutput.suggestion = 'Missing assembly references detected. Check project references.';
                } else if (stderr.includes('CS0104')) {
                    buildOutput.suggestion = 'Ambiguous type references detected. Check for duplicate class definitions.';
                } else if (stderr.includes('global using')) {
                    buildOutput.suggestion = '.NET Framework 4.8 does not support global using. Use regular using statements.';
                }
                
                return res.status(500).json(buildOutput);
            }
            
            buildOutput.message = 'Build completed successfully';
            console.log('Build completed successfully');
            res.json(buildOutput);
        });
    });
});

// Package addon endpoint - uses your PackageNT8 target exactly
app.post('/api/package', async (req, res) => {
    console.log('Package request received');
    
    try {
        // Use your custom PackageNT8 target
        const packageCommand = 'cd /workspace/src && dotnet build FKS.csproj --target PackageNT8 -c Release';
        
        exec(packageCommand, { 
            maxBuffer: 2 * 1024 * 1024,
            timeout: 120000
        }, async (error, stdout, stderr) => {
            if (error) {
                console.error('Package build error:', error.message);
                return res.status(500).json({ 
                    success: false, 
                    error: error.message,
                    stderr: stderr
                });
            }
            
            try {
                // Your PackageNT8 target creates structure in ../packages/temp
                const tempPackageDir = '/workspace/packages/temp';
                const zipPath = '/workspace/packages/fks_addon-final.zip';
                
                if (!fs.existsSync(tempPackageDir)) {
                    return res.status(500).json({
                        success: false,
                        error: 'PackageNT8 target did not create expected temp directory',
                        expectedPath: tempPackageDir,
                        availableDirs: fs.existsSync('/workspace/packages') ? 
                            fs.readdirSync('/workspace/packages') : ['packages directory not found']
                    });
                }
                
                // Also copy the compiled DLL to the package
                const dllSource = '/workspace/bin/Release/FKS.dll';
                const dllDest = path.join(tempPackageDir, 'bin', 'FKS.dll');
                
                if (fs.existsSync(dllSource)) {
                    // Ensure bin directory exists in package
                    const binDir = path.join(tempPackageDir, 'bin');
                    if (!fs.existsSync(binDir)) {
                        fs.mkdirSync(binDir, { recursive: true });
                    }
                    fs.copyFileSync(dllSource, dllDest);
                    console.log('Copied compiled DLL to package');
                }
                
                const output = fs.createWriteStream(zipPath);
                const archive = archiver('zip', { zlib: { level: 9 } });

                output.on('close', () => {
                    console.log(`Final package created: ${archive.pointer()} bytes`);
                    res.json({ 
                        success: true, 
                        message: 'Addon packaged successfully using PackageNT8 target',
                        path: zipPath,
                        size: archive.pointer(),
                        buildOutput: stdout,
                        files: getPackageContents(tempPackageDir)
                    });
                });

                output.on('error', (err) => {
                    console.error('Output stream error:', err);
                    res.status(500).json({ success: false, error: err.message });
                });

                archive.on('error', (err) => {
                    console.error('Archive error:', err);
                    res.status(500).json({ success: false, error: err.message });
                });

                archive.pipe(output);
                
                // Add the entire temp package directory to ZIP
                archive.directory(tempPackageDir, false);
                
                await archive.finalize();
                
            } catch (zipError) {
                console.error('ZIP creation error:', zipError);
                res.status(500).json({ success: false, error: zipError.message });
            }
        });
        
    } catch (error) {
        console.error('Package error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Helper function to get package contents
function getPackageContents(dir) {
    const contents = {};
    
    function scanDir(currentDir, relativePath = '') {
        if (!fs.existsSync(currentDir)) return;
        
        const items = fs.readdirSync(currentDir, { withFileTypes: true });
        contents[relativePath || 'root'] = items.map(item => ({
            name: item.name,
            isDirectory: item.isDirectory(),
            size: item.isFile() ? fs.statSync(path.join(currentDir, item.name)).size : null
        }));
        
        items.forEach(item => {
            if (item.isDirectory()) {
                const subPath = path.join(relativePath, item.name);
                scanDir(path.join(currentDir, item.name), subPath);
            }
        });
    }
    
    scanDir(dir);
    return contents;
}

// Download endpoint - updated paths
app.get('/api/download/:filename', (req, res) => {
    const filename = req.params.filename;
    let filePath;
    
    // Try multiple possible locations
    const possiblePaths = [
        path.join('/workspace/packages', filename),
        path.join('/workspace/packages', 'fks_addon-final.zip'),
        path.join('/workspace/bin/Release', filename)
    ];
    
    for (const testPath of possiblePaths) {
        if (fs.existsSync(testPath)) {
            filePath = testPath;
            break;
        }
    }
    
    console.log(`Download request for: ${filename}, found at: ${filePath}`);
    
    if (filePath && fs.existsSync(filePath)) {
        res.download(filePath, 'fks_trading-system.zip');
    } else {
        res.status(404).json({ 
            error: 'File not found',
            searched: possiblePaths,
            available: fs.existsSync('/workspace/packages') ? 
                fs.readdirSync('/workspace/packages') : ['packages directory not found']
        });
    }
});

// Download external DLL package endpoint
app.get('/api/download/external-dll', (req, res) => {
    console.log('External DLL package download requested');
    
    const packagePath = path.join('/workspace', 'packages', 'FKS_TradingSystem_v1.0.0_External_DLL.zip');
    
    // Check if package exists
    if (!fs.existsSync(packagePath)) {
        console.log('Package not found, attempting to build...');
        
        // Build the package first
        const buildCommand = 'cd /workspace/src && dotnet msbuild FKS.csproj -t:PackageNT8 -p:Configuration=Release && cd ../packages && zip -r FKS_TradingSystem_v1.0.0_External_DLL.zip temp/';
        
        exec(buildCommand, { timeout: 60000 }, (error, stdout, stderr) => {
            if (error) {
                console.error('Package build failed:', error.message);
                return res.status(500).json({ 
                    error: 'Failed to build package', 
                    details: error.message,
                    stdout: stdout,
                    stderr: stderr
                });
            }
            
            // Try to send the file again
            if (fs.existsSync(packagePath)) {
                console.log('Package built successfully, sending file...');
                res.download(packagePath, 'FKS_TradingSystem_v1.0.0_External_DLL.zip', (err) => {
                    if (err) {
                        console.error('Download error:', err);
                        res.status(500).json({ error: 'Download failed' });
                    }
                });
            } else {
                res.status(500).json({ error: 'Package build completed but file not found' });
            }
        });
    } else {
        console.log('Sending existing package file...');
        
        // Send file info
        const stats = fs.statSync(packagePath);
        const fileSizeInBytes = stats.size;
        const fileSizeInMB = (fileSizeInBytes / (1024 * 1024)).toFixed(2);
        
        console.log(`Package size: ${fileSizeInMB}MB`);
        
        res.download(packagePath, 'FKS_TradingSystem_v1.0.0_External_DLL.zip', (err) => {
            if (err) {
                console.error('Download error:', err);
                res.status(500).json({ error: 'Download failed' });
            } else {
                console.log('Package download completed successfully');
            }
        });
    }
});

// Get package info endpoint
app.get('/api/package/info', (req, res) => {
    const packagePath = path.join('/workspace', 'packages', 'FKS_TradingSystem_v1.0.0_External_DLL.zip');
    
    if (fs.existsSync(packagePath)) {
        const stats = fs.statSync(packagePath);
        res.json({
            exists: true,
            name: 'FKS_TradingSystem_v1.0.0_External_DLL.zip',
            size: stats.size,
            sizeMB: (stats.size / (1024 * 1024)).toFixed(2),
            modified: stats.mtime,
            type: 'External Development DLL Package',
            description: 'Complete FKS Trading Systems package for external development and NinjaTrader 8 import'
        });
    } else {
        res.json({
            exists: false,
            message: 'Package not found. Build the project first.'
        });
    }
});

// List available files endpoint
app.get('/api/files', (req, res) => {
    const dirs = ['/workspace/packages', '/workspace/bin', '/workspace/src'];
    const files = {};
    
    dirs.forEach(dir => {
        if (fs.existsSync(dir)) {
            files[dir] = fs.readdirSync(dir, { withFileTypes: true })
                .map(dirent => ({
                    name: dirent.name,
                    isDirectory: dirent.isDirectory(),
                    size: dirent.isFile() ? fs.statSync(path.join(dir, dirent.name)).size : null
                }));
        } else {
            files[dir] = ['Directory does not exist'];
        }
    });
    
    res.json(files);
});

// Template generation endpoint - updated for your file structure
app.post('/api/template', (req, res) => {
    const { type, fileName } = req.body;
    
    console.log(`Template request: ${type} -> ${fileName}`);
    
    const templates = {
        'ai_indicator': generateAIIndicatorTemplate(fileName),
        'basic_indicator': generateBasicIndicatorTemplate(fileName),
        'main_strategy': generateStrategyTemplate(fileName),
        'addon': generateAddonTemplate(fileName)
    };
    
    const templateContent = templates[type];
    if (!templateContent) {
        return res.status(400).json({ 
            success: false, 
            error: `Unknown template type: ${type}` 
        });
    }
    
    // Corrected: Determine target directory based on actual structure
    let targetDir;
    if (fileName.includes('Indicator') || type.includes('indicator')) {
        targetDir = '/workspace/src/Indicators';
    } else if (fileName.includes('Strategy') || type.includes('strategy')) {
        targetDir = '/workspace/src/Strategies';
    } else {
        // AddOns go in the AddOns subdirectory
        targetDir = '/workspace/src/AddOns';
    }
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
    }
    
    // Write template file
    const filePath = path.join(targetDir, fileName);
    try {
        fs.writeFileSync(filePath, templateContent);
        res.json({ 
            success: true, 
            message: `Template ${fileName} created successfully`,
            path: filePath,
            directory: targetDir
        });
    } catch (writeError) {
        res.status(500).json({
            success: false,
            error: `Failed to write template: ${writeError.message}`
        });
    }
});

// Template generation functions (updated for your structure)
function generateAIIndicatorTemplate(fileName) {
    const className = path.basename(fileName, '.cs');
    return `#region Using declarations
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Windows.Media;
using NinjaTrader.Cbi;
using NinjaTrader.Gui;
using NinjaTrader.Gui.Chart;
using NinjaTrader.Data;
using NinjaTrader.NinjaScript;
using NinjaTrader.Core.FloatingPoint;
using NinjaTrader.NinjaScript.DrawingTools;
#endregion

namespace NinjaTrader.NinjaScript.Indicators
{
    public class ${className} : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"${className} - AI-powered indicator";
                Name = "${className}";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                DisplayInDataBox = true;
                DrawOnPricePanel = false;
                PaintPriceMarkers = true;
                ScaleJustification = NinjaTrader.Gui.Chart.ScaleJustification.Right;
                IsSuspendedWhileInactive = true;
                
                AddPlot(Brushes.Orange, "Signal");
            }
        }

        protected override void OnBarUpdate()
        {
            if (CurrentBar < 20) return;
            
            // AI logic here
            Value[0] = Close[0];
        }

        [Browsable(false)]
        [XmlIgnore]
        public Series<double> Signal => Values[0];
    }
}`;
}

function generateBasicIndicatorTemplate(fileName) {
    const className = path.basename(fileName, '.cs');
    return `#region Using declarations
using System;
using System.ComponentModel;
using System.Windows.Media;
using NinjaTrader.NinjaScript;
using NinjaTrader.NinjaScript.Indicators;
#endregion

namespace NinjaTrader.NinjaScript.Indicators
{
    public class ${className} : Indicator
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"${className} - Basic indicator";
                Name = "${className}";
                Calculate = Calculate.OnBarClose;
                IsOverlay = false;
                
                AddPlot(Brushes.Blue, "Value");
            }
        }

        protected override void OnBarUpdate()
        {
            Value[0] = Close[0];
        }

        [Browsable(false)]
        public Series<double> Value => Values[0];
    }
}`;
}

function generateStrategyTemplate(fileName) {
    const className = path.basename(fileName, '.cs');
    return `#region Using declarations
using System;
using System.ComponentModel;
using NinjaTrader.Cbi;
using NinjaTrader.NinjaScript;
using NinjaTrader.NinjaScript.Strategies;
#endregion

namespace NinjaTrader.NinjaScript.Strategies
{
    public class ${className} : Strategy
    {
        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = @"${className} - FKS Trading Strategy";
                Name = "${className}";
                Calculate = Calculate.OnBarClose;
                EntriesPerDirection = 1;
                EntryHandling = EntryHandling.AllEntries;
                IsExitOnSessionCloseStrategy = true;
                ExitOnSessionCloseSeconds = 30;
                IsFillLimitOnTouch = false;
                MaximumBarsLookBack = MaximumBarsLookBack.TwoHundredFiftySix;
                OrderFillResolution = OrderFillResolution.Standard;
                Slippage = 0;
                StartBehavior = StartBehavior.WaitUntilFlat;
                TimeInForce = TimeInForce.Gtc;
                TraceOrders = false;
                RealtimeErrorHandling = RealtimeErrorHandling.StopCancelClose;
                StopTargetHandling = StopTargetHandling.PerEntryExecution;
                BarsRequiredToTrade = 20;
                IsInstantiatedOnEachOptimizationIteration = true;
            }
        }

        protected override void OnBarUpdate()
        {
            if (CurrentBar < BarsRequiredToTrade) return;
            
            // Strategy logic here
        }
    }
}`;
}

function generateAddonTemplate(fileName) {
    const className = path.basename(fileName, '.cs');
    return `#region Using declarations
using System;
using System.ComponentModel;
using NinjaTrader.NinjaScript;
#endregion

namespace NinjaTrader.NinjaScript.AddOns
{
    public class ${className}
    {
        public ${className}()
        {
            // AddOn initialization
        }
    }
}`;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FKS Build API running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
    console.log(`Project structure: /workspace/src/FKS.csproj`);
    console.log(`Output: /workspace/packages/`);
});

process.on('SIGINT', () => {
    console.log('Shutting down Build API...');
    process.exit(0);
});