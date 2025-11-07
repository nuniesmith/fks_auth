# Quick start script for just the API services
Write-Host "Starting FKS Development Services..." -ForegroundColor Green

# Start Python API server
Write-Host "Starting Python API server..." -ForegroundColor Green
Set-Location python
Start-Process -WindowStyle Hidden python -ArgumentList "main.py"

# Start VS Code server proxy  
Write-Host "Starting VS Code proxy server..." -ForegroundColor Green
Set-Location ..
Start-Process -WindowStyle Hidden node -ArgumentList "vscode-proxy.js"

Write-Host "Services started in background!" -ForegroundColor Green
Write-Host "Python API: http://localhost:8002/healthz" -ForegroundColor Yellow
Write-Host "VS Code Proxy: http://localhost:8081/healthz" -ForegroundColor Yellow
Write-Host ""
Write-Host "Now you can start your React app with: npm start" -ForegroundColor Cyan
