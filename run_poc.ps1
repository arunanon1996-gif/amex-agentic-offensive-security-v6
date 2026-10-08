$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$python = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Creating Python 3.13 virtual environment..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.13 -m venv .venv
    } else {
        & python -m venv .venv
    }
}

if (-not (Test-Path $python)) {
    throw "Could not create the project virtual environment. Install Python 3.13+ and try again."
}

Write-Host "Installing POC dependencies..." -ForegroundColor Cyan
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Warning "Nmap is not on PATH. The dashboard will use its localhost-safe built-in TCP reconnaissance fallback; install Nmap to enable real service/version enumeration."
}

try {
    $juice = Invoke-WebRequest -Uri "http://127.0.0.1:3000" -UseBasicParsing -TimeoutSec 5
    if ($juice.StatusCode -ne 200) {
        Write-Warning "Juice Shop responded with HTTP $($juice.StatusCode)."
    } else {
        Write-Host "Juice Shop detected at http://127.0.0.1:3000" -ForegroundColor Green
    }
} catch {
    Write-Warning "Juice Shop was not detected at http://127.0.0.1:3000. Start your authorized Juice Shop sandbox before running an assessment."
}

Write-Host "" 
Write-Host "Starting AMEX Agentic Offensive Security POC..." -ForegroundColor Cyan
Write-Host "Dashboard: http://127.0.0.1:5000" 
Write-Host "Scope: localhost / 127.0.0.1 only" 
Write-Host "Stop: Ctrl+C" 
Write-Host "" 

& $python -m app.main
