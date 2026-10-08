$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.13 -m venv .venv
    } else {
        & python -m venv .venv
    }
}

& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

Write-Host "Running deterministic POC test suite..." -ForegroundColor Cyan
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) {
    throw "POC test suite failed."
}

Write-Host "Running Python compilation check..." -ForegroundColor Cyan
& $python -m compileall -q agent app evidence evaluation policy report tools validation tests
if ($LASTEXITCODE -ne 0) {
    throw "Python compilation failed."
}

Write-Host "Running offline baseline-vs-agentic evaluation..." -ForegroundColor Cyan
& $python -m evaluation.run_evaluation
if ($LASTEXITCODE -ne 0) {
    throw "Evaluation harness failed."
}

Write-Host "" 
Write-Host "All deterministic tests, compilation checks, and offline evaluation passed." -ForegroundColor Green
Write-Host "For the live demo, start Juice Shop and run .\run_poc.ps1." -ForegroundColor Yellow
