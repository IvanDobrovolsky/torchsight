# TorchSight desktop — post-install bootstrap
# Invoked by NSIS_HOOK_POSTINSTALL in a visible window so the user sees
# Ollama and Tesseract installer progress and the ~20 GB model pulls.

$ErrorActionPreference = 'Continue'

$OllamaUrl   = 'https://ollama.com/download/OllamaSetup.exe'
$TesseractUrl = 'https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe'

function Have-Ollama {
    if (Get-Command ollama -ErrorAction SilentlyContinue) { return $true }
    return (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe")
}

function Have-Tesseract {
    if (Get-Command tesseract -ErrorAction SilentlyContinue) { return $true }
    if (Test-Path "$env:ProgramFiles\Tesseract-OCR\tesseract.exe")        { return $true }
    if (Test-Path "${env:ProgramFiles(x86)}\Tesseract-OCR\tesseract.exe") { return $true }
    return $false
}

Write-Host ""
Write-Host "  TorchSight is finishing setup." -ForegroundColor Cyan
Write-Host "  You can close this window any time — TorchSight will pull missing pieces on first scan." -ForegroundColor DarkGray
Write-Host ""

# ── Ollama ────────────────────────────────────────────────────────────
if (Have-Ollama) {
    Write-Host "  [skip] Ollama already installed." -ForegroundColor DarkGray
} else {
    Write-Host "  [1/3] Downloading Ollama..." -ForegroundColor Cyan
    $tmp = Join-Path $env:TEMP "OllamaSetup.exe"
    try {
        Invoke-WebRequest -Uri $OllamaUrl -OutFile $tmp -UseBasicParsing
        Write-Host "         Installing..." -ForegroundColor Cyan
        Start-Process -FilePath $tmp -ArgumentList '/S' -Wait
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Ollama install failed: $_" -ForegroundColor Yellow
    }
}

# ── Tesseract ─────────────────────────────────────────────────────────
if (Have-Tesseract) {
    Write-Host "  [skip] Tesseract already installed." -ForegroundColor DarkGray
} else {
    Write-Host "  [2/3] Downloading Tesseract OCR..." -ForegroundColor Cyan
    $tmp = Join-Path $env:TEMP "TesseractSetup.exe"
    try {
        Invoke-WebRequest -Uri $TesseractUrl -OutFile $tmp -UseBasicParsing
        Write-Host "         Installing..." -ForegroundColor Cyan
        Start-Process -FilePath $tmp -ArgumentList '/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES' -Wait
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Tesseract install failed: $_" -ForegroundColor Yellow
    }
}

# ── Models ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [3/3] Pulling models (~20 GB, one-time)..." -ForegroundColor Cyan
$pullScript = Join-Path $PSScriptRoot "pull-models.ps1"
if (Test-Path $pullScript) {
    & $pullScript
} else {
    Write-Host "  pull-models.ps1 not found at $pullScript" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Setup complete. Launch TorchSight from the Start Menu." -ForegroundColor Green
Start-Sleep -Seconds 5
