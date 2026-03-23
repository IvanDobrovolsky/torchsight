# TorchSight Windows Installer
# Run: irm https://torchsight.io/install.ps1 | iex

$ErrorActionPreference = "Stop"

$VERSION = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/IvanDobrovolsky/torchsight/main/VERSION" -UseBasicParsing).Content.Trim()
$TAG = "v$VERSION"
$REPO = "https://github.com/IvanDobrovolsky/torchsight/releases/download/$TAG"
$TEXT_MODEL = if ($env:TORCHSIGHT_TEXT_MODEL) { $env:TORCHSIGHT_TEXT_MODEL } else { "torchsight/beam" }
$VISION_MODEL = if ($env:TORCHSIGHT_VISION_MODEL) { $env:TORCHSIGHT_VISION_MODEL } else { "llama3.2-vision" }

function Info($msg)  { Write-Host "  >>> " -ForegroundColor Cyan -NoNewline; Write-Host $msg }
function Ok($msg)    { Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Warn($msg)  { Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Fail($msg)  { Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host $msg; exit 1 }

Write-Host ""
Write-Host "  TorchSight Installer" -ForegroundColor White
Write-Host "  On-Premise Security Scanner ($TAG)" -ForegroundColor DarkGray
Write-Host ""

# ── 1. Install Ollama ──────────────────────────────────────────────────────

$ollamaPath = Get-Command ollama -ErrorAction SilentlyContinue
if ($ollamaPath) {
    Ok "Ollama already installed"
} else {
    Info "Downloading Ollama installer..."
    $ollamaInstaller = "$env:TEMP\OllamaSetup.exe"
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $ollamaInstaller -UseBasicParsing
    Info "Installing Ollama (this may require admin)..."
    Start-Process -FilePath $ollamaInstaller -ArgumentList "/S" -Wait
    # Refresh PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if (Get-Command ollama -ErrorAction SilentlyContinue) {
        Ok "Ollama installed"
    } else {
        Warn "Ollama installed but not in PATH yet. Restart your terminal after this script."
    }
}

# ── 2. Install Tesseract OCR ──────────────────────────────────────────────

$tesseractPath = Get-Command tesseract -ErrorAction SilentlyContinue
if ($tesseractPath) {
    Ok "Tesseract OCR already installed"
} else {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Info "Installing Tesseract via Chocolatey..."
        choco install tesseract -y
        Ok "Tesseract installed"
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        Info "Installing Tesseract via winget..."
        winget install --id UB-Mannheim.TesseractOCR --accept-package-agreements --accept-source-agreements
        Ok "Tesseract installed"
    } else {
        Warn "Install Tesseract manually: https://github.com/UB-Mannheim/tesseract/wiki"
        Warn "Image scanning will be unavailable without Tesseract."
    }
}

# ── 3. Start Ollama service ───────────────────────────────────────────────

Info "Checking Ollama service..."
try {
    $null = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 3
    Ok "Ollama is running"
} catch {
    Info "Starting Ollama..."
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    try {
        $null = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 5
        Ok "Ollama started"
    } catch {
        Warn "Could not start Ollama. Run 'ollama serve' manually."
    }
}

# ── 4. Pull models ────────────────────────────────────────────────────────

Info "Pulling model: $TEXT_MODEL (this may take a while on first run)..."
& ollama pull $TEXT_MODEL
Ok "Model '$TEXT_MODEL' ready"

Info "Pulling vision model: $VISION_MODEL (for image analysis)..."
& ollama pull $VISION_MODEL
if ($LASTEXITCODE -eq 0) {
    Ok "Vision model '$VISION_MODEL' ready"
} else {
    Warn "Vision model pull failed. Image analysis will be unavailable."
}

# ── 5. Download TorchSight CLI ────────────────────────────────────────────

$installDir = "$env:LOCALAPPDATA\Programs\torchsight"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Info "Downloading TorchSight CLI ($TAG)..."
$cliUrl = "$REPO/torchsight-windows-x86_64.exe"
Invoke-WebRequest -Uri $cliUrl -OutFile "$installDir\torchsight.exe" -UseBasicParsing
Ok "Downloaded to $installDir\torchsight.exe"

# Add to user PATH
$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$installDir;$userPath", "User")
    $env:PATH = "$installDir;$env:PATH"
    Ok "Added to PATH"
} else {
    Ok "Already in PATH"
}

# ── 6. Download Desktop App (optional) ────────────────────────────────────

$desktopChoice = Read-Host "  Install desktop app? (Y/n)"
if ($desktopChoice -ne "n" -and $desktopChoice -ne "N") {
    Info "Downloading TorchSight Desktop installer..."
    $setupUrl = "$REPO/TorchSight_${VERSION}_x64-setup.exe"
    $setupPath = "$env:TEMP\TorchSight-setup.exe"
    Invoke-WebRequest -Uri $setupUrl -OutFile $setupPath -UseBasicParsing
    Info "Running installer..."
    Start-Process -FilePath $setupPath -Wait
    Ok "Desktop app installed"
}

# ── Done ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Usage:" -ForegroundColor DarkGray
Write-Host "    torchsight C:\path\to\scan" -ForegroundColor Cyan -NoNewline; Write-Host "     Scan files"
Write-Host "    torchsight" -ForegroundColor Cyan -NoNewline; Write-Host "                       Start REPL"
Write-Host "    torchsight --help" -ForegroundColor Cyan -NoNewline; Write-Host "                All options"
Write-Host ""
