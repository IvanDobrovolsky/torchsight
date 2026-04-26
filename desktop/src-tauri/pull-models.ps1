# TorchSight — post-install model pulls
# Invoked by torchsight-setup.iss in a visible console so users see Ollama's
# native progress bar while ~20GB downloads.

$ErrorActionPreference = "Stop"

$TextModel   = if ($env:TORCHSIGHT_TEXT_MODEL)   { $env:TORCHSIGHT_TEXT_MODEL }   else { "torchsight/beam" }
$VisionModel = if ($env:TORCHSIGHT_VISION_MODEL) { $env:TORCHSIGHT_VISION_MODEL } else { "llama3.2-vision" }

function Resolve-Ollama {
    $cmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $local = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
    if (Test-Path $local) { return $local }
    return $null
}

$ollama = Resolve-Ollama
if (-not $ollama) {
    Write-Host ""
    Write-Host "  Ollama is not on PATH yet. Open a new terminal and run:" -ForegroundColor Yellow
    Write-Host "    ollama pull $TextModel"
    Write-Host "    ollama pull $VisionModel"
    Write-Host ""
    Read-Host "  Press Enter to close"
    exit 0
}

function Wait-OllamaReady {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" `
                                      -UseBasicParsing -TimeoutSec 2
            return $true
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    return $false
}

# Make sure the Ollama service is running before pulling.
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" `
                              -UseBasicParsing -TimeoutSec 2
} catch {
    Write-Host "  Starting Ollama..." -ForegroundColor Cyan
    Start-Process -FilePath $ollama -ArgumentList "serve" -WindowStyle Hidden
    if (-not (Wait-OllamaReady)) {
        Write-Host "  Ollama did not start in time. Pulls may fail." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  TorchSight will now download two models." -ForegroundColor White
Write-Host "  This is a one-time download of roughly 20 GB." -ForegroundColor DarkGray
Write-Host "  You can close this window to skip — pulls resume automatically on first scan." -ForegroundColor DarkGray
Write-Host ""

Write-Host "  [1/2] Pulling text model: $TextModel" -ForegroundColor Cyan
& $ollama pull $TextModel
$textOk = ($LASTEXITCODE -eq 0)

Write-Host ""
Write-Host "  [2/2] Pulling vision model: $VisionModel" -ForegroundColor Cyan
& $ollama pull $VisionModel
$visionOk = ($LASTEXITCODE -eq 0)

Write-Host ""
if ($textOk -and $visionOk) {
    Write-Host "  All models ready. TorchSight is installed." -ForegroundColor Green
} else {
    if (-not $textOk)   { Write-Host "  Text model pull failed — retry with: ollama pull $TextModel"     -ForegroundColor Yellow }
    if (-not $visionOk) { Write-Host "  Vision model pull failed — retry with: ollama pull $VisionModel" -ForegroundColor Yellow }
}
Write-Host ""
Start-Sleep -Seconds 3
