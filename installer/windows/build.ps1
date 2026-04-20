# TorchSight — Windows installer build script
# Run from installer\windows\ on a Windows machine with:
#   - Rust toolchain (x86_64-pc-windows-msvc)
#   - Inno Setup 6.3+ (ISCC.exe on PATH or at default location)
#
# Usage: .\build.ps1 [-Version <ver>] [-SkipCargo]

param(
    [string]$Version   = "",
    [switch]$SkipCargo
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$staging   = Join-Path $scriptDir "staging"
$dist      = Join-Path $scriptDir "dist"

if (-not $Version) {
    $Version = (Get-Content (Join-Path $repoRoot "VERSION") -Raw).Trim()
}
Write-Host "  Building TorchSight Windows installer for v$Version" -ForegroundColor Cyan

# ── 1. Build the Rust binary (unless skipped) ─────────────────────────────
if (-not $SkipCargo) {
    Write-Host "  [1/4] cargo build --release (x86_64-pc-windows-msvc)..." -ForegroundColor Cyan
    Push-Location $repoRoot
    try {
        & cargo build --release --target x86_64-pc-windows-msvc -p torchsight
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}

# ── 2. Stage files next to the .iss ───────────────────────────────────────
Write-Host "  [2/4] Staging files..." -ForegroundColor Cyan
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force -Path $staging | Out-Null
New-Item -ItemType Directory -Force -Path $dist    | Out-Null

$exeCandidates = @(
    (Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release\torchsight.exe"),
    (Join-Path $repoRoot "target\release\torchsight.exe")
)
$exe = $exeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "torchsight.exe not found. Run without -SkipCargo or build it manually." }

Copy-Item $exe                                                      (Join-Path $staging "torchsight.exe")
Copy-Item (Join-Path $scriptDir "pull-models.ps1")                  (Join-Path $staging "pull-models.ps1")
Copy-Item (Join-Path $repoRoot "desktop\src-tauri\icons\icon.ico") (Join-Path $staging "icon.ico")
Copy-Item (Join-Path $repoRoot "LICENSE")                          (Join-Path $staging "LICENSE.txt")
Copy-Item (Join-Path $repoRoot "desktop\src-tauri\icons\icon.ico") (Join-Path $scriptDir "icon.ico")     -Force
Copy-Item (Join-Path $repoRoot "LICENSE")                          (Join-Path $scriptDir "LICENSE.txt") -Force

# ── 3. Locate ISCC.exe ────────────────────────────────────────────────────
Write-Host "  [3/4] Locating Inno Setup..." -ForegroundColor Cyan
$iscc = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
    )
    $iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) { throw "ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php" }

# ── 4. Compile the installer ──────────────────────────────────────────────
Write-Host "  [4/4] Compiling installer..." -ForegroundColor Cyan
Push-Location $scriptDir
try {
    & $iscc "/DMyAppVersion=$Version" "torchsight-setup.iss"
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
} finally {
    Pop-Location
}

$out = Join-Path $dist "TorchSight-Setup-$Version.exe"
Write-Host ""
Write-Host "  Done -> $out" -ForegroundColor Green
Write-Host ""
