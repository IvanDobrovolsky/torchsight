; TorchSight desktop NSIS hooks
; Runs after the Tauri-built desktop app is installed.
; Spawns a visible PowerShell window that bootstraps Ollama + Tesseract
; and pulls the beam + vision models. Detached so the installer can finish
; while the (large) downloads continue.

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Setting up Ollama, Tesseract, and models in a separate window..."
  ExecShell "open" "powershell.exe" `-NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\installer-bootstrap.ps1"`
!macroend
