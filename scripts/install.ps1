# apkdec first-run installer for Windows.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#   (or just double-click scripts\install.bat)
#
# - verifies Python 3.8+
# - installs the `apkdec` command (pipx if available, else pip --user / venv)
# - optionally creates a Desktop shortcut that opens the interactive wizard
# - runs a health check
param(
    [switch]$NoShortcut
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # repo root = parent of scripts\

Write-Host "==> apkdec installer (Windows)"

# Find a working Python 3.8+. Prefer an active virtual environment, then the
# venv-aware `python`, and only then the global `py` launcher (which ignores
# venvs). The version probe also skips the broken Windows Store `python` alias.
$py = $null
if ($env:VIRTUAL_ENV) {
    $cand = Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe'
    if (Test-Path $cand) { $py = $cand }
}
if (-not $py) {
    foreach ($c in 'python', 'py') {
        if (Get-Command $c -ErrorAction SilentlyContinue) {
            try {
                & $c -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 8) else 1)' 2>$null
                if ($LASTEXITCODE -eq 0) { $py = $c; break }
            } catch {}
        }
    }
}
if (-not $py) {
    Write-Error "Python 3.8+ not found. Install from https://www.python.org/ (tick 'Add python.exe to PATH'), then reopen the terminal."
    exit 1
}
Write-Host "    Python: $(& $py --version)"

# Choose the best install method.
$inVenv = ((& $py -c 'import sys; print(1 if sys.prefix != sys.base_prefix else 0)') -eq '1')
if ($inVenv) {
    Write-Host "    Detected active virtual environment; installing into it."
    & $py -m pip install --upgrade $root
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    Write-Host "    Installing with pipx (isolated, auto-PATH)."
    pipx install --force $root
} else {
    Write-Host "    Installing with pip --user."
    & $py -m pip install --user --upgrade $root
}

# Optional Desktop shortcut that launches the interactive wizard.
if (-not $NoShortcut) {
    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $lnkPath = Join-Path $desktop 'apkdec.lnk'
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($lnkPath)
        $sc.TargetPath = Join-Path $root 'apkdec.bat'
        $sc.WorkingDirectory = $root
        $sc.IconLocation = "$env:SystemRoot\System32\shell32.dll, 13"
        $sc.Description = 'apkdec - APK decompiler & inspector (interactive)'
        $sc.Save()
        Write-Host "    Desktop shortcut created: $lnkPath"
        Write-Host "    (double-click it to open the interactive wizard)"
    } catch {
        Write-Warning "Could not create desktop shortcut: $_"
    }
}

Write-Host "`n==> Health check"
try { apkdec doctor } catch { & $py -m apkdec doctor }

Write-Host "`n==> Done. Try:"
Write-Host "      apkdec wizard            # interactive menu"
Write-Host "      apkdec info  app.apk     # quick inspect"
Write-Host "      apkdec scan  app.apk     # security review"
