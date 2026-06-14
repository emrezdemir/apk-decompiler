# Zero-install launcher for PowerShell (Windows / macOS / Linux).
#   ./apkdec.ps1 info app.apk   run a command
#   ./apkdec.ps1                 launch the interactive wizard
# Requires only Python 3.8+; no `pip install` needed.
$src = Join-Path $PSScriptRoot 'src'
$env:PYTHONPATH = $src + [IO.Path]::PathSeparator + $env:PYTHONPATH
$py = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }
& $py -m apkdec @args
exit $LASTEXITCODE
