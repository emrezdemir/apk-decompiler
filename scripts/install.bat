@echo off
REM apkdec first-run installer for Windows - double-click this file.
REM It runs install.ps1, bypassing the PowerShell execution policy for this run only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
echo.
pause
