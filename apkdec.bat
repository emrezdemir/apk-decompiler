@echo off
REM Zero-install launcher for Windows (double-click or run from a terminal).
REM   apkdec.bat info app.apk   run a command
REM   apkdec.bat                launch the interactive wizard
REM Requires only Python 3.8+ on PATH; no "pip install" needed.
setlocal
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
where py >nul 2>nul && (set "PYEXE=py -3") || (set "PYEXE=python")
%PYEXE% -m apkdec %*
set "RC=%ERRORLEVEL%"
REM Keep the window open when launched by double-click (no arguments).
if "%~1"=="" pause
endlocal & exit /b %RC%
