@echo off
setlocal EnableExtensions
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Run install-windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" windows_check.py
if errorlevel 1 (
  echo [WARN] PenX check failed. To repair Python packages, run repair-python.bat.
  pause
  exit /b 1
)
pause
exit /b 0
