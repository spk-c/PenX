@echo off
setlocal EnableExtensions
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
title PenX Windows
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing. Run install-windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" penx.py --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python packages are missing or incompatible.
  echo         Run repair-python.bat to fix the environment.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" penx.py
if errorlevel 1 (
  echo.
  echo [ERROR] PenX exited with an error. See details above.
  pause
  exit /b 1
)
exit /b 0
