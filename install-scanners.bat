@echo off
setlocal
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
title PenX - All Scanner Setup
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Run install-windows.bat first.
  pause
  exit /b 1
)
echo [*] Installing missing Nmap/Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder and Katana...
".venv\Scripts\python.exe" install_scanners_windows.py
set "result=%errorlevel%"
echo.
".venv\Scripts\python.exe" windows_check.py
if errorlevel 1 (
  echo [WARN] Component verification failed after scanner setup.
  if "%result%"=="0" set "result=2"
)
pause
exit /b %result%
