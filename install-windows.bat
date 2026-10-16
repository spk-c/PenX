@echo off
setlocal EnableExtensions
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
title PenX - Windows Setup

echo ==============================================
echo  PenX - Windows Installation and Repair
echo ==============================================
echo [*] Checking Python compatibility and .venv health...
where py >nul 2>&1
if not errorlevel 1 goto :launch_py
where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] No Python launcher found. Install Python 3.13:
  echo https://www.python.org/downloads/windows/
  goto :fail
)
python windows_python_setup.py
if errorlevel 1 goto :fail
goto :python_ready

:launch_py
py -3 windows_python_setup.py
if errorlevel 1 goto :fail

:python_ready
if not exist ".venv\Scripts\python.exe" goto :fail
if not exist ".env" (
  copy /Y ".env.example" ".env" >nul
  if errorlevel 1 (
    echo [ERROR] Could not create private .env configuration.
    goto :fail
  )
)

echo.
echo ==============================================
echo  Automatic setup: Nmap/Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder, Katana
echo  Official sources only; requires network and sometimes UAC.
echo ==============================================
".venv\Scripts\python.exe" install_scanners_windows.py
set "scanner_result=%errorlevel%"
if not "%scanner_result%"=="0" (
  echo [WARN] Some external scanners are missing or failed to install.
  echo [WARN] Run install-scanners.bat to retry all missing scanners.
) else (
  echo [OK] Nmap/Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder and Katana setup completed.
)

echo.
echo [*] Checking components and runtime imports...
".venv\Scripts\python.exe" windows_check.py
if errorlevel 1 (
  echo [WARN] Component checks failed. See details above.
  echo [WARN] Core Python dependencies passed bootstrap validation.
  pause
  exit /b 2
)
echo.
if not "%scanner_result%"=="0" (
  echo.
  echo [WARN] Python setup finished, but not all external scanners are ready.
  echo [WARN] Review the error messages above and retry install-scanners.bat.
  pause
  exit /b 2
)
echo [OK] PenX Windows installation and scanner setup verified.
echo First launch offers local LLM setup when .env is not yet configured.
echo Double-click start-windows.bat to launch PenX.
pause
exit /b 0

:fail
echo.
echo [ERROR] PenX Windows installation failed. Check the message above.
echo        Existing settings and scanner installations were not removed.
pause
exit /b 1
