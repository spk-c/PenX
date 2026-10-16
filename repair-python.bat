@echo off
setlocal EnableExtensions
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
title PenX - Repair Python Dependencies

echo [*] Repairing only the PenX Python environment. Scanners are NOT reinstalled.
where py >nul 2>&1
if not errorlevel 1 goto :use_launcher
where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python not found. Install Python 3.13 and retry.
  pause
  exit /b 1
)
python windows_python_setup.py
if errorlevel 1 goto :fail
goto :check

:use_launcher
py -3 windows_python_setup.py
if errorlevel 1 goto :fail

:check
echo.
echo [*] Checking PenX and existing scanner installations...
".venv\Scripts\python.exe" windows_check.py
if errorlevel 1 (
  echo [WARN] Some scanner or configuration checks did not pass.
  echo [INFO] Core Python imports were repaired successfully.
  pause
  exit /b 2
)
echo [OK] PenX is ready. Start it with PenX.bat.
pause
exit /b 0

:fail
echo [ERROR] Python repair failed; see the log above.
pause
exit /b 1
