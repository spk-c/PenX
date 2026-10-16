@echo off
setlocal EnableExtensions
set PYTHONUTF8=1
chcp 65001 >nul
cd /d "%~dp0"
title PenX - Windows EXE Build

echo ======================================
echo   PenX - Build standalone EXE folder
echo ======================================
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Run install-windows.bat first.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" penx.py --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Incompatible Python dependencies. Run repair-python.bat first.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m pip install -r requirements-build.txt
if errorlevel 1 goto :fail
".venv\Scripts\python.exe" scripts\build_windows.py --clean
if errorlevel 1 goto :fail

if not exist "dist\PenX\PenX.exe" goto :fail
if not exist "dist\PenX\vendor" mkdir "dist\PenX\vendor"
if exist "vendor\whatweb\whatweb" xcopy "vendor\whatweb" "dist\PenX\vendor\whatweb\" /E /I /Y >nul
if exist "vendor\nikto\program\nikto.pl" xcopy "vendor\nikto" "dist\PenX\vendor\nikto\" /E /I /Y >nul
copy /Y ".env.example" "dist\PenX\.env.example" >nul
if not exist "dist\PenX\data" mkdir "dist\PenX\data"

"dist\PenX\PenX.exe" --version
if errorlevel 1 goto :fail
"dist\PenX\PenX.exe" --setup-status
if errorlevel 1 goto :fail

echo.
echo [OK] Built dist\PenX\PenX.exe
echo [NOTE] External scanners can be installed on first EXE start after approval.
echo [NOTE] Your .env and scan history are deliberately NOT copied into dist.
echo [NOTE] First interactive EXE start guides local LLM setup if missing.
echo [NOTE] To share the app, zip the complete dist\PenX folder, not just the EXE.
pause
exit /b 0

:fail
echo [FAIL] Build unsuccessful. Check PyInstaller and Python messages above.
pause
exit /b 1
