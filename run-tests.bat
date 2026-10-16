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
".venv\Scripts\python.exe" offline_tests.py
if errorlevel 1 goto :fail
pause
exit /b 0
:fail
echo [FAIL] An offline test suite failed.
pause
exit /b 1
