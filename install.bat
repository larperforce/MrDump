@echo off
setlocal
cd /d "%~dp0"
echo [MrDump] Creating Python virtual environment...
py -3 -m venv .venv
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 goto oldpython
echo [MrDump] Updating pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto fail
echo [MrDump] Installing Textual interface and PE parser...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo.
echo [MrDump] Installation completed. Run run.bat.
pause
exit /b 0
:oldpython
echo [MrDump] Python 3.10 or later is required.
goto fail
:fail
echo.
echo [MrDump] Installation failed. Check Python 3.10+ and internet access.
pause
exit /b 1
