@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [MrDump] Python environment not found. Run install.bat first.
  pause
  exit /b 1
)
if "%~1"=="" goto ask_target
set "TARGET=%~1"
goto launch
:ask_target
set /p "TARGET=Enter full path to the file to inspect: "
:launch
rem Remove quotes entered manually, then add one safe pair around the path.
set "TARGET=%TARGET:"=%"
if not defined TARGET (
  echo [MrDump] No file path was entered.
  pause
  exit /b 2
)
".venv\Scripts\python.exe" mrdump.py "%TARGET%"
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" echo [MrDump] Application exited with code %EXITCODE%.
pause
exit /b %EXITCODE%
