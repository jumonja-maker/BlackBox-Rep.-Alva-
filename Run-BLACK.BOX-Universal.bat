@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo Python 3.11+ is required to run source. Portable EXE users need no Python.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3.11 -m venv ".venv"
  if errorlevel 1 (
    echo Could not create the virtual environment.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Desktop requirements installation failed.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 (
  echo BLACK.BOX observer core installation failed.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 pause
