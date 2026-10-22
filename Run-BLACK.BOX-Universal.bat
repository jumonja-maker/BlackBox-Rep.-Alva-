@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo Python 3.11+ is needed to run from source. For ordinary users, download the portable EXE from GitHub Actions.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3.11 -m venv ".venv"
  if errorlevel 1 (
    echo Could not create Python virtual environment.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 pause
