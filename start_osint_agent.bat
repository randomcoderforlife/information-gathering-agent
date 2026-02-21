@echo off
setlocal

cd /d "%~dp0"

echo [OSINT Agent] Startup initiated...

where py >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py -3"
) else (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python was not found in PATH.
        echo Install Python 3 and try again.
        pause
        exit /b 1
    )
    set "PY_CMD=python"
)

if not exist ".venv\Scripts\python.exe" (
    echo [OSINT Agent] Creating virtual environment...
    %PY_CMD% -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [OSINT Agent] Activating virtual environment...
call ".venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

echo [OSINT Agent] Installing dependencies...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo [ERROR] Failed to upgrade pip.
    pause
    exit /b 1
)

pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

echo [OSINT Agent] Launching dashboard...
python -m streamlit run app.py
set "APP_EXIT_CODE=%errorlevel%"

if %APP_EXIT_CODE% neq 0 (
    echo [ERROR] Streamlit exited with code %APP_EXIT_CODE%.
    pause
)

exit /b %APP_EXIT_CODE%
