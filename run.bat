@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo           PHISHGUARD AGENT - ONE-CLICK STARTUP
echo ============================================================

:: 1. Python Virtual Environment Setup
if not exist "backend\.venv\Scripts\python.exe" (
    echo [*] Creating Python virtual environment in backend\.venv...
    python -m venv backend\.venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment. Ensure Python 3.11+ is installed.
        exit /b 1
    )
)

echo [*] Installing / verifying backend dependencies...
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt --quiet

:: 2. Check and Prepare Dataset & ML Model
if not exist "backend\models\phishguard_model.joblib" (
    echo [*] No trained ML model found. Initializing dataset acquisition and model training...
    if not exist "backend\data\dataset.csv" (
        backend\.venv\Scripts\python.exe scripts\fetch_datasets.py
    )
    backend\.venv\Scripts\python.exe backend\ml\train.py
)

:: 3. Frontend Installation & Build
if not exist "frontend\node_modules" (
    echo [*] Installing frontend npm packages...
    cd frontend
    call npm.cmd install
    cd ..
)

if not exist "frontend\dist\index.html" (
    echo [*] Building production frontend bundle...
    cd frontend
    call npm.cmd run build
    cd ..
)

:: 4. Start Application
echo ============================================================
echo [*] PhishGuard Agent is starting!
echo [*] Access the Web UI at: http://127.0.0.1:8000
echo [*] (Optional) Vite Dev Server at: http://127.0.0.1:5173
echo ============================================================

:: Start Uvicorn Backend
backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
