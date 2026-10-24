#!/usr/bin/env bash
set -e

echo "============================================================"
echo "          PHISHGUARD AGENT - ONE-CLICK STARTUP"
echo "============================================================"

# 1. Virtual Environment Setup
if [ ! -f "backend/.venv/bin/python" ]; then
    echo "[*] Creating Python virtual environment in backend/.venv..."
    python3 -m venv backend/.venv
fi

echo "[*] Installing / verifying backend dependencies..."
backend/.venv/bin/python -m pip install -r backend/requirements.txt --quiet

# 2. Check and Prepare Dataset & ML Model
if [ ! -f "backend/models/phishguard_model.joblib" ]; then
    echo "[*] No trained ML model found. Initializing dataset acquisition and model training..."
    if [ ! -f "backend/data/dataset.csv" ]; then
        backend/.venv/bin/python scripts/fetch_datasets.py
    fi
    backend/.venv/bin/python backend/ml/train.py
fi

# 3. Frontend Installation & Build
if [ ! -d "frontend/node_modules" ]; then
    echo "[*] Installing frontend npm packages..."
    (cd frontend && npm install)
fi

if [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Building production frontend bundle..."
    (cd frontend && npm run build)
fi

# 4. Start Application
echo "============================================================"
echo "[*] PhishGuard Agent is starting!"
echo "[*] Access the Web UI at: http://127.0.0.1:8000"
echo "============================================================"

backend/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
