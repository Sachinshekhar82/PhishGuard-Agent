"""
FastAPI application entrypoint for PhishGuard Agent.
Provides RESTful APIs for single/batch URL analysis, interactive explanations,
history management, and model telemetry.
"""

import os
import json
import time
from typing import List
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.config import settings
from backend.app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    ExplainChatRequest,
    ExplainChatResponse,
    HealthResponse,
    HistoryItem
)
from backend.app.db import init_db, save_history, get_history, clear_history
from backend.app.agent.orchestrator import PhishGuardAgent
from backend.app.agent.tools.ml_model import get_model
from backend.app.agent.llm import chat_about_analysis

# In-memory sliding window rate limiter (simple per-client IP protection)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 120  # requests per window
_request_records = {}


def check_rate_limit(request: Request):
    """Enforces basic IP-based rate limiting to prevent denial of service."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    records = _request_records.get(client_ip, [])
    # Filter records within current window
    records = [t for t in records if now - t < RATE_LIMIT_WINDOW]
    if len(records) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait a minute before submitting further analysis requests."
        )
    records.append(now)
    _request_records[client_ip] = records


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events."""
    # 1. Initialize SQLite Database
    init_db()

    # 2. Check if trained model exists, else trigger auto-training
    if not settings.MODEL_PATH.exists():
        print("No trained ML model found at", settings.MODEL_PATH)
        print("Initiating automatic dataset acquisition and model training...")
        try:
            from backend.ml.train import train_and_evaluate
            train_and_evaluate()
            print("Auto-training successfully completed.")
        except Exception as e:
            print(f"Warning: Auto-training encountered an error: {e}")
    else:
        # Preload model in memory
        get_model()

    yield


app = FastAPI(
    title="PhishGuard Agent API",
    description="Agentic AI-based Phishing URL Detection & Analysis System (Defensive Tool)",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local Vite dev server and web frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = PhishGuardAgent()


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Returns application health and configuration readiness."""
    model_loaded = (get_model() is not None)
    llm_enabled = bool(settings.ENABLE_LLM_EXPLANATION and settings.GEMINI_API_KEY)
    return HealthResponse(
        status="ok",
        model_loaded=model_loaded,
        offline_mode_default=False,
        llm_enabled=llm_enabled,
        version="1.0.0"
    )


@app.post("/api/analyze", response_model=AnalyzeResponse, dependencies=[Depends(check_rate_limit)])
async def analyze_url(payload: AnalyzeRequest):
    """
    Analyzes a single URL locally using the multi-tool Agentic AI loop.
    Never fetches or executes the remote page.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    try:
        response = agent.analyze(
            raw_url=raw_url,
            offline_mode=bool(payload.offline_mode),
            ai_explanation_requested=bool(payload.ai_explanation)
        )

        # Record analysis in database history
        top_reasons = [r.reason for r in response.reasons[:3]]
        save_history(
            url=response.url,
            verdict=response.verdict,
            risk_score=response.risk_score,
            confidence=response.confidence,
            summary=response.summary,
            top_reasons=top_reasons,
            offline_mode=bool(payload.offline_mode)
        )

        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@app.post("/api/analyze/batch", response_model=BatchAnalyzeResponse, dependencies=[Depends(check_rate_limit)])
async def analyze_batch(payload: BatchAnalyzeRequest):
    """
    Analyzes up to 50 URLs in a single batch request.
    """
    if len(payload.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum batch size is 50 URLs.")

    results: List[AnalyzeResponse] = []
    for raw_url in payload.urls:
        clean = raw_url.strip()
        if not clean:
            continue
        try:
            res = agent.analyze(
                raw_url=clean,
                offline_mode=bool(payload.offline_mode),
                ai_explanation_requested=False
            )
            top_reasons = [r.reason for r in res.reasons[:3]]
            save_history(
                url=res.url,
                verdict=res.verdict,
                risk_score=res.risk_score,
                confidence=res.confidence,
                summary=res.summary,
                top_reasons=top_reasons,
                offline_mode=bool(payload.offline_mode)
            )
            results.append(res)
        except Exception:
            # Handle invalid single URL in batch gracefully
            pass

    return BatchAnalyzeResponse(
        total=len(results),
        results=results
    )


@app.post("/api/explain-chat", response_model=ExplainChatResponse)
async def chat_explanation(payload: ExplainChatRequest):
    """
    Provides interactive conversational follow-ups about an analyzed URL via Gemini LLM.
    Strictly isolated from verdict generation.
    """
    reply = chat_about_analysis(
        url=payload.url,
        analysis_summary=payload.analysis_summary,
        user_message=payload.user_message,
        history=payload.history
    )
    return ExplainChatResponse(reply=reply)


@app.get("/api/history", response_model=List[HistoryItem])
async def list_history():
    """Retrieves recent URL analysis history records from SQLite."""
    return get_history(limit=50)


@app.delete("/api/history")
async def delete_history():
    """Clears all stored analysis history."""
    clear_history()
    return {"status": "success", "message": "History cleared"}


@app.get("/api/metrics")
async def get_model_metrics():
    """
    Returns trained model evaluation results, slice tests, feature importances,
    and dataset provenance.
    """
    metrics_path = settings.METRICS_PATH
    dataset_info_path = settings.DATA_DIR / "dataset_info.json"

    metrics_data = {}
    dataset_info = {}

    if metrics_path.exists():
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception as e:
            metrics_data = {"error": f"Failed to read metrics: {str(e)}"}
    else:
        metrics_data = {"status": "Model not yet trained or metrics missing"}

    if dataset_info_path.exists():
        try:
            with open(dataset_info_path, "r", encoding="utf-8") as f:
                dataset_info = json.load(f)
        except Exception as e:
            dataset_info = {"error": f"Failed to read dataset info: {str(e)}"}
    else:
        dataset_info = {"status": "Dataset info not available"}

    return {
        "model_metrics": metrics_data,
        "dataset_info": dataset_info
    }


# Mount Frontend static assets if built
FRONTEND_DIST = settings.BASE_DIR.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="static_assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't hijack API routes
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API endpoint not found")
        target_file = FRONTEND_DIST / full_path
        if target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(FRONTEND_DIST / "index.html")

