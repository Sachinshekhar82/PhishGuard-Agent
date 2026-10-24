"""
Machine Learning prediction tool for PhishGuard Agent.
Loads the trained Random Forest / Logistic Regression pipeline and computes phishing risk probability.
"""

import time
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import numpy as np

from backend.app.schemas import Evidence
from backend.app.config import settings
from backend.ml.features import features_to_vector, FEATURE_NAMES

# Cached model instance
_MODEL_PIPELINE: Optional[Any] = None
_MODEL_TIMESTAMP: float = 0.0


def get_model():
    """Loads and caches the trained ML model pipeline."""
    global _MODEL_PIPELINE, _MODEL_TIMESTAMP
    model_path = settings.MODEL_PATH
    if not model_path.exists():
        return None

    try:
        current_mtime = model_path.stat().st_mtime
        if _MODEL_PIPELINE is None or current_mtime > _MODEL_TIMESTAMP:
            _MODEL_PIPELINE = joblib.load(model_path)
            _MODEL_TIMESTAMP = current_mtime
        return _MODEL_PIPELINE
    except Exception as e:
        print(f"Warning: Failed to load ML model from {model_path}: {e}")
        return None


def run_ml_tool(url: str, features: Dict[str, Any]) -> Evidence:
    """
    Executes ML inference on the extracted URL feature vector.
    Returns Evidence containing probability, model verdict contribution, and elapsed time.
    """
    start_time = time.perf_counter()
    pipeline_obj = get_model()

    if pipeline_obj is None:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return Evidence(
            tool="ml_model",
            features={"error": "Model not loaded or not trained yet"},
            score_contribution=50.0,
            severity="medium",
            reasons=["ML model is not yet trained or loaded; utilizing baseline heuristics."],
            status="failed",
            time_ms=elapsed_ms
        )

    # Format feature vector
    vector = features_to_vector(features)
    X = np.array([vector], dtype=float)

    try:
        model = pipeline_obj["model"]
        scaler = pipeline_obj.get("scaler")
        model_name = pipeline_obj.get("model_name", "Random Forest")

        if scaler is not None:
            X_scaled = scaler.transform(X)
        else:
            X_scaled = X

        # Predict probability of phishing class (label = 1)
        proba = model.predict_proba(X_scaled)[0][1]
        score_contribution = round(float(proba) * 100, 1)

        reasons = []
        if score_contribution >= 65:
            severity = "high"
            reasons.append(f"Trained {model_name} model predicts {score_contribution:.1f}% probability of malicious phishing intent")
        elif score_contribution >= 35:
            severity = "medium"
            reasons.append(f"Trained {model_name} model flagged borderline characteristics ({score_contribution:.1f}% risk score)")
        else:
            severity = "low"
            reasons.append(f"Trained {model_name} model classified pattern as consistent with benign URLs ({100-score_contribution:.1f}% legitimacy confidence)")

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return Evidence(
            tool="ml_model",
            features={
                "model_name": model_name,
                "phishing_probability": round(float(proba), 4),
                "risk_contribution": score_contribution
            },
            score_contribution=score_contribution,
            severity=severity,
            reasons=reasons,
            status="ok",
            time_ms=elapsed_ms
        )
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return Evidence(
            tool="ml_model",
            features={"error": str(e)},
            score_contribution=50.0,
            severity="medium",
            reasons=[f"ML inference encountered an error: {str(e)}"],
            status="failed",
            time_ms=elapsed_ms
        )
