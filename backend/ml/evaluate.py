"""
Model evaluation module for PhishGuard Agent.
Calculates comprehensive metrics on the held-out test set, including:
- Overall Accuracy, Precision, Recall, F1, ROC-AUC
- Confusion matrix
- ROC Curve data points for plotting
- Feature importances
- Sliced metrics (Domain-only vs Full-URL) to evaluate dataset bias mitigation
"""

from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve
)
from backend.ml.features import FEATURE_NAMES


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray
) -> Dict[str, Any]:
    """Calculates standard classification performance metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    try:
        auc = float(roc_auc_score(y_true, y_proba))
    except Exception:
        auc = 0.5

    cm = confusion_matrix(y_true, y_pred).tolist()

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": cm
    }


def evaluate_slices(
    urls: List[str],
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray
) -> Dict[str, Any]:
    """
    Evaluates performance separately on:
    - Domain-only slice: URLs where path is empty or just '/'
    - Full-URL slice: URLs with path components
    """
    from urllib.parse import urlparse

    domain_only_indices = []
    full_url_indices = []

    for i, u in enumerate(urls):
        try:
            path = urlparse(u).path or ""
            if path in ("", "/"):
                domain_only_indices.append(i)
            else:
                full_url_indices.append(i)
        except Exception:
            full_url_indices.append(i)

    results = {}

    if domain_only_indices:
        d_idx = np.array(domain_only_indices)
        d_metrics = compute_metrics(y_true[d_idx], y_pred[d_idx], y_proba[d_idx])
        d_metrics["count"] = len(domain_only_indices)
        results["domain_only_slice"] = d_metrics

    if full_url_indices:
        f_idx = np.array(full_url_indices)
        f_metrics = compute_metrics(y_true[f_idx], y_pred[f_idx], y_proba[f_idx])
        f_metrics["count"] = len(full_url_indices)
        results["full_url_slice"] = f_metrics

    return results


def extract_roc_curve_data(y_true: np.ndarray, y_proba: np.ndarray, max_points: int = 50) -> List[Dict[str, float]]:
    """Generates downsampled FPR/TPR coordinate pairs for frontend chart rendering."""
    try:
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        # Downsample to ~50 evenly spaced points
        step = max(1, len(fpr) // max_points)
        sampled = []
        for i in range(0, len(fpr), step):
            sampled.append({"fpr": round(float(fpr[i]), 4), "tpr": round(float(tpr[i]), 4)})
        # Ensure (1.0, 1.0) is present
        if sampled[-1]["fpr"] < 1.0:
            sampled.append({"fpr": 1.0, "tpr": 1.0})
        return sampled
    except Exception:
        return [{"fpr": 0.0, "tpr": 0.0}, {"fpr": 1.0, "tpr": 1.0}]


def get_feature_importances(model: Any, scaler: Any = None) -> List[Dict[str, Any]]:
    """Extracts ranked feature importance or normalized weights from the best model."""
    importances = []
    if hasattr(model, "feature_importances_"):
        # Tree-based model (Random Forest)
        scores = model.feature_importances_
        for name, score in zip(FEATURE_NAMES, scores):
            importances.append({"feature": name, "importance": round(float(score), 4)})
    elif hasattr(model, "coef_"):
        # Linear model (Logistic Regression)
        weights = np.abs(model.coef_[0])
        total = np.sum(weights) if np.sum(weights) > 0 else 1.0
        norm_weights = weights / total
        for name, score in zip(FEATURE_NAMES, norm_weights):
            importances.append({"feature": name, "importance": round(float(score), 4)})
    else:
        for name in FEATURE_NAMES:
            importances.append({"feature": name, "importance": 0.0})

    importances.sort(key=lambda x: x["importance"], reverse=True)
    return importances
