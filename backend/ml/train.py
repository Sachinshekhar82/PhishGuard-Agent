"""
Model training and pipeline serialization script for PhishGuard Agent.
Trains Random Forest and Logistic Regression models on domain-grouped splits,
selects the top performer via validation F1, and writes metrics.json and phishguard_model.joblib.
"""

import sys
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Tuple, List
import numpy as np
import pandas as pd
import joblib

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit

from backend.ml.features import extract_features, features_to_vector, FEATURE_NAMES
from backend.ml.dataset import load_dataset, DATASET_INFO_JSON
from backend.ml.evaluate import (
    compute_metrics,
    evaluate_slices,
    extract_roc_curve_data,
    get_feature_importances
)

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_SAVE_PATH = MODELS_DIR / "phishguard_model.joblib"
METRICS_SAVE_PATH = MODELS_DIR / "metrics.json"


def extract_features_parallel(urls: List[str], max_workers: int = 8) -> np.ndarray:
    """Extracts feature vectors across URLs using parallel workers."""
    def extract_one(u: str) -> List[float]:
        try:
            feats = extract_features(u)
            return features_to_vector(feats)
        except Exception:
            return [0.0] * len(FEATURE_NAMES)

    print(f"Extracting features for {len(urls)} URLs...")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        vectors = list(executor.map(extract_one, urls, chunksize=250))
    elapsed = time.time() - start_time
    print(f"Feature extraction completed in {elapsed:.2f}s ({len(urls)/elapsed:.0f} URLs/sec)")
    return np.array(vectors, dtype=float)


def train_and_evaluate() -> Dict[str, Any]:
    """
    Main training workflow:
    1. Loads dataset
    2. Extracts feature matrix X
    3. Performs domain-grouped 70/15/15 train/val/test split
    4. Trains Random Forest and Logistic Regression
    5. Selects best model based on validation F1
    6. Evaluates best model on held-out test set (overall and slices)
    7. Persists artifacts to disk
    """
    print("\n" + "=" * 60)
    print("        PHISHGUARD AGENT MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 1. Load dataset
    df = load_dataset()
    if df.empty or len(df) < 50:
        raise ValueError("Dataset is empty or too small to train an effective model.")

    print(f"Dataset loaded: {len(df)} samples ({int((df['label']==0).sum())} Legit, {int((df['label']==1).sum())} Phishing)")

    # 2. Extract feature matrix X and label vector y
    urls = df["url"].tolist()
    y = df["label"].values.astype(int)
    groups = df["registered_domain"].values

    X = extract_features_parallel(urls)

    # 3. Domain-grouped 70 / 15 / 15 split
    # Step A: Split 70% Train, 30% Temp (Val + Test)
    gss_outer = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    train_idx, temp_idx = next(gss_outer.split(X, y, groups=groups))

    X_train, y_train, groups_train = X[train_idx], y[train_idx], groups[train_idx]
    X_temp, y_temp, groups_temp = X[temp_idx], y[temp_idx], groups[temp_idx]
    urls_temp = [urls[i] for i in temp_idx]

    # Step B: Split Temp 50/50 into Validation and Test (15% and 15% of total)
    gss_inner = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    val_rel_idx, test_rel_idx = next(gss_inner.split(X_temp, y_temp, groups=groups_temp))

    X_val, y_val = X_temp[val_rel_idx], y_temp[val_rel_idx]
    X_test, y_test = X_temp[test_rel_idx], y_temp[test_rel_idx]
    urls_test = [urls_temp[i] for i in test_rel_idx]

    print(f"Splits: Train={len(y_train)} (unique domains: {len(set(groups_train))}), "
          f"Val={len(y_val)} (unique domains: {len(set(groups_temp[val_rel_idx]))}), "
          f"Test={len(y_test)} (unique domains: {len(set(groups_temp[test_rel_idx]))})")

    # 4. Train Candidate 1: Random Forest
    print("\nTraining Candidate 1: Random Forest (100 estimators, max_depth=16)...")
    rf_start = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_time = time.time() - rf_start
    print(f"Random Forest training finished in {rf_time:.2f}s")

    rf_val_proba = rf.predict_proba(X_val)[:, 1]
    rf_val_pred = (rf_val_proba >= 0.5).astype(int)
    rf_val_metrics = compute_metrics(y_val, rf_val_pred, rf_val_proba)
    print(f"Random Forest Validation F1: {rf_val_metrics['f1']:.4f} (Accuracy: {rf_val_metrics['accuracy']:.4f})")

    # 5. Train Candidate 2: Logistic Regression (with StandardScaler)
    print("\nTraining Candidate 2: Logistic Regression (L2 regularization, max_iter=1000)...")
    lr_start = time.time()
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    lr = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_time = time.time() - lr_start
    print(f"Logistic Regression training finished in {lr_time:.2f}s")

    lr_val_proba = lr.predict_proba(X_val_scaled)[:, 1]
    lr_val_pred = (lr_val_proba >= 0.5).astype(int)
    lr_val_metrics = compute_metrics(y_val, lr_val_pred, lr_val_proba)
    print(f"Logistic Regression Validation F1: {lr_val_metrics['f1']:.4f} (Accuracy: {lr_val_metrics['accuracy']:.4f})")

    # 6. Model Selection based on validation F1
    if rf_val_metrics["f1"] >= lr_val_metrics["f1"]:
        best_name = "Random Forest"
        best_model = rf
        best_scaler = None
        X_test_eval = X_test
        best_val_metrics = rf_val_metrics
        print(f"\n[WINNER] Selected: Random Forest (Val F1: {rf_val_metrics['f1']:.4f})")
    else:
        best_name = "Logistic Regression"
        best_model = lr
        best_scaler = scaler
        X_test_eval = X_test_scaled
        best_val_metrics = lr_val_metrics
        print(f"\n[WINNER] Selected: Logistic Regression (Val F1: {lr_val_metrics['f1']:.4f})")

    # 7. Evaluate Best Model on held-out Test Set
    test_proba = best_model.predict_proba(X_test_eval)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    test_metrics = compute_metrics(y_test, test_pred, test_proba)

    # Evaluate Slices
    slice_metrics = evaluate_slices(urls_test, y_test, test_pred, test_proba)

    # ROC curve and Feature Importances
    roc_data = extract_roc_curve_data(y_test, test_proba)
    feature_importances = get_feature_importances(best_model, best_scaler)

    # Read dataset metadata
    dataset_info = {}
    if DATASET_INFO_JSON.exists():
        with open(DATASET_INFO_JSON, "r", encoding="utf-8") as f:
            dataset_info = json.load(f)

    # Build final metrics report
    metrics_report = {
        "model_name": best_name,
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "validation_metrics": best_val_metrics,
        "test_metrics": test_metrics,
        "slice_metrics": slice_metrics,
        "roc_curve": roc_data,
        "feature_importances": feature_importances[:15],
        "all_feature_importances": feature_importances,
        "split_summary": {
            "train_samples": len(y_train),
            "val_samples": len(y_val),
            "test_samples": len(y_test),
            "total_samples": len(df)
        },
        "candidate_comparison": {
            "random_forest": rf_val_metrics,
            "logistic_regression": lr_val_metrics
        }
    }

    # Save metrics JSON
    with open(METRICS_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)
    print(f"Persisted evaluation metrics to {METRICS_SAVE_PATH}")

    # 8. Persist serialized model
    joblib_payload = {
        "model": best_model,
        "scaler": best_scaler,
        "model_name": best_name,
        "feature_names": FEATURE_NAMES
    }
    joblib.dump(joblib_payload, MODEL_SAVE_PATH)
    print(f"Serialized model pipeline to {MODEL_SAVE_PATH}")

    # Print summary results to console
    print("\n" + "=" * 60)
    print(f"       HELD-OUT TEST SET EVALUATION ({best_name})")
    print("=" * 60)
    print(f" Accuracy:       {test_metrics['accuracy']*100:.2f}%")
    print(f" Precision:      {test_metrics['precision']*100:.2f}%")
    print(f" Recall:         {test_metrics['recall']*100:.2f}%")
    print(f" F1 Score:       {test_metrics['f1']:.4f}")
    print(f" ROC-AUC:        {test_metrics['roc_auc']:.4f}")
    print(f" Confusion Matrix: TN={test_metrics['confusion_matrix'][0][0]}, "
          f"FP={test_metrics['confusion_matrix'][0][1]}, "
          f"FN={test_metrics['confusion_matrix'][1][0]}, "
          f"TP={test_metrics['confusion_matrix'][1][1]}")

    if "domain_only_slice" in slice_metrics:
        dom_slice = slice_metrics["domain_only_slice"]
        print(f"\n [Slice] Domain-Only (N={dom_slice['count']}): Acc={dom_slice['accuracy']*100:.1f}%, F1={dom_slice['f1']:.4f}")
    if "full_url_slice" in slice_metrics:
        full_slice = slice_metrics["full_url_slice"]
        print(f" [Slice] Full-URL (N={full_slice['count']}):    Acc={full_slice['accuracy']*100:.1f}%, F1={full_slice['f1']:.4f}")

    print("\nTop Contributing Features:")
    for item in feature_importances[:5]:
        print(f" - {item['feature']}: {item['importance']:.4f}")
    print("=" * 60 + "\n")

    return metrics_report


if __name__ == "__main__":
    train_and_evaluate()
