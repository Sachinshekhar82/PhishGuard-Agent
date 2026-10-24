#!/usr/bin/env python3
"""
CLI script to evaluate the local PhishGuard ML model on the test dataset.
Usage: python scripts/evaluate_local.py
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.config import settings


def main():
    metrics_path = settings.METRICS_PATH
    if not metrics_path.exists():
        print(f"Error: Metrics file not found at {metrics_path}. Please train the model first.")
        sys.exit(1)

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    print("\n" + "=" * 65)
    print("           PHISHGUARD AGENT - LOCAL MODEL EVALUATION")
    print("=" * 65)
    print(f" Model Architecture:      {metrics.get('model_name', 'N/A')}")
    print(f" Evaluation Timestamp:    {metrics.get('evaluation_timestamp', 'N/A')}")

    test = metrics.get("test_metrics", {})
    print("-" * 65)
    print(" Overall Test Metrics (Held-out 15%):")
    print(f"  • Accuracy:             {test.get('accuracy', 0)*100:.2f}%")
    print(f"  • Precision:            {test.get('precision', 0)*100:.2f}%")
    print(f"  • Recall:               {test.get('recall', 0)*100:.2f}%")
    print(f"  • F1 Score:             {test.get('f1', 0):.4f}")
    print(f"  • ROC-AUC:              {test.get('roc_auc', 0):.4f}")

    cm = test.get("confusion_matrix", [[0, 0], [0, 0]])
    print("\n Confusion Matrix:")
    print(f"                 Predicted Legit   Predicted Phish")
    print(f"  Actual Legit:       {cm[0][0]:<15}   {cm[0][1]:<15}")
    print(f"  Actual Phish:       {cm[1][0]:<15}   {cm[1][1]:<15}")

    slices = metrics.get("slice_metrics", {})
    if slices:
        print("\n Dataset Bias Mitigation Slice Evaluation:")
        if "domain_only_slice" in slices:
            d = slices["domain_only_slice"]
            print(f"  • Domain-Only Slice (N={d.get('count', 0)}):")
            print(f"      Accuracy: {d.get('accuracy', 0)*100:.2f}% | Precision: {d.get('precision', 0)*100:.2f}% | Recall: {d.get('recall', 0)*100:.2f}% | F1: {d.get('f1', 0):.4f}")
        if "full_url_slice" in slices:
            f_slice = slices["full_url_slice"]
            print(f"  • Full-URL Slice (N={f_slice.get('count', 0)}):")
            print(f"      Accuracy: {f_slice.get('accuracy', 0)*100:.2f}% | Precision: {f_slice.get('precision', 0)*100:.2f}% | Recall: {f_slice.get('recall', 0)*100:.2f}% | F1: {f_slice.get('f1', 0):.4f}")

    importances = metrics.get("feature_importances", [])
    if importances:
        print("\n Top 10 Most Influential Detection Features:")
        for item in importances[:10]:
            print(f"  • {item['feature']:<30} {item['importance']:.4f}")

    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
