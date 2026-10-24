#!/usr/bin/env python3
"""
CLI script to download, verify, clean, and build the real PhishGuard training dataset.
Can be executed independently: python scripts/fetch_datasets.py
"""

import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.ml.dataset import build_and_save_dataset


def main():
    print("Starting PhishGuard dataset download and curation...")
    df = build_and_save_dataset()
    print(f"Dataset build completed successfully with {len(df)} records.")


if __name__ == "__main__":
    main()
