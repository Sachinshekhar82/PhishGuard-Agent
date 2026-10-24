#!/usr/bin/env python3
"""
Optional benchmark script comparing PhishGuard local agent detections against VirusTotal.
STRICT REQUIREMENT: VirusTotal is NEVER called in normal analysis flows.
This script is disabled by default unless VT_API_KEY is explicitly configured in .env.
Used strictly for offline dataset benchmarking and labeling verification.
"""

import os
import sys
import time
import base64
import json
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.agent.orchestrator import PhishGuardAgent

# Load environment
load_dotenv(ROOT_DIR / ".env")
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()


def query_virustotal(url: str, api_key: str) -> dict:
    """Queries VirusTotal v3 API for URL analysis summary."""
    # VT v3 URL identifier is base64 of URL without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    req = urllib.request.Request(api_endpoint, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
    except Exception as e:
        return {"error": str(e)}


def main():
    print("=" * 65)
    print("      PHISHGUARD vs VIRUSTOTAL BENCHMARKING UTILITY")
    print("=" * 65)

    if not VT_API_KEY:
        print("[DISABLED] VT_API_KEY is not configured in .env.")
        print("This script is disabled by default. Set VT_API_KEY in .env to run comparative benchmarks.")
        print("Note: PhishGuard primary detection operates entirely locally without external reputation APIs.")
        sys.exit(0)

    print("VT_API_KEY detected. Starting benchmark on sample test cases...\n")

    sample_urls = [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "http://paypal-security-update.account-verify.xyz/login.php",
        "http://192.168.1.100/chase-online/auth",
        "https://netflix.com/browse"
    ]

    agent = PhishGuardAgent()
    print(f"{'Test URL':<50} | {'PhishGuard':<12} | {'Risk':<5} | {'VT Malicious':<12}")
    print("-" * 88)

    for u in sample_urls:
        local_res = agent.analyze(u, offline_mode=True)
        vt_res = query_virustotal(u, VT_API_KEY)

        vt_mal = vt_res.get("malicious", "err") if "error" not in vt_res else "N/A"
        print(f"{u[:48]:<50} | {local_res.verdict:<12} | {local_res.risk_score:<5} | {str(vt_mal):<12}")
        time.sleep(1.0)  # VT public API rate limit (4 req/min)

    print("-" * 88)
    print("Benchmark complete.")


if __name__ == "__main__":
    main()
