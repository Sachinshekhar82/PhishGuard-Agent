"""
Lexical analysis tool for PhishGuard Agent.
Analyzes the structural and character-level properties of the URL.
"""

import time
from typing import Dict, Any
from backend.app.schemas import Evidence
from backend.ml.features import extract_features, is_ip_address


def run_lexical_tool(url: str, features: Dict[str, Any]) -> Evidence:
    """
    Evaluates lexical and structural properties of the URL.
    Returns Evidence with score contribution, severity, and plain-English reasons.
    """
    start_time = time.perf_counter()
    reasons = []
    score_contribution = 0.0
    severity = "none"

    # URL and Host Length
    if features.get("url_length", 0) > 120:
        reasons.append(f"Abnormally long URL length ({features['url_length']} characters)")
        score_contribution += 15.0
    elif features.get("url_length", 0) > 75:
        reasons.append(f"Elevated URL length ({features['url_length']} characters)")
        score_contribution += 8.0

    if features.get("hostname_length", 0) > 40:
        reasons.append(f"Unusually long hostname ({features['hostname_length']} characters)")
        score_contribution += 10.0

    # IP address as host
    if features.get("is_ip_host", 0) == 1:
        reasons.append("URL uses a raw IP address instead of a domain name (common evasion technique)")
        score_contribution += 35.0
        severity = "high"

    # Suspicious TLD
    if features.get("is_suspicious_tld", 0) == 1:
        reasons.append("Domain utilizes a high-risk Top-Level Domain (TLD) frequently associated with abuse")
        score_contribution += 20.0

    # Obfuscation & Evasion (@ symbol, // in path)
    if features.get("has_at_symbol", 0) == 1:
        reasons.append("Contains '@' symbol, which may trick browsers into ignoring preceding credentials")
        score_contribution += 25.0
        severity = "high"

    if features.get("has_double_slash_path", 0) == 1:
        reasons.append("Path contains '//' sequence, often used to bypass filters or redirect users")
        score_contribution += 20.0

    # Excessive subdomains
    if features.get("subdomain_count", 0) >= 3:
        reasons.append(f"Excessive subdomain nesting ({features['subdomain_count']} levels)")
        score_contribution += 15.0

    # High Shannon entropy (random-looking strings / DGA)
    if features.get("hostname_entropy", 0.0) > 4.2:
        reasons.append(f"High hostname character randomness/entropy ({features['hostname_entropy']:.2f})")
        score_contribution += 15.0

    # Digit / Special character density
    if features.get("digit_ratio", 0.0) > 0.25 and features.get("digit_count", 0) > 6:
        reasons.append(f"High density of numerical digits ({features['digit_ratio']*100:.1f}% of URL)")
        score_contribution += 10.0

    # URL Shortener
    if features.get("is_shortener", 0) == 1:
        reasons.append("Domain is a known URL shortening service, masking destination destination")
        score_contribution += 18.0

    # Determine severity
    if score_contribution >= 40:
        severity = "high"
    elif score_contribution >= 20:
        severity = "medium"
    elif score_contribution > 0:
        severity = "low"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return Evidence(
        tool="lexical",
        features=features,
        score_contribution=min(100.0, score_contribution),
        severity=severity,
        reasons=reasons,
        status="ok",
        time_ms=elapsed_ms
    )
