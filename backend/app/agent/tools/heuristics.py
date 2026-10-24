"""
Heuristics and rule-based scoring engine for PhishGuard Agent.
Applies deterministic cybersecurity rules and behavioral signatures to quantify phishing risk.
"""

import time
from typing import Dict, Any, List
import tldextract
from backend.app.schemas import Evidence
from backend.app.config import settings


def run_heuristics_tool(url: str, features: Dict[str, Any]) -> Evidence:
    """
    Applies expert cybersecurity heuristics and returns Evidence with composite score contribution.
    """
    start_time = time.perf_counter()
    reasons: List[str] = []
    raw_score = 0.0

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".strip(".").lower() if ext.domain else ""

    # Rule 1: Allowlist check (Exact registrable domain only, never substring!)
    is_allowlisted = registered_domain in settings.TOP_LEGITIMATE_DOMAINS

    # Rule 2: IP host rule
    if features.get("is_ip_host", 0) == 1:
        raw_score += 40.0
        reasons.append("Heuristic Rule Triggered: Bare IP host used in place of validated domain")

    # Rule 3: Brand impersonation or typosquatting
    if features.get("brand_typosquat_detected", 0) == 1:
        raw_score += 45.0
        reasons.append("Heuristic Rule Triggered: Critical typosquatting signature matching popular brand")
    elif features.get("brand_in_subdomain_or_path", 0) == 1 and not is_allowlisted:
        raw_score += 35.0
        reasons.append("Heuristic Rule Triggered: Brand keyword baiting detected in subdomain or path")

    # Rule 4: Credential/Auth keywords combined with unencrypted HTTP
    if features.get("has_https", 1) == 0 and features.get("count_auth_keywords", 0) > 0:
        raw_score += 30.0
        reasons.append("Heuristic Rule Triggered: Insecure HTTP connection soliciting authentication/credentials")

    # Rule 5: High-risk TLD
    if features.get("is_suspicious_tld", 0) == 1:
        raw_score += 25.0
        reasons.append("Heuristic Rule Triggered: High-abuse TLD registered")

    # Rule 6: Obfuscation with @ symbol or // in path
    if features.get("has_at_symbol", 0) == 1:
        raw_score += 30.0
        reasons.append("Heuristic Rule Triggered: '@' character in URL string indicates credential obscuration")
    if features.get("has_double_slash_path", 0) == 1:
        raw_score += 20.0
        reasons.append("Heuristic Rule Triggered: Path redirect evasion sequence ('//')")

    # Rule 7: Suspicious keyword density in subdomain
    if features.get("keyword_in_subdomain", 0) == 1 and not is_allowlisted:
        raw_score += 25.0
        reasons.append("Heuristic Rule Triggered: Sensitive target keyword in subdomain prefix")

    # Rule 8: Financial / urgency lure keywords
    if (features.get("count_financial_keywords", 0) > 0 and features.get("count_urgency_keywords", 0) > 0) and not is_allowlisted:
        raw_score += 20.0
        reasons.append("Heuristic Rule Triggered: High-pressure urgency combined with financial/banking terminology")

    # Rule 9: URL shortener
    if features.get("is_shortener", 0) == 1:
        raw_score += 15.0
        reasons.append("Heuristic Rule Triggered: URL shortener masks original landing destination")

    # Rule 10: Non-standard port
    if features.get("has_port", 0) == 1:
        raw_score += 20.0
        reasons.append("Heuristic Rule Triggered: Explicit non-standard port designation in URL")

    # If the domain is on the top legitimate allowlist and no blatant typosquatting/IP attack occurred,
    # bound the heuristic score to protect against false positives on legitimate complex URLs (e.g. github auth or google search)
    if is_allowlisted and features.get("brand_typosquat_detected", 0) == 0 and features.get("is_ip_host", 0) == 0:
        raw_score = min(raw_score, 12.0)
        reasons = [f"Verified registrable domain '{registered_domain}' matches top legitimate allowlist."]

    final_score = min(100.0, max(0.0, round(raw_score, 1)))

    if final_score >= 65:
        severity = "high"
    elif final_score >= 35:
        severity = "medium"
    elif final_score > 0:
        severity = "low"
    else:
        severity = "none"
        reasons.append("No heuristic threat signatures or behavioral anomalies detected")

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return Evidence(
        tool="heuristics",
        features={
            "rules_triggered_count": len(reasons),
            "allowlist_matched": is_allowlisted,
            "raw_heuristic_score": final_score
        },
        score_contribution=final_score,
        severity=severity,
        reasons=reasons,
        status="ok",
        time_ms=elapsed_ms
    )
