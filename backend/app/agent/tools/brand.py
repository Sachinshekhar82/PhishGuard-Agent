"""
Brand impersonation and typosquatting detection tool for PhishGuard Agent.
Detects targeted brand attacks, deceptive subdomains, typosquatting, and homoglyphs.
"""

import time
from typing import Dict, Any, List
from urllib.parse import urlparse
import tldextract
from backend.app.schemas import Evidence
from backend.ml.features import BRANDS_DATA, HOMOGLYPH_MAP, levenshtein_distance


def run_brand_tool(url: str, features: Dict[str, Any]) -> Evidence:
    """
    Evaluates brand impersonation, deceptive naming, and typosquatting.
    Returns Evidence with score contribution, severity, and plain-English reasons.
    """
    start_time = time.perf_counter()
    reasons: List[str] = []
    score_contribution = 0.0
    severity = "none"

    if features.get("is_ip_host", 0) == 1:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return Evidence(
            tool="brand",
            features={"impersonation_checked": True, "ip_host": True},
            score_contribution=0.0,
            severity="none",
            reasons=["Skipped brand check: Host is a direct IP address."],
            status="ok",
            time_ms=elapsed_ms
        )

    ext = tldextract.extract(url)
    subdomain = (ext.subdomain or "").lower()
    domain = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()
    registered_domain = f"{domain}.{suffix}".strip(".") if domain else ""

    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    lower_sub = subdomain.lower()

    # Homoglyph detection in domain
    normalized_domain = domain
    homoglyph_used = False
    for h_char, rep in HOMOGLYPH_MAP.items():
        if h_char in normalized_domain:
            normalized_domain = normalized_domain.replace(h_char, rep)
            homoglyph_used = True

    impersonated_brands = []
    typosquatted_brands = []

    for brand in BRANDS_DATA:
        b_name = brand["name"]
        b_domains = [d.lower() for d in brand.get("domains", [])]
        b_kws = [k.lower() for k in brand.get("keywords", [])]

        is_official = any(registered_domain == d or registered_domain.endswith("." + d) for d in b_domains)

        if not is_official:
            # Check if brand keyword is in subdomain or path
            matched_kws = [kw for kw in b_kws if kw in lower_sub or kw in path]
            if matched_kws:
                impersonated_brands.append((b_name, matched_kws[0]))

            # Check typosquatting against official domains
            for official_dom in b_domains:
                off_name = official_dom.split(".")[0]
                if domain and off_name:
                    dist = levenshtein_distance(domain, off_name)
                    if (dist == 1 and domain != off_name) or (dist == 2 and len(off_name) >= 7 and domain != off_name):
                        typosquatted_brands.append((b_name, official_dom, dist))
                        break
                    elif homoglyph_used:
                        h_dist = levenshtein_distance(normalized_domain, off_name)
                        if h_dist <= 1:
                            typosquatted_brands.append((b_name, official_dom, h_dist))
                            break

    if typosquatted_brands:
        for b_name, off_dom, dist in typosquatted_brands:
            reasons.append(
                f"Typosquatting detected: domain '{registered_domain}' appears to mimic '{off_dom}' ({b_name}) with edit distance {dist}"
            )
        score_contribution += 45.0
        severity = "critical"

    if impersonated_brands:
        for b_name, kw in impersonated_brands:
            reasons.append(
                f"Brand impersonation alert: brand keyword '{kw}' ({b_name}) found in subdomain/path, but registered domain '{registered_domain}' is not legitimate {b_name}"
            )
        score_contribution += 40.0
        if severity != "critical":
            severity = "high"

    if homoglyph_used and not typosquatted_brands:
        reasons.append(f"Visual character substitution (homoglyph) observed in domain '{domain}'")
        score_contribution += 25.0
        if severity == "none":
            severity = "medium"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return Evidence(
        tool="brand",
        features={
            "brand_in_subdomain_or_path": 1 if impersonated_brands else 0,
            "brand_typosquat_detected": 1 if typosquatted_brands else 0,
            "homoglyph_detected": 1 if homoglyph_used else 0,
            "impersonated_brands": [b[0] for b in impersonated_brands],
            "typosquatted_brands": [b[0] for b in typosquatted_brands]
        },
        score_contribution=min(100.0, score_contribution),
        severity=severity,
        reasons=reasons,
        status="ok",
        time_ms=elapsed_ms
    )
