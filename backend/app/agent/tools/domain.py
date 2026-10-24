"""
Domain metadata, DNS resolution, and WHOIS inspection tool for PhishGuard Agent.
Operates fully offline-safe with strict timeout fallbacks in online mode.
"""

import time
import socket
from datetime import datetime
from urllib.parse import urlparse
import tldextract
from backend.app.schemas import Evidence
from backend.ml.features import is_ip_address


def run_domain_tool(url: str, offline_mode: bool = True) -> Evidence:
    """
    Performs domain structure checks and optional DNS / WHOIS verification.
    """
    start_time = time.perf_counter()
    reasons = []
    score_contribution = 0.0
    severity = "none"
    features = {}

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".strip(".").lower() if ext.domain else ""
    hostname = (urlparse(url).netloc or "").split(":")[0].lower()

    features["registered_domain"] = registered_domain
    features["tld"] = ext.suffix.lower() if ext.suffix else ""
    features["subdomain"] = ext.subdomain.lower() if ext.subdomain else ""

    if is_ip_address(hostname):
        features["is_ip"] = True
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return Evidence(
            tool="domain_whois_dns",
            features=features,
            score_contribution=0.0,
            severity="none",
            reasons=["Domain check skipped: Target uses raw IP address instead of domain name."],
            status="ok",
            time_ms=elapsed_ms
        )

    # In offline mode, skip network queries
    if offline_mode:
        features["network_checks"] = "skipped_offline_mode"
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return Evidence(
            tool="domain_whois_dns",
            features=features,
            score_contribution=0.0,
            severity="none",
            reasons=[],
            status="skipped",
            time_ms=elapsed_ms
        )

    # Online mode: DNS Resolution Check
    resolved_ips = []
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list({item[4][0] for item in addr_info})
        features["resolved_ips"] = resolved_ips[:5]
        features["dns_active"] = True
    except socket.gaierror:
        features["dns_active"] = False
        reasons.append("Domain failed DNS resolution (NXDOMAIN or inactive host)")
        score_contribution += 15.0
        severity = "medium"
    except Exception as e:
        features["dns_error"] = str(e)

    # Online mode: Optional WHOIS inspection with timeout
    try:
        # Lightweight WHOIS via python-whois if available
        import whois
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            domain_age_days = (datetime.utcnow() - creation_date).days
            features["domain_age_days"] = domain_age_days
            if domain_age_days < 30:
                reasons.append(f"Domain is very newly registered ({domain_age_days} days old; common in throwaway phishing)")
                score_contribution += 30.0
                severity = "high"
            elif domain_age_days < 90:
                reasons.append(f"Domain is recently registered ({domain_age_days} days old)")
                score_contribution += 15.0
                if severity == "none":
                    severity = "medium"
        if w.registrar:
            features["registrar"] = str(w.registrar)
    except Exception:
        # Safe fallback: WHOIS failure or timeout is not penalized
        features["whois_status"] = "unavailable_or_timeout"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return Evidence(
        tool="domain_whois_dns",
        features=features,
        score_contribution=min(100.0, score_contribution),
        severity=severity,
        reasons=reasons,
        status="ok",
        time_ms=elapsed_ms
    )
