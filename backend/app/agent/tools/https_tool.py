"""
HTTPS and SSL/TLS certificate inspection tool for PhishGuard Agent.
Operates safely offline or with strict timeouts in online mode.
Never crashes or blocks the agent pipeline.
"""

import time
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
from backend.app.schemas import Evidence


def run_https_tool(url: str, offline_mode: bool = True) -> Evidence:
    """
    Evaluates HTTPS protocol usage and optional SSL/TLS certificate validity.
    """
    start_time = time.perf_counter()
    reasons = []
    score_contribution = 0.0
    severity = "none"
    features = {}

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.netloc or "").split(":")[0]

    uses_https = (scheme == "https")
    features["uses_https"] = uses_https
    features["scheme"] = scheme

    if not uses_https:
        reasons.append("URL uses unencrypted HTTP protocol; credentials and data transmitted in cleartext")
        score_contribution += 20.0
        severity = "medium"
    else:
        # If offline_mode is False and hostname is not an IP, attempt lightweight certificate verification
        if not offline_mode and hostname:
            try:
                context = ssl.create_default_context()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED

                with socket.create_connection((hostname, 443), timeout=1.5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        not_after_str = cert.get("notAfter")
                        if not_after_str:
                            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            days_remaining = (expiry - datetime.utcnow()).days
                            features["cert_days_remaining"] = days_remaining
                            if days_remaining < 0:
                                reasons.append(f"SSL certificate has expired ({abs(days_remaining)} days ago)")
                                score_contribution += 35.0
                                severity = "high"
                            elif days_remaining < 7:
                                reasons.append(f"SSL certificate expiring very soon ({days_remaining} days remaining)")
                                score_contribution += 10.0
                        features["cert_valid"] = True
            except ssl.SSLCertVerificationError as e:
                reasons.append(f"SSL/TLS Certificate verification failed: {e.verify_message}")
                score_contribution += 40.0
                severity = "high"
                features["cert_valid"] = False
            except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
                # Safe network fallback: mark as unverified without penalizing legitimate offline checks
                features["cert_check_status"] = "network_timeout_or_unreachable"
            except Exception as e:
                features["cert_check_status"] = f"error: {str(e)}"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return Evidence(
        tool="https_cert",
        features=features,
        score_contribution=min(100.0, score_contribution),
        severity=severity,
        reasons=reasons,
        status="ok",
        time_ms=elapsed_ms
    )
