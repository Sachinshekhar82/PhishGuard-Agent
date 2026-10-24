"""
Unit tests for the diagnostic tools in PhishGuard Agent.
"""

import pytest
from backend.ml.features import extract_features
from backend.app.agent.tools.lexical import run_lexical_tool
from backend.app.agent.tools.brand import run_brand_tool
from backend.app.agent.tools.heuristics import run_heuristics_tool
from backend.app.agent.tools.ml_model import run_ml_tool
from backend.app.agent.tools.https_tool import run_https_tool
from backend.app.agent.tools.domain import run_domain_tool


def test_lexical_tool_benign():
    url = "https://www.google.com"
    feats = extract_features(url)
    ev = run_lexical_tool(url, feats)
    assert ev.tool == "lexical"
    assert ev.status == "ok"
    assert ev.score_contribution < 25.0
    assert ev.time_ms >= 0


def test_lexical_tool_suspicious():
    url = "http://192.168.1.100:8080/path//double/@fake/long/suspicious/url/path/test.xyz"
    feats = extract_features(url)
    ev = run_lexical_tool(url, feats)
    assert ev.tool == "lexical"
    assert ev.status == "ok"
    assert ev.score_contribution >= 40.0
    assert len(ev.reasons) >= 2


def test_brand_tool_impersonation():
    url = "http://paypal-verification.secure-account-update.xyz/login.php"
    feats = extract_features(url)
    ev = run_brand_tool(url, feats)
    assert ev.tool == "brand"
    assert ev.status == "ok"
    assert ev.score_contribution >= 35.0
    assert any("brand" in r.lower() or "impersonation" in r.lower() for r in ev.reasons)


def test_brand_tool_typosquatting():
    url = "http://paypa1.com/update"
    feats = extract_features(url)
    ev = run_brand_tool(url, feats)
    assert ev.tool == "brand"
    assert ev.status == "ok"
    assert ev.severity in ("high", "critical")
    assert ev.score_contribution >= 30.0


def test_heuristics_tool_allowlist_mitigation():
    url = "https://www.google.com/search?q=bank+login+verification+secure"
    feats = extract_features(url)
    ev = run_heuristics_tool(url, feats)
    assert ev.tool == "heuristics"
    assert ev.status == "ok"
    # Even though words like bank, login, verification are in path/query,
    # exact allowlisted domain google.com bounds the heuristic score
    assert ev.score_contribution <= 20.0


def test_ml_tool_inference():
    url = "http://paypal-security-update.xyz/login.php"
    feats = extract_features(url)
    ev = run_ml_tool(url, feats)
    assert ev.tool == "ml_model"
    assert ev.status == "ok"
    assert 0.0 <= ev.score_contribution <= 100.0
    assert len(ev.reasons) >= 1


def test_https_tool_offline():
    url_http = "http://insecure-example.com"
    ev_http = run_https_tool(url_http, offline_mode=True)
    assert ev_http.status == "ok"
    assert ev_http.score_contribution > 0
    assert any("http" in r.lower() for r in ev_http.reasons)

    url_https = "https://secure-example.com"
    ev_https = run_https_tool(url_https, offline_mode=True)
    assert ev_https.status == "ok"
    assert ev_https.score_contribution == 0.0


def test_domain_tool_offline():
    url = "https://example.com"
    ev = run_domain_tool(url, offline_mode=True)
    assert ev.tool == "domain_whois_dns"
    assert ev.status == "skipped"
    assert ev.score_contribution == 0.0
