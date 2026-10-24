"""
Unit and integration tests for the PhishGuard Agent loop, planner, evaluator, and reflection.
"""

import time
import pytest
from backend.app.agent.orchestrator import PhishGuardAgent
from backend.app.agent.planner import create_plan
from backend.app.agent.evaluator import evaluate_decision
from backend.app.agent.explainer import build_explanation
from backend.app.schemas import Evidence, ReasonItem
from backend.app.config import settings


def test_planner_ip_host():
    perceive_ctx = {
        "is_ip_host": True,
        "is_shortener": False,
        "registered_domain": ""
    }
    plan = create_plan(perceive_ctx, offline_mode=True)
    assert "brand" not in plan
    assert "domain_whois_dns" not in plan
    assert "https_cert" not in plan
    assert "lexical" in plan
    assert "heuristics" in plan
    assert "ml_model" in plan


def test_planner_online_named_host():
    perceive_ctx = {
        "is_ip_host": False,
        "is_shortener": False,
        "registered_domain": "example.com"
    }
    plan = create_plan(perceive_ctx, offline_mode=False)
    assert "brand" in plan
    assert "https_cert" in plan
    assert "domain_whois_dns" in plan


def test_evaluator_thresholds():
    # 1. High risk evidence
    ev_high = [
        Evidence(tool="ml_model", score_contribution=90.0, severity="high", status="ok"),
        Evidence(tool="heuristics", score_contribution=85.0, severity="high", status="ok"),
        Evidence(tool="brand", score_contribution=40.0, severity="high", status="ok")
    ]
    verdict, score, conf, _ = evaluate_decision("http://malicious-login.xyz", ev_high)
    assert verdict == "Phishing"
    assert score >= settings.PHISHING_THRESHOLD

    # 2. Low risk evidence
    ev_low = [
        Evidence(tool="ml_model", score_contribution=10.0, severity="low", status="ok"),
        Evidence(tool="heuristics", score_contribution=5.0, severity="low", status="ok"),
        Evidence(tool="brand", score_contribution=0.0, severity="none", status="ok")
    ]
    verdict, score, conf, _ = evaluate_decision("https://innocent-site.org", ev_low)
    assert verdict == "Legitimate"
    assert score <= settings.LEGITIMATE_THRESHOLD


def test_evaluator_allowlist_exact_match():
    # Exact allowlisted domain (e.g. google.com)
    ev = [
        Evidence(tool="ml_model", score_contribution=45.0, severity="medium", status="ok"),
        Evidence(tool="heuristics", score_contribution=30.0, severity="medium", status="ok")
    ]
    verdict, score, conf, details = evaluate_decision("https://www.google.com/search?q=bank+login", ev)
    assert verdict == "Legitimate"
    assert score <= settings.LEGITIMATE_THRESHOLD
    assert details["is_allowlisted"] is True

    # Substring trick domain should NOT be allowlisted
    verdict_fake, score_fake, _, details_fake = evaluate_decision("https://google.com.attacker-fake.xyz", ev)
    assert details_fake["is_allowlisted"] is False


def test_explainer_ordering():
    ev_list = [
        Evidence(
            tool="lexical",
            score_contribution=15.0,
            severity="low",
            reasons=["Elevated URL length"],
            status="ok"
        ),
        Evidence(
            tool="brand",
            score_contribution=45.0,
            severity="critical",
            reasons=["Critical typosquatting detected"],
            status="ok"
        ),
        Evidence(
            tool="heuristics",
            score_contribution=35.0,
            severity="high",
            reasons=["Insecure HTTP credential solicitation"],
            status="ok"
        )
    ]
    summary, reasons = build_explanation("Phishing", 85, 0.95, ev_list)
    assert len(reasons) == 3
    # Critical should be first
    assert reasons[0].severity == "critical"
    assert "typosquatting" in reasons[0].reason.lower()
    assert "85/100" in summary


def test_agent_full_analysis_timing_under_1_second(tiny_dataset):
    """Offline mode analysis should take well under 1 second per URL."""
    agent = PhishGuardAgent()
    # Warm up cached model
    agent.analyze("https://warmup.example.com", offline_mode=True)

    for case in tiny_dataset:
        start = time.perf_counter()
        resp = agent.analyze(case["url"], offline_mode=True)
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"Analysis for {case['url']} took {elapsed:.2f}s (must be < 1s)"
        assert resp.verdict in ("Legitimate", "Suspicious", "Phishing")
        assert 0 <= resp.risk_score <= 100
        assert 0.0 <= resp.confidence <= 1.0
        assert resp.agent_trace is not None
        assert len(resp.agent_trace.plan) >= 3
