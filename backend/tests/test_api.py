"""
API endpoint and integration tests for PhishGuard Agent using FastAPI TestClient.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data
    assert "version" in data


def test_analyze_legitimate_url(client: TestClient):
    response = client.post(
        "/api/analyze",
        json={"url": "https://www.google.com", "offline_mode": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Legitimate"
    assert data["risk_score"] <= 34
    assert data["confidence"] >= 0.70
    assert "agent_trace" in data
    assert len(data["agent_trace"]["plan"]) >= 3


def test_analyze_phishing_url(client: TestClient):
    response = client.post(
        "/api/analyze",
        json={
            "url": "http://paypal-secure-login.verify-account.example-xyz.top/signin",
            "offline_mode": True
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Phishing"
    assert data["risk_score"] >= 65
    assert len(data["reasons"]) >= 1


def test_analyze_ip_address_host(client: TestClient):
    response = client.post(
        "/api/analyze",
        json={"url": "http://192.168.1.10/bank/login.php", "offline_mode": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Phishing"
    assert data["risk_score"] >= 65


def test_analyze_invalid_scheme(client: TestClient):
    response = client.post(
        "/api/analyze",
        json={"url": "ftp://files.example.com", "offline_mode": True}
    )
    assert response.status_code == 400
    assert "Only HTTP and HTTPS" in response.json()["detail"]


def test_batch_analyze(client: TestClient):
    urls = [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "http://paypal-verification-account.xyz/login.php"
    ]
    response = client.post(
        "/api/analyze/batch",
        json={"urls": urls, "offline_mode": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["results"]) == 3


def test_batch_analyze_limit_exceeded(client: TestClient):
    urls = [f"https://example{i}.com" for i in range(55)]
    response = client.post(
        "/api/analyze/batch",
        json={"urls": urls, "offline_mode": True}
    )
    assert response.status_code in (400, 422)


def test_history_flow(client: TestClient):
    # 1. Clear history
    del_res = client.delete("/api/history")
    assert del_res.status_code == 200

    # 2. Analyze one URL
    client.post("/api/analyze", json={"url": "https://www.google.com", "offline_mode": True})

    # 3. Retrieve history
    get_res = client.get("/api/history")
    assert get_res.status_code == 200
    items = get_res.json()
    assert len(items) >= 1
    assert items[0]["url"] == "https://www.google.com"


def test_metrics_endpoint(client: TestClient):
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "model_metrics" in data
    assert "dataset_info" in data


def test_llm_fallback_path(client: TestClient):
    """Verifies that explain-chat returns a graceful fallback when LLM is unavailable or fails."""
    # Test chat endpoint with mock failure
    with patch("backend.app.agent.llm.get_gemini_client", return_value=None):
        response = client.post(
            "/api/explain-chat",
            json={
                "url": "http://suspicious-site.xyz",
                "analysis_summary": "Classified as Suspicious with risk score 55/100.",
                "user_message": "Why is this domain flagged?"
            }
        )
        assert response.status_code == 200
        reply = response.json()["reply"]
        assert "AI Follow-up is currently unavailable" in reply or "Agent Trace" in reply
