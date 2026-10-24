"""
Pytest configuration and shared fixtures for PhishGuard Agent tests.
Ensures hermetic testing with zero internet dependencies.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app
from backend.app.config import settings
from backend.app.db import init_db, clear_history


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Initializes the database and test state."""
    init_db()
    clear_history()
    yield
    clear_history()


@pytest.fixture
def client():
    """Provides a FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def tiny_dataset():
    """Returns a tiny fixture dataset of diverse test URLs with known expected classes."""
    return [
        {
            "url": "https://www.google.com",
            "expected_verdict": "Legitimate",
            "description": "Top allowlisted search engine"
        },
        {
            "url": "https://github.com/user/repo",
            "expected_verdict": "Legitimate",
            "description": "Legitimate code repository"
        },
        {
            "url": "http://paypal-secure-login.verify-account.example-xyz.top/signin",
            "expected_verdict": "Phishing",
            "description": "Brand impersonation + suspicious TLD + auth keywords"
        },
        {
            "url": "http://192.168.1.10/bank/login.php",
            "expected_verdict": "Phishing",
            "description": "IP host + banking keyword + cleartext HTTP"
        },
        {
            "url": "http://paypa1.com/update-security",
            "expected_verdict": "Phishing",
            "description": "Homoglyph / typosquatting imitating PayPal"
        },
        {
            "url": "http://bit.ly/secure-account-token",
            "expected_verdict": "Suspicious",
            "description": "URL shortener with sensitive auth keywords"
        }
    ]
