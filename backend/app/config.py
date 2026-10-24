"""
Configuration management for PhishGuard Agent.
Loads environment variables and specifies application thresholds, weights, and file paths.
"""

from pathlib import Path
from typing import Optional, Set
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent


class Settings(BaseSettings):
    # Server
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = False

    # LLM Enhancement (Off by default unless key and flag are present)
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    ENABLE_LLM_EXPLANATION: bool = False

    # Benchmarking only
    VT_API_KEY: Optional[str] = None

    # Storage
    DATABASE_URL: str = "sqlite:///./phishguard.db"

    # Agent Fusion Weights
    ML_WEIGHT: float = 0.6
    HEURISTIC_WEIGHT: float = 0.4

    # Risk Score Classification Thresholds
    LEGITIMATE_THRESHOLD: int = 34  # 0 to 34: Legitimate
    PHISHING_THRESHOLD: int = 65    # 65 to 100: Phishing; 35 to 64: Suspicious

    # Paths
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = BASE_DIR / "data"
    MODELS_DIR: Path = BASE_DIR / "models"
    MODEL_PATH: Path = BASE_DIR / "models" / "phishguard_model.joblib"
    METRICS_PATH: Path = BASE_DIR / "models" / "metrics.json"

    # Top legitimate domains allowlist (exact registrable-domain match only)
    TOP_LEGITIMATE_DOMAINS: Set[str] = {
        "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
        "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "microsoft.com",
        "apple.com", "netflix.com", "github.com", "reddit.com", "wordpress.org",
        "cloudflare.com", "adobe.com", "whatsapp.com", "zoom.us", "spotify.com",
        "paypal.com", "dropbox.com", "office.com", "live.com", "bing.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com"
    }

    model_config = SettingsConfigDict(
        env_file=[ROOT_DIR / ".env", BASE_DIR / ".env"],
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
