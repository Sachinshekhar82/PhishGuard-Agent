"""
SQLite database persistence for PhishGuard Agent history.
Provides thread-safe operations for storing, querying, and clearing URL analysis history.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any
from backend.app.config import settings


def get_db_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database."""
    # Strip sqlite:/// prefix if present
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    summary TEXT NOT NULL,
                    top_reasons TEXT NOT NULL,
                    offline_mode INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_created_at ON analysis_history (created_at DESC)")
    finally:
        conn.close()


def save_history(
    url: str,
    verdict: str,
    risk_score: int,
    confidence: float,
    summary: str,
    top_reasons: List[str],
    offline_mode: bool
) -> int:
    """Saves an analysis record to the database and returns its new ID."""
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO analysis_history 
                (url, verdict, risk_score, confidence, summary, top_reasons, offline_mode, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    verdict,
                    risk_score,
                    confidence,
                    summary,
                    json.dumps(top_reasons),
                    1 if offline_mode else 0,
                    datetime.utcnow().isoformat() + "Z"
                )
            )
            return cursor.lastrowid or 0
    finally:
        conn.close()


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves the most recent analysis history records."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            SELECT id, url, verdict, risk_score, confidence, summary, top_reasons, offline_mode, created_at
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            reasons = []
            try:
                reasons = json.loads(row["top_reasons"])
            except Exception:
                pass
            results.append({
                "id": row["id"],
                "url": row["url"],
                "verdict": row["verdict"],
                "risk_score": row["risk_score"],
                "confidence": row["confidence"],
                "summary": row["summary"],
                "top_reasons": reasons,
                "offline_mode": bool(row["offline_mode"]),
                "created_at": row["created_at"]
            })
        return results
    finally:
        conn.close()


def clear_history() -> bool:
    """Deletes all records from the analysis history table."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM analysis_history")
        return True
    finally:
        conn.close()
