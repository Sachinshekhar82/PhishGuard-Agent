"""
Pydantic schemas and data models for PhishGuard Agent.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ReasonItem(BaseModel):
    reason: str
    severity: str = "medium"  # low, medium, high, critical
    impact: float = 0.0


class Evidence(BaseModel):
    tool: str
    features: Dict[str, Any] = Field(default_factory=dict)
    score_contribution: float = 0.0
    severity: str = "none"  # none, low, medium, high, critical
    reasons: List[str] = Field(default_factory=list)
    status: str = "ok"      # ok, skipped, failed
    time_ms: float = 0.0


class AgentTrace(BaseModel):
    perceive: Dict[str, Any] = Field(default_factory=dict)
    plan: List[str] = Field(default_factory=list)
    act: List[Evidence] = Field(default_factory=list)
    reflection: Optional[Dict[str, Any]] = None
    decide: Dict[str, Any] = Field(default_factory=dict)
    explain: Dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze")
    offline_mode: Optional[bool] = False
    ai_explanation: Optional[bool] = False


class AnalyzeResponse(BaseModel):
    url: str
    verdict: str  # Legitimate, Suspicious, Phishing
    risk_score: int  # 0 - 100
    confidence: float  # 0.0 - 1.0
    summary: str
    reasons: List[ReasonItem]
    ai_explanation: Optional[str] = None
    features: Dict[str, Any]
    agent_trace: AgentTrace
    timestamp: str


class BatchAnalyzeRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=50, description="List of URLs to analyze (max 50)")
    offline_mode: Optional[bool] = False


class BatchAnalyzeResponse(BaseModel):
    total: int
    results: List[AnalyzeResponse]


class ExplainChatRequest(BaseModel):
    url: str
    analysis_summary: str
    user_message: str = Field(..., min_length=1, max_length=1000)
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class ExplainChatResponse(BaseModel):
    reply: str


class HistoryItem(BaseModel):
    id: int
    url: str
    verdict: str
    risk_score: int
    confidence: float
    summary: str
    top_reasons: List[str]
    offline_mode: bool
    created_at: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    offline_mode_default: bool
    llm_enabled: bool
    version: str
