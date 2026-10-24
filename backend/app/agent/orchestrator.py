"""
Agent Orchestrator module for PhishGuard Agent.
Executes the core Agentic AI loop in pure Python without requiring an external LLM:
1. PERCEIVE: Normalize, validate, and parse URL into structural context.
2. PLAN: Dynamically select diagnostic tools.
3. ACT: Run diagnostic tools safely with timeouts and structured evidence.
4. REFLECT: Identify disagreements or uncertainties and trigger deeper verification.
5. DECIDE: Fuse evidence into calibrated risk score and verdict.
6. EXPLAIN: Synthesize plain-English explanations and optional LLM summary.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract

from backend.app.schemas import (
    AnalyzeResponse,
    AgentTrace,
    Evidence,
    ReasonItem
)
from backend.ml.features import (
    normalize_url,
    extract_features,
    is_ip_address,
    shannon_entropy
)
from backend.app.agent.planner import create_plan
from backend.app.agent.evaluator import evaluate_decision
from backend.app.agent.explainer import build_explanation
from backend.app.agent.llm import rewrite_explanation
from backend.app.agent.tools.lexical import run_lexical_tool
from backend.app.agent.tools.brand import run_brand_tool
from backend.app.agent.tools.heuristics import run_heuristics_tool
from backend.app.agent.tools.ml_model import run_ml_tool
from backend.app.agent.tools.https_tool import run_https_tool
from backend.app.agent.tools.domain import run_domain_tool


class PhishGuardAgent:
    """
    Autonomous cybersecurity agent specialized in defensive phishing detection.
    """

    def analyze(
        self,
        raw_url: str,
        offline_mode: bool = False,
        ai_explanation_requested: bool = False
    ) -> AnalyzeResponse:
        """
        Executes the full agent analysis loop on a URL.
        """
        # ==================== STEP 1: PERCEIVE ====================
        normalized_url = normalize_url(raw_url)
        parsed = urlparse(normalized_url)
        scheme = (parsed.scheme or "").lower()

        # Reject unsupported schemes early
        if scheme not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are supported.")

        hostname = (parsed.netloc or "").split(":")[0].lower()
        ext = tldextract.extract(normalized_url)
        registered_domain = f"{ext.domain}.{ext.suffix}".strip(".").lower() if ext.domain else ""

        # Extract complete shared feature set
        features = extract_features(normalized_url)

        perceive_context = {
            "raw_url": raw_url,
            "normalized_url": normalized_url,
            "scheme": scheme,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "is_ip_host": bool(features.get("is_ip_host", 0)),
            "is_shortener": bool(features.get("is_shortener", 0)),
            "url_length": len(normalized_url),
            "offline_mode": offline_mode
        }

        # ==================== STEP 2: PLAN ====================
        plan = create_plan(perceive_context, offline_mode=offline_mode)

        # ==================== STEP 3: ACT ====================
        evidence_list: List[Evidence] = []

        # Tool 1: Lexical
        if "lexical" in plan:
            ev_lexical = run_lexical_tool(normalized_url, features)
            evidence_list.append(ev_lexical)

        # Tool 2: Brand & Typosquatting
        if "brand" in plan:
            ev_brand = run_brand_tool(normalized_url, features)
            evidence_list.append(ev_brand)

        # Tool 3: Heuristics
        if "heuristics" in plan:
            ev_heuristics = run_heuristics_tool(normalized_url, features)
            evidence_list.append(ev_heuristics)

        # Tool 4: ML Prediction
        if "ml_model" in plan:
            ev_ml = run_ml_tool(normalized_url, features)
            evidence_list.append(ev_ml)

        # Tool 5: HTTPS & SSL
        if "https_cert" in plan:
            ev_https = run_https_tool(normalized_url, offline_mode=offline_mode)
            evidence_list.append(ev_https)

        # Tool 6: Domain WHOIS & DNS
        if "domain_whois_dns" in plan:
            ev_domain = run_domain_tool(normalized_url, offline_mode=offline_mode)
            evidence_list.append(ev_domain)

        # ==================== STEP 4: REFLECT ====================
        reflection_data = self._reflect(normalized_url, features, evidence_list)

        # ==================== STEP 5: DECIDE ====================
        verdict, risk_score, confidence, decision_details = evaluate_decision(
            normalized_url,
            evidence_list,
            reflection_data
        )

        # ==================== STEP 6: EXPLAIN ====================
        summary, reasons = build_explanation(
            verdict,
            risk_score,
            confidence,
            evidence_list,
            reflection_data
        )

        # Optional LLM rewrite if requested and enabled
        ai_summary: Optional[str] = None
        if ai_explanation_requested:
            plain_reasons = [r.reason for r in reasons[:5]]
            ai_summary = rewrite_explanation(normalized_url, verdict, risk_score, plain_reasons)

        agent_trace = AgentTrace(
            perceive=perceive_context,
            plan=plan,
            act=evidence_list,
            reflection=reflection_data,
            decide=decision_details,
            explain={"summary": summary, "reasons_count": len(reasons), "ai_generated": bool(ai_summary)}
        )

        return AnalyzeResponse(
            url=normalized_url,
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            summary=summary,
            reasons=reasons,
            ai_explanation=ai_summary,
            features=features,
            agent_trace=agent_trace,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    def _reflect(
        self,
        url: str,
        features: Dict[str, Any],
        evidence_list: List[Evidence]
    ) -> Dict[str, Any]:
        """
        Reflection Step:
        Examines divergence between ML model probability and heuristic score.
        If divergence exceeds 30 points or confidence is borderline (40-60),
        runs deeper inspection and logs reasons.
        """
        ev_map = {e.tool: e for e in evidence_list}
        ml_score = ev_map.get("ml_model").score_contribution if "ml_model" in ev_map else 50.0
        heuristic_score = ev_map.get("heuristics").score_contribution if "heuristics" in ev_map else 0.0

        disagreement = abs(ml_score - heuristic_score)
        is_borderline = (40.0 <= ml_score <= 60.0)

        reflection_triggered = (disagreement > 30.0) or is_borderline
        reflection_reasons: List[str] = []
        extra_risk_points = 0.0

        if not reflection_triggered:
            return {
                "triggered": False,
                "reason": "ML prediction and Heuristic rule scores are in strong consensus.",
                "disagreement_points": round(disagreement, 1),
                "extra_risk_points": 0.0,
                "reflection_reasons": []
            }

        # Identify reason for reflection
        trigger_msg = []
        if disagreement > 30.0:
            trigger_msg.append(f"Significant divergence ({disagreement:.1f} pts) between ML model ({ml_score:.1f}) and Heuristics ({heuristic_score:.1f})")
        if is_borderline:
            trigger_msg.append(f"ML probability is within the ambiguous decision zone ({ml_score:.1f}%)")

        # Deeper inspection 1: Path entropy and hidden query parameters
        parsed = urlparse(url)
        path = parsed.path or ""
        query = parsed.query or ""
        path_entropy = shannon_entropy(path)
        if path_entropy > 4.5 and len(path) > 20:
            reflection_reasons.append(f"Deep Path Analysis: High Shannon entropy in path segments ({path_entropy:.2f}), suggesting randomized evasion payloads.")
            extra_risk_points += 15.0

        # Deeper inspection 2: Mixed scripts or multiple dots in path
        if path.count(".") >= 3:
            reflection_reasons.append(f"Deep Path Analysis: Excessive extension or file-masking dots in URL path ({path.count('.')}).")
            extra_risk_points += 10.0

        # Deeper inspection 3: Multiple sensitive words concatenated
        sensitive_combos = [("login", "verify"), ("bank", "secure"), ("account", "update"), ("password", "reset")]
        lower_url = url.lower()
        for w1, w2 in sensitive_combos:
            if w1 in lower_url and w2 in lower_url:
                reflection_reasons.append(f"Compound Threat Signature: Paired sensitive action keywords ('{w1}' and '{w2}') detected in URL.")
                extra_risk_points += 15.0
                break

        return {
            "triggered": True,
            "trigger_reasons": trigger_msg,
            "disagreement_points": round(disagreement, 1),
            "extra_risk_points": extra_risk_points,
            "reflection_reasons": reflection_reasons
        }
