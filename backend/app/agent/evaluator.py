"""
Evaluator module for PhishGuard Agent.
Fuses multi-modal evidence from ML models, heuristics, brand inspection, and network tools
into a calibrated 0-100 risk score, categorical verdict, and confidence score.
"""

from typing import List, Dict, Any, Tuple
import tldextract
from backend.app.schemas import Evidence
from backend.app.config import settings


def evaluate_decision(
    url: str,
    evidence_list: List[Evidence],
    reflection_data: Dict[str, Any] = None
) -> Tuple[str, int, float, Dict[str, Any]]:
    """
    Fuses evidence into:
    - verdict: 'Legitimate' | 'Suspicious' | 'Phishing'
    - risk_score: int (0 - 100)
    - confidence: float (0.0 - 1.0)
    - decision_details: dict explaining weights and contributions
    """
    evidence_map = {e.tool: e for e in evidence_list}

    # Extract primary components
    ml_ev = evidence_map.get("ml_model")
    heuristics_ev = evidence_map.get("heuristics")
    brand_ev = evidence_map.get("brand")
    lexical_ev = evidence_map.get("lexical")
    https_ev = evidence_map.get("https_cert")

    ml_score = ml_ev.score_contribution if ml_ev and ml_ev.status == "ok" else 50.0
    heuristic_score = heuristics_ev.score_contribution if heuristics_ev and heuristics_ev.status == "ok" else 0.0

    # Base weighted fusion
    w_ml = settings.ML_WEIGHT
    w_heuristics = settings.HEURISTIC_WEIGHT

    base_fused = (ml_score * w_ml) + (heuristic_score * w_heuristics)

    # Incorporate brand severity modifier if critical typosquatting or brand impersonation was detected
    brand_penalty = 0.0
    if brand_ev and brand_ev.status == "ok":
        if brand_ev.severity == "critical":
            brand_penalty = 25.0
        elif brand_ev.severity == "high":
            brand_penalty = 15.0

    # Insecure HTTP credential solicitation penalty
    https_penalty = 0.0
    if https_ev and https_ev.status == "ok" and https_ev.severity == "high":
        https_penalty = 10.0

    # Apply reflection adjustments if reflection found high-risk indicators
    reflection_modifier = 0.0
    if reflection_data and reflection_data.get("extra_risk_points"):
        reflection_modifier = reflection_data["extra_risk_points"]

    fused_risk = base_fused + brand_penalty + https_penalty + reflection_modifier

    # Allowlist check: Exact registrable-domain match only!
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".strip(".").lower() if ext.domain else ""
    is_allowlisted = registered_domain in settings.TOP_LEGITIMATE_DOMAINS

    # If domain is strictly on the legitimate allowlist AND no blatant brand typosquat was detected,
    # cap the risk score to prevent false positives on major sites
    is_brand_typosquat = (brand_ev and brand_ev.features.get("brand_typosquat_detected", 0) == 1) if brand_ev else False
    if is_allowlisted and not is_brand_typosquat:
        # Heavily attenuate risk for verified major domains
        fused_risk = min(fused_risk * 0.15, float(settings.LEGITIMATE_THRESHOLD - 5))

    final_score = int(min(100, max(0, round(fused_risk))))

    # Classification Thresholds:
    # 0 - 34: Legitimate
    # 35 - 64: Suspicious
    # 65 - 100: Phishing
    if final_score <= settings.LEGITIMATE_THRESHOLD:
        verdict = "Legitimate"
    elif final_score >= settings.PHISHING_THRESHOLD:
        verdict = "Phishing"
    else:
        verdict = "Suspicious"

    # Confidence calculation:
    # 1. Consensus between ML and heuristics
    diff = abs(ml_score - heuristic_score)
    consensus_score = max(0.0, 1.0 - (diff / 100.0))  # 1.0 when perfectly agreeing, 0.0 when 100 apart

    # 2. Distance from decision boundaries (34 and 65)
    dist_to_boundary = min(abs(final_score - settings.LEGITIMATE_THRESHOLD), abs(final_score - settings.PHISHING_THRESHOLD))
    boundary_confidence = min(1.0, 0.5 + (dist_to_boundary / 40.0))

    if is_allowlisted:
        confidence = 0.98
    elif is_brand_typosquat:
        confidence = 0.95
    else:
        confidence = round(0.5 * consensus_score + 0.5 * boundary_confidence, 2)
        confidence = max(0.50, min(0.99, confidence))

    decision_details = {
        "ml_weight": w_ml,
        "heuristic_weight": w_heuristics,
        "ml_score": ml_score,
        "heuristic_score": heuristic_score,
        "brand_penalty": brand_penalty,
        "https_penalty": https_penalty,
        "reflection_modifier": reflection_modifier,
        "is_allowlisted": is_allowlisted,
        "registered_domain": registered_domain
    }

    return verdict, final_score, confidence, decision_details
