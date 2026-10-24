"""
Explainer module for PhishGuard Agent.
Extracts, orders, and formats plain-English explanations of findings from all diagnostic tools.
"""

from typing import List, Dict, Any, Tuple
from backend.app.schemas import Evidence, ReasonItem


def build_explanation(
    verdict: str,
    risk_score: int,
    confidence: float,
    evidence_list: List[Evidence],
    reflection_data: Dict[str, Any] = None
) -> Tuple[str, List[ReasonItem]]:
    """
    Constructs an ordered list of contributing factors and a one-sentence summary.
    """
    severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "none": 0
    }

    items: List[ReasonItem] = []

    # Gather reasons from each evidence object
    for ev in evidence_list:
        if ev.status != "ok":
            continue
        for r_text in ev.reasons:
            if not r_text:
                continue
            # Deduplicate similar phrases
            if any(r_text.lower() == existing.reason.lower() for existing in items):
                continue

            impact_val = ev.score_contribution
            items.append(ReasonItem(
                reason=r_text,
                severity=ev.severity,
                impact=round(impact_val, 1)
            ))

    # Add reflection reasons if present
    if reflection_data and reflection_data.get("reflection_reasons"):
        for ref_reason in reflection_data["reflection_reasons"]:
            items.append(ReasonItem(
                reason=f"Reflection Check: {ref_reason}",
                severity="high",
                impact=30.0
            ))

    # Sort reasons by severity rank descending, then by impact score descending
    items.sort(key=lambda item: (severity_rank.get(item.severity, 0), item.impact), reverse=True)

    # Generate one-sentence summary
    if verdict == "Phishing":
        primary_threat = items[0].reason if items else "Multiple high-risk structural and brand signals"
        summary = f"Identified as Phishing (Risk Score {risk_score}/100) due to {primary_threat.lower()}."
    elif verdict == "Suspicious":
        primary_concern = items[0].reason if items else "Elevated anomalies and borderline indicators"
        summary = f"Flagged as Suspicious (Risk Score {risk_score}/100) with moderate risk indicators, primarily: {primary_concern.lower()}."
    else:
        summary = f"Classified as Legitimate (Risk Score {risk_score}/100) with no substantial malicious patterns or deception detected."

    return summary, items
