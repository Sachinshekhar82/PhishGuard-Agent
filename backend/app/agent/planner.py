"""
Agent Planner module for PhishGuard Agent.
Dynamically devises an inspection plan based on parsed URL characteristics and operational context.
"""

from typing import List, Dict, Any


def create_plan(perceive_context: Dict[str, Any], offline_mode: bool = False) -> List[str]:
    """
    Formulates the list of diagnostic tools to execute.
    
    Planning Logic:
    - Always schedule 'lexical' analysis for structural metrics.
    - Always schedule 'ml_model' for probabilistic classification.
    - If host is a raw IP address: prioritize 'heuristics' and skip 'brand' check.
    - If offline_mode is True: skip network-bound WHOIS/DNS ('domain') and certificate checks ('https_cert').
    - If host is a known URL shortener: prioritize 'heuristics' and flag masked destination.
    - Otherwise: include full suite ('lexical', 'brand', 'heuristics', 'ml_model', 'https_cert', 'domain').
    """
    plan = ["lexical", "heuristics", "ml_model"]

    is_ip = perceive_context.get("is_ip_host", False)
    is_shortener = perceive_context.get("is_shortener", False)

    # Brand tool selection
    if not is_ip:
        plan.append("brand")

    # Network-dependent tools
    if not offline_mode:
        plan.append("https_cert")
        if not is_ip:
            plan.append("domain_whois_dns")

    return plan
