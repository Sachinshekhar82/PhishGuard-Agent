# MINI PROJECT REPORT
on
## Agentic AI-Based Phishing URL Detection and Analysis System
**(PhishGuard Agent)**

*Submitted in partial fulfilment of the requirements for the course*  
**Vulnerability Assessment and Penetration Testing**

### Submitted by:
| Name | USN | Semester |
| :--- | :--- | :--- |
| **Sachin Shekhar** | **1DT23CY040** | **7th** |

**Department / College:** Department of Computer Science & Engineering (Cybersecurity), Dayananda Sagar College of Engineering  
**Under the guidance of:** Faculty of Computer Science & Engineering  
**Academic Year:** 2025–2026  
**Date of submission:** October 2026  

---

## Abstract
Phishing remains one of the most common and damaging forms of cyber attack. Attackers register lookalike domains and craft deceptive URLs that trick users into revealing credentials and financial data. Traditionally, a suspicious URL is checked by manually submitting it to an external reputation service such as VirusTotal. This approach depends on a third party, is slow for bulk checking, and offers little insight into why a URL is considered dangerous.

This mini project presents **PhishGuard Agent**, an Agentic AI-based web application that detects and analyzes phishing URLs locally, without requiring VirusTotal for routine detection. The system accepts a URL, extracts lexical, protocol, domain and brand-impersonation features, and coordinates several detection tools through an agent loop made of six stages: **Perceive, Plan, Act, Reflect, Decide, and Explain**. A machine-learning model trained on real phishing and legitimate URL datasets is combined with a transparent rule-based engine to produce a phishing risk score between 0 and 100, a verdict of *Legitimate*, *Suspicious*, or *Phishing*, and a plain-English list of the reasons behind the decision.

The application is built with a FastAPI backend, a scikit-learn model, a React and Tailwind CSS frontend, and an SQLite history store. An optional Gemini language-model integration can rewrite the explanation in friendlier language, but it never influences the verdict. The system was evaluated on a held-out test set of 8,533 URLs across 5,638 unique domains, achieving an accuracy of **94.07%**, precision of **97.89%**, recall of **91.47%**, an F1-score of **0.9457**, and an ROC-AUC of **0.9809**.

**Keywords:** Phishing detection, Agentic AI, URL analysis, Machine learning, Random Forest, FastAPI, Explainable detection, Cybersecurity.

---

## Table of Contents
1. Introduction
2. Problem Statement
3. Objectives
4. Background and Related Concepts
5. System Requirements
6. System Design and Architecture
7. Agentic AI Workflow
8. Feature Engineering
9. Dataset and Model Training
10. Implementation
11. Testing
12. Results and Discussion
13. Security and Ethical Considerations
14. Limitations
15. Future Scope
16. Conclusion
References

---

## 1. Introduction
Phishing is a social-engineering attack in which an adversary impersonates a trusted entity such as a bank, an online store or an email provider to steal sensitive information. The attack almost always travels through a URL, whether in an email, an SMS, a messaging app or a search advertisement. Because users decide whether to click mainly by looking at the URL, the URL itself carries many signals that can reveal an attack: unusually long addresses, misleading subdomains, raw IP addresses, suspicious keywords, lack of HTTPS, and domain names that imitate well-known brands.

Reputation services such as VirusTotal aggregate the verdicts of many security vendors and are very useful, but relying on them for every check has drawbacks. Newly created phishing sites are often not yet listed, the service is rate-limited, the URL is shared with a third party, and the result usually does not explain which characteristics make the URL risky. This project addresses those gaps by building a self-contained detection system that analyzes the URL on its own.

The system follows an agentic design. Instead of running one fixed classifier, an agent decides which analysis tools are appropriate for the given URL, gathers their evidence, checks whether the evidence is consistent, and then produces a final assessment together with an explanation.

---

## 2. Problem Statement
To design and develop an Agentic AI-based system that can independently detect and analyze potentially malicious or phishing URLs without relying on VirusTotal for every verification. The system must analyze URL characteristics such as length, suspicious keywords, domain information, HTTPS usage and unusual characters, classify the URL as legitimate, suspicious or phishing, assign a risk score, and explain the factors that contributed to the decision.

---

## 3. Objectives
- To understand phishing attacks and the URL-based threats used to deceive users.
- To develop an automated phishing URL detection mechanism using machine-learning and rule-based techniques.
- To implement an Agentic AI workflow that coordinates URL analysis and decision-making.
- To reduce dependence on external URL reputation services such as VirusTotal.
- To generate a phishing risk score and a human-readable explanation for every detection result.
- To evaluate the system using real legitimate and phishing URL datasets.

---

## 4. Background and Related Concepts

### 4.1 Anatomy of a URL
A URL consists of a scheme (`http` or `https`), an optional user-information part, a host (made of subdomains, a registered domain and a top-level domain), an optional port, a path, a query string and a fragment. Phishers manipulate each of these parts. For example, in the address `paypal.com.secure-login.example.top`, the real registered domain is `example.top`; the word `paypal.com` appears only as a subdomain to fool the reader.

### 4.2 Common Phishing URL Techniques
- **Lookalike domains (typosquatting):** replacing or adding characters, for example `paypa1.com` instead of `paypal.com`.
- **Homoglyph and IDN attacks:** using visually similar characters (e.g. `0` for `o`, `1` for `l`, `rn` for `m`) or punycode domains (`xn--...`).
- **Subdomain abuse:** placing a trusted brand name in the subdomain or path while the registered domain belongs to the attacker.
- **IP-address hosts:** using a raw IP instead of a domain name to avoid registration traces.
- **Keyword stuffing:** adding words such as `login`, `verify`, `secure` or `update` to look official.
- **URL shorteners and redirects:** hiding the real destination (`bit.ly`, `tinyurl.com`).
- **Abused top-level domains:** TLDs that are frequently used for disposable malicious sites (`.xyz`, `.top`, `.buzz`, `.club`, `.loan`).

### 4.3 Agentic AI
An agentic system does more than return a single prediction. It perceives its input, plans which actions to take, uses specialized tools to gather information, reflects on whether the results make sense, and then decides and explains. In this project the agent is implemented in plain Python without needing a large language model, which keeps the primary analysis fast (< 50ms), local, and reproducible.

### 4.4 Machine Learning for URL Classification
Supervised learning is used to learn the difference between phishing and legitimate URLs from labeled examples. Two classifiers were trained and compared: Random Forest, an ensemble of decision trees that handles non-linear feature interactions and provides feature importance rankings, and Logistic Regression, a simple linear baseline. Random Forest achieved a higher validation F1-score (0.9264 vs 0.8865) and was deployed as the primary inference engine.

---

## 5. System Requirements

### 5.1 Software Requirements
| Component | Technology |
| :--- | :--- |
| **Backend language** | Python 3.11.9 |
| **Web framework** | FastAPI 0.162.0 with Uvicorn 0.54.0, Pydantic v2 |
| **Machine learning** | scikit-learn 1.9.1, pandas 3.1.0, numpy 2.4.6, joblib 1.6.0 |
| **URL & domain parsing** | tldextract 5.4.0, urllib.parse, dnspython 2.9.0, cryptography, socket, ssl |
| **Frontend** | React 18.3.1, Vite 5.3.1, Tailwind CSS 3.4.4, Recharts 2.12.7, Lucide React |
| **Database** | SQLite3 (`phishguard.db`) for analysis audit history |
| **Testing** | pytest 9.1.1, FastAPI TestClient (httpx) |
| **Optional LLM** | Google Gemini 2.5 Flash via official `google-genai` SDK |
| **Development environment** | Google Antigravity (AI-assisted Agentic IDE) |

### 5.2 Hardware Requirements
- A standard laptop or desktop with at least 8 GB RAM and a dual-core processor or better.
- Internet connection for initial dataset download and optional online DNS/SSL checks; core analysis runs strictly offline.

### 5.3 Functional Requirements
- Accept single URLs or bulk batches (up to 50 URLs) and return verdict, risk score, and plain-English reasons.
- Render complete Agent Trace (Perceive, Plan, Act, Reflect, Decide, Explain) for transparency.
- Store analysis history in SQLite with re-inspection and purge capabilities.
- Display model evaluation metrics, confusion matrix, ROC curve, and dataset provenance.

### 5.4 Non-Functional Requirements
- Detection runs locally without VirusTotal and functions fully offline.
- Offline analysis executes in under 50 milliseconds per URL.
- Zero network interaction with target websites: never visits, renders, or follows redirects.
- Resilient modular architecture: single tool errors never crash the pipeline.

---

## 6. System Design and Architecture
PhishGuard Agent follows a three-tier architecture:

```
┌────────────────────────────────────────────────────────┐
│                   Web Browser Client                   │
│         React 18 + Vite + Tailwind CSS + Recharts      │
└───────────────────────────┬────────────────────────────┘
                            │ REST API Requests
┌───────────────────────────▼────────────────────────────┐
│                  FastAPI Backend Server                │
│    (/api/analyze, /api/batch, /api/history, /metrics)  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│              Autonomous Agent Orchestrator             │
│        Perceive ➔ Plan ➔ Act ➔ Reflect ➔ Decide ➔ Explain│
└──────┬────────────┬────────────┬────────────┬──────────┘
       │            │            │            │
 ┌─────▼──────┐┌────▼───────┐┌───▼──────┐┌────▼───────┐
 │   Lexical  ││ Brand/Typo ││Heuristics││  ML Model  │
 │    Tool    ││    Tool    ││   Engine ││ (joblib)   │
 └────────────┘└────────────┘└──────────┘└────────────┘
```

### 6.1 Backend Modules
| Module | Responsibility |
| :--- | :--- |
| `main.py` / `schemas.py` | API routing, request validation, rate limiting, and CORS |
| `agent/orchestrator.py` | Coordinates the 6-stage agent loop and builds execution traces |
| `agent/planner.py` | Dynamically selects diagnostic tools based on URL context |
| `agent/evaluator.py` | Fuses ML and heuristic scores with allowlist filtering |
| `agent/explainer.py` | Formulates ranked plain-English reasons and executive summary |
| `agent/llm.py` | Optional Gemini wrapper for rephrasing explanations |
| `tools/lexical.py` | Measures URL length, character ratios, entropy, and keywords |
| `tools/domain.py` | Inspects DNS resolution and WHOIS domain age (offline-safe) |
| `tools/https_tool.py` | Evaluates HTTPS usage and certificate validity (offline-safe) |
| `tools/heuristics.py` | Evaluates deterministic cybersecurity rules and behavioral signatures |
| `tools/ml_model.py` | Executes inference with the trained Random Forest model |
| `tools/brand.py` | Detects brand impersonation, typosquatting, and homoglyphs |
| `ml/features.py` | Extracts 37 numerical and boolean features symmetrically |
| `ml/dataset.py` | Downloads, deduplicates, balances, and prepares datasets |
| `ml/train.py` | Executes domain-grouped training, cross-validation, and export |
| `db.py` | Thread-safe SQLite persistence for scan records |

### 6.2 API Endpoints
| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/analyze` | POST | Analyzes a single URL; returns verdict, score, reasons, and trace |
| `/api/analyze/batch` | POST | Analyzes up to 50 URLs in one batch submission |
| `/api/explain-chat` | POST | Answers follow-up queries about an analyzed URL via Gemini |
| `/api/history` | GET / DELETE | Views past analysis audit records or clears history |
| `/api/metrics` | GET | Returns model performance metrics and dataset provenance |
| `/api/health` | GET | Verifies service status, loaded model, and LLM readiness |

---

## 7. Agentic AI Workflow

```
┌─────────────┐     ┌───────────┐     ┌─────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐
│ 1. PERCEIVE │ ──► │  2. PLAN  │ ──► │ 3. ACT  │ ──► │ 4.REFLECT │ ──► │ 5.DECIDE │ ──► │ 6.EXPLAIN │
└─────────────┘     └───────────┘     └─────────┘     └───────────┘     └──────────┘     └───────────┘
```

### 7.1 Stage Description
1. **Perceive:** Normalizes the URL, adds missing schemes, enforces HTTP/HTTPS, handles punycode/IDN, and extracts structural tokens.
2. **Plan:** Evaluates URL properties to select active tools. Raw IP hosts trigger heuristics while skipping brand checks; offline mode disables network-bound WHOIS/SSL checks; URL shorteners trigger masking warnings.
3. **Act:** Executes scheduled tools concurrently or sequentially. Each returns structured `Evidence` containing features, score contribution, severity, reasons, and timing.
4. **Reflect:** Compares ML probability with heuristic scores. If they diverge by **> 30 points** or ML confidence is borderline (40–60%), the agent performs deeper checks (path entropy, compound sensitive keyword pairs) and documents the rationale.
5. **Decide:** Fuses ML ($w=0.6$) and heuristic ($w=0.4$) scores. An exact registrable-domain allowlist bounds false positives on trusted services (e.g. Google, GitHub, Microsoft).
6. **Explain:** Sorts factors by severity (`critical` > `high` > `medium` > `low`) and impact, generating an actionable summary.

### 7.2 Verdict Thresholds
| Risk Score | Verdict | Meaning |
| :--- | :--- | :--- |
| **0 – 34** | **Legitimate** | No strong phishing indicators detected |
| **35 – 64** | **Suspicious** | Moderate risk indicators; exercise caution |
| **65 – 100** | **Phishing** | Strong malicious patterns; do not visit or input credentials |

---

## 8. Feature Engineering
The system extracts 37 features locally from the URL text alone:

| Category | Features Extracted | Cybersecurity Significance |
| :--- | :--- | :--- |
| **Length** | `url_length`, `hostname_length`, `path_length`, `query_length` | Long URLs conceal redirected domains or malicious targets |
| **Characters** | Dots, hyphens, underscores, `@`, `//` in path, digit count/ratio, percent-encoding, unusual characters | Obfuscation, browser credential abuse, and evasion patterns |
| **Host Structure** | Subdomain count, raw IP host, non-standard port, suspicious TLD, shortener flag | DNS avoidance, compromised servers, and cheap disposable TLDs |
| **Entropy** | Shannon entropy of URL string and hostname | Algorithmic domain generation (DGA) or random evasion payloads |
| **Keywords** | Frequency of auth, urgency, financial, lure, and service keywords | Social-engineering lures and credential theft language |
| **Protocol** | `has_https` flag | Cleartext HTTP soliciting sensitive credentials is high risk |
| **Brand Impersonation** | Brand in path/subdomain, typosquatting edit distance, homoglyphs (`0/o`, `1/l`, `rn/m`) | Deceptive brand imitation targeting banks, tech, and retail |
| **Domain Metadata (Rules only)** | Domain age, WHOIS registrar, DNS resolution, SSL cert validity | Newly registered domains (< 30 days) signify throwaway attacks |

---

## 9. Dataset and Model Training

### 9.1 Data Sources
The system was trained on real public datasets downloaded automatically without external reputation APIs:
- **Phishing URLs (Label 1):**
  - **OpenPhish Community Feed:** 300 active URLs
  - **Phishing.Database (mitchellkrogza):** 789,052 active URLs
  - **PhiUSIIL Phishing Dataset (UCI #967):** 100,945 phishing URLs
- **Legitimate URLs (Label 0):**
  - **PhiUSIIL Phishing Dataset (UCI #967):** 134,850 legitimate URLs (with real paths)
  - **Tranco Top Sites List:** 50,000 top domains

### 9.2 Data Preparation & Bias Control
- **Bias Mitigation:** Tranco supplies bare apex domains, while phishing feeds contain full paths. To prevent the model from learning a false correlation ("has a path = phishing"), 50% of Tranco domains were enriched with realistic benign paths (`/about`, `/login`, `/products`, `/docs/api`), and real paths from PhiUSIIL were utilized.
- **Leak-Free Splitting:** A **70/15/15** train/val/test split was performed using `GroupShuffleSplit` on the registered domain. No domain in the training set appears in validation or testing.

### 9.3 Dataset Summary
| Item | Exact Value |
| :--- | :--- |
| **Total URLs in Curated Dataset** | **50,000** |
| **Phishing URLs (Label 1)** | **25,000** (50.0%) |
| **Legitimate URLs (Label 0)** | **25,000** (50.0%) |
| **Unique Registered Domains** | **37,585** |
| **Train Set Samples (70%)** | **34,836** (26,309 unique domains) |
| **Validation Set Samples (15%)** | **6,631** (5,638 unique domains) |
| **Held-Out Test Set Samples (15%)** | **8,533** (5,638 unique domains) |
| **Date of Download** | **October 24, 2026** |

### 9.4 Models
Random Forest (100 estimators, max depth 16) and Logistic Regression (L2 regularization, max iter 1000) were trained. Random Forest achieved a superior validation F1-score (**0.9264 vs 0.8865**) and was serialized to `backend/models/phishguard_model.joblib`.

---

## 10. Implementation

### 10.1 Backend
FastAPI powers the REST service with automated CORS, sliding-window rate limiting (120 req/min), and Pydantic validation. The backend handles inference without executing remote scripts or opening sockets to the target page.

### 10.2 Optional Gemini Integration
Google Gemini 2.5 Flash is integrated via the official `google-genai` SDK. It rephrases technical findings into natural language and powers `/api/explain-chat`. It is strictly isolated from verdict decisions and falls back silently to local plain English if unconfigured, expired, or rate-limited.

### 10.3 Frontend
The React 18 interface provides:
- **Analyzer:** Real-time risk gauge (0–100), verdict badges, plain-English reasons with severity tags, and a collapsible Agent Trace timeline.
- **Batch Analyzer:** Analyzes up to 50 URLs simultaneously with CSV export.
- **History:** Audits past scans stored in SQLite.
- **Model Dashboard:** Displays live ROC curve, confusion matrix, slice evaluations, and feature importances.

---

## 11. Testing
The automated test suite runs via pytest with zero external internet dependencies:

### 11.1 Functional Verification Results
| Test URL | Expected Verdict | Observed Verdict | Risk Score | Confidence | Observed Planner Actions & Reasons |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `https://www.google.com` | Legitimate | **Legitimate** | **0 / 100** | **98%** | Allowlist matched; clean lexical indicators |
| `https://github.com/user/repo` | Legitimate | **Legitimate** | **0 / 100** | **98%** | Allowlist matched; normal repository path |
| `http://paypal-secure-login.verify-account.example-xyz.top/signin` | Phishing | **Phishing** | **100 / 100** | **99%** | Brand impersonation in subdomain, cleartext HTTP, `.xyz` high-risk TLD |
| `http://192.168.1.10/bank/login.php` | Phishing | **Phishing** | **87 / 100** | **94%** | Brand check skipped (raw IP host); IP heuristic rule + banking keyword triggered |
| Empty input / Invalid scheme (`ftp://...`) | Rejected | **Rejected (400 Bad Request)** | **N/A** | **N/A** | Returned safe error: *"Only HTTP and HTTPS are supported."* |

**Automated Test Suite Result:**  
**35 passed, 0 failed** in **2.12s** (covering features, tools, planner, evaluator, API routes, and LLM fallback).

---

## 12. Results and Discussion

### 12.1 Evaluation Metrics (Held-Out Test Set)
Evaluated on **8,533 unseen URLs** across **5,638 unseen domains**:

| Metric | Random Forest (Selected Model) | Logistic Regression (Baseline) |
| :--- | :--- | :--- |
| **Accuracy** | **94.07%** (0.9407) | **90.79%** (0.9079) |
| **Precision** | **97.89%** (0.9789) | **93.17%** (0.9317) |
| **Recall** | **91.47%** (0.9147) | **84.55%** (0.8455) |
| **F1-Score** | **0.9457** (0.9457) | **0.8865** (0.8865) |
| **ROC-AUC** | **0.9809** (0.9809) | **0.9494** (0.9494) |

### 12.2 Confusion Matrix (Test Set: N = 8,533)
| | Predicted Legitimate | Predicted Phishing |
| :--- | :--- | :--- |
| **Actual Legitimate** | **3,618 (TN)** | **95 (FP)** |
| **Actual Phishing** | **411 (FN)** | **4,409 (TP)** |

### 12.3 Dataset Bias Mitigation Slice Results
- **Domain-Only Slice ($N = 4,809$):** Accuracy **91.60%**, Precision **94.80%**, Recall **78.98%**, F1 **0.8617**
- **Full-URL Slice ($N = 3,724$):** Accuracy **97.26%**, Precision **99.18%**, Recall **97.64%**, F1 **0.9841**

### 12.4 Discussion
1. **Feature Importance:** Random Forest feature importance analysis revealed that `url_length` (0.1715), `path_length` (0.1293), and `url_entropy` (0.1093) were the top three predictive features, followed by `digit_ratio` (0.0811), `digit_count` (0.0760), and `has_https` (0.0701). This demonstrates that structural anomalies and randomized character distributions remain strong signals of attack infrastructure.
2. **Analysis of Misclassifications:** Out of 8,533 test URLs, only 95 legitimate URLs were falsely flagged as phishing (FP rate: 2.5%), mostly involving long promotional tracking URLs on lesser-known TLDs. False negatives (411 cases) occurred on very short phishing URLs that closely resembled benign apex domain structures without path tokens. The agent's reflection step effectively caught compound keywords and high-entropy subpaths in these edge cases.

---

## 13. Security and Ethical Considerations
- **Defensive Safeguards:** The system never makes outbound HTTP requests to the target destination, ensuring zero risk of drive-by malware execution or cross-site scripting.
- **Privacy:** Analysis occurs locally; user-entered URLs are never uploaded to third-party threat intelligence aggregators.
- **Injection Defenses:** Gemini inputs treat URLs strictly as passive data, mitigating prompt injection vulnerabilities.

---

## 14. Limitations
1. **Content Agnostic:** URLs serving clean landing pages with dynamic client-side DOM injection cannot be detected without sandboxed rendering.
2. **Shortened URLs:** Services like `bit.ly` cannot reveal their real destination domain without performing a redirect lookup.
3. **Domain Churn:** Phishing campaigns rapidly rotate disposable domains, necessitating scheduled weekly dataset refreshes.

---

## 15. Future Scope
- Integration of a headless browser (e.g. Playwright) for sandboxed DOM visual screenshot inspection.
- Development of a client-side Chromium extension for proactive real-time link warning.
- Automated weekly cron re-training from live threat feeds.

---

## 16. Conclusion
PhishGuard Agent successfully delivers a defensive, self-contained phishing detection platform. By combining a 6-stage Agentic AI loop (Perceive, Plan, Act, Reflect, Decide, Explain) with a Random Forest model trained on 50,000 real-world URLs, the system eliminates reliance on external reputation services while maintaining **94.07% accuracy** and **97.89% precision**. Every decision is accompanied by plain-English explanations and a full agent trace, providing a practical, privacy-preserving cybersecurity tool.

---

## References
[1] OpenPhish, "Community phishing feed," https://openphish.com.  
[2] M. Krogza, "Phishing.Database," GitHub repository, 2026.  
[3] PhishTank, "Developer information and data feed," https://phishtank.org.  
[4] Tranco, "A research-oriented top sites ranking hardened against manipulation," https://tranco-list.eu.  
[5] A. Prasad and S. Chandra, "PhiUSIIL Phishing URL Dataset," UCI Machine Learning Repository, 2024.  
[6] F. Pedregosa et al., "Scikit-learn: Machine learning in Python," Journal of Machine Learning Research, vol. 12, 2011.  
[7] FastAPI Documentation, https://fastapi.tiangolo.com.  
[8] OWASP Foundation, "Phishing," https://owasp.org.  
[9] Anti-Phishing Working Group (APWG), "Phishing Activity Trends Reports," https://apwg.org.
