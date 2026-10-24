# PhishGuard Agent: Agentic AI Phishing Detection & Analysis System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg)](https://react.dev/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E.svg)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**PhishGuard Agent** is a defensive, autonomous cybersecurity application for phishing URL detection and analysis. It operates **strictly locally** without depending on external reputation lookups (such as VirusTotal) during primary detection, eliminating third-party latency, cost, and telemetry leaks.

> **Defensive Tool Notice:** This application analyzes URL text and metadata only. It never fetches, renders, executes, or follows redirects to remote target pages.

---

## 1. Quick Start (One-Command Startup)

### Windows
Run the single-click batch script from the repository root:
```bat
run.bat
```

### Linux / macOS
Make executable and run the startup script:
```bash
chmod +x run.sh
./run.sh
```

Both scripts automatically:
1. Create a Python virtual environment (`backend/.venv`) if one does not exist.
2. Install all required backend dependencies from `backend/requirements.txt`.
3. Check for the trained machine learning model; if absent, they automatically fetch real open-source phishing/legitimate datasets and train the Random Forest model.
4. Install frontend npm dependencies and compile the production bundle.
5. Launch the application server at **`http://127.0.0.1:8000`**.

---

## 2. Manual Setup & Development

### Backend Setup
```bash
# 1. Create and activate virtual environment
python -m venv backend/.venv

# Windows
backend\.venv\Scripts\activate
# Linux/macOS
source backend/.venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. (Optional) Fetch datasets and train model manually
python scripts/fetch_datasets.py
python backend/ml/train.py

# 4. Run backend server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend Development Server (Optional)
```bash
cd frontend
npm install
npm run dev
# Vite runs on http://127.0.0.1:5173 with automatic proxying to http://127.0.0.1:8000
```

---

## 3. Tech Stack

- **Backend:** Python 3.11+, FastAPI, Uvicorn, Pydantic v2, Pydantic-Settings
- **Machine Learning:** scikit-learn (Random Forest & Logistic Regression), pandas, numpy, joblib
- **URL & Domain Parsing:** `tldextract`, `urllib.parse`, `dnspython`, `cryptography`, `ssl`, `socket`
- **Frontend:** React 18, Vite, Tailwind CSS, Recharts (ROC Curve, Feature Importances), Lucide React
- **Storage:** SQLite for persistent historical audit trails
- **Testing:** pytest, FastAPI TestClient
- **Optional LLM:** Google GenAI SDK (`google-genai`), Gemin-2.5-flash (off by default)

---

## 4. Agentic AI Workflow (Core Engine)

PhishGuard Agent implements a multi-step Agentic AI loop in pure Python without requiring an external LLM for detection:

```
┌─────────────┐     ┌───────────┐     ┌─────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐
│ 1. PERCEIVE │ ──► │  2. PLAN  │ ──► │ 3. ACT  │ ──► │ 4.REFLECT │ ──► │ 5.DECIDE │ ──► │ 6.EXPLAIN │
└─────────────┘     └───────────┘     └─────────┘     └───────────┘     └──────────┘     └───────────┘
```

1. **PERCEIVE:**
   - Normalizes and sanitizes the URL (enforces `http`/`https`, strips padding, handles punycode and mixed encodings).
   - Extracts hostname, registered domain, path segments, and query parameters.
   - Computes structural feature representations.

2. **PLAN:**
   - Evaluates contextual parameters to dynamically construct a diagnostic execution plan:
     - If the host is a raw IP address: prioritizes heuristic rules and skips domain-based brand impersonation checks.
     - If `offline_mode` is enabled: skips network-dependent WHOIS/DNS and SSL certificate checks.
     - If the domain matches a known URL shortener: activates shortener masking alerts.
     - Always schedules `lexical`, `heuristics`, and `ml_model` tools.

3. **ACT:**
   - Executes each selected tool with isolated exception handling and strict timeouts.
   - Each tool generates a structured `Evidence` object:
     `{tool, features, score_contribution, severity, reasons[], status, time_ms}`.

4. **REFLECT:**
   - Compares the probabilistic ML risk score with the deterministic heuristic score.
   - If scores diverge by **> 30 points** or the ML confidence is within the borderline ambiguous zone (40–60%), the agent triggers a reflection routine:
     - Conducts deep Shannon entropy analysis across sub-path segments.
     - Scans for compound threat signatures (e.g., paired sensitive keywords like `login` + `verify`).
     - Inspects path dot counts and extension masquerading.
     - Documents the trigger justification in `agent_trace.reflection`.

5. **DECIDE:**
   - The Evaluator fuses ML probability ($w = 0.6$) and heuristic scores ($w = 0.4$):
     $$\text{Risk Score} = (0.6 \times \text{ML}) + (0.4 \times \text{Heuristics}) + \text{Brand Penalty} + \text{Cert Penalty} + \text{Reflection Modifier}$$
   - Exact Registrable-Domain Allowlist: verified domains matching top trusted sites (e.g., `google.com`, `github.com`) are protected against false positives unless blatant typosquatting or raw IP attacks occur.
   - Calibrates final score (0–100) and assigns classification verdict:
     - **0 to 34:** Legitimate
     - **35 to 64:** Suspicious
     - **65 to 100:** Phishing

6. **EXPLAIN:**
   - Ranks all triggered indicators by severity (`critical` > `high` > `medium` > `low`) and numerical impact.
   - Formulates a succinct one-sentence executive summary.
   - Optionally sends findings to Gemini (if enabled) for natural language synthesis.

---

## 5. Extracted Features & Cybersecurity Meaning

All features used for machine learning are extracted locally from the URL string itself without external network requests:

| Feature Name | Category | Cybersecurity Significance |
| :--- | :--- | :--- |
| `url_length` | Lexical | Phishing URLs often use lengthy strings to embed redirect parameters or obscure targets. |
| `hostname_length` | Lexical | Excessively long hostnames frequently indicate automated domain generation (DGA) or subdomains. |
| `path_length` | Lexical | Deep paths are used to conceal phishing credential collectors within benign hosting providers. |
| `query_length` | Lexical | Encoded tokens, victim emails, or tracking IDs are often appended to query strings. |
| `num_dots` / `num_dots_host` | Lexical | Multiple dots in hostnames indicate subdomain proliferation to spoof brand identities. |
| `num_hyphens` / `num_hyphens_host` | Lexical | Hyphens are widely used in brand typosquatting (e.g., `paypal-security-update`). |
| `num_underscores` | Lexical | Underscores in URLs are uncommon in standard sites and often signify automated script generation. |
| `num_percent` | Lexical | High frequency of percent-encoding (`%20`, `%2E`) indicates character obfuscation. |
| `num_slashes_path` | Lexical | Deep directory hierarchies used to mimic legitimate URL tree structures. |
| `has_at_symbol` | Lexical | The `@` symbol causes browsers to ignore all preceding characters as basic auth credentials. |
| `has_double_slash_path` | Lexical | `//` inside path sequences is a common redirection evasion and filter bypass technique. |
| `digit_count` / `digit_ratio` | Lexical | High numerical density reflects automated DGA hostnames or hex session IDs. |
| `special_char_count` / `special_char_ratio` | Lexical | Punctuation clutter intended to evade naive regex patterns. |
| `has_unusual_chars` | Lexical | Flags non-ASCII characters, percent encoding, or IDN punycode (`xn--`) scripts. |
| `subdomain_count` | Structural | High nesting counts (e.g. `login.verify.bank.evil.com`) signify spoofed infrastructure. |
| `is_ip_host` | Structural | URLs pointing to raw IPv4/IPv6 addresses bypass DNS blacklists and conceal domain identity. |
| `has_port` | Structural | Explicit non-standard ports (e.g. `:8080`, `:8443`) typically indicate compromised hosts or rogue servers. |
| `is_shortener` | Structural | URL shorteners (e.g. `bit.ly`, `tinyurl.com`) hide the final destination and redirect chains. |
| `url_entropy` / `hostname_entropy` | Entropy | Shannon entropy measures character randomness; high entropy signals DGA or encoded payloads. |
| `is_suspicious_tld` | Reputation | Known high-abuse TLDs (`.xyz`, `.top`, `.buzz`, `.club`, `.work`, `.loan`, etc.) with cheap registration. |
| `has_https` | Security | Legitimate services overwhelmingly use TLS; cleartext HTTP soliciting logins is high risk. |
| `count_auth_keywords` | Content | Frequency of authentication words (`login`, `signin`, `password`, `credential`, `sso`, `2fa`). |
| `count_urgency_keywords` | Content | Frequency of high-pressure words (`verify`, `confirm`, `update`, `suspend`, `locked`, `alert`). |
| `count_financial_keywords` | Content | Frequency of monetary lures (`bank`, `wallet`, `billing`, `invoice`, `payment`, `card`, `crypto`). |
| `count_lure_keywords` | Content | Free gifts, bonus claims, or prize scams (`free`, `bonus`, `prize`, `reward`, `airdrop`). |
| `count_service_keywords` | Content | Corporate impersonation keywords (`support`, `account`, `portal`, `helpdesk`, `client`). |
| `total_suspicious_keywords` | Content | Aggregate keyword density across entire URL. |
| `keyword_in_subdomain` | Structural | Sensitive words placed in subdomain prefixes to trick users viewing the start of the address bar. |
| `keyword_in_path` | Structural | Sensitive words located in path directories. |
| `brand_in_subdomain_or_path` | Brand | A recognized brand name appears in the subdomain/path, but the registered domain is NOT the brand's official domain. |
| `brand_typosquat_detected` | Brand | Levenshtein distance $\le 1$ or $\le 2$ matching a major protected brand domain (e.g. `paypa1.com`). |
| `homoglyph_detected` | Brand | Visual substitutions (e.g. `0` for `o`, `1` for `l`, `rn` for `m`) targeting brand names. |

---

## 6. Real Dataset Sources & Training Results

### Data Provenance (No Synthetic Main Data, No VirusTotal)
The model was trained exclusively on real-world public datasets downloaded automatically:

| Dataset Source | Category | Real URLs Fetched | Included in Final Training Set |
| :--- | :--- | :--- | :--- |
| **OpenPhish Community Feed** | Phishing (Label 1) | 300 active URLs | Yes |
| **Phishing.Database (mitchellkrogza)** | Phishing (Label 1) | 789,052 active URLs | Yes |
| **PhiUSIIL Phishing Dataset (UCI #967)** | Phishing & Legit | 100,945 Phish / 134,850 Legit | Yes |
| **Tranco Top Sites List** | Legitimate (Label 0) | 50,000 top domains | Yes |
| **Total Available Pool** | Balanced Pool | **184,848 Legit / 884,571 Phish** | **50,000 Cleaned Samples (1:1)** |

### Mitigating Dataset Bias
- **The Problem:** Public phishing feeds consist of complete URLs with deep paths, whereas standard benign lists (like Tranco) only list apex domains. A naive model would simply learn that "having a path = phishing".
- **The Solution:**
  1. Utilized the real-path legitimate URLs from the PhiUSIIL dataset.
  2. Enriched Tranco apex domains with realistic benign paths (e.g. `/about`, `/login`, `/products/item-101`, `/search?q=...`, `/blog/security`) for 50% of entries.
  3. Evaluated models separately on a **Domain-Only Slice** and a **Full-URL Slice** on held-out test data.
  4. Applied **Grouped Stratified Splitting** by registrable domain so that no domain in the training set ever leaks into the validation or test sets.

### Held-out Test Set Evaluation (15% Split, 8,533 URLs, 5,638 Unique Domains)

| Metric | Score | Note |
| :--- | :--- | :--- |
| **Overall Accuracy** | **94.07%** | Generalization on completely unseen domains |
| **Precision** | **97.89%** | Very low false positive rate |
| **Recall** | **91.47%** | Catches over 91 out of 100 phishing attacks |
| **F1 Score** | **0.9457** | Balanced harmonic score |
| **ROC-AUC** | **0.9809** | Near-optimal class discrimination |

#### Confusion Matrix (Held-out Test Set)
```
                   Predicted Legitimate    Predicted Phishing
Actual Legitimate:         3,618 (TN)               95 (FP)
Actual Phishing:             411 (FN)            4,409 (TP)
```

#### Bias Mitigation Slice Performance
- **Domain-Only Slice ($N = 4,809$):** Accuracy **91.60%**, Precision **94.80%**, F1 **0.8617**
- **Full-URL Slice ($N = 3,724$):** Accuracy **97.26%**, Precision **99.18%**, F1 **0.9841**

---

## 7. Optional LLM Enhancement (Google Gemini)

- Enabled via `.env` (`GEMINI_API_KEY` and `GEMINI_MODEL=gemini-2.5-flash`).
- **Strict Role Isolation:** The LLM **NEVER** decides the verdict or risk score. Verdicts and scores are strictly computed by the local ML and rule engines.
- **Functions:**
  1. Synthesizes technical indicators into a 2–3 sentence plain-English explanation.
  2. Powers `POST /api/explain-chat` for interactive follow-up questions about an analysis.
- **Defensive Safeguards:**
  - Treats the URL strictly as passive data.
  - Hardened system prompt defends against prompt injection payloads inside malicious URLs.
  - If the API key is revoked, missing, rate-limited, or times out (5s), the system **silently falls back** to the local plain-English explanation without impacting detection.

---

## 8. Optional VirusTotal Benchmarking Script

In strict accordance with defensive design principles, **VirusTotal is never called in the normal detection pipeline**.

An optional benchmarking script is provided at `scripts/benchmark_virustotal.py`. It is disabled by default unless `VT_API_KEY` is configured in `.env`.
```bash
python scripts/benchmark_virustotal.py
```
This utility compares local PhishGuard risk scores with live VirusTotal multi-engine consensus on benchmark samples.

---

## 9. API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `POST /api/analyze` | POST | Analyzes a single URL with full agent trace (`{url, offline_mode, ai_explanation}`) |
| `POST /api/analyze/batch` | POST | Analyzes up to 50 URLs in one batch request (`{urls: [], offline_mode}`) |
| `POST /api/explain-chat` | POST | Interactive cybersecurity Q&A about an analyzed URL via Gemini |
| `GET /api/history` | GET | Returns recent analysis records stored in SQLite |
| `DELETE /api/history` | DELETE | Clears stored analysis history |
| `GET /api/metrics` | GET | Returns model performance metrics, slice results, and dataset provenance |
| `GET /api/health` | GET | Returns engine health, loaded models, and LLM availability status |

---

## 10. Known Limitations

1. **Target Content Agnostic:** PhishGuard analyzes URL string patterns, lexical structure, and metadata only. It does not visit the webpage or execute client-side JavaScript. Sophisticated multi-stage exploits hosted on otherwise benign-looking paths require sandbox analysis.
2. **Shortener Masking:** URL shorteners mask the destination domain. In offline mode, PhishGuard flags the shortener as a high-risk obfuscation tactic rather than following the redirection hop.
3. **Stale Public Feeds:** Phishing URLs in public threat feeds have a short half-life (~24–48 hours). The dataset fetcher caches feeds for 7 days to maintain reproducibility.
