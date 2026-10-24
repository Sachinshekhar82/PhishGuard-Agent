"""
Feature extraction module for PhishGuard Agent.
Extracts lexical, structural, keyword, and brand-based features directly from URL strings.
Used symmetrically during model training and real-time inference.
"""

import math
import re
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse, unquote
import tldextract
from typing import Dict, Any, List

# Load static reference lists for keywords, suspicious TLDs, and brands
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

try:
    with open(DATA_DIR / "suspicious_keywords.json", "r", encoding="utf-8") as f:
        KEYWORDS_DICT = json.load(f)
except Exception:
    KEYWORDS_DICT = {
        "auth": ["login", "signin", "password", "credential", "auth"],
        "urgency": ["verify", "confirm", "update", "secure", "suspend", "locked"],
        "financial": ["bank", "wallet", "billing", "invoice", "payment", "card", "crypto"],
        "lure": ["free", "bonus", "prize", "winner", "reward", "claim"],
        "service": ["support", "account", "portal", "helpdesk"]
    }

try:
    with open(DATA_DIR / "suspicious_tlds.json", "r", encoding="utf-8") as f:
        SUSPICIOUS_TLDS = set(json.load(f))
except Exception:
    SUSPICIOUS_TLDS = {"top", "xyz", "buzz", "club", "work", "loan", "icu", "cfd", "sbs"}

try:
    with open(DATA_DIR / "brands.json", "r", encoding="utf-8") as f:
        BRANDS_DATA = json.load(f)
except Exception:
    BRANDS_DATA = [
        {"name": "PayPal", "domains": ["paypal.com"], "keywords": ["paypal"]},
        {"name": "Google", "domains": ["google.com"], "keywords": ["google", "gmail"]},
        {"name": "Microsoft", "domains": ["microsoft.com", "office.com"], "keywords": ["microsoft", "office365", "outlook"]},
        {"name": "Apple", "domains": ["apple.com", "icloud.com"], "keywords": ["apple", "icloud"]},
        {"name": "Amazon", "domains": ["amazon.com"], "keywords": ["amazon"]}
    ]

# Known URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at"
}

# Homoglyph character substitutions (e.g., 0 for o, 1 for l, etc.)
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '8': 'b',
    '@': 'a',
    '$': 's'
}

SPECIAL_CHARS = set("-_.?=&%+~$!@#:,;~")

# Ordered list of feature names used by the ML model
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_dots_host",
    "num_hyphens",
    "num_hyphens_host",
    "num_underscores",
    "num_percent",
    "num_slashes_path",
    "has_at_symbol",
    "has_double_slash_path",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "special_char_ratio",
    "has_unusual_chars",
    "subdomain_count",
    "is_ip_host",
    "has_port",
    "is_shortener",
    "url_entropy",
    "hostname_entropy",
    "is_suspicious_tld",
    "has_https",
    "count_auth_keywords",
    "count_urgency_keywords",
    "count_financial_keywords",
    "count_lure_keywords",
    "count_service_keywords",
    "total_suspicious_keywords",
    "keyword_in_subdomain",
    "keyword_in_path",
    "brand_in_subdomain_or_path",
    "brand_typosquat_detected",
    "homoglyph_detected"
]


def shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a given text string."""
    if not text:
        return 0.0
    length = len(text)
    prob_map: Dict[str, int] = {}
    for char in text:
        prob_map[char] = prob_map.get(char, 0) + 1
    entropy = 0.0
    for count in prob_map.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_address(host: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address."""
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_url(raw_url: str) -> str:
    """
    Normalizes and validates a URL:
    - Strips leading/trailing whitespace
    - Defaults to 'http://' scheme if no scheme is specified
    - Lowercases scheme and netloc while preserving path casing
    """
    url = raw_url.strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        # Missing scheme: default to http://
        url = "http://" + url
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        if parsed.query:
            path += "?" + parsed.query
        if parsed.fragment:
            path += "#" + parsed.fragment
        return f"{scheme}://{netloc}{path}"
    except Exception:
        return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts numerical and boolean features for a URL.
    Returns a dictionary mapping each feature name in FEATURE_NAMES to a float or int.
    """
    url = normalize_url(raw_url)
    try:
        parsed = urlparse(url)
    except Exception:
        # Fallback for heavily malformed URLs
        parsed = urlparse("http://invalid.url")

    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Separate hostname and port if present
    hostname = netloc.split(":")[0]
    has_port = 1 if (":" in netloc and not netloc.startswith("[")) else 0

    # Extract domain components using tldextract
    ext = tldextract.extract(url)
    subdomain = (ext.subdomain or "").lower()
    domain = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()
    registered_domain = f"{domain}.{suffix}".strip(".") if domain else ""

    # 1. Lexical features
    url_len = len(url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = url.count(".")
    num_dots_host = hostname.count(".")
    num_hyphens = url.count("-")
    num_hyphens_host = hostname.count("-")
    num_underscores = url.count("_")
    num_percent = url.count("%")
    num_slashes_path = path.count("/")
    has_at_symbol = 1 if "@" in url else 0
    has_double_slash_path = 1 if "//" in path else 0

    digits = [c for c in url if c.isdigit()]
    digit_count = len(digits)
    digit_ratio = round(digit_count / max(url_len, 1), 4)

    specials = [c for c in url if c in SPECIAL_CHARS]
    special_char_count = len(specials)
    special_char_ratio = round(special_char_count / max(url_len, 1), 4)

    # Unusual characters: percent-encoded sequences, non-ascii, punycode (xn--)
    has_unusual = 0
    if "xn--" in hostname or "%" in url:
        has_unusual = 1
    try:
        url.encode("ascii")
    except UnicodeEncodeError:
        has_unusual = 1

    subdomain_parts = [p for p in subdomain.split(".") if p]
    subdomain_count = len(subdomain_parts)

    ip_host = 1 if is_ip_address(hostname) else 0
    is_short = 1 if (registered_domain in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS) else 0

    url_ent = shannon_entropy(url)
    host_ent = shannon_entropy(hostname)

    is_susp_tld = 1 if (suffix and suffix in SUSPICIOUS_TLDS) else 0
    has_https = 1 if scheme == "https" else 0

    # 2. Suspicious keywords analysis
    lower_url = url.lower()
    lower_path = path.lower()
    lower_sub = subdomain.lower()

    def count_matches(keywords: List[str], text: str) -> int:
        return sum(1 for kw in keywords if kw in text)

    count_auth = count_matches(KEYWORDS_DICT.get("auth", []), lower_url)
    count_urgency = count_matches(KEYWORDS_DICT.get("urgency", []), lower_url)
    count_financial = count_matches(KEYWORDS_DICT.get("financial", []), lower_url)
    count_lure = count_matches(KEYWORDS_DICT.get("lure", []), lower_url)
    count_service = count_matches(KEYWORDS_DICT.get("service", []), lower_url)
    total_keywords = count_auth + count_urgency + count_financial + count_lure + count_service

    all_kws = [kw for group in KEYWORDS_DICT.values() for kw in group]
    keyword_in_sub = 1 if any(kw in lower_sub for kw in all_kws) else 0
    keyword_in_pth = 1 if any(kw in lower_path for kw in all_kws) else 0

    # 3. Brand Impersonation & Typosquatting
    brand_in_sub_or_path = 0
    brand_typosquat = 0
    homoglyph_det = 0

    # Check homoglyph substitutions in domain
    normalized_domain = domain
    for h_char, rep in HOMOGLYPH_MAP.items():
        if h_char in normalized_domain:
            normalized_domain = normalized_domain.replace(h_char, rep)
            homoglyph_det = 1

    for brand in BRANDS_DATA:
        b_name = brand["name"].lower()
        b_domains = [d.lower() for d in brand.get("domains", [])]
        b_kws = [k.lower() for k in brand.get("keywords", [])]

        is_official = any(registered_domain == d or registered_domain.endswith("." + d) for d in b_domains)

        if not is_official:
            # Case A: Brand keyword appears in subdomain or path
            if any(kw in lower_sub or kw in lower_path for kw in b_kws):
                brand_in_sub_or_path = 1

            # Case B: Typosquatting on brand's primary registered domain
            for official_dom in b_domains:
                off_name = official_dom.split(".")[0]
                if domain and off_name:
                    dist = levenshtein_distance(domain, off_name)
                    # 1 edit distance or 2 edit distance for long names (>= 7 chars)
                    if (dist == 1 and domain != off_name) or (dist == 2 and len(off_name) >= 7 and domain != off_name):
                        brand_typosquat = 1
                        break
                    # Also check homoglyph normalized domain
                    if homoglyph_det:
                        h_dist = levenshtein_distance(normalized_domain, off_name)
                        if h_dist <= 1:
                            brand_typosquat = 1
                            break

    features = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_dots_host": num_dots_host,
        "num_hyphens": num_hyphens,
        "num_hyphens_host": num_hyphens_host,
        "num_underscores": num_underscores,
        "num_percent": num_percent,
        "num_slashes_path": num_slashes_path,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_count": special_char_count,
        "special_char_ratio": special_char_ratio,
        "has_unusual_chars": has_unusual,
        "subdomain_count": subdomain_count,
        "is_ip_host": ip_host,
        "has_port": has_port,
        "is_shortener": is_short,
        "url_entropy": url_ent,
        "hostname_entropy": host_ent,
        "is_suspicious_tld": is_susp_tld,
        "has_https": has_https,
        "count_auth_keywords": count_auth,
        "count_urgency_keywords": count_urgency,
        "count_financial_keywords": count_financial,
        "count_lure_keywords": count_lure,
        "count_service_keywords": count_service,
        "total_suspicious_keywords": total_keywords,
        "keyword_in_subdomain": keyword_in_sub,
        "keyword_in_path": keyword_in_pth,
        "brand_in_subdomain_or_path": brand_in_sub_or_path,
        "brand_typosquat_detected": brand_typosquat,
        "homoglyph_detected": homoglyph_det
    }

    return features


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Converts a features dictionary to an ordered feature vector matching FEATURE_NAMES."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
