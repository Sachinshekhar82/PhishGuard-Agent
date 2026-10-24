"""
Dataset management, downloading, cleaning, and preparation module for PhishGuard Agent.
Fetches real datasets from OpenPhish, Phishing.Database, Tranco, and PhiUSIIL.
Mitigates path bias, ensures clean deduplication, and groups domains to prevent data leakage.
"""

import os
import sys
import time
import json
import random
import zipfile
import urllib.request
import io
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Any
import pandas as pd
import tldextract

from backend.ml.features import normalize_url

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
DATASET_CSV = DATA_DIR / "dataset.csv"
DATASET_INFO_JSON = DATA_DIR / "dataset_info.json"

RAW_DIR.mkdir(parents=True, exist_ok=True)

COMMON_BENIGN_PATHS = [
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/contact-us",
    "/login",
    "/signin",
    "/products",
    "/products/item-101",
    "/services",
    "/blog",
    "/blog/security-updates",
    "/news/latest",
    "/help",
    "/help/faq",
    "/support",
    "/pricing",
    "/features",
    "/privacy-policy",
    "/terms-of-service",
    "/docs",
    "/docs/api/v1",
    "/search?q=cybersecurity",
    "/search?q=technology",
    "/account/settings"
]


def is_cache_valid(file_path: Path, max_age_days: int = 7) -> bool:
    """Checks whether a cached file exists and was modified within max_age_days."""
    if not file_path.exists():
        return False
    file_age = datetime.now() - datetime.fromtimestamp(file_path.stat().st_mtime)
    return file_age < timedelta(days=max_age_days)


def download_with_retry(url: str, output_path: Path, timeout: int = 25, retries: int = 2) -> bool:
    """Downloads a file with user-agent headers, timeout, and retry logic."""
    if is_cache_valid(output_path):
        print(f"Using cached file: {output_path.name}")
        return True

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0"}
    for attempt in range(retries):
        try:
            print(f"Downloading {url} (Attempt {attempt+1}/{retries})...")
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = response.read()
                    with open(output_path, "wb") as f:
                        f.write(data)
                    print(f"Saved {output_path.name} ({len(data) / 1024:.1f} KB)")
                    return True
        except Exception as e:
            print(f"Download attempt {attempt+1} failed for {url}: {e}")
            time.sleep(1.5)
    return False


def fetch_openphish() -> List[str]:
    """Downloads and extracts URLs from the OpenPhish community feed."""
    cache_file = RAW_DIR / "openphish_feed.txt"
    url = "https://openphish.com/feed.txt"
    urls = []
    if download_with_retry(url, cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if u and u.startswith(("http://", "https://")):
                        urls.append(u)
        except Exception as e:
            print(f"Error reading OpenPhish cache: {e}")
    return urls


def fetch_phishing_database() -> List[str]:
    """Downloads URLs from Phishing.Database (mitchellkrogza)."""
    cache_file = RAW_DIR / "phishing_database_active.txt"
    url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    urls = []
    if download_with_retry(url, cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if u and u.startswith(("http://", "https://")):
                        urls.append(u)
        except Exception as e:
            print(f"Error reading Phishing.Database cache: {e}")
    return urls


def fetch_phishtank() -> List[str]:
    """Attempts to download PhishTank feed if available without auth."""
    cache_file = RAW_DIR / "phishtank.csv"
    url = "http://data.phishtank.com/data/online-valid.csv"
    urls = []
    try:
        if download_with_retry(url, cache_file, timeout=10, retries=1):
            df = pd.read_csv(cache_file)
            if "url" in df.columns:
                urls = df["url"].dropna().astype(str).tolist()
    except Exception:
        # Silently skip if auth required or unreachable
        pass
    return urls


def fetch_tranco_top_sites(limit: int = 50000) -> List[str]:
    """Downloads the Tranco top sites list and extracts the top domains."""
    cache_file = RAW_DIR / "tranco_top1m.zip"
    url = "https://tranco-list.eu/top-1m.csv.zip"
    domains = []
    if download_with_retry(url, cache_file):
        try:
            with zipfile.ZipFile(cache_file, "r") as z:
                csv_filename = z.namelist()[0]
                with z.open(csv_filename) as f:
                    # Tranco format: rank,domain
                    count = 0
                    for line in f:
                        parts = line.decode("utf-8", errors="ignore").strip().split(",")
                        if len(parts) >= 2:
                            dom = parts[1].strip()
                            if dom:
                                domains.append(dom)
                                count += 1
                                if count >= limit:
                                    break
        except Exception as e:
            print(f"Error reading Tranco list: {e}")
    return domains


def fetch_phiusiil_dataset() -> Tuple[List[str], List[str]]:
    """
    Downloads the PhiUSIIL Phishing URL Dataset (UCI #967).
    Contains both legitimate and phishing URLs with full paths.
    """
    cache_file = RAW_DIR / "phiusiil_dataset.zip"
    url = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
    legit_urls = []
    phish_urls = []

    if download_with_retry(url, cache_file, timeout=35):
        try:
            with zipfile.ZipFile(cache_file, "r") as z:
                # Find CSV file inside the zip
                csv_candidates = [n for n in z.namelist() if n.endswith(".csv")]
                if csv_candidates:
                    with z.open(csv_candidates[0]) as f:
                        df = pd.read_csv(f)
                        # Check columns: URL column name is often 'URL' and label is 'label' (1=legit, 0=phish or vice versa)
                        url_col = None
                        label_col = None
                        for col in df.columns:
                            if col.lower() == "url":
                                url_col = col
                            elif col.lower() == "label":
                                label_col = col

                        if url_col and label_col:
                            for _, row in df.iterrows():
                                u = str(row[url_col]).strip()
                                l = int(row[label_col])
                                # PhiUSIIL dataset: 1 is legitimate, 0 is phishing
                                if l == 1:
                                    legit_urls.append(u)
                                else:
                                    phish_urls.append(u)
        except Exception as e:
            print(f"Error parsing PhiUSIIL dataset: {e}")

    return legit_urls, phish_urls


def generate_synthetic_seed_dataset() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Emergency fallback generator if all online datasets are unreachable.
    Generates at least 500 benign and 500 phishing URLs across realistic patterns.
    """
    print("\n[WARNING] All online data sources failed. Falling back to synthetic seed dataset.")
    print("[WARNING] Metrics will be marked as 'synthetic - not real-world'.\n")

    random.seed(42)
    legit = []
    phish = []

    legit_domains = [
        "google.com", "microsoft.com", "github.com", "wikipedia.org", "apple.com",
        "amazon.com", "youtube.com", "reddit.com", "mozilla.org", "cloudflare.com",
        "stackoverflow.com", "python.org", "apache.org", "ubuntu.com", "debian.org",
        "nih.gov", "cdc.gov", "harvard.edu", "mit.edu", "stanford.edu",
        "nytimes.com", "bbc.co.uk", "cnn.com", "theguardian.com", "reuters.com",
        "salesforce.com", "atlassian.com", "slack.com", "zoom.us", "dropbox.com"
    ]

    for dom in legit_domains:
        for _ in range(20):
            scheme = "https" if random.random() > 0.1 else "http"
            path = random.choice(COMMON_BENIGN_PATHS)
            u = f"{scheme}://{dom}{path}"
            legit.append({"url": u, "label": 0, "source": "synthetic_seed"})

    # Synthetic Phishing Patterns
    target_brands = ["paypal", "apple", "chase", "bofa", "microsoft", "netflix", "amazon", "wellsfargo"]
    tlds = ["xyz", "top", "buzz", "club", "work", "loan", "icu", "cfd", "online"]
    actions = ["login", "verify-account", "update-billing", "secure-sso", "confirm-identity", "unlock-card"]

    for brand in target_brands:
        for _ in range(70):
            tld = random.choice(tlds)
            action = random.choice(actions)
            r_type = random.random()
            if r_type < 0.35:
                # Subdomain impersonation
                u = f"http://{brand}-{action}.secure-client-auth.{tld}/index.php?token={random.randint(10000, 99999)}"
            elif r_type < 0.7:
                # Typosquatting
                typo_brand = brand.replace("o", "0").replace("l", "1").replace("m", "rn")
                u = f"http://{typo_brand}-support.{tld}/{action}/auth"
            else:
                # IP host
                ip = f"{random.randint(100, 220)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(2, 250)}"
                u = f"http://{ip}/{brand}/{action}.html"
            phish.append({"url": u, "label": 1, "source": "synthetic_seed"})

    return legit, phish


def build_and_save_dataset(target_samples_per_class: int = 25000) -> pd.DataFrame:
    """
    Orchestrates downloading from real data sources, deduplication, bias mitigation,
    and saves dataset.csv and dataset_info.json.
    """
    raw_phishing: List[Dict[str, str]] = []
    raw_legitimate: List[Dict[str, str]] = []

    source_counts = {
        "OpenPhish": 0,
        "Phishing.Database": 0,
        "PhishTank": 0,
        "PhiUSIIL (Phishing)": 0,
        "PhiUSIIL (Legitimate)": 0,
        "Tranco Top Sites": 0,
        "Synthetic Fallback": 0
    }

    # 1. Fetch Phishing Feeds
    print("Fetching OpenPhish community feed...")
    op_urls = fetch_openphish()
    for u in op_urls:
        raw_phishing.append({"url": u, "source": "OpenPhish"})
    source_counts["OpenPhish"] = len(op_urls)
    print(f"OpenPhish fetched: {len(op_urls)} URLs")

    print("Fetching Phishing.Database...")
    pdb_urls = fetch_phishing_database()
    for u in pdb_urls:
        raw_phishing.append({"url": u, "source": "Phishing.Database"})
    source_counts["Phishing.Database"] = len(pdb_urls)
    print(f"Phishing.Database fetched: {len(pdb_urls)} URLs")

    pt_urls = fetch_phishtank()
    if pt_urls:
        for u in pt_urls:
            raw_phishing.append({"url": u, "source": "PhishTank"})
        source_counts["PhishTank"] = len(pt_urls)
        print(f"PhishTank fetched: {len(pt_urls)} URLs")

    # 2. Fetch Legitimate Datasets & PhiUSIIL
    print("Fetching PhiUSIIL Phishing URL Dataset (UCI #967)...")
    phi_legit, phi_phish = fetch_phiusiil_dataset()
    for u in phi_legit:
        raw_legitimate.append({"url": u, "source": "PhiUSIIL"})
    source_counts["PhiUSIIL (Legitimate)"] = len(phi_legit)
    for u in phi_phish:
        raw_phishing.append({"url": u, "source": "PhiUSIIL"})
    source_counts["PhiUSIIL (Phishing)"] = len(phi_phish)
    print(f"PhiUSIIL fetched: {len(phi_legit)} legitimate, {len(phi_phish)} phishing URLs")

    print("Fetching Tranco Top Sites list...")
    tranco_domains = fetch_tranco_top_sites(limit=50000)
    source_counts["Tranco Top Sites"] = len(tranco_domains)
    print(f"Tranco fetched: {len(tranco_domains)} top domains")

    # Mitigate dataset bias for Tranco domains
    # Tranco provides bare domains; convert ~50% to full realistic URLs with paths to prevent model bias
    random.seed(42)
    for dom in tranco_domains:
        use_https = (random.random() > 0.15)
        scheme = "https" if use_https else "http"
        # 50% get a realistic benign path, 50% bare domain or trailing slash
        if random.random() < 0.50:
            path = random.choice(COMMON_BENIGN_PATHS)
        else:
            path = "/" if random.random() < 0.5 else ""
        u = f"{scheme}://{dom}{path}"
        raw_legitimate.append({"url": u, "source": "Tranco"})

    # Check if we obtained real data
    total_real_phish = len(raw_phishing)
    total_real_legit = len(raw_legitimate)
    is_synthetic = False

    if total_real_phish < 100 or total_real_legit < 100:
        synth_legit, synth_phish = generate_synthetic_seed_dataset()
        raw_legitimate.extend(synth_legit)
        raw_phishing.extend(synth_phish)
        source_counts["Synthetic Fallback"] = len(synth_legit) + len(synth_phish)
        is_synthetic = True

    # 3. Clean, Deduplicate & Validate
    print("Cleaning and balancing dataset...")
    cleaned_rows = []
    seen_urls = set()

    for item in raw_phishing:
        u = normalize_url(item["url"])
        if not u or len(u) > 2000 or u in seen_urls:
            continue
        seen_urls.add(u)
        cleaned_rows.append({"url": u, "label": 1, "source": item["source"]})

    for item in raw_legitimate:
        u = normalize_url(item["url"])
        if not u or len(u) > 2000 or u in seen_urls:
            continue
        seen_urls.add(u)
        cleaned_rows.append({"url": u, "label": 0, "source": item["source"]})

    df = pd.DataFrame(cleaned_rows)

    # 4. Extract registered domain for group splitting and balanced sampling
    print("Extracting registrable domains for leak-free grouping...")
    def get_registered_domain(url_str: str) -> str:
        try:
            ext = tldextract.extract(url_str)
            return ext.registered_domain.lower() if ext.registered_domain else "unknown"
        except Exception:
            return "unknown"

    df["registered_domain"] = df["url"].apply(get_registered_domain)

    # Sample balanced dataset capped at target_samples_per_class
    df_phish = df[df["label"] == 1]
    df_legit = df[df["label"] == 0]

    sample_size = min(len(df_phish), len(df_legit), target_samples_per_class)
    print(f"Available: {len(df_legit)} Legitimate, {len(df_phish)} Phishing. Sampling {sample_size} per class...")

    df_phish_sampled = df_phish.sample(n=sample_size, random_state=42)
    df_legit_sampled = df_legit.sample(n=sample_size, random_state=42)

    df_final = pd.concat([df_phish_sampled, df_legit_sampled], ignore_index=True)
    df_final = df_final.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # Save to dataset.csv
    df_final[["url", "label", "source", "registered_domain"]].to_csv(DATASET_CSV, index=False)
    print(f"Saved cleaned balanced dataset to {DATASET_CSV} ({len(df_final)} rows)")

    # Save provenance metadata
    dataset_info = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "total_urls": len(df_final),
        "legitimate_count": int((df_final["label"] == 0).sum()),
        "phishing_count": int((df_final["label"] == 1).sum()),
        "unique_domains": int(df_final["registered_domain"].nunique()),
        "sources_count": source_counts,
        "is_synthetic": is_synthetic,
        "notes": (
            "Prepared from public open sources without external reputation lookups (no VirusTotal required). "
            "Tranco domains enriched with common paths to mitigate length/path bias."
        )
    }

    with open(DATASET_INFO_JSON, "w", encoding="utf-8") as f:
        json.dump(dataset_info, f, indent=2)

    print(f"Saved dataset info to {DATASET_INFO_JSON}")
    return df_final


def load_dataset() -> pd.DataFrame:
    """Loads existing dataset or triggers build if not present."""
    if DATASET_CSV.exists():
        return pd.read_csv(DATASET_CSV)
    return build_and_save_dataset()


if __name__ == "__main__":
    build_and_save_dataset()
