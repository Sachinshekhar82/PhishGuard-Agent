"""
Unit tests for URL feature extraction in PhishGuard Agent.
"""

import pytest
from backend.ml.features import (
    normalize_url,
    extract_features,
    features_to_vector,
    is_ip_address,
    shannon_entropy,
    levenshtein_distance,
    FEATURE_NAMES
)


def test_url_normalization():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("  https://github.com/test  ") == "https://github.com/test"
    assert normalize_url("HTTP://EXAMPLE.COM/PATH") == "http://example.com/PATH"
    assert normalize_url("") == ""


def test_ip_address_detection():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1:8080") is True
    assert is_ip_address("127.0.0.1") is True
    assert is_ip_address("google.com") is False
    assert is_ip_address("paypal-login.com") is False


def test_shannon_entropy():
    # Identical repeated characters should have 0 entropy
    assert shannon_entropy("aaaaaa") == 0.0
    # Randomized mixed string has high entropy
    low_ent = shannon_entropy("google")
    high_ent = shannon_entropy("x8z9q1w7k4m2")
    assert high_ent > low_ent
    assert shannon_entropy("") == 0.0


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("apple", "aple") == 1
    assert levenshtein_distance("microsoft", "micros0ft") == 1


def test_feature_vector_structure():
    url = "https://www.google.com/search?q=test"
    feats = extract_features(url)
    assert isinstance(feats, dict)

    vector = features_to_vector(feats)
    assert len(vector) == len(FEATURE_NAMES)
    for v in vector:
        assert isinstance(v, (int, float))


def test_ip_host_features():
    url = "http://192.168.1.1/admin/login.php"
    feats = extract_features(url)
    assert feats["is_ip_host"] == 1
    assert feats["has_https"] == 0
    assert feats["count_auth_keywords"] >= 1


def test_punycode_and_unusual_characters():
    # Punycode domain
    url = "http://xn--pypal-4ve.com/signin"
    feats = extract_features(url)
    assert feats["has_unusual_chars"] == 1
    assert feats["count_auth_keywords"] >= 1

    # Percent encoded URL
    url2 = "http://example.com/%20%2F%2E"
    feats2 = extract_features(url2)
    assert feats2["num_percent"] >= 3
    assert feats2["has_unusual_chars"] == 1


def test_url_shortener_feature():
    url = "https://bit.ly/3xyzMasked"
    feats = extract_features(url)
    assert feats["is_shortener"] == 1


def test_brand_typosquatting_feature():
    url = "http://paypa1-security.com/login"
    feats = extract_features(url)
    assert feats["brand_typosquat_detected"] == 1 or feats["homoglyph_detected"] == 1


def test_extremely_long_url():
    long_url = "http://example.com/" + "a" * 1500
    feats = extract_features(long_url)
    assert feats["url_length"] > 1500
    assert feats["path_length"] > 1500


def test_malformed_url_safety():
    malformed = "http:///:invalid$$$:::url"
    feats = extract_features(malformed)
    assert isinstance(feats, dict)
    assert len(features_to_vector(feats)) == len(FEATURE_NAMES)
