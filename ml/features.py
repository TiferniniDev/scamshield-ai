"""
ScamShield AI - Feature Extraction, Homoglyph Normalization & Privacy PII Redaction
Runs locally in <2ms per URL with zero external API calls.
"""
import json
import math
import os
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import tldextract

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BRANDS_PATH = os.path.join(BASE_DIR, "uae_brands.json")

with open(BRANDS_PATH, "r", encoding="utf-8") as f:
    UAE_BRANDS: List[Dict] = json.load(f)

# Major social media platforms where we verify official handles instead of flagging the domain
SOCIAL_PLATFORMS = {
    "instagram.com", "x.com", "twitter.com", "facebook.com", "linkedin.com",
    "youtube.com", "tiktok.com", "threads.net", "snapchat.com",
}

# Trusted global, news, app store & UAE official roots to avoid false positives
TRUSTED_GLOBAL_DOMAINS = {
    "google.com", "google.ae", "maps.google.com", "play.google.com",
    "apple.com", "apps.apple.com", "microsoft.com",
    "github.com", "wikipedia.org", "amazon.ae", "amazon.com", "noon.com",
    "talabat.com", "careem.com", "uber.com", "whatsapp.com",
    "telegram.org", "t.me", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
    "khaleejtimes.com", "gulfnews.com", "thenationalnews.com", "wam.ae",
    "emaratalyoum.com", "albayan.ae", "alittihad.ae", "24.ae",
    "u.ae", "abudhabi.ae", "dubai.ae", "42abudhabi.ae", "nyuad.nyu.edu",
    "ku.ac.ae", "uaeu.ac.ae", "emirates.com", "flydubai.com",
    "visitabudhabi.ae", "louvreabudhabi.ae", "yasisland.com",
    "ferrariworldabudhabi.com", "booking.com", "airbnb.com", "tripadvisor.com",
    "bayut.com", "propertyfinder.ae", "dubizzle.com", "carrefouruae.com",
    "luluhypermarket.com", "sharafdg.com", "cloudflare.com", "stripe.com",
    "paytabs.com", "network.ae",
} | SOCIAL_PLATFORMS

SOCIAL_SCAM_LURE_WORDS = {
    "pay", "fines", "fine", "verify", "kyc", "otp", "card", "discount",
    "refund", "support", "helpdesk", "claim", "winner", "bonus", "loan",
}

OFFICIAL_UAE_DOMAINS = set()
for _b in UAE_BRANDS:
    for _d in _b["official_domains"]:
        OFFICIAL_UAE_DOMAINS.add(_d.lower())

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "vip", "icu", "online", "site", "cc", "tk", "ml",
    "ga", "cf", "gq", "buzz", "live", "shop", "info", "work", "support",
    "cfd", "sbs", "rest", "cyou", "monster", "loan", "win", "bid", "test", "link",
}

ABUSED_CLOUD_HOSTS = {
    "vercel.app", "pages.dev", "firebaseapp.com", "web.app", "netlify.app",
    "workers.dev", "blogspot.com", "sites.google.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "herokuapp.com", "ngrok-free.app",
    "trycloudflare.com", "github.io", "gitlab.io", "azurewebsites.net",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
}

FINANCIAL_LURE_KEYWORDS = [
    "verify", "login", "signin", "secure", "update", "confirm", "account",
    "bank", "card", "otp", "pin", "cvv", "iban", "wallet", "pay", "payment",
    "checkout", "billing", "invoice", "refund", "fine", "fines", "traffic",
    "violation", "penalty", "toll", "recharge", "parcel", "delivery", "customs",
    "clearance", "kyc", "suspend", "blocked", "urgent", "expire", "claim",
    "reward", "bonus", "gift", "winner", "gov", "police", "emirates", "uae",
    "abudhabi", "dubai", "mokhalafat", "shurta", "hawiyati", "rasom", "tasdeed",
    "tahdith", "bitaqa", "tawseel", "crypto", "invest", "profit", "forex",
]

# Common Unicode / leetspeak confusables used in homoglyph attacks
HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lookalikes
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u043d": "h",
    "\u043c": "m", "\u0442": "t", "\u0432": "b", "\u043a": "k",
    # Greek lookalikes
    "\u03b1": "a", "\u03bf": "o", "\u03b5": "e", "\u03b9": "i", "\u03c1": "p",
    # Common digit substitutions
    "0": "o", "1": "l", "3": "e", "5": "s", "4": "a",
})

PII_PARAM_NAMES = {
    "phone", "mobile", "tel", "eid", "emirates_id", "emiratesid", "id",
    "email", "mail", "token", "auth", "session", "sid", "card", "otp",
    "pass", "password", "iban", "account", "user", "name", "civil_id",
}

EID_REGEX = re.compile(r"784[- ]?\d{4}[- ]?\d{7}[- ]?\d")
PHONE_REGEX = re.compile(r"(\+?971|00971|05)\d{7,9}")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def redact_url_pii(raw_url: str) -> Tuple[str, bool]:
    """
    Privacy-by-Design: Automatically strips personal identifiers (Emirates ID,
    UAE phone numbers, emails, sensitive query tokens) from URLs before storage.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    redacted = False

    # Redact sensitive query params
    clean_params = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if (
            k.lower() in PII_PARAM_NAMES
            or EID_REGEX.search(v)
            or PHONE_REGEX.search(v)
            or EMAIL_REGEX.search(v)
            or len(v) > 32
        ):
            clean_params.append((k, "[REDACTED]"))
            redacted = True
        else:
            clean_params.append((k, v))

    # Also scrub path if EID/phone/email appears directly in URL path
    clean_path = parsed.path
    for pattern in (EID_REGEX, PHONE_REGEX, EMAIL_REGEX):
        if pattern.search(clean_path):
            clean_path = pattern.sub("[REDACTED]", clean_path)
            redacted = True

    rebuilt = urlunparse((
        parsed.scheme,
        parsed.netloc,
        clean_path,
        parsed.params,
        urlencode(clean_params),
        "",  # strip fragment
    ))
    return rebuilt, redacted


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_homoglyph(host: str) -> Tuple[bool, str]:
    """Detects Punycode (xn--) or non-ASCII / confusable character tricks."""
    has_punycode = "xn--" in host.lower()
    has_non_ascii = any(ord(ch) > 127 for ch in host)
    normalized = host.lower().translate(HOMOGLYPH_MAP).replace("rn", "m")
    has_digit_trick = bool(re.search(r"[a-z][01345][a-z]", host.lower()))
    return (has_punycode or has_non_ascii or has_digit_trick), normalized


def match_uae_brand(url: str, host: str, registered_domain: str, path: str = "") -> Dict:
    """
    Context-aware UAE brand & social-handle verifier:
    - Verifies official UAE domains (.gov.ae, official bank/telecom roots).
    - Verifies official social media handles on Instagram/X/Facebook/YouTube/LinkedIn
      so verified accounts like instagram.com/adpolicehq are marked SAFE, while fake
      impersonation handles with payment lures (e.g. instagram.com/adpolice_pay_fines)
      are flagged SUSPICIOUS.
    - Never false-flags trusted news/app-store/encyclopedia articles mentioning a UAE brand.
    """
    host_l = host.lower()
    reg_l = registered_domain.lower()

    # 1. Exact official UAE domain match?
    for brand in UAE_BRANDS:
        for off in brand["official_domains"]:
            if host_l == off or host_l.endswith("." + off) or reg_l == off:
                return {
                    "is_official": True,
                    "is_official_social": False,
                    "social_handle": None,
                    "social_impersonation": False,
                    "impersonating": False,
                    "brand": brand,
                    "similarity": 1.0,
                }

    # 2. Context check: Is this on a major Social Media platform?
    is_social = reg_l in SOCIAL_PLATFORMS or any(host_l.endswith("." + sp) for sp in SOCIAL_PLATFORMS)
    if is_social:
        segments = [seg.strip().lstrip("@").lower() for seg in path.split("/") if seg.strip()]
        # Skip generic platform routes (/p/, /reel/, /watch, /company/, /in/)
        handle = None
        for seg in segments:
            if seg not in ("p", "reel", "reels", "stories", "watch", "channel", "c", "user", "company", "in", "pages", "profile.php"):
                handle = seg
                break

        if handle:
            # Exact match to an official UAE social media handle? -> VERIFIED SAFE
            for brand in UAE_BRANDS:
                official_handles = [h.lower() for h in brand.get("official_handles", [])]
                if handle in official_handles:
                    return {
                        "is_official": True,
                        "is_official_social": True,
                        "social_handle": f"@{handle}",
                        "social_impersonation": False,
                        "impersonating": False,
                        "brand": brand,
                        "similarity": 1.0,
                    }

            # Unverified handle combining a UAE brand + scam/payment lure? -> SUSPICIOUS
            handle_norm = handle.translate(HOMOGLYPH_MAP)
            for brand in UAE_BRANDS:
                if any(kw.replace("-", "") in handle_norm.replace("_", "").replace(".", "") for kw in brand["keywords"]):
                    if any(lure in handle_norm for lure in SOCIAL_SCAM_LURE_WORDS):
                        return {
                            "is_official": False,
                            "is_official_social": False,
                            "social_handle": f"@{handle}",
                            "social_impersonation": True,
                            "impersonating": False,
                            "brand": brand,
                            "similarity": 0.75,
                        }

        # Regular social page/post mentioning a brand is NOT domain spoofing
        return {
            "is_official": False,
            "is_official_social": False,
            "social_handle": f"@{handle}" if handle else None,
            "social_impersonation": False,
            "impersonating": False,
            "brand": None,
            "similarity": 0.0,
        }

    # 3. Trusted news / app store / encyclopedia / UAE gov portals: never flag path mentions!
    is_trusted_global = (
        reg_l in TRUSTED_GLOBAL_DOMAINS
        or host_l in TRUSTED_GLOBAL_DOMAINS
        or any(host_l.endswith("." + td) for td in TRUSTED_GLOBAL_DOMAINS)
        or host_l.endswith(".gov.ae")
    )
    if is_trusted_global:
        return {
            "is_official": False,
            "is_official_social": False,
            "social_handle": None,
            "social_impersonation": False,
            "impersonating": False,
            "brand": None,
            "similarity": 0.0,
        }

    # 4. Untrusted / unknown / cloud-hosted domains: check host & URL for brand impersonation
    _, norm_host = detect_homoglyph(host_l)
    url_norm = url.lower().translate(HOMOGLYPH_MAP)
    norm_no_tld = norm_host.rsplit(".", 1)[0] if "." in norm_host else norm_host

    best_match = None
    best_score = 0.0

    for brand in UAE_BRANDS:
        for kw in brand["keywords"]:
            if kw in host_l or kw in norm_host:
                return {
                    "is_official": False,
                    "is_official_social": False,
                    "social_handle": None,
                    "social_impersonation": False,
                    "impersonating": True,
                    "brand": brand,
                    "similarity": 0.95,
                }
            if len(kw) >= 5 and kw in url_norm:
                if 0.85 > best_score:
                    best_score = 0.85
                    best_match = brand

        for off in brand["official_domains"]:
            stem = off.split(".")[0]
            if len(stem) < 4:
                continue
            for token in re.split(r"[.\-_]", norm_no_tld):
                if len(token) < 4:
                    continue
                ratio = SequenceMatcher(None, stem, token).ratio()
                if ratio >= 0.82 and ratio > best_score:
                    best_score = ratio
                    best_match = brand

    if best_match and best_score >= 0.82:
        return {
            "is_official": False,
            "is_official_social": False,
            "social_handle": None,
            "social_impersonation": False,
            "impersonating": True,
            "brand": best_match,
            "similarity": round(best_score, 2),
        }

    return {
        "is_official": False,
        "is_official_social": False,
        "social_handle": None,
        "social_impersonation": False,
        "impersonating": False,
        "brand": None,
        "similarity": 0.0,
    }


FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "host_entropy",
    "is_https",
    "is_ip_host",
    "has_at_symbol",
    "has_double_slash_path",
    "has_punycode",
    "has_homoglyph",
    "is_suspicious_tld",
    "is_abused_cloud",
    "is_shortener",
    "lure_keyword_count",
    "brand_impersonation",
    "brand_similarity",
    "query_param_count",
    "is_uae_gov_tld",
]


def extract_features(raw_url: str) -> Tuple[List[float], Dict]:
    """
    Extracts 24 numeric ML features + rich explainable metadata from a URL.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    ext = tldextract.extract(url)
    registered_domain = ext.top_domain_under_public_suffix or host
    tld = (ext.suffix or "").lower().split(".")[-1] if ext.suffix else ""
    subdomains = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []

    has_homoglyph, _ = detect_homoglyph(host)
    brand_info = match_uae_brand(url, host, registered_domain, path)

    is_trusted_global = (
        registered_domain in TRUSTED_GLOBAL_DOMAINS
        or host in TRUSTED_GLOBAL_DOMAINS
        or any(host.endswith("." + td) for td in TRUSTED_GLOBAL_DOMAINS)
    )

    is_abused_cloud = (
        registered_domain in ABUSED_CLOUD_HOSTS
        or any(host.endswith("." + ch) for ch in ABUSED_CLOUD_HOSTS)
    )
    is_shortener = registered_domain in URL_SHORTENERS or host in URL_SHORTENERS
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    is_uae_gov_tld = host.endswith(".gov.ae") or host.endswith(".abudhabi")
    is_ip = bool(IPV4_REGEX.match(host))

    url_lower = url.lower()
    matched_keywords = [kw for kw in FINANCIAL_LURE_KEYWORDS if kw in url_lower]

    digits = sum(c.isdigit() for c in host)
    digit_ratio = digits / max(len(host), 1)
    specials = sum(url.count(ch) for ch in ["-", "_", "?", "=", "&", "%", "@", "~"])

    features = [
        float(len(url)),
        float(len(host)),
        float(len(path)),
        float(len(subdomains)),
        float(host.count(".")),
        float(host.count("-")),
        float(digits),
        float(round(digit_ratio, 4)),
        float(specials),
        float(round(shannon_entropy(host), 4)),
        1.0 if parsed.scheme == "https" else 0.0,
        1.0 if is_ip else 0.0,
        1.0 if "@" in url else 0.0,
        1.0 if "//" in path else 0.0,
        1.0 if "xn--" in host else 0.0,
        1.0 if has_homoglyph else 0.0,
        1.0 if is_suspicious_tld else 0.0,
        1.0 if is_abused_cloud else 0.0,
        1.0 if is_shortener else 0.0,
        float(len(matched_keywords)),
        1.0 if brand_info["impersonating"] else 0.0,
        float(brand_info["similarity"]),
        float(len(parse_qsl(query))),
        1.0 if is_uae_gov_tld else 0.0,
    ]

    meta = {
        "normalized_url": url,
        "host": host,
        "registered_domain": registered_domain,
        "tld": tld,
        "is_https": parsed.scheme == "https",
        "is_ip": is_ip,
        "has_homoglyph": has_homoglyph,
        "has_punycode": "xn--" in host,
        "is_suspicious_tld": is_suspicious_tld,
        "is_abused_cloud": is_abused_cloud,
        "is_shortener": is_shortener,
        "is_uae_gov_tld": is_uae_gov_tld,
        "is_official_uae": brand_info["is_official"],
        "is_official_social": brand_info.get("is_official_social", False),
        "social_handle": brand_info.get("social_handle"),
        "social_impersonation": brand_info.get("social_impersonation", False),
        "is_trusted_global": is_trusted_global,
        "impersonating_brand": brand_info["brand"] if (brand_info["impersonating"] or brand_info.get("social_impersonation")) else None,
        "official_brand": brand_info["brand"] if brand_info["is_official"] else None,
        "brand_similarity": brand_info["similarity"],
        "matched_keywords": matched_keywords[:6],
        "host_entropy": round(shannon_entropy(host), 2),
        "subdomain_count": len(subdomains),
    }

    return features, meta

