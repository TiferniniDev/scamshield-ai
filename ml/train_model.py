"""
ScamShield AI - Lightweight Local ML Model Trainer
Trains an explainable RandomForest + GradientBoosting ensemble on UAE-focused
and global phishing/benign URL patterns, saving model.joblib + metrics.json.
"""
import json
import os
import random
import time
from typing import List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml.features import (
    ABUSED_CLOUD_HOSTS,
    FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    TRUSTED_GLOBAL_DOMAINS,
    UAE_BRANDS,
    URL_SHORTENERS,
    extract_features,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "scam_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "metrics.json")


def build_dataset(seed: int = 42) -> Tuple[List[str], List[int]]:
    rng = random.Random(seed)
    benign_urls: List[str] = []
    fraud_urls: List[str] = []

    # 1. Official UAE Government, Banking, Telecom, Transport & Trusted Global URLs
    safe_paths = [
        "", "/", "/en", "/ar", "/en/services", "/ar/home", "/contact-us",
        "/about", "/help/faq", "/news/2026/update", "/locations/abu-dhabi",
        "/personal/accounts", "/search?q=abu+dhabi", "/branches", "/careers",
        "/en/eservices/traffic", "/products/home", "/maps/place/Abu+Dhabi",
    ]
    for brand in UAE_BRANDS:
        for dom in brand["official_domains"]:
            for p in safe_paths:
                benign_urls.append(f"https://{dom}{p}")
                benign_urls.append(f"https://www.{dom}{p}")

    for dom in sorted(TRUSTED_GLOBAL_DOMAINS):
        for _ in range(12):
            p = rng.choice(safe_paths)
            prefix = rng.choice(["", "www.", "m.", "support.", "en.", "ae."])
            benign_urls.append(f"https://{prefix}{dom}{p}")

    # Legit UAE local business websites (clinics, cafes, hotels, real estate, car rentals)
    biz_words_1 = [
        "alreem", "yas", "corniche", "saadiyat", "khalifa", "alain", "marina",
        "capital", "emirates", "gulf", "oasis", "palm", "desert", "pearl",
        "falcon", "horizon", "emerald", "royal", "golden", "sunset", "harbor",
    ]
    biz_words_2 = [
        "dental", "clinic", "cafe", "bakery", "hotel", "resort", "motors",
        "auto", "fitness", "gym", "pharmacy", "flowers", "tailor", "studio",
        "gallery", "kitchen", "grill", "bistro", "optical", "salon", "vet",
        "properties", "logistics", "engineering", "consulting", "academy",
    ]
    safe_tlds = ["ae", "com", "com.ae", "org", "net", "co"]
    for _ in range(1400):
        w1 = rng.choice(biz_words_1)
        w2 = rng.choice(biz_words_2)
        sep = rng.choice(["", "-"])
        tld = rng.choice(safe_tlds)
        path = rng.choice(safe_paths)
        benign_urls.append(f"https://www.{w1}{sep}{w2}.{tld}{path}")

    # 2. Fraudulent & Phishing URLs (UAE Impersonation, Maps Hijacks, Malvertising, Payment Harvest)
    lure_tokens = [
        "verify", "pay", "fines", "fine-pay", "secure", "login", "update",
        "kyc", "portal", "online", "support", "helpdesk", "refund", "claim",
        "clearance", "parcel", "toll", "recharge", "mokhalafat", "tasdeed",
        "billing", "card-verify", "otp-check", "account-alert", "urgent",
    ]
    fraud_paths = [
        "/verify/login", "/pay/traffic-fine", "/en/card-payment", "/otp/confirm",
        "/update-emirates-id", "/secure/checkout", "/billing/pay-now?ref=8821",
        "/uae/account/verify?session=99182736451234567890", "/fine-settlement",
        "/customs/fee-pay", "/parcel/reschedule-payment", "/bank/kyc-update",
        "/portal/signin.php", "/auth/uaepass-login", "/customer-care/pay",
    ]
    bad_tlds = sorted(SUSPICIOUS_TLDS) + ["com", "net", "org", "co"]
    cloud_hosts = sorted(ABUSED_CLOUD_HOSTS)
    shorteners = sorted(URL_SHORTENERS)

    # Pattern A: Direct UAE brand impersonation on sketchy TLDs & hyphens
    for _ in range(900):
        brand = rng.choice(UAE_BRANDS)
        kw = rng.choice(brand["keywords"])
        lure = rng.choice(lure_tokens)
        tld = rng.choice(bad_tlds)
        scheme = rng.choice(["http", "https", "https"])
        sep = rng.choice(["-", ".", ""])
        num = rng.choice(["", str(rng.randint(10, 999)), "247", "2026"])
        host = f"{kw}{sep}{lure}{num}.{tld}"
        path = rng.choice(fraud_paths)
        fraud_urls.append(f"{scheme}://{host}{path}")

    # Pattern B: Cloud-hosted zero-day phishing (vercel.app, pages.dev, firebaseapp)
    for _ in range(450):
        brand = rng.choice(UAE_BRANDS)
        kw = rng.choice(brand["keywords"])
        lure = rng.choice(lure_tokens)
        cloud = rng.choice(cloud_hosts)
        sub = f"{kw}-{lure}-{rng.randint(10, 999)}"
        fraud_urls.append(f"https://{sub}.{cloud}{rng.choice(fraud_paths)}")

    # Pattern C: Typosquatting & Homoglyph / Leetspeak / Punycode impersonation
    typos = [
        ("adpolice", ["adp0lice", "adpo1ice", "adpolicce", "ad-pol1ce", "xn--adplice-9za"]),
        ("uaepass", ["uaepas5", "uaepasss", "uae-p4ss", "xn--uaepass-8ya"]),
        ("salik", ["sa1ik", "sal1k", "saliik", "xn--salik-0va"]),
        ("darb", ["d4rb", "darbb", "darb-ae", "xn--darb-2ta"]),
        ("bankfab", ["bankf4b", "b4nkfab", "bankfabb", "fab-b4nk"]),
        ("emiratesnbd", ["emiratesn8d", "em1ratesnbd", "emirates-n6d"]),
        ("etisalat", ["et1salat", "etisaiat", "etisalat-0nline"]),
        ("emiratespost", ["emiratesp0st", "em1ratespost", "emirates-p0st"]),
        ("adnoc", ["adn0c", "4dnoc", "adnoc-p4y"]),
        ("tamm", ["t4mm", "tammm", "tamm-abudhab1"]),
    ]
    for _ in range(400):
        _, variants = rng.choice(typos)
        v = rng.choice(variants)
        tld = rng.choice(["com", "net", "xyz", "top", "online", "site", "click", "info"])
        suffix = rng.choice(["", "-uae", "-pay", "-secure", "-verify"])
        fraud_urls.append(f"https://{v}{suffix}.{tld}{rng.choice(fraud_paths)}")

    # Pattern D: Fake Google Maps business hijacks (fake car rentals, towing, bank customer care, typing centers)
    maps_scam_stems = [
        "abudhabi-car-rental-deposit", "uae-fast-towing-pay", "bank-customer-care-uae",
        "typing-center-visa-pay", "cheap-holiday-villa-ad", "instant-loan-uae-approve",
        "crypto-dubai-profit-vip", "free-salik-waiver-claim", "ad-police-fine-discount",
        "emirates-id-express-renew", "uae-delivery-customs-fee", "abudhabi-visa-urgent",
    ]
    for _ in range(350):
        stem = rng.choice(maps_scam_stems)
        tld = rng.choice(list(SUSPICIOUS_TLDS))
        num = rng.choice(["", f"-{rng.randint(1, 99)}"])
        fraud_urls.append(f"https://{stem}{num}.{tld}{rng.choice(fraud_paths)}")

    # Pattern E: IP-hosted, shortened, high-entropy random scam links & @-obfuscated links
    for _ in range(300):
        kind = rng.choice(["ip", "short", "random", "at"])
        if kind == "ip":
            ip = f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            fraud_urls.append(f"http://{ip}{rng.choice(fraud_paths)}")
        elif kind == "short":
            sh = rng.choice(shorteners)
            code = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
            fraud_urls.append(f"https://{sh}/{code}")
        elif kind == "at":
            brand = rng.choice(UAE_BRANDS)
            off = brand["official_domains"][0]
            tld = rng.choice(list(SUSPICIOUS_TLDS))
            fraud_urls.append(f"https://{off}@secure-verify-{rng.randint(10,999)}.{tld}/pay")
        else:
            rand_host = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(14, 24)))
            tld = rng.choice(list(SUSPICIOUS_TLDS))
            fraud_urls.append(f"https://{rand_host}.{tld}{rng.choice(fraud_paths)}")

    # Balance classes cleanly
    n = min(len(benign_urls), len(fraud_urls))
    rng.shuffle(benign_urls)
    rng.shuffle(fraud_urls)
    urls = benign_urls[:n] + fraud_urls[:n]
    labels = [0] * n + [1] * n
    return urls, labels


def train():
    print("[ScamShield ML] Generating balanced UAE + Global dataset...")
    urls, labels = build_dataset()
    X = np.array([extract_features(u)[0] for u in urls], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42,
    )

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
        weights=[1, 1],
    )

    print(f"[ScamShield ML] Training ensemble on {len(X_train)} samples...")
    t0 = time.perf_counter()
    ensemble.fit(X_train, y_train)
    train_sec = round(time.perf_counter() - t0, 2)

    # Evaluate on held-out test set
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    # Measure average single-URL latency (feature extraction + inference)
    sample_urls = urls[:100]
    t_inf = time.perf_counter()
    for su in sample_urls:
        feats, _ = extract_features(su)
        ensemble.predict_proba([feats])
    avg_latency_ms = round(((time.perf_counter() - t_inf) / len(sample_urls)) * 1000, 2)

    # Extract top feature importances from RF sub-estimator
    rf_fitted = ensemble.named_estimators_["rf"]
    importances = sorted(
        zip(FEATURE_NAMES, [round(float(v), 4) for v in rf_fitted.feature_importances_]),
        key=lambda x: x[1],
        reverse=True,
    )

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    metrics = {
        "model_type": "Soft-Voting Ensemble (RandomForest + GradientBoosting)",
        "privacy_mode": "100% Local On-Prem Inference (Zero External LLM/Cloud APIs)",
        "dataset_size": int(len(urls)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "train_time_sec": train_sec,
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
        "avg_latency_ms": avg_latency_ms,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "top_features": [{"feature": k, "importance": v} for k, v in importances[:8]],
    }

    joblib.dump(ensemble, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"[ScamShield ML] Saved model -> {MODEL_PATH}")
    print(f"[ScamShield ML] Metrics -> Accuracy={metrics['accuracy']*100:.2f}%, "
          f"Precision={metrics['precision']*100:.2f}%, Recall={metrics['recall']*100:.2f}%, "
          f"F1={metrics['f1_score']*100:.2f}%, Latency={avg_latency_ms}ms/URL")


if __name__ == "__main__":
    train()

