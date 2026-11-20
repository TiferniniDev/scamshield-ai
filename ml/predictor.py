"""
ScamShield AI - Fast Local Predictor with Bilingual (EN + AR) Explainability
"""
import json
import os
import time
from typing import Dict, List, Optional

import joblib

from ml.features import extract_features, redact_url_pii

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "scam_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "metrics.json")

_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH):
            from ml.train_model import train
            train()
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def get_model_metrics() -> Dict:
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def predict_url_fast(raw_url: str) -> Dict:
    """
    Runs the fast (<15ms) local ML + UAE Brand Impersonation + Homoglyph scorer.
    Returns bilingual explanations (English & Arabic) and privacy-redacted URL.
    """
    t0 = time.perf_counter()
    redacted_url, pii_redacted = redact_url_pii(raw_url)
    features, meta = extract_features(raw_url)
    model = get_model()

    # Fast-path official UAE domains, restricted .gov/.edu domains & verified official social handles
    if meta["is_official_uae"] or meta.get("is_official_tld"):
        brand = meta.get("official_brand")
        if brand and meta.get("is_official_social"):
            handle = meta.get("social_handle") or ""
            reason_en = f"Verified official social account ({handle}) for {brand['name_en']} on {meta['registered_domain']}."
            reason_ar = f"حساب رسمي موثق ({handle}) لـ {brand['name_ar']} على منصة {meta['registered_domain']}."
        elif brand:
            reason_en = f"Verified official UAE domain for {brand['name_en']} ({meta['registered_domain']})."
            reason_ar = f"نطاق إماراتي رسمي موثق لـ {brand['name_ar']} ({meta['registered_domain']})."
        else:
            reason_en = f"Verified restricted government or official institution domain ({meta['host']})."
            reason_ar = f"نطاق حكومي أو مؤسسي رسمي موثق ({meta['host']})."
        return {
            "url": redacted_url,
            "host": meta["host"],
            "registered_domain": meta["registered_domain"],
            "pii_redacted": pii_redacted,
            "ml_score": 2,
            "verdict": "SAFE",
            "impersonated_brand_en": None,
            "impersonated_brand_ar": None,
            "verified_entity_en": brand["name_en"] if brand else "Official Government Domain",
            "verified_entity_ar": brand["name_ar"] if brand else "جهة حكومية رسمية",
            "reasons_en": [reason_en],
            "reasons_ar": [reason_ar],
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            "meta": meta,
        }

    prob_fraud = float(model.predict_proba([features])[0][1])
    score = int(round(prob_fraud * 100))

    reasons_en: List[str] = []
    reasons_ar: List[str] = []

    if meta.get("social_impersonation") and meta["impersonating_brand"]:
        brand = meta["impersonating_brand"]
        handle = meta.get("social_handle") or ""
        score = max(55, min(68, score + 45))
        reasons_en.append(
            f"Unverified social profile ({handle}) referencing {brand['name_en']} with payment/verification terms — confirm official handle before trusting."
        )
        reasons_ar.append(
            f"حساب تواصل غير موثق ({handle}) يشير إلى {brand['name_ar']} مع عبارات دفع/تحقق — تأكد من الحساب الرسمي قبل التعامل."
        )
    elif meta["is_trusted_global"] and not meta["impersonating_brand"]:
        score = min(score, 10)
        reasons_en.append(f"Recognized trusted platform ({meta['registered_domain']}).")
        reasons_ar.append(f"منصة معروفة وموثوقة ({meta['registered_domain']}).")

    # Add deterministic high-signal boosts & plain-language reasons
    brand = meta["impersonating_brand"]
    if brand and not meta.get("social_impersonation"):
        score = max(score, 85)
        reasons_en.append(
            f"Impersonates {brand['name_en']} (official domain is {brand['official_domains'][0]})."
        )
        reasons_ar.append(
            f"ينتحل صفة {brand['name_ar']} (النطاق الرسمي هو {brand['official_domains'][0]})."
        )

    if meta["has_punycode"]:
        score = max(score, 82)
        reasons_en.append("Uses Punycode (IDN) internationalized domain encoding often used in lookalike attacks.")
        reasons_ar.append("يستخدم ترميز Punycode الذي يُستغل غالباً في هجمات انتحال النطاقات المشابهة.")
    elif meta["has_homoglyph"]:
        score = min(100, max(score, 70) + 10)
        reasons_en.append("Contains deceptive lookalike characters / digit substitution (homoglyph trick).")
        reasons_ar.append("يحتوي على أحرف أو أرقام مضللة لمحاكاة نطاق رسمي (خدعة الأحرف المتشابهة).")

    if meta["is_ip"]:
        score = max(score, 80)
        reasons_en.append("Uses a raw IP address instead of a registered domain name.")
        reasons_ar.append("يستخدم عنوان IP مباشر بدلاً من اسم نطاق مسجل.")

    if meta["is_abused_cloud"]:
        score = min(100, score + 15)
        reasons_en.append(f"Hosted on free cloud hosting ({meta['registered_domain']}), frequently abused for zero-day scams.")
        reasons_ar.append(f"مُستضاف على منصة سحابية مجانية ({meta['registered_domain']}) تُستغل بكثرة في صفحات الاحتيال.")

    if meta["is_shortener"]:
        score = max(score, 55)
        reasons_en.append("Uses a URL shortener that hides the true destination website.")
        reasons_ar.append("يستخدم رابطاً مختصراً يخفي الوجهة الحقيقية للموقع.")

    if meta["is_suspicious_tld"]:
        score = min(100, score + 10)
        reasons_en.append(f"Uses high-risk top-level domain (.{meta['tld']}).")
        reasons_ar.append(f"يستخدم امتداد نطاق عالي الخطورة (.{meta['tld']}).")

    if not meta["is_https"]:
        score = min(100, score + 8)
        reasons_en.append("Insecure HTTP connection (no TLS encryption).")
        reasons_ar.append("اتصال HTTP غير آمن بدون تشفير.")

    if len(meta["matched_keywords"]) >= 2 and not meta["is_trusted_global"]:
        kws = ", ".join(meta["matched_keywords"][:4])
        reasons_en.append(f"Contains high-risk financial/urgency lure keywords ({kws}).")
        reasons_ar.append(f"يحتوي على كلمات استدراج مالي أو استعجال مشبوهة ({kws}).")

    score = max(0, min(100, score))

    if score >= 70:
        verdict = "FRAUD"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    if not reasons_en:
        if verdict == "SAFE":
            reasons_en.append("No phishing, homoglyph, or UAE brand-impersonation indicators detected.")
            reasons_ar.append("لم يتم رصد مؤشرات احتيال أو انتحال لهويات إماراتية.")
        else:
            reasons_en.append("URL structure and lexical patterns closely match known financial fraud links.")
            reasons_ar.append("بنية الرابط وأنماطه النصية تتطابق مع روابط الاحتيال المالي المعروفة.")

    return {
        "url": redacted_url,
        "host": meta["host"],
        "registered_domain": meta["registered_domain"],
        "pii_redacted": pii_redacted,
        "ml_score": score,
        "verdict": verdict,
        "impersonated_brand_en": brand["name_en"] if brand else None,
        "impersonated_brand_ar": brand["name_ar"] if brand else None,
        "verified_entity_en": None,
        "verified_entity_ar": None,
        "reasons_en": reasons_en,
        "reasons_ar": reasons_ar,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        "meta": meta,
    }

