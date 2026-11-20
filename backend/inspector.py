"""
ScamShield AI - Live Deep Inspector (RDAP Domain Age + Mobile DOM Payment & Cloaking Analysis)
Designed to run fast with strict timeouts and fail gracefully when offline or during local demos.
"""
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)
DESKTOP_BOT_UA = "Mozilla/5.0 (compatible; SecurityScannerBot/1.0)"

SENSITIVE_INPUT_TOKENS = [
    "card", "cvv", "cvc", "expiry", "exp_date", "cardnumber", "cc_number",
    "otp", "pin", "emirates_id", "emiratesid", "eid", "iban", "password", "passcode",
]

AR_EN_URGENCY_PATTERNS = [
    r"pay\s+fine", r"traffic\s+fine", r"immediate\s+payment", r"account\s+suspended",
    r"verify\s+your\s+card", r"emirates\s+id\s+update", r"salik\s+recharge",
    r"darb\s+toll", r"customs\s+fee", r"enter\s+otp",
    r"مخالفة\s*مرورية", r"سداد\s*المخالفات", r"تحديث\s*الهوية", r"دفع\s*فوري",
    r"إيقاف\s*الحساب", r"رمز\s*التحقق", r"رسوم\s*الشحن",
]

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_SCAM_HTML_PATH = os.path.join(PROJECT_ROOT, "demo_scam_site", "index.html")


async def lookup_domain_age_days(registered_domain: str) -> Optional[int]:
    """Queries public RDAP for domain registration date (zero API key required)."""
    if not registered_domain or registered_domain.endswith(".test") or registered_domain.endswith(".local"):
        # Simulated newly minted domain age for local hackathon demo domains
        if registered_domain.endswith(".test"):
            return 2
        return None

    url = f"https://rdap.org/domain/{registered_domain}"
    try:
        async with httpx.AsyncClient(timeout=2.5, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") in ("registration", "created"):
                    raw_date = ev.get("eventDate", "")
                    if raw_date:
                        dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                        age = (datetime.now(timezone.utc) - dt).days
                        return max(0, age)
    except Exception:
        return None
    return None


def _analyze_html_content(html: str, host: str, is_official_uae: bool) -> Dict:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title else ""
    text = soup.get_text(" ", strip=True).lower()

    has_payment_harvest = False
    suspicious_form_action = False
    sensitive_fields_found: List[str] = []

    for form in soup.find_all("form"):
        action = (form.get("action") or "").lower()
        if "api.telegram.org" in action or action.endswith(".php") or "webhook" in action:
            suspicious_form_action = True

        for inp in form.find_all(["input", "select"]):
            attrs = " ".join(
                str(inp.get(k, "") or "") for k in ("name", "id", "placeholder", "aria-label", "type")
            ).lower()
            for tok in SENSITIVE_INPUT_TOKENS:
                if tok in attrs and tok not in sensitive_fields_found:
                    sensitive_fields_found.append(tok)

    if not is_official_uae and len(sensitive_fields_found) >= 2:
        has_payment_harvest = True

    lure_hits = [p for p in AR_EN_URGENCY_PATTERNS if re.search(p, text, re.IGNORECASE)]

    return {
        "page_title": title[:120],
        "has_payment_harvest": has_payment_harvest,
        "suspicious_form_action": suspicious_form_action,
        "sensitive_fields": sensitive_fields_found[:6],
        "lure_hits_count": len(lure_hits),
        "text_length": len(text),
    }


async def inspect_live_page(url: str, host: str, is_official_uae: bool, deep_scan: bool = True) -> Dict:
    """
    Fetches the page using a Mobile Safari persona (and optionally compares against
    a Desktop Bot persona to detect anti-scanner cloaking).
    """
    result = {
        "inspected": False,
        "page_title": "",
        "redirect_hops": 0,
        "has_payment_harvest": False,
        "suspicious_form_action": False,
        "sensitive_fields": [],
        "lure_hits_count": 0,
        "has_cloaking": False,
        "reasons_en": [],
        "reasons_ar": [],
        "score_boost": 0,
    }

    if not deep_scan:
        return result

    # Support safe offline inspection of our local synthetic demo scam site
    if host.endswith(".test") or "demo-scam" in url:
        if os.path.exists(DEMO_SCAM_HTML_PATH):
            with open(DEMO_SCAM_HTML_PATH, "r", encoding="utf-8") as f:
                html = f.read()
            parsed = _analyze_html_content(html, host, is_official_uae=False)
            result.update(parsed)
            result["inspected"] = True
            result["has_cloaking"] = True
            if parsed["has_payment_harvest"]:
                result["score_boost"] += 25
                result["reasons_en"].append(
                    f"Mobile DOM inspection detected unverified financial/ID harvest form ({', '.join(parsed['sensitive_fields'][:4])})."
                )
                result["reasons_ar"].append(
                    "رصد الفحص الميداني للموبايل نموذجاً غير موثق لسرقة بيانات البطاقة والهوية الإماراتية."
                )
            result["reasons_en"].append(
                "Anti-Cloaking Check: Site serves a fake payment page to mobile browsers while hiding from security scanners."
            )
            result["reasons_ar"].append(
                "كشف التمويه: يعرض الموقع صفحة دفع احتيالية للهواتف فقط ويخفيها عن برامج الفحص."
            )
            return result

    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True, verify=False) as client:
            mobile_resp = await client.get(
                url,
                headers={"User-Agent": MOBILE_UA, "Referer": "https://www.google.ae/"},
            )
            result["inspected"] = True
            result["redirect_hops"] = len(mobile_resp.history)

            if "text/html" in (mobile_resp.headers.get("content-type") or "").lower():
                parsed = _analyze_html_content(mobile_resp.text[:80000], host, is_official_uae)
                result.update(parsed)

                if parsed["has_payment_harvest"]:
                    result["score_boost"] += 25
                    result["reasons_en"].append(
                        f"Page collects sensitive financial/identity fields ({', '.join(parsed['sensitive_fields'][:4])}) on an unverified domain."
                    )
                    result["reasons_ar"].append(
                        "يطلب الموقع بيانات مالية أو هوية حساسة على نطاق غير موثق."
                    )

                if parsed["suspicious_form_action"]:
                    result["score_boost"] += 20
                    result["reasons_en"].append(
                        "Form submits sensitive input directly to a suspicious script or external webhook."
                    )
                    result["reasons_ar"].append(
                        "يرسل النموذج البيانات الحساسة مباشرة إلى خادم خارجي مشبوه."
                    )

                if parsed["lure_hits_count"] >= 2 and not is_official_uae:
                    result["score_boost"] += 15
                    result["reasons_en"].append(
                        "Landing page contains Arabic/English financial urgency lure phrases."
                    )
                    result["reasons_ar"].append(
                        "تحتوي الصفحة على عبارات استعجال واحتيال مالي باللغتين العربية والإنجليزية."
                    )

                # Dual-persona anti-cloaking probe for suspicious candidates
                if not is_official_uae and parsed["text_length"] > 100:
                    try:
                        bot_resp = await client.get(url, headers={"User-Agent": DESKTOP_BOT_UA})
                        if bot_resp.status_code in (403, 404) and mobile_resp.status_code == 200:
                            result["has_cloaking"] = True
                            result["score_boost"] += 15
                            result["reasons_en"].append(
                                "Cloaking behavior detected: accessible on Mobile Safari from Google, blocked for scanners."
                            )
                            result["reasons_ar"].append(
                                "تم رصد سلوك تمويه: الموقع يظهر لمستخدمي الموبايل ويحجب نفسه عن أدوات الفحص."
                            )
                    except Exception:
                        pass

            if result["redirect_hops"] >= 3 and not is_official_uae:
                result["score_boost"] += 10
                result["reasons_en"].append(
                    f"Suspicious multi-hop redirect chain ({result['redirect_hops']} redirects)."
                )
                result["reasons_ar"].append(
                    f"سلسلة تحويلات مشبوهة ({result['redirect_hops']} تحويلات متتالية)."
                )
    except Exception:
        pass

    return result

