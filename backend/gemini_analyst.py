"""
ScamShield AI - Optional Free-Tier Gemini AI Contextual Analyst (Layer 3)
Uses Google AI Studio free tier (gemini-2.5-flash) via standard HTTPS REST (zero extra SDK needed).
Privacy-by-Design:
  - Only receives the ALREADY PII-REDACTED URL and public page metadata (title/domain/form flags).
  - Gracefully skipped if GEMINI_API_KEY is not set in .env (falls back cleanly to 100% local ML).
"""
import json
import os
from typing import Dict, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def is_gemini_enabled() -> bool:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    return bool(key and key != "your_free_gemini_api_key_here")


async def analyze_with_gemini(
    redacted_url: str,
    host: str,
    page_title: str = "",
    local_verdict: str = "SUSPICIOUS",
    has_payment_harvest: bool = False,
    domain_age_days: Optional[int] = None,
) -> Optional[Dict]:
    """
    Asks Gemini (Free Tier) for deep contextual reasoning on a privacy-scrubbed URL
    to distinguish real newspapers/businesses/verified social accounts from clever scams.
    Returns {verdict, reason_en, reason_ar} or None if unavailable.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "your_free_gemini_api_key_here":
        return None

    endpoint = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={api_key}"
    )

    prompt = (
        "You are ScamShield AI, an expert UAE cybersecurity analyst evaluating whether a link "
        "is SAFE, SUSPICIOUS, or FRAUD.\n"
        "Be smart and avoid false positives:\n"
        "- Legitimate news articles, government sites (.gov.ae, .gov), official verified social accounts, "
        "and normal local businesses are SAFE even if the URL mentions police, banks, or fines.\n"
        "- Spoofed domains impersonating UAE banks/government/tolls/delivery, homoglyph lookalikes, "
        "fake payment pages, or cloud-hosted phishing (pages.dev/vercel.app impersonating brands) are FRAUD.\n"
        "- Ambiguous unverified profiles or questionable newly registered sites are SUSPICIOUS.\n\n"
        f"Redacted URL: {redacted_url}\n"
        f"Hostname: {host}\n"
        f"Page Title: {page_title or 'N/A'}\n"
        f"Domain Age (days): {domain_age_days if domain_age_days is not None else 'Unknown'}\n"
        f"Unverified Payment/ID Form Found: {has_payment_harvest}\n"
        f"Local ML Preliminary Verdict: {local_verdict}\n\n"
        "Reply ONLY with valid JSON matching this exact schema (no markdown fences):\n"
        '{"verdict": "SAFE" | "SUSPICIOUS" | "FRAUD", '
        '"reason_en": "One concise plain-English sentence explaining why.", '
        '"reason_ar": "One concise natural Arabic sentence explaining why."}'
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code != 200:
                return None
            data = resp.json()
            text = (
                data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
                .strip()
            )
            if not text:
                return None
            # Strip accidental code fences if returned
            if text.startswith("```"):
                text = text.strip("`").replace("json", "", 1).strip()
            parsed = json.loads(text)
            verdict = str(parsed.get("verdict", "")).upper()
            if verdict not in ("SAFE", "SUSPICIOUS", "FRAUD"):
                return None
            return {
                "verdict": verdict,
                "reason_en": str(parsed.get("reason_en", "")).strip(),
                "reason_ar": str(parsed.get("reason_ar", "")).strip(),
                "model": GEMINI_MODEL,
            }
    except Exception:
        return None
