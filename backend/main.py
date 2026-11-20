"""
ScamShield AI - Central FastAPI Core Server
Powers:
  - Shared Multi-Signal AI Engine (/api/analyze)
  - Abu Dhabi Police Command Dashboard (/)
  - Proactive Patrol (#1), Mobile DNS Shield (#2), and Telegram Bot (#3)
  - Bilingual Mobile DNS Block Page (/blocked)
  - Safe Synthetic Demo Scam Page (/demo-scam)
"""
import base64
import os
import time
from typing import Any, Dict, Optional

from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from backend.database import (
    approve_and_block_threat,
    block_domain_direct,
    check_domain_blocked,
    dismiss_threat,
    get_stats,
    get_threat,
    init_db,
    list_blocked_domains,
    list_threats,
    record_dns_event,
    unblock_domain,
    upsert_threat,
)
from backend.gemini_analyst import analyze_with_gemini, is_gemini_enabled
from backend.inspector import inspect_live_page, lookup_domain_age_days
from ml.predictor import get_model, get_model_metrics, predict_url_fast

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_HTML = os.path.join(PROJECT_ROOT, "dashboard", "index.html")
DASHBOARD_LOGO = os.path.join(PROJECT_ROOT, "dashboard", "logo.png")
BLOCK_PAGE_HTML = os.path.join(PROJECT_ROOT, "dns_shield", "block_page.html")
MOBILE_SETUP_HTML = os.path.join(PROJECT_ROOT, "dns_shield", "mobile_setup.html")
DEMO_SCAM_HTML = os.path.join(PROJECT_ROOT, "demo_scam_site", "index.html")

app = FastAPI(
    title="ScamShield AI — Proactive Anti-Fraud Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str
    source: str = "manual_scan"  # patrol_maps | patrol_search | patrol_certstream | citizen_bot | manual_scan
    source_label: str = ""
    lat: Optional[float] = None
    lng: Optional[float] = None
    deep_scan: bool = True
    use_ai: bool = True
    save_to_db: bool = True


class UnblockRequest(BaseModel):
    domain: str


class DirectBlockRequest(BaseModel):
    domain: str
    reason_en: str = "Manually blocked by ScamShield AI Operator"
    reason_ar: str = "تم الحجب يدوياً بواسطة مشغّل نظام ScamShield AI"
    impersonated_brand: str = ""


@app.on_event("startup")
def startup_event():
    init_db()
    get_model()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ScamShield AI"}


@app.post("/api/analyze")
async def analyze_url(req: AnalyzeRequest) -> Dict[str, Any]:
    t0 = time.perf_counter()

    # Stage 1: Fast (<10ms) Local ML + Homoglyph + UAE Brand Impersonation + PII Redaction
    ml_res = predict_url_fast(req.url)
    score = ml_res["ml_score"]
    reasons_en = list(ml_res["reasons_en"])
    reasons_ar = list(ml_res["reasons_ar"])
    meta = ml_res["meta"]

    domain_age_days: Optional[int] = None
    has_payment_harvest = False
    has_cloaking = False
    page_title = ""

    # Stage 2 & 3: Domain Age (RDAP) + Mobile Sandbox DOM/Payment/Cloaking Inspector
    if req.deep_scan and not meta["is_official_uae"] and not meta.get("is_official_tld") and not meta["is_trusted_global"]:
        domain_age_days = await lookup_domain_age_days(ml_res["registered_domain"])
        if domain_age_days is not None and domain_age_days <= 30:
            score = min(100, score + 18)
            reasons_en.append(
                f"Newly registered domain ({domain_age_days} days old) — strong early-stage fraud signal."
            )
            reasons_ar.append(
                f"نطاق مسجل حديثاً (منذ {domain_age_days} أيام فقط) — مؤشر قوي على موقع احتيال جديد."
            )

        live = await inspect_live_page(
            ml_res["meta"]["normalized_url"],
            ml_res["host"],
            is_official_uae=meta["is_official_uae"],
            deep_scan=True,
        )
        has_payment_harvest = live["has_payment_harvest"]
        has_cloaking = live["has_cloaking"]
        page_title = live["page_title"]
        if live["score_boost"] > 0:
            score = min(100, score + live["score_boost"])
            reasons_en.extend(live["reasons_en"])
            reasons_ar.extend(live["reasons_ar"])

    score = max(0, min(100, int(score)))
    if meta["is_official_uae"] or meta.get("is_official_tld"):
        verdict = "SAFE"
    elif score >= 80:
        verdict = "FRAUD"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Optional Layer 3: Free Gemini AI Contextual Reasoning (only receives PII-redacted URL)
    ai_verified = False
    if req.use_ai and is_gemini_enabled() and not meta["is_official_uae"] and not meta.get("is_official_tld"):
        if req.deep_scan or verdict in ("SUSPICIOUS", "FRAUD"):
            gem = await analyze_with_gemini(
                redacted_url=ml_res["url"],
                host=ml_res["host"],
                page_title=page_title,
                local_verdict=verdict,
                has_payment_harvest=has_payment_harvest,
                domain_age_days=domain_age_days,
            )
            if gem:
                ai_verified = True
                verdict = gem["verdict"]
                if gem["reason_en"]:
                    reasons_en.insert(0, f"AI Analysis: {gem['reason_en']}")
                if gem["reason_ar"]:
                    reasons_ar.insert(0, f"تحليل الذكاء الاصطناعي: {gem['reason_ar']}")

    total_latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    payload = {
        "url": ml_res["url"],
        "host": ml_res["host"],
        "registered_domain": ml_res["registered_domain"],
        "source": req.source,
        "source_label": req.source_label or page_title,
        "lat": req.lat,
        "lng": req.lng,
        "risk_score": score,
        "verdict": verdict,
        "impersonated_brand_en": ml_res["impersonated_brand_en"],
        "impersonated_brand_ar": ml_res["impersonated_brand_ar"],
        "verified_entity_en": ml_res["verified_entity_en"],
        "verified_entity_ar": ml_res["verified_entity_ar"],
        "reasons_en": reasons_en,
        "reasons_ar": reasons_ar,
        "domain_age_days": domain_age_days,
        "has_payment_harvest": has_payment_harvest,
        "has_cloaking": has_cloaking,
        "pii_redacted": ml_res["pii_redacted"],
        "ai_verified": ai_verified,
        "ml_latency_ms": ml_res["latency_ms"],
        "latency_ms": total_latency_ms,
    }

    saved = None
    if req.save_to_db and (verdict in ("FRAUD", "SUSPICIOUS") or req.source != "manual_scan"):
        saved = upsert_threat(payload)
        payload["threat_id"] = saved["id"]
        payload["status"] = saved["status"]
    else:
        payload["threat_id"] = None
        payload["status"] = "safe"

    return payload


@app.get("/api/threats")
def api_list_threats(
    source: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    return {"threats": list_threats(source=source, verdict=verdict, status=status, limit=limit)}


@app.post("/api/threats/{threat_id}/block")
def api_block_threat(threat_id: int):
    updated = approve_and_block_threat(threat_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "blocked", "threat": updated}


@app.post("/api/threats/{threat_id}/dismiss")
def api_dismiss_threat(threat_id: int):
    updated = dismiss_threat(threat_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "dismissed", "threat": updated}


@app.get("/api/threats/{threat_id}/takedown")
def api_takedown_dossier(threat_id: int):
    threat = get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {
        "dossier_standard": "SCAMSHIELD-TAKEDOWN-V1",
        "platform": "ScamShield AI Threat Intelligence",
        "recommended_actions": [
            "Push domain to ScamShield Mobile Private DNS Blocklist",
            "Submit ISP block request to telecom providers",
            "Submit Google Safe Browsing & Google Maps Abuse takedown ticket",
            "Notify registrar abuse desk for domain suspension",
        ],
        "privacy_compliance": {
            "uae_pdpl_compliant": True,
            "pii_redacted_before_storage": threat["pii_redacted"],
            "citizen_identity_stored": False,
        },
        "evidence": threat,
    }


@app.get("/api/blocked-domains")
def api_blocked_domains():
    return {"blocked_domains": list_blocked_domains()}


@app.post("/api/blocked-domains/block")
def api_direct_block(req: DirectBlockRequest):
    block_domain_direct(
        req.domain,
        reason_en=req.reason_en,
        reason_ar=req.reason_ar,
        impersonated_brand=req.impersonated_brand,
    )
    return {"status": "blocked", "domain": req.domain}


@app.post("/api/blocked-domains/unblock")
def api_unblock_domain(req: UnblockRequest):
    removed = unblock_domain(req.domain)
    return {"status": "unblocked" if removed else "not_found", "domain": req.domain}


@app.get("/api/stats")
def api_stats():
    stats = get_stats()
    stats["model_metrics"] = get_model_metrics()
    stats["gemini_enabled"] = is_gemini_enabled()
    return stats


@app.post("/api/patrol/run")
async def api_run_patrol(deep_scan: bool = False):
    from patrol.patrol_worker import run_patrol_sweep
    summary = await run_patrol_sweep(deep_scan=deep_scan)
    return {"status": "completed", "summary": summary}


@app.get("/logo.png")
def serve_logo():
    if os.path.exists(DASHBOARD_LOGO):
        return FileResponse(DASHBOARD_LOGO, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/mobile-setup", response_class=HTMLResponse)
def serve_mobile_setup():
    if os.path.exists(MOBILE_SETUP_HTML):
        return FileResponse(MOBILE_SETUP_HTML)
    return HTMLResponse("<h1>ScamShield AI Mobile Setup</h1>")


def _resolve_doh_wire(raw_wire: bytes) -> bytes:
    """
    RFC 8484 DNS-over-HTTPS (DoH) resolver sharing the exact same Police/Bot blocklist
    & local fast ML zero-day filter as Pillar #2 UDP DNS Shield.
    """
    req = DNSRecord.parse(raw_wire)
    qname = str(req.q.qname).rstrip(".").lower()
    qtype = QTYPE[req.q.qtype]
    reply = req.reply()

    # 1. Check active blocklist
    blocked_entry = check_domain_blocked(qname)
    if blocked_entry:
        record_dns_event(blocked=True, domain=blocked_entry["domain"])
        reply.header.rcode = RCODE.NXDOMAIN
        return reply.pack()

    # 2. Zero-day fast ML check for high-confidence UAE brand impersonators
    if qtype in ("A", "AAAA") and "." in qname and not qname.endswith((".local", ".arpa", ".lan")):
        pred = predict_url_fast(f"https://{qname}")
        if pred["verdict"] == "FRAUD" and pred["ml_score"] >= 92 and pred["impersonated_brand_en"]:
            block_domain_direct(
                qname,
                reason_en=pred["reasons_en"][0],
                reason_ar=pred["reasons_ar"][0],
                impersonated_brand=pred["impersonated_brand_en"],
                blocked_by="ScamShield AI Real-Time DoH",
            )
            record_dns_event(blocked=True, domain=qname)
            reply.header.rcode = RCODE.NXDOMAIN
            return reply.pack()

    # 3. Safe domain -> forward privately upstream (zero domain/IP logging!)
    record_dns_event(blocked=False)
    try:
        return req.send("1.1.1.1", 53, timeout=2.5)
    except Exception:
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()


@app.get("/dns-query")
async def doh_get(dns: str = Query(...)):
    padding = "=" * (-len(dns) % 4)
    raw = base64.urlsafe_b64decode(dns + padding)
    ans = bytes(_resolve_doh_wire(raw))
    return Response(content=ans, media_type="application/dns-message")


@app.post("/dns-query")
async def doh_post(request: Request):
    raw = await request.body()
    ans = bytes(_resolve_doh_wire(raw))
    return Response(content=ans, media_type="application/dns-message")


@app.get("/scamshield.mobileconfig")
def serve_ios_dns_profile(request: Request, dns_host: Optional[str] = Query(None)):
    """
    1-Tap Apple iOS DNS-over-HTTPS Configuration Profile (.mobileconfig).
    Automatically embeds the live HTTPS host (e.g., Cloudflare Tunnel) so non-technical
    iPhone users can activate ScamShield DNS with a single link tap!
    """
    raw_host = dns_host or request.headers.get("x-forwarded-host") or request.headers.get("host") or "dns.scamshield.local"
    safe_host = "".join(c for c in raw_host.split(":")[0] if c.isalnum() or c in ".-") or "dns.scamshield.local"
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>https://{safe_host}/dns-query</string>
      </dict>
      <key>PayloadDescription</key>
      <string>Protects Google Maps, Google Search, Safari, and all apps from fraudulent links with zero browsing logs.</string>
      <key>PayloadDisplayName</key>
      <string>ScamShield AI Mobile DNS Protection</string>
      <key>PayloadIdentifier</key>
      <string>ai.scamshield.dns.profile.settings</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>7F42A01B-6C11-4E21-9A01-100000000001</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>1-Tap ScamShield AI Protection for iPhone &amp; iPad. Domain-only privacy protection with zero browsing history logged.</string>
  <key>PayloadDisplayName</key>
  <string>ScamShield AI Protection</string>
  <key>PayloadIdentifier</key>
  <string>ai.scamshield.dns.profile</string>
  <key>PayloadOrganization</key>
  <string>ScamShield AI</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>7F42A01B-6C11-4E21-9A01-100000000000</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""
    return Response(
        content=plist,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="ScamShield-AI-iOS-Protection.mobileconfig"'},
    )


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    if os.path.exists(DASHBOARD_HTML):
        return FileResponse(DASHBOARD_HTML)
    return HTMLResponse("<h1>ScamShield AI API Running</h1><p>Dashboard coming in next step.</p>")


@app.get("/blocked", response_class=HTMLResponse)
def serve_block_page():
    if os.path.exists(BLOCK_PAGE_HTML):
        return FileResponse(BLOCK_PAGE_HTML)
    return HTMLResponse("<h1>Blocked by ScamShield AI</h1>")


@app.get("/demo-scam", response_class=HTMLResponse)
def serve_demo_scam():
    if os.path.exists(DEMO_SCAM_HTML):
        return FileResponse(DEMO_SCAM_HTML)
    return HTMLResponse("<h1>Demo Scam Simulation</h1>")

