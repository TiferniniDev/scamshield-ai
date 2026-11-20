"""
ScamShield AI - SQLite Thread-Safe Database Layer (WAL Mode)
Shared cleanly across FastAPI, Proactive Patrol (#1), Mobile DNS Shield (#2), and Telegram Bot (#3).
Privacy-by-Design: Zero citizen IP addresses or personal browsing history stored.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "scamshield.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                registered_domain TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual_scan',
                source_label TEXT DEFAULT '',
                lat REAL,
                lng REAL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                verdict TEXT NOT NULL DEFAULT 'SAFE',
                impersonated_brand_en TEXT,
                impersonated_brand_ar TEXT,
                reasons_en TEXT NOT NULL DEFAULT '[]',
                reasons_ar TEXT NOT NULL DEFAULT '[]',
                domain_age_days INTEGER,
                has_payment_harvest INTEGER NOT NULL DEFAULT 0,
                has_cloaking INTEGER NOT NULL DEFAULT 0,
                pii_redacted INTEGER NOT NULL DEFAULT 0,
                latency_ms REAL DEFAULT 0.0,
                status TEXT NOT NULL DEFAULT 'pending',
                report_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_host_source
                ON threats (host, source);

            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY,
                reason_en TEXT NOT NULL DEFAULT '',
                reason_ar TEXT NOT NULL DEFAULT '',
                impersonated_brand TEXT DEFAULT '',
                blocked_by TEXT NOT NULL DEFAULT 'ScamShield AI Operator',
                hits INTEGER NOT NULL DEFAULT 0,
                blocked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS privacy_metrics (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        for key in ("dns_queries_allowed", "dns_queries_blocked", "pii_urls_scrubbed"):
            conn.execute(
                "INSERT OR IGNORE INTO privacy_metrics (key, value) VALUES (?, 0)",
                (key,),
            )
        conn.commit()
    finally:
        conn.close()


def _row_to_threat(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["reasons_en"] = json.loads(d.get("reasons_en") or "[]")
    d["reasons_ar"] = json.loads(d.get("reasons_ar") or "[]")
    d["has_payment_harvest"] = bool(d.get("has_payment_harvest"))
    d["has_cloaking"] = bool(d.get("has_cloaking"))
    d["pii_redacted"] = bool(d.get("pii_redacted"))
    return d


def upsert_threat(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_conn()
    now = utc_now()
    try:
        host = data["host"].lower()
        source = data.get("source", "manual_scan")
        existing = conn.execute(
            "SELECT id, report_count, status FROM threats WHERE host = ? AND source = ?",
            (host, source),
        ).fetchone()

        if data.get("pii_redacted"):
            conn.execute(
                "UPDATE privacy_metrics SET value = value + 1 WHERE key = 'pii_urls_scrubbed'"
            )

        # Keep blocked status if domain is already actively blocked
        blocked_row = conn.execute(
            "SELECT domain FROM blocked_domains WHERE domain = ? OR domain = ?",
            (host, data.get("registered_domain", host).lower()),
        ).fetchone()
        initial_status = "blocked" if blocked_row else data.get("status", "pending")

        if existing:
            new_status = "blocked" if blocked_row else existing["status"]
            conn.execute(
                """
                UPDATE threats SET
                    url = ?,
                    registered_domain = ?,
                    source_label = COALESCE(NULLIF(?, ''), source_label),
                    lat = COALESCE(?, lat),
                    lng = COALESCE(?, lng),
                    risk_score = ?,
                    verdict = ?,
                    impersonated_brand_en = ?,
                    impersonated_brand_ar = ?,
                    reasons_en = ?,
                    reasons_ar = ?,
                    domain_age_days = COALESCE(?, domain_age_days),
                    has_payment_harvest = ?,
                    has_cloaking = ?,
                    pii_redacted = ?,
                    latency_ms = ?,
                    status = ?,
                    report_count = report_count + 1,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    data["url"],
                    data.get("registered_domain", host),
                    data.get("source_label", ""),
                    data.get("lat"),
                    data.get("lng"),
                    int(data["risk_score"]),
                    data["verdict"],
                    data.get("impersonated_brand_en"),
                    data.get("impersonated_brand_ar"),
                    json.dumps(data.get("reasons_en", []), ensure_ascii=False),
                    json.dumps(data.get("reasons_ar", []), ensure_ascii=False),
                    data.get("domain_age_days"),
                    1 if data.get("has_payment_harvest") else 0,
                    1 if data.get("has_cloaking") else 0,
                    1 if data.get("pii_redacted") else 0,
                    float(data.get("latency_ms", 0.0)),
                    new_status,
                    now,
                    existing["id"],
                ),
            )
            threat_id = existing["id"]
        else:
            cur = conn.execute(
                """
                INSERT INTO threats (
                    url, host, registered_domain, source, source_label, lat, lng,
                    risk_score, verdict, impersonated_brand_en, impersonated_brand_ar,
                    reasons_en, reasons_ar, domain_age_days, has_payment_harvest,
                    has_cloaking, pii_redacted, latency_ms, status, report_count,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    data["url"],
                    host,
                    data.get("registered_domain", host),
                    source,
                    data.get("source_label", ""),
                    data.get("lat"),
                    data.get("lng"),
                    int(data["risk_score"]),
                    data["verdict"],
                    data.get("impersonated_brand_en"),
                    data.get("impersonated_brand_ar"),
                    json.dumps(data.get("reasons_en", []), ensure_ascii=False),
                    json.dumps(data.get("reasons_ar", []), ensure_ascii=False),
                    data.get("domain_age_days"),
                    1 if data.get("has_payment_harvest") else 0,
                    1 if data.get("has_cloaking") else 0,
                    1 if data.get("pii_redacted") else 0,
                    float(data.get("latency_ms", 0.0)),
                    initial_status,
                    now,
                    now,
                ),
            )
            threat_id = cur.lastrowid

        conn.commit()
        row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        return _row_to_threat(row)
    finally:
        conn.close()


def list_threats(
    source: Optional[str] = None,
    verdict: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        query = "SELECT * FROM threats WHERE 1=1"
        params: List[Any] = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC, risk_score DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [_row_to_threat(r) for r in rows]
    finally:
        conn.close()


def get_threat(threat_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        return _row_to_threat(row) if row else None
    finally:
        conn.close()


def approve_and_block_threat(threat_id: int, blocked_by: str = "ScamShield AI Operator") -> Optional[Dict[str, Any]]:
    conn = get_conn()
    now = utc_now()
    try:
        row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        if not row:
            return None
        threat = _row_to_threat(row)
        domain = threat["host"].lower()
        reason_en = threat["reasons_en"][0] if threat["reasons_en"] else "Confirmed fraudulent website."
        reason_ar = threat["reasons_ar"][0] if threat["reasons_ar"] else "موقع احتيالي مؤكد."

        conn.execute(
            """
            INSERT INTO blocked_domains (domain, reason_en, reason_ar, impersonated_brand, blocked_by, hits, blocked_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(domain) DO UPDATE SET
                reason_en = excluded.reason_en,
                reason_ar = excluded.reason_ar,
                impersonated_brand = excluded.impersonated_brand,
                blocked_by = excluded.blocked_by,
                blocked_at = excluded.blocked_at
            """,
            (
                domain,
                reason_en,
                reason_ar,
                threat.get("impersonated_brand_en") or "",
                blocked_by,
                now,
            ),
        )
        conn.execute(
            "UPDATE threats SET status = 'blocked', updated_at = ? WHERE host = ?",
            (now, domain),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        return _row_to_threat(updated)
    finally:
        conn.close()


def block_domain_direct(
    domain: str,
    reason_en: str = "Blocked by ScamShield AI",
    reason_ar: str = "تم الحجب بواسطة درع الحماية الذكي",
    impersonated_brand: str = "",
    blocked_by: str = "Auto-Shield",
) -> None:
    conn = get_conn()
    now = utc_now()
    try:
        dom = domain.lower().strip().rstrip(".")
        conn.execute(
            """
            INSERT INTO blocked_domains (domain, reason_en, reason_ar, impersonated_brand, blocked_by, hits, blocked_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(domain) DO NOTHING
            """,
            (dom, reason_en, reason_ar, impersonated_brand, blocked_by, now),
        )
        conn.execute(
            "UPDATE threats SET status = 'blocked', updated_at = ? WHERE host = ?",
            (now, dom),
        )
        conn.commit()
    finally:
        conn.close()


def unblock_domain(domain: str) -> bool:
    conn = get_conn()
    now = utc_now()
    try:
        dom = domain.lower().strip().rstrip(".")
        cur = conn.execute("DELETE FROM blocked_domains WHERE domain = ?", (dom,))
        conn.execute(
            "UPDATE threats SET status = 'pending', updated_at = ? WHERE host = ?",
            (now, dom),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def dismiss_threat(threat_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    now = utc_now()
    try:
        conn.execute(
            "UPDATE threats SET status = 'dismissed', updated_at = ? WHERE id = ?",
            (now, threat_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        return _row_to_threat(row) if row else None
    finally:
        conn.close()


def list_blocked_domains() -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM blocked_domains ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def check_domain_blocked(domain: str) -> Optional[Dict[str, Any]]:
    """Checks exact domain or parent domain against blocked_domains."""
    conn = get_conn()
    try:
        dom = domain.lower().strip().rstrip(".")
        parts = dom.split(".")
        candidates = [".".join(parts[i:]) for i in range(max(len(parts) - 1, 1))]
        placeholders = ",".join("?" for _ in candidates)
        row = conn.execute(
            f"SELECT * FROM blocked_domains WHERE domain IN ({placeholders}) LIMIT 1",
            candidates,
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def record_dns_event(blocked: bool, domain: Optional[str] = None) -> None:
    """
    Privacy-by-Design: Only increments anonymous aggregate counters (never logs user IP or benign domains).
    """
    conn = get_conn()
    try:
        if blocked:
            conn.execute(
                "UPDATE privacy_metrics SET value = value + 1 WHERE key = 'dns_queries_blocked'"
            )
            if domain:
                conn.execute(
                    "UPDATE blocked_domains SET hits = hits + 1 WHERE domain = ?",
                    (domain.lower().strip().rstrip("."),),
                )
        else:
            conn.execute(
                "UPDATE privacy_metrics SET value = value + 1 WHERE key = 'dns_queries_allowed'"
            )
        conn.commit()
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        fraud = conn.execute("SELECT COUNT(*) FROM threats WHERE verdict = 'FRAUD'").fetchone()[0]
        suspicious = conn.execute("SELECT COUNT(*) FROM threats WHERE verdict = 'SUSPICIOUS'").fetchone()[0]
        maps_count = conn.execute("SELECT COUNT(*) FROM threats WHERE source = 'patrol_maps'").fetchone()[0]
        search_count = conn.execute("SELECT COUNT(*) FROM threats WHERE source = 'patrol_search'").fetchone()[0]
        cert_count = conn.execute("SELECT COUNT(*) FROM threats WHERE source = 'patrol_certstream'").fetchone()[0]
        bot_count = conn.execute("SELECT COUNT(*) FROM threats WHERE source = 'citizen_bot'").fetchone()[0]
        active_blocks = conn.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
        total_block_hits = conn.execute("SELECT COALESCE(SUM(hits), 0) FROM blocked_domains").fetchone()[0]

        pm_rows = conn.execute("SELECT key, value FROM privacy_metrics").fetchall()
        pm = {r["key"]: r["value"] for r in pm_rows}

        return {
            "total_threats_analyzed": total,
            "fraud_detected": fraud,
            "suspicious_detected": suspicious,
            "maps_threats": maps_count,
            "search_threats": search_count,
            "certstream_early_warnings": cert_count,
            "citizen_bot_reports": bot_count,
            "active_dns_blocks": active_blocks,
            "mobile_attacks_blocked": max(total_block_hits, pm.get("dns_queries_blocked", 0)),
            "dns_queries_allowed": pm.get("dns_queries_allowed", 0),
            "pii_urls_scrubbed": pm.get("pii_urls_scrubbed", 0),
        }
    finally:
        conn.close()

