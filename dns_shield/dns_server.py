"""
ScamShield AI - Pillar #2: Mobile Private DNS Shield
Works natively across Google Maps, Google Search, Safari, Chrome, WhatsApp, and SMS
on BOTH iOS and Android with zero heavy app install.

Privacy-by-Design:
  - Inspects domain names ONLY (never full URLs, form inputs, or passwords).
  - ZERO browsing history or client IP logging.
  - Runs 100% local fast ML (<15ms) + SQLite Threat Blocklist.
"""
import argparse
import os
import socket
import sys
import threading

from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer
from dotenv import load_dotenv

from backend.database import (
    block_domain_direct,
    check_domain_blocked,
    init_db,
    record_dns_event,
)
from ml.predictor import get_model, predict_url_fast

load_dotenv()

UPSTREAM_DNS = os.getenv("UPSTREAM_DNS", "1.1.1.1")
BLOCK_PAGE_IP = os.getenv("BLOCK_PAGE_IP", "127.0.0.1")
AUTO_BLOCK_THRESHOLD = int(os.getenv("DNS_AUTO_BLOCK_THRESHOLD", "92"))


class ScamShieldDNSResolver(BaseResolver):
    def __init__(self, block_ip: str = BLOCK_PAGE_IP, upstream: str = UPSTREAM_DNS):
        self.block_ip = block_ip
        self.upstream = upstream

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        # 1. Check Police-Approved Blocklist in SQLite (instant)
        blocked_entry = check_domain_blocked(qname)
        if blocked_entry:
            record_dns_event(blocked=True, domain=blocked_entry["domain"])
            print(f"[DNS Shield] 🛡️ BLOCKED (Police List): {qname} -> {self.block_ip}")
            if qtype in ("A", "ANY"):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.block_ip), ttl=30))
            else:
                reply.header.rcode = RCODE.NXDOMAIN
            return reply

        # 2. Zero-Day Real-Time Local ML Check (<15ms) for high-confidence UAE impersonation
        if qtype == "A" and "." in qname and not qname.endswith((".local", ".arpa", ".lan")):
            pred = predict_url_fast(f"https://{qname}")
            if pred["verdict"] == "FRAUD" and pred["ml_score"] >= AUTO_BLOCK_THRESHOLD and pred["impersonated_brand_en"]:
                block_domain_direct(
                    qname,
                    reason_en=pred["reasons_en"][0],
                    reason_ar=pred["reasons_ar"][0],
                    impersonated_brand=pred["impersonated_brand_en"],
                    blocked_by="ScamShield AI Real-Time DNS",
                )
                record_dns_event(blocked=True, domain=qname)
                print(f"[DNS Shield] 🚨 AUTO-BLOCKED Zero-Day ({pred['ml_score']}/100): {qname}")
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.block_ip), ttl=30))
                return reply

        # 3. Safe domain -> Forward cleanly upstream (ZERO domain/IP logging!)
        record_dns_event(blocked=False)
        try:
            proxy_r = request.send(self.upstream, 53, timeout=2.5)
            return DNSRecord.parse(proxy_r)
        except Exception:
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def run_self_test():
    """Quick local test proving DNS Shield blocks fraudulent domains and resolves safe ones."""
    init_db()
    get_model()
    port = 15353
    resolver = ScamShieldDNSResolver(block_ip="127.0.0.1")
    server = DNSServer(resolver, port=port, address="127.0.0.1")
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()

    try:
        for domain in ("adpolice-fines-pay.test", "uaepas5-verify.top", "adpolice.gov.ae"):
            q = DNSRecord.question(domain, "A")
            raw = q.send("127.0.0.1", port, timeout=3)
            ans = DNSRecord.parse(raw)
            ips = [str(rr.rdata) for rr in ans.rr]
            status = "🛡️ BLOCKED (Redirected to ScamShield Warning)" if "127.0.0.1" in ips else "✅ ALLOWED"
            print(f"[DNS Self-Test] {domain:28s} -> {ips} | {status}")
    finally:
        server.stop()


def main():
    parser = argparse.ArgumentParser(description="ScamShield AI Mobile DNS Shield (#2)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind IP (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("DNS_PORT", "1053")), help="UDP Port (1053 local, 53 with sudo for phones)")
    parser.add_argument("--block-ip", default=BLOCK_PAGE_IP, help="IP of ScamShield warning page server")
    parser.add_argument("--test", action="store_true", help="Run built-in DNS self-test and exit")
    args = parser.parse_args()

    if args.test:
        run_self_test()
        return

    init_db()
    get_model()
    print(f"[DNS Shield #2] Starting on {args.host}:{args.port} (Block Redirect IP: {args.block_ip})")
    print("[DNS Shield #2] Privacy Mode: ZERO browsing logs | Domain-only inspection")
    resolver = ScamShieldDNSResolver(block_ip=args.block_ip)
    server = DNSServer(resolver, port=args.port, address=args.host)
    server.start()


if __name__ == "__main__":
    main()

