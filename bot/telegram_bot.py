"""
ScamShield AI - Pillar #3: Citizen Mobile "Share-to-Check" Telegram Bot
Any iPhone or Android user can forward a suspicious link from Google Maps,
Google Search, WhatsApp, or SMS and receive a 3-second Arabic & English AI verdict.
Confirmed scams automatically feed the Abu Dhabi Police Command Dashboard & DNS Shield!
"""
import os
import re
from typing import Optional

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from backend.database import approve_and_block_threat, get_stats, init_db, upsert_threat
from backend.inspector import inspect_live_page, lookup_domain_age_days
from ml.predictor import get_model, predict_url_fast

load_dotenv()

URL_REGEX = re.compile(
    r"(https?://[^\s<>\"']+|(?:[a-zA-Z0-9-]+\.)+(?:com|ae|org|net|gov|xyz|top|click|site|online|vip|shop|info|dev|app|io|test|link)(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)


def extract_first_url(text: str) -> Optional[str]:
    if not text:
        return None
    m = URL_REGEX.search(text)
    if not m:
        return None
    return m.group(1).rstrip(".,);!?")


async def run_full_check(url: str) -> dict:
    ml_res = predict_url_fast(url)
    score = ml_res["ml_score"]
    reasons_en = list(ml_res["reasons_en"])
    reasons_ar = list(ml_res["reasons_ar"])
    meta = ml_res["meta"]

    domain_age_days = None
    has_payment_harvest = False
    has_cloaking = False

    if not meta["is_official_uae"] and not meta["is_trusted_global"]:
        domain_age_days = await lookup_domain_age_days(ml_res["registered_domain"])
        if domain_age_days is not None and domain_age_days <= 30:
            score = min(100, score + 18)
            reasons_en.append(f"Newly registered domain ({domain_age_days} days old).")
            reasons_ar.append(f"نطاق مسجل حديثاً (منذ {domain_age_days} أيام).")

        live = await inspect_live_page(
            meta["normalized_url"], ml_res["host"], meta["is_official_uae"], deep_scan=True
        )
        has_payment_harvest = live["has_payment_harvest"]
        has_cloaking = live["has_cloaking"]
        if live["score_boost"] > 0:
            score = min(100, score + live["score_boost"])
            reasons_en.extend(live["reasons_en"])
            reasons_ar.extend(live["reasons_ar"])

    score = max(0, min(100, int(score)))
    verdict = "SAFE" if meta["is_official_uae"] else ("FRAUD" if score >= 70 else ("SUSPICIOUS" if score >= 40 else "SAFE"))

    saved = upsert_threat({
        "url": ml_res["url"],
        "host": ml_res["host"],
        "registered_domain": ml_res["registered_domain"],
        "source": "citizen_bot",
        "source_label": "Citizen Share-to-Check (Mobile Telegram)",
        "lat": 24.4667,
        "lng": 54.3667,
        "risk_score": score,
        "verdict": verdict,
        "impersonated_brand_en": ml_res["impersonated_brand_en"],
        "impersonated_brand_ar": ml_res["impersonated_brand_ar"],
        "reasons_en": reasons_en,
        "reasons_ar": reasons_ar,
        "domain_age_days": domain_age_days,
        "has_payment_harvest": has_payment_harvest,
        "has_cloaking": has_cloaking,
        "pii_redacted": ml_res["pii_redacted"],
        "latency_ms": ml_res["latency_ms"],
    })
    saved["verified_entity_en"] = ml_res["verified_entity_en"]
    saved["verified_entity_ar"] = ml_res["verified_entity_ar"]
    return saved


def format_verdict_message(res: dict) -> str:
    verdict = res["verdict"]
    score = res["risk_score"]
    if verdict == "FRAUD":
        header = f"🔴 *HIGH-RISK FRAUD DETECTED* (`{score}/100`)\n🔴 *تحذير: موقع احتيالي عالي الخطورة*"
    elif verdict == "SUSPICIOUS":
        header = f"🟡 *SUSPICIOUS LINK — PROCEED WITH CAUTION* (`{score}/100`)\n🟡 *رابط مشبوه — يرجى الحذر*"
    else:
        header = f"🟢 *VERIFIED SAFE* (`{score}/100`)\n🟢 *رابط آمن وموثوق*"

    lines = [header, "", f"🌐 *Domain:* `{res['host']}`"]

    if res.get("impersonated_brand_en"):
        lines.append(
            f"⚠️ *Impersonating:* {res['impersonated_brand_en']} ({res['impersonated_brand_ar']})"
        )
    elif res.get("verified_entity_en"):
        lines.append(
            f"✅ *Official UAE Entity:* {res['verified_entity_en']} ({res['verified_entity_ar']})"
        )

    if res.get("domain_age_days") is not None:
        lines.append(f"📅 *Domain Age:* `{res['domain_age_days']} days`")

    if res.get("has_payment_harvest"):
        lines.append("💳 *Alert:* Unverified card / Emirates ID harvesting form detected!")

    if res.get("pii_redacted"):
        lines.append("🔒 *Privacy Shield:* Personal info in this link was automatically redacted before analysis.")

    lines.append("")
    lines.append("*Why (EN):*")
    for r in res.get("reasons_en", [])[:3]:
        lines.append(f"• {r}")

    lines.append("")
    lines.append("*التفاصيل (AR):*")
    for r in res.get("reasons_ar", [])[:3]:
        lines.append(f"• {r}")

    return "\n".join(lines)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome = (
        "🛡️ *Welcome to ScamShield AI*\n"
        "🛡️ *مرحباً بك في نظام درع الحماية الذكي ScamShield AI*\n\n"
        "Share or paste *any suspicious link* from *Google Maps, Google Search, WhatsApp, or SMS* "
        "and I will analyze it in seconds.\n\n"
        "أرسل أو شارك أي رابط مشبوه من خرائط جوجل أو البحث أو الرسائل النصية وسأفحصه خلال ثوانٍ.\n\n"
        "Try testing me with:\n"
        "• `https://adpolice-fines-pay.test/pay/traffic-fine`\n"
        "• `https://www.adpolice.gov.ae`\n\n"
        "🔒 *Privacy Guarantee:* Zero personal data stored; PII is auto-scrubbed."
    )
    await update.message.reply_text(welcome, parse_mode="Markdown")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_stats()
    msg = (
        "📊 *ScamShield AI Live Protection Stats*\n\n"
        f"• Total Links Analyzed: `{s['total_threats_analyzed']}`\n"
        f"• Fraud Websites Caught: `{s['fraud_detected']}`\n"
        f"• Google Maps Fake Pins: `{s['maps_threats']}`\n"
        f"• Active Mobile DNS Blocks: `{s['active_dns_blocks']}`\n"
        f"• Mobile Attacks Prevented: `{s['mobile_attacks_blocked']}`\n"
        f"• PII Links Auto-Scrubbed: `{s['pii_urls_scrubbed']}`"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    url = extract_first_url(text)
    if not url:
        await update.message.reply_text(
            "Please send or share a website link (e.g., `https://example.com`).\n"
            "يرجى إرسال رابط موقع لفحصه.",
            parse_mode="Markdown",
        )
        return

    wait_msg = await update.message.reply_text("🔍 Scanning link with ScamShield AI...\nجاري فحص الرابط...")
    res = await run_full_check(url)
    reply_text = format_verdict_message(res)

    keyboard = None
    if res["verdict"] in ("FRAUD", "SUSPICIOUS") and res.get("id"):
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "🚨 Report & Block on DNS Shield / إبلاغ وحجب فوري",
                    callback_data=f"escalate:{res['id']}",
                )
            ]
        ])

    await wait_msg.edit_text(reply_text, parse_mode="Markdown", reply_markup=keyboard)


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    if data.startswith("escalate:"):
        threat_id = int(data.split(":")[1])
        updated = approve_and_block_threat(threat_id, blocked_by="Citizen Report -> ScamShield DNS")
        if updated:
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text(
                f"✅ *Reported to ScamShield Command Center & pushed to Mobile DNS Shield!*\n"
                f"Domain `{updated['host']}` is now blocked across protected devices.\n\n"
                f"✅ تم رفع البلاغ إلى مركز ScamShield وحجب النطاق `{updated['host']}` لحماية جميع المستخدمين.",
                parse_mode="Markdown",
            )


def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token or token == "your_telegram_bot_token_here":
        print("[Bot #3] ERROR: Please set TELEGRAM_BOT_TOKEN in .env")
        return

    init_db()
    get_model()
    print("[Bot #3] Starting ScamShield AI Telegram Bot (long-polling)...")
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()

