"""
ScamShield AI - Pillar #3: Citizen Mobile "Share-to-Check" Telegram Bot
Uses HTML parse mode with strict escaping so URLs containing underscores or special
characters never fail to send or sync to the Command Center Dashboard.
"""
import html
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

    if not meta["is_official_uae"] and not meta.get("is_official_tld") and not meta["is_trusted_global"]:
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
    if meta["is_official_uae"] or meta.get("is_official_tld"):
        verdict = "SAFE"
    elif score >= 70:
        verdict = "FRAUD"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    saved = upsert_threat({
        "url": ml_res["url"],
        "host": ml_res["host"],
        "registered_domain": ml_res["registered_domain"],
        "source": "citizen_bot",
        "source_label": "Reported via Mobile Telegram Bot",
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


def format_verdict_html(res: dict) -> str:
    verdict = res["verdict"]
    if verdict == "FRAUD":
        header = "🔴 <b>FRAUD — High-Risk Link</b>\n🔴 <b>تحذير: رابط احتيالي خطير</b>"
    elif verdict == "SUSPICIOUS":
        header = "🟡 <b>SUSPICIOUS — Proceed With Caution</b>\n🟡 <b>رابط مشبوه — يرجى الحذر</b>"
    else:
        header = "🟢 <b>SAFE — Verified Link</b>\n🟢 <b>رابط آمن وموثوق</b>"

    lines = [header, "", f"<b>Domain:</b> <code>{html.escape(res['host'])}</code>"]

    if res.get("impersonated_brand_en"):
        lines.append(
            f"<b>Impersonating:</b> {html.escape(res['impersonated_brand_en'])} ({html.escape(res.get('impersonated_brand_ar') or '')})"
        )
    elif res.get("verified_entity_en"):
        lines.append(
            f"<b>Verified Entity:</b> {html.escape(res['verified_entity_en'])} ({html.escape(res.get('verified_entity_ar') or '')})"
        )

    if res.get("domain_age_days") is not None:
        lines.append(f"<b>Domain Age:</b> {res['domain_age_days']} days")

    if res.get("has_payment_harvest"):
        lines.append("<b>Alert:</b> Unverified card or Emirates ID collection form detected.")

    if res.get("pii_redacted"):
        lines.append("<b>Privacy:</b> Personal details in this link were redacted automatically.")

    lines.append("")
    lines.append("<b>Analysis (EN):</b>")
    for r in res.get("reasons_en", [])[:3]:
        lines.append(f"• {html.escape(r)}")

    lines.append("")
    lines.append("<b>التفاصيل (AR):</b>")
    for r in res.get("reasons_ar", [])[:3]:
        lines.append(f"• {html.escape(r)}")

    return "\n".join(lines)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome = (
        "<b>Welcome to ScamShield AI</b>\n"
        "<b>مرحباً بك في نظام ScamShield AI للحماية من الاحتيال</b>\n\n"
        "Share or paste any suspicious link from Google Maps, Google Search, WhatsApp, or SMS "
        "to check if it is <b>Safe</b>, <b>Suspicious</b>, or <b>Fraud</b>.\n\n"
        "أرسل أو شارك أي رابط من خرائط جوجل أو البحث أو الرسائل النصية للتحقق من أمانه خلال ثوانٍ.\n\n"
        "<b>Privacy Guarantee:</b> Personal details in links are stripped automatically."
    )
    await update.message.reply_text(welcome, parse_mode="HTML")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_stats()
    msg = (
        "<b>ScamShield AI — Live Protection Summary</b>\n\n"
        f"• Links Analyzed: <code>{s['total_threats_analyzed']}</code>\n"
        f"• Fraud Sites Detected: <code>{s['fraud_detected']}</code>\n"
        f"• Flagged Maps Listings: <code>{s['maps_threats']}</code>\n"
        f"• Active Mobile DNS Blocks: <code>{s['active_dns_blocks']}</code>\n"
        f"• Privacy Scrubs Performed: <code>{s['pii_urls_scrubbed']}</code>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    url = extract_first_url(text)
    if not url:
        await update.message.reply_text(
            "Please send or share a website link (for example: <code>https://example.com</code>).\n"
            "يرجى إرسال رابط موقع لفحصه.",
            parse_mode="HTML",
        )
        return

    wait_msg = await update.message.reply_text("Checking link with ScamShield AI...\nجاري فحص الرابط...")
    res = await run_full_check(url)
    reply_text = format_verdict_html(res)

    keyboard = None
    if res["verdict"] in ("FRAUD", "SUSPICIOUS") and res.get("id"):
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "Report & Block Domain / إبلاغ وحجب النطاق",
                    callback_data=f"escalate:{res['id']}",
                )
            ]
        ])

    await wait_msg.edit_text(reply_text, parse_mode="HTML", reply_markup=keyboard)


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    if data.startswith("escalate:"):
        threat_id = int(data.split(":")[1])
        updated = approve_and_block_threat(threat_id, blocked_by="Bot Report -> DNS Shield")
        if updated:
            dom = html.escape(updated["host"])
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text(
                f"<b>Reported &amp; Blocked</b>\n"
                f"<code>{dom}</code> is now listed in the ScamShield Dashboard and blocked on Mobile DNS.\n\n"
                f"<b>تم الإبلاغ والحجب بنجاح</b>\n"
                f"تمت إضافة النطاق <code>{dom}</code> إلى لوحة التحكم وحجبه لحماية المستخدمين.",
                parse_mode="HTML",
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
