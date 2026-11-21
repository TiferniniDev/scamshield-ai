"""
Generates ScamShield_AI_Pitch.pptx — Clean Light-Mode Executive Presentation (16:9)
Aligned with all Hackathon Submission Requirements: Architecture, Model Choices, Privacy Design & Demo.
"""
import os
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(DOCS_DIR, "scamshield_logo.png")
OUT_PATH = os.path.join(DOCS_DIR, "ScamShield_AI_Pitch.pptx")

# Clean light shadcn/ui palette
C_BG = RGBColor(0xFA, 0xFA, 0xFA)
C_WHITE = RGBColor(0xFF, 0xFF, 0xFF)
C_FG = RGBColor(0x09, 0x09, 0x0B)
C_MUTED = RGBColor(0x52, 0x52, 0x5B)
C_SUBTLE = RGBColor(0x71, 0x71, 0x7A)
C_BORDER = RGBColor(0xE4, 0xE4, 0xE7)
C_SEC = RGBColor(0xF4, 0xF4, 0xF5)
C_PRIMARY = RGBColor(0x18, 0x18, 0x1B)
C_BLUE = RGBColor(0x02, 0x84, 0xC7)
C_SAFE_BG = RGBColor(0xEC, 0xFD, 0xF5)
C_SAFE_FG = RGBColor(0x04, 0x78, 0x57)
C_SUSP_BG = RGBColor(0xFF, 0xFB, 0xEB)
C_SUSP_FG = RGBColor(0xB4, 0x53, 0x09)
C_FRAUD_BG = RGBColor(0xFE, 0xF2, 0xF2)
C_FRAUD_FG = RGBColor(0xB9, 0x1C, 0x1C)
C_BLOCK_BG = RGBColor(0xF5, 0xF3, 0xFF)
C_BLOCK_FG = RGBColor(0x6D, 0x28, 0xD9)

FONT = "Helvetica Neue"


def set_bg(slide, color=C_BG):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_header(slide, kicker, title, slide_num):
    # Subtle top bar
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.06))
    line.fill.solid()
    line.fill.fore_color.rgb = C_PRIMARY
    line.line.fill.background()

    # Kicker pill
    tb_k = slide.shapes.add_textbox(Inches(0.7), Inches(0.35), Inches(8.0), Inches(0.35))
    tf_k = tb_k.text_frame
    tf_k.word_wrap = True
    p_k = tf_k.paragraphs[0]
    p_k.text = kicker.upper()
    p_k.font.name = FONT
    p_k.font.size = Pt(11)
    p_k.font.bold = True
    p_k.font.color.rgb = C_BLUE

    # Title
    tb_t = slide.shapes.add_textbox(Inches(0.7), Inches(0.66), Inches(11.0), Inches(0.65))
    tf_t = tb_t.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title
    p_t.font.name = FONT
    p_t.font.size = Pt(28)
    p_t.font.bold = True
    p_t.font.color.rgb = C_FG

    # Small logo top right
    if os.path.exists(LOGO_PATH):
        slide.shapes.add_picture(LOGO_PATH, Inches(12.25), Inches(0.38), width=Inches(0.55), height=Inches(0.55))

    # Footer
    tb_f = slide.shapes.add_textbox(Inches(0.7), Inches(7.05), Inches(11.9), Inches(0.3))
    tf_f = tb_f.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = f"ScamShield AI  •  Proactive Search, Maps & Mobile Anti-Fraud Platform  •  Slide {slide_num} / 9"
    p_f.font.name = FONT
    p_f.font.size = Pt(10)
    p_f.font.color.rgb = C_SUBTLE


def add_card(slide, left, top, width, height, title, bullets, accent_bg=C_WHITE, title_color=C_FG, border_color=C_BORDER):
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    box.adjustments[0] = 0.04
    box.fill.solid()
    box.fill.fore_color.rgb = accent_bg
    box.line.color.rgb = border_color
    box.line.width = Pt(1.2)

    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.22)
    tf.margin_right = Inches(0.22)
    tf.margin_top = Inches(0.18)
    tf.margin_bottom = Inches(0.15)
    tf.vertical_anchor = MSO_ANCHOR.TOP

    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.name = FONT
    p0.font.size = Pt(15.5)
    p0.font.bold = True
    p0.font.color.rgb = title_color
    p0.space_after = Pt(8)

    for b in bullets:
        p = tf.add_paragraph()
        p.text = f"•  {b}"
        p.font.name = FONT
        p.font.size = Pt(12.5)
        p.font.color.rgb = C_MUTED
        p.space_after = Pt(5)
    return box


def add_pill(slide, left, top, width, height, text, bg, fg):
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    sh.adjustments[0] = 0.5
    sh.fill.solid()
    sh.fill.fore_color.rgb = bg
    sh.line.fill.background()
    tf = sh.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    p.text = text
    p.font.name = FONT
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = fg


def build_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # =========================================================
    # SLIDE 1 — TITLE SLIDE
    # =========================================================
    s1 = prs.slides.add_slide(blank)
    set_bg(s1, C_WHITE)

    band = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.14))
    band.fill.solid()
    band.fill.fore_color.rgb = C_PRIMARY
    band.line.fill.background()

    if os.path.exists(LOGO_PATH):
        s1.shapes.add_picture(LOGO_PATH, Inches(0.9), Inches(1.45), width=Inches(1.55), height=Inches(1.55))

    tb = s1.shapes.add_textbox(Inches(0.9), Inches(3.25), Inches(11.5), Inches(2.5))
    tf = tb.text_frame
    tf.word_wrap = True
    p1 = tf.paragraphs[0]
    p1.text = "ScamShield AI"
    p1.font.name = FONT
    p1.font.size = Pt(46)
    p1.font.bold = True
    p1.font.color.rgb = C_FG

    p2 = tf.add_paragraph()
    p2.text = "Proactive Detection & Real-Time Blocking of Fraudulent Links Across Search Engines, Google Maps & Mobile Apps"
    p2.font.name = FONT
    p2.font.size = Pt(20)
    p2.font.color.rgb = C_MUTED
    p2.space_before = Pt(10)

    p3 = tf.add_paragraph()
    p3.text = "Hunt Early  •  Verify Locally (Zero PII Stored)  •  Protect Mobile & Desktop Users"
    p3.font.name = FONT
    p3.font.size = Pt(14)
    p3.font.bold = True
    p3.font.color.rgb = C_BLUE
    p3.space_before = Pt(18)

    add_pill(s1, 0.9, 5.75, 2.0, 0.42, "Safe — Verified", C_SAFE_BG, C_SAFE_FG)
    add_pill(s1, 3.05, 5.75, 2.3, 0.42, "Suspicious — Caution", C_SUSP_BG, C_SUSP_FG)
    add_pill(s1, 5.5, 5.75, 2.1, 0.42, "Fraud — Blocked", C_FRAUD_BG, C_FRAUD_FG)

    tb_sub = s1.shapes.add_textbox(Inches(0.9), Inches(6.55), Inches(11.5), Inches(0.45))
    ps = tb_sub.text_frame.paragraphs[0]
    ps.text = "SCAMSHIELD AI Hackathon  •  42 Abu Dhabi  •  GitHub: github.com/TiferniniDev/scamshield-ai (master branch)"
    ps.font.name = FONT
    ps.font.size = Pt(12)
    ps.font.color.rgb = C_SUBTLE

    # =========================================================
    # SLIDE 2 — THE PROBLEM
    # =========================================================
    s2 = prs.slides.add_slide(blank)
    set_bg(s2)
    add_header(s2, "01 • The Challenge", "Why Fraudulent Links Still Beat Traditional Defenses", 2)

    add_card(s2, 0.7, 1.55, 5.8, 2.45, "Hijacked Google Maps Listings & Sponsored Ads", [
        "Scammers create or hijack Google Maps pins (car rentals, bank support, towing, typing centers) pointing to card-harvesting portals.",
        "Malvertising pushes fake UAE government, toll (DARB/Salik), and bank sites to #1 in Search results using /aclk ad redirects.",
    ], accent_bg=C_FRAUD_BG, title_color=C_FRAUD_FG, border_color=RGBColor(0xFE, 0xCA, 0xCA))

    add_card(s2, 6.8, 1.55, 5.8, 2.45, "The 80%+ Mobile Blind Spot", [
        "Most UAE residents browse Google Maps, Search, WhatsApp & SMS on iPhones and Androids.",
        "Desktop browser extensions cannot run inside native mobile apps, and everyday users struggle with manual DNS setup.",
    ], accent_bg=C_WHITE)

    add_card(s2, 0.7, 4.25, 5.8, 2.45, "Reactive Blocklists & Slow Takedowns", [
        "Traditional blocklists only react after victims lose money to newly minted phishing domains.",
        "Analysts waste 20+ minutes manually assembling proof for telecom ISPs, registrars, and Google Abuse tickets.",
    ], accent_bg=C_WHITE)

    add_card(s2, 6.8, 4.25, 5.8, 2.45, "Privacy & False-Positive Pitfalls", [
        "Sending citizen links to third-party cloud LLMs risks leaking Emirates IDs, phone numbers, and browsing history.",
        "Naive keyword filters falsely flag legitimate .gov.ae sites, verified Instagram accounts, and news articles.",
    ], accent_bg=C_SUSP_BG, title_color=C_SUSP_FG, border_color=RGBColor(0xFD, 0xE6, 0x8A))

    # =========================================================
    # SLIDE 3 — OUR SOLUTION
    # =========================================================
    s3 = prs.slides.add_slide(blank)
    set_bg(s3)
    add_header(s3, "02 • The Solution", "ScamShield AI: Closed-Loop Hunt → Verify → Block Ecosystem", 3)

    add_card(s3, 0.7, 1.55, 3.8, 2.5, "1. Proactive Patrol Engine", [
        "Continuously sweeps Abu Dhabi Google Maps listings, Mobile Search ads & live SSL Certificate Transparency logs.",
        "Catches newly minted UAE lookalike domains before victims click.",
    ], accent_bg=C_WHITE)

    add_card(s3, 4.75, 1.55, 3.8, 2.5, "2. 1-Tap Mobile Protection", [
        "Installable Mobile App (/app PWA) + Native Android Link Interceptor: 1 big switch protects WhatsApp, SMS, Maps & Safari.",
        "Advanced OS-level DoH DNS Shield (/dns-query + 1-tap iOS .mobileconfig).",
    ], accent_bg=C_SAFE_BG, title_color=C_SAFE_FG, border_color=RGBColor(0xA7, 0xF3, 0xD0))

    add_card(s3, 8.8, 1.55, 3.8, 2.5, "3. Citizen Telegram Bot", [
        "Zero-install Share-to-Check bot (@ScamShieldAD_bot) on any phone.",
        "Returns bilingual Arabic & English verdicts in 3 seconds + 1-tap live escalation to Command Dashboard.",
    ], accent_bg=C_WHITE)

    add_card(s3, 0.7, 4.3, 5.8, 2.4, "4. Pre-Click Chrome Extension (Search & Maps)", [
        "Unwraps organic & Sponsored Google Ad redirects (/aclk?adurl=).",
        "Displays clean Safe / Suspicious / Fraud pills right beside links before click and stops clicks on confirmed Fraud.",
    ], accent_bg=C_WHITE)

    add_card(s3, 6.8, 4.3, 5.8, 2.4, "5. Command Center Dashboard & Takedown Dossiers", [
        "Clean light shadcn/ui workspace with Abu Dhabi Threat Map & 2.5s live Bot toast alerts.",
        "1-Click Block Domain pushes instantly to Mobile DNS + exports privacy-certified JSON Takedown Dossiers for ISPs.",
    ], accent_bg=C_BLOCK_BG, title_color=C_BLOCK_FG, border_color=RGBColor(0xDD, 0xD6, 0xFE))

    # =========================================================
    # SLIDE 4 — SYSTEM ARCHITECTURE
    # =========================================================
    s4 = prs.slides.add_slide(blank)
    set_bg(s4)
    add_header(s4, "03 • System Architecture", "One Shared Local AI Core Powering All 5 Protection Surfaces", 4)

    # Left Column: Inputs
    add_card(s4, 0.7, 1.6, 3.5, 4.95, "Discovery & Citizen Inputs", [
        "Proactive Patrol (Maps geo-grid, Mobile Search & CertStream CT logs)",
        "1-Tap Mobile Companion App (/app PWA & Android Interceptor)",
        "Telegram Share-to-Check Bot (@ScamShieldAD_bot)",
        "Chrome Pre-Click Guard (Search & Sponsored Maps Ads)",
    ], accent_bg=C_WHITE)

    # Center Column: Core Brain
    add_card(s4, 4.65, 1.6, 4.0, 4.95, "ScamShield AI Core (FastAPI + SQLite WAL)", [
        "PII Auto-Redactor (strips Emirates IDs, UAE phones & tokens first)",
        "Stage 1: Local RF+GB ML Ensemble (~32ms/URL on CPU)",
        "Context Verifier: 22 UAE brands, .gov/.gov.ae TLDs & verified social handles",
        "Stage 2: RDAP Domain Age + Mobile Safari DOM Payment & Cloaking Inspector",
        "Stage 3: Optional Free Gemini 3.1 Flash Lite bilingual reasoning",
    ], accent_bg=C_SEC, title_color=C_FG, border_color=C_PRIMARY)

    # Right Column: Outputs & Enforcement
    add_card(s4, 9.1, 1.6, 3.5, 4.95, "Real-Time Defense & Action", [
        "Light shadcn Command Center + Interactive Abu Dhabi Threat Map",
        "Mobile DNS & RFC 8484 DoH Shield (blocks domains in <15ms)",
        "Bilingual Arabic/English Block Warning Page (/blocked)",
        "Standardized JSON Takedown Dossier (SCAMSHIELD-TAKEDOWN-V1)",
    ], accent_bg=C_SAFE_BG, title_color=C_SAFE_FG, border_color=RGBColor(0xA7, 0xF3, 0xD0))

    # =========================================================
    # SLIDE 5 — AI & MODEL CHOICES
    # =========================================================
    s5 = prs.slides.add_slide(blank)
    set_bg(s5)
    add_header(s5, "04 • AI & Model Choices", "Multi-Stage Hybrid Cascade: Fast, Explainable & Context-Aware", 5)

    add_card(s5, 0.7, 1.55, 3.8, 3.35, "Stage 1: Local Ensemble (~32ms)", [
        "Soft-Voting RandomForest + GradientBoosting (scikit-learn) over 24 host-focused features.",
        "Checks hostname entropy, Punycode, Unicode/leetspeak homoglyphs (uaepas5), free cloud hosts (pages.dev, vercel.app), and UAE Arabizi lures.",
        "Runs 100% locally on CPU — fast enough for live DNS & pre-click badges.",
    ], accent_bg=C_WHITE)

    add_card(s5, 4.75, 1.55, 3.8, 3.35, "Stage 2: Live Mobile Sandbox", [
        "Public RDAP lookup flags newly registered domains (<30 days).",
        "Mobile Safari HTML parser detects unverified card/CVV/OTP/Emirates ID forms and Telegram exfiltration webhooks.",
        "Dual-persona probe (Mobile vs. Scanner Bot) exposes mobile cloaking.",
    ], accent_bg=C_WHITE)

    add_card(s5, 8.8, 1.55, 3.8, 3.35, "Stage 3: Context & Gemini AI", [
        "Restricted .gov / .gov.ae / .edu TLDs & major news publishers avoid false alarms.",
        "Official social handle verification: instagram.com/adpolicehq -> Safe; fake pay handles -> Suspicious.",
        "Optional Gemini 3.1 Flash Lite adds deep bilingual reasoning on PII-scrubbed URLs.",
    ], accent_bg=C_WHITE)

    add_card(s5, 0.7, 5.15, 11.9, 1.6, "Clear Human-Centric Verdicts (No Confusing Numeric Scores)", [
        "Users see only clear traffic-light outcomes:  Safe (Green, verified)  |  Suspicious (Yellow, uncertain — proceed with caution)  |  Fraud (Red, high-confidence threat >=80% — blocked).",
        "Every verdict ships with plain-language explanations in both English and Arabic.",
    ], accent_bg=C_SEC)

    # =========================================================
    # SLIDE 6 — MOBILE-FIRST UX
    # =========================================================
    s6 = prs.slides.add_slide(blank)
    set_bg(s6)
    add_header(s6, "05 • Mobile-First Protection", "Zero Technical Friction for Everyday Mobile Users", 6)

    add_card(s6, 0.7, 1.55, 5.8, 5.1, "For Everyday Users: 1-Tap Mobile App (/app)", [
        "Installable PWA (iOS & Android Home Screen with ScamShield logo) + Native Android Kotlin Link Interceptor (/android_app).",
        "Single giant ON/OFF switch guards WhatsApp, SMS, Google Maps, Google Search, Safari & Chrome.",
        "Intercepts tapped links with a native bottom sheet showing Safe / Suspicious / Fraud before any fake payment page loads.",
        "Includes 1-tap 'Block For All Users' — one citizen's report protects everyone in seconds.",
    ], accent_bg=C_SAFE_BG, title_color=C_SAFE_FG, border_color=RGBColor(0xA7, 0xF3, 0xD0))

    add_card(s6, 6.8, 1.55, 5.8, 2.4, "For Zero-Install Users: Telegram Bot", [
        "Forward any Google Maps link, SMS, or WhatsApp text directly to @ScamShieldAD_bot.",
        "Instant Arabic & English analysis + live sync to the Command Dashboard within 2.5 seconds.",
    ], accent_bg=C_WHITE)

    add_card(s6, 6.8, 4.25, 5.8, 2.4, "For Power Users & IT Teams: Private DNS / DoH", [
        "Live RFC 8484 DNS-over-HTTPS (/dns-query) + 1-Tap Apple iOS .mobileconfig profile + UDP DNS Shield.",
        "Works silently across all native mobile apps with zero battery drain.",
    ], accent_bg=C_WHITE)

    # =========================================================
    # SLIDE 7 — PRIVACY BY DESIGN
    # =========================================================
    s7 = prs.slides.add_slide(blank)
    set_bg(s7)
    add_header(s7, "06 • Privacy Design (UAE PDPL Aligned)", "Built-In Data Minimization & Sovereign AI Architecture", 7)

    add_card(s7, 0.7, 1.55, 5.8, 2.45, "1. Automatic PII Scrubbing Before Storage", [
        "redact_url_pii() automatically strips Emirates IDs (784-XXXX-XXXXXXX-X), UAE phone numbers (+971/05...), emails, and auth tokens into [REDACTED].",
        "No raw personal identifiers are ever persisted or sent to Layer-3 AI.",
    ], accent_bg=C_SAFE_BG, title_color=C_SAFE_FG, border_color=RGBColor(0xA7, 0xF3, 0xD0))

    add_card(s7, 6.8, 1.55, 5.8, 2.45, "2. Zero Browsing Logs on Mobile DNS", [
        "DNS & DoH resolvers inspect domain names only (never paths, form inputs, or passwords).",
        "Zero client IP logging; safe queries increment only an anonymous aggregate integer counter.",
    ], accent_bg=C_WHITE)

    add_card(s7, 0.7, 4.25, 5.8, 2.45, "3. Zero Citizen GPS Tracking", [
        "Abu Dhabi map dots represent public Google Maps business pin coordinates only — never user locations.",
        "Proactive patrol monitors purely public internet & SSL Certificate Transparency infrastructure.",
    ], accent_bg=C_WHITE)

    add_card(s7, 6.8, 4.25, 5.8, 2.45, "4. Sovereign Local ML + Certified Takedowns", [
        "Full system operates 100% locally offline if cloud AI is disabled.",
        "JSON Takedown Dossiers embed a privacy_compliance attestation proving zero reporter PII before sharing with ISPs.",
    ], accent_bg=C_WHITE)

    # =========================================================
    # SLIDE 8 — TRADE-OFFS & ROADMAP
    # =========================================================
    s8 = prs.slides.add_slide(blank)
    set_bg(s8)
    add_header(s8, "07 • Engineering Rigor", "Real-World QA Fixes, Honest Trade-Offs & Roadmap", 8)

    add_card(s8, 0.7, 1.55, 5.8, 5.1, "Real-World QA Bugs Caught & Solved", [
        "Verified Social Accounts: Fixed false positive on instagram.com/adpolicehq by adding official social handle registry.",
        "Restricted .gov.ae & Major Newspapers: Re-engineered host-vs-path features and retrained on 4,240 URLs including long news slugs (abudhabipolice.gov.ae & timesofindia -> Safe).",
        "Sponsored Google Maps Ads: Added /aclk?adurl= unwrapping so Sponsored Maps pins get badged cleanly with zero duplicates.",
        "Honest MVP Trade-Offs: Curated Abu Dhabi Maps patrol set + safe watermarked /demo-scam page for legal, CAPTCHA-free live demos.",
    ], accent_bg=C_WHITE)

    add_card(s8, 6.8, 1.55, 5.8, 5.1, "Production Roadmap (Next 90 Days)", [
        "Continuous Retraining Pipeline: Ingest live PhishTank, OpenPhish, URLhaus & Tranco feeds daily.",
        "Signed Native iOS & Android Store Releases: Package our Android Kotlin interceptor + iOS NEDNSProxyProvider for 1-tap App Store install.",
        "Multimodal Visual Clone Engine: Headless Playwright + quantized OpenCLIP embeddings to catch image-only phishing pages.",
        "Fraud Ring Graph Clustering: Link related scam domains by shared ASN, favicon hash, and TLS certificates.",
    ], accent_bg=C_SEC)

    # =========================================================
    # SLIDE 9 — LIVE DEMO
    # =========================================================
    s9 = prs.slides.add_slide(blank)
    set_bg(s9, C_WHITE)
    add_header(s9, "08 • Live Demonstration", "3-Minute End-to-End Live System Walkthrough", 9)

    add_card(s9, 0.7, 1.65, 3.8, 4.1, "Act 1: Proactive Map & Chrome Guard", [
        "Open Light shadcn Dashboard (http://127.0.0.1:8000) & click flagged Abu Dhabi Google Maps pins.",
        "Show live Chrome Extension Safe / Fraud badges on Google Search & Sponsored Maps listings.",
        "Open Evidence & ISP Takedown JSON Dossier.",
    ], accent_bg=C_BG)

    add_card(s9, 4.75, 1.65, 3.8, 4.1, "Act 2: Live Mobile Bot & PII Scrub", [
        "Send fake fine link with an Emirates ID to @ScamShieldAD_bot on a real phone.",
        "Watch instant Arabic & English Fraud verdict + automatic PII redaction.",
        "Watch live green toast banner pop up on the Dashboard in 2.5 seconds!",
    ], accent_bg=C_SAFE_BG, title_color=C_SAFE_FG, border_color=RGBColor(0xA7, 0xF3, 0xD0))

    add_card(s9, 8.8, 1.65, 3.8, 4.1, "Act 3: 1-Tap Mobile App & DNS Block", [
        "Open /app Mobile Companion App -> tap simulated WhatsApp & Google Maps scam links -> watch live bottom-sheet intercept.",
        "Tap Block For All Users -> domain turns purple on Map & joins live Mobile DNS/DoH Blocklist.",
    ], accent_bg=C_BLOCK_BG, title_color=C_BLOCK_FG, border_color=RGBColor(0xDD, 0xD6, 0xFE))

    tb_end = s9.shapes.add_textbox(Inches(0.7), Inches(6.1), Inches(11.9), Inches(0.6))
    pe = tb_end.text_frame.paragraphs[0]
    pe.alignment = PP_ALIGN.CENTER
    pe.text = "Thank You  •  Questions & Live Testing  •  github.com/TiferniniDev/scamshield-ai"
    pe.font.name = FONT
    pe.font.size = Pt(16)
    pe.font.bold = True
    pe.font.color.rgb = C_FG

    prs.save(OUT_PATH)
    print(f"[PPT] Generated {OUT_PATH} ({len(prs.slides)} slides)")


if __name__ == "__main__":
    build_deck()
