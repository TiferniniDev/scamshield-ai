# ScamShield AI — Pitch Deck Outline & 3-Minute Live Demo Script

Use this slide-by-slide blueprint to build your 8–10 slide presentation in PowerPoint, Google Slides, or Canva in ~15 minutes.

---

## Slide-by-Slide Deck Content

### Slide 1 — Title Slide
* **Title:** 🛡️ ScamShield AI
* **Subtitle:** Proactive Fraudulent Link & Maps Pin Defense for Mobile and Web
* **Tagline:** *Hunt Early • Verify Locally • Block Across Every Mobile App*
* **Team:** [Your Names] — 42 Abu Dhabi Hackathon

### Slide 2 — The Problem (Why Existing Tools Miss 80% of Victims)
* Fraudsters no longer rely only on obvious spam emails—they **hijack Google Maps listings** (fake bank support, car rentals, typing centers) and buy **sponsored Google Search ads** impersonating UAE portals (`adpolice`, `UAE PASS`, `DARB`, `Salik`, `FAB`).
* **The Mobile Gap:** Most UAE residents browse Google Maps and Search on **iPhones and Androids**, where desktop browser extensions cannot run inside native apps.
* **Slow Response:** Manual verification and ISP takedown reporting take hours—long after financial losses occur.

### Slide 3 — Our Solution: The Closed-Loop "Hunt → Verify → Block" Ecosystem
* **#1 Proactive Patrol:** Continuously sweeps Abu Dhabi Google Maps pins, Mobile Search results, and live SSL Certificate Transparency logs *before* victims click.
* **#2 Mobile Private DNS Shield:** Protects **native Google Maps, Search, Safari, Chrome & SMS** on iOS and Android automatically—zero heavy app required.
* **#3 Citizen Telegram "Share-to-Check" Bot:** Instant 3-second Arabic & English AI verification on any phone + 1-tap escalation.
* **#4 Pre-Click Chrome Extension:** Live `🟢 Safe / 🔴 FRAUD` badges directly inside Google Search & Google Maps on laptops.
* **Command Center Dashboard:** Turns 1 detection into instant protection for all users + 1-click JSON Takedown Dossiers.

### Slide 4 — System Architecture Diagram
*(Copy the ASCII diagram from `README.md` into clean boxes/arrows in PowerPoint/Canva)*
* Show the 4 channels (**Proactive Patrol, Citizen Bot, Mobile DNS, Chrome Extension**) all connected to **one shared Local FastAPI + AI Engine + SQLite Threat Store**.

### Slide 5 — AI & Model Choices (Fast, Local, Bilingual, Context-Aware)
* **Multi-Stage Cascade:**
  1. **Local Soft-Voting Ensemble (RandomForest + GradientBoosting, 24 features):** ~32ms/URL on CPU, zero external API dependency.
  2. **UAE Localization & Context Awareness:** 22-entity UAE brand registry (`ml/uae_brands.json`) verifying both official domains **and official social handles** (`instagram.com/adpolicehq` → 🟢 SAFE; `instagram.com/adpolice_fines_pay` → 🟡 SUSPICIOUS; `adpolice-fines-pay.xyz` → 🔴 FRAUD).
  3. **Deep Mobile Inspector:** RDAP domain-age check (<30 days), Mobile Safari DOM inspection for unverified card/CVV/OTP/Emirates ID forms, and dual-persona anti-cloaking.
* **Explainable Bilingual Output:** Plain-language reasons in both **English and Arabic**.

### Slide 6 — Privacy-by-Design (UAE PDPL Compliant)
* **Zero Browsing History Logged:** Mobile DNS Shield sees domains only (never paths, forms, or passwords) and stores zero client IPs or benign domains.
* **Automatic PII Redaction:** Regex scrubber automatically strips Emirates IDs (`784-...`), UAE phone numbers (`+971`/`05...`), emails, and auth tokens to `[REDACTED]` *before* storage.
* **100% Local Sovereign AI:** Zero URLs sent to foreign third-party LLM APIs.
* **Zero Citizen GPS Tracking:** Map pins represent public Google Maps business listings only.

### Slide 7 — Live Demo (3-Minute Stage Script)
*(Keep this slide minimal: Big QR code to `@ScamShieldAD_bot` + "LIVE DEMO" title)*

### Slide 8 — Trade-Offs, Lessons Learned & Production Roadmap
* **Real-World QA Win:** Caught and solved false positives on verified official social media accounts (`@adpolicehq`) via context-aware handle verification.
* **Honest MVP Trade-Offs:** Curated UAE patrol targets & synthetic demo scam page for safe, repeatable offline-proof demo; lightweight DOM analysis instead of heavy 2GB GPU vision models.
* **Next Steps:** Production DoH/DoT Anycast DNS gateway, live PhishTank/OpenPhish retraining loop, headless OpenCLIP visual brand-clone detection, and Telegram screenshot OCR.

---

## 🎬 Your 3-Minute Live Demo Script (Step-by-Step)

1. **Act 1 — Proactive Command Map (45 sec):**
   * Show `http://127.0.0.1:8000`. Point to the dark Abu Dhabi map with red flagged fake Google Maps pins, green official UAE controls (`adpolice.gov.ae`, `tamm.abudhabi`), and click **🛰️ Run Patrol Sweep (#1)**.
   * Click **📄 Dossier** on a flagged pin to show the machine-readable JSON Takedown file + `privacy_compliance` block.
2. **Act 2 — Live Mobile Telegram Bot + PII Scrubbing (60 sec):**
   * Hold up your phone (or invite a judge to message `@ScamShieldAD_bot`).
   * Send: `https://adpolice-fines-pay.test/pay/traffic-fine?eid=784-1990-1234567-1`
   * Show the 3-second bilingual **🔴 FRAUD (100/100)** response, highlighting **Emirates ID auto-redacted** + **Card/ID Harvest detected**.
   * Switch to the Dashboard → click **`📱 Telegram Bot (#3)`** → judges watch the report appear live!
3. **Act 3 — Instant Blocking Across Mobile & Desktop (60 sec):**
   * Tap **🚨 Report & Block on DNS Shield** in Telegram (or click **Approve & Block on DNS** on Dashboard) → watch the map dot turn 🟣 **Purple** and appear in the **Active Mobile DNS Blocklist**.
   * Show `/blocked` (what mobile users see when DNS intercepts the scam inside Google Maps/Search) + quickly show **Chrome Extension** badges on Google Search (`instagram.com/adpolicehq` = 🟢 **Safe**, scam links = 🔴 **FRAUD**).

---

## 💡 Top 4 Judge Questions & Ready Answers

1. **"How does this work on iPhones inside the Google Maps app?"**
   * *Answer:* Through **Mobile Private DNS (#2)**—every app on iOS and Android must resolve DNS before opening a link, so our DNS shield blocks confirmed & zero-day scam domains natively inside Google Maps, Search, Safari, and SMS without needing app-store hacks. Plus anyone without DNS can use our **Telegram Share-to-Check Bot (#3)**.
2. **"Why didn't you just use ChatGPT / GPT-4 API to classify URLs?"**
   * *Answer:* Three reasons: **Latency** (DNS & pre-click badges need <35ms, not 2–4 seconds), **Privacy & UAE Data Sovereignty** (we never send citizen URLs to external cloud APIs), and **Cost/Reliability** (runs 100% locally offline on CPU).
3. **"What about false positives on real websites or verified Instagram accounts?"**
   * *Answer:* We explicitly tested this on live Google Search and built a **3-tier context verifier**: verified UAE official domains & official social handles (`@adpolicehq`) return `🟢 SAFE`, trusted news/app stores never trigger path alarms, and unverified social handles with payment lures trigger a `🟡 SUSPICIOUS` caution rather than hard-blocking the platform.
4. **"How do you protect citizen privacy?"**
   * *Answer:* Three concrete controls implemented in code: (1) `redact_url_pii()` strips Emirates IDs, phone numbers & auth tokens before saving; (2) the DNS server logs zero client IPs and zero safe domains; (3) map pins show public business listings only, never user GPS.

