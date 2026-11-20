# 🛡️ ScamShield AI — Proactive Anti-Fraud Defense for Search, Maps & Mobile

> **Early detection and real-time blocking of fraudulent links, hijacked Google Maps business pins, and sponsored search scams across mobile and desktop — built with Privacy-by-Design and 100% local AI.**

---

## 1. Problem & Solution

### The Problem
Online financial fraud in the UAE increasingly exploits **high-trust discovery surfaces** where citizens expect safety:
1. **Hijacked & Fake Google Maps Pins:** Fraudsters create or edit Google Maps listings (car rentals, towing, bank customer care, typing centers, traffic-fine helpdesks) and link them to card/Emirates ID harvesting sites.
2. **Sponsored Search Ads & SEO Poisoning:** Lookalike domains (`adpolice-fines-pay.xyz`, `uaepas5-verify.top`, `darb-toll.pages.dev`) impersonate UAE banks, toll portals, and government services in mobile search results.
3. **The Mobile Blind Spot:** Over 80% of residents browse Google Maps and Search on **iOS and Android**, where traditional desktop browser extensions cannot run inside native mobile apps.
4. **Reactive Takedowns:** Traditional blocklists only react *after* victims lose money, and analysts spend 20+ minutes manually assembling evidence for ISP or Google Abuse takedowns.

### Our Solution — Closed-Loop "Hunt → Verify → Block" Ecosystem
**ScamShield AI** unifies **four real-time layers** around one shared local AI Core Engine and SQLite Threat Intelligence store:

```text
  [ #1 PROACTIVE PATROL ]                [ #3 CITIZEN SHARE-TO-CHECK ]
  • Abu Dhabi Maps geo-grid sweep        • Telegram Bot (iOS & Android)
  • Mobile Search (SERP) sweep           • Share URLs from Maps/Search/SMS
  • Live SSL Cert Transparency (CT)      • 3s Arabic + English AI verdict
             │                                         │
             └───────────────────┬─────────────────────┘
                                 ▼
               ┌───────────────────────────────────┐
               │    SCAMSHIELD AI CORE ENGINE      │
               │ 1. Local RF+GB URL ML (~32ms)     │
               │ 2. Context-Aware UAE Brand &      │
               │    Official Social Handle Check   │
               │ 3. RDAP Age + Mobile DOM Payment  │
               │    Harvest & Cloaking Inspector   │
               │ 4. Auto PII Scrubber (UAE PDPL)   │
               └─────────────────┬─────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
[ COMMAND CENTER ]    [ #2 MOBILE DNS SHIELD ]   [ #4 CHROME GUARD ]
• Live Abu Dhabi Map  • Blocks scams inside      • Pre-click SAFE / FRAUD
• Unified Triage Feed   native Google Maps,        badges right on Google
• 1-Click DNS Block     Search, Safari & SMS       Search & Google Maps
• JSON Takedown File  • Bilingual Block Screen   • Click-stop warning
```

---

## 2. Technical Choices, Trade-Offs & Roadmap

### Reasoning Behind Our Technical Choices
| Layer | Choice | Why We Chose It |
| :--- | :--- | :--- |
| **Core AI Model** | Local Soft-Voting Ensemble (**RandomForest + GradientBoosting**, 24 lexical/entropy/homoglyph/brand features via `scikit-learn`) | Runs in **~32ms/URL** on CPU with **zero external cloud LLM API calls**—ensuring UAE data sovereignty, zero latency bottlenecks at the DNS/browser layer, and full explainability. |
| **Context-Aware Brand & Social Verification** | Curated **22-entity UAE Registry** (`ml/uae_brands.json`) with official domains **and** verified social media handles (`@adpolicehq`, `@tammabudhabi`, `@uaepass_ae`, etc.) | Prevents false positives on legitimate verified social accounts (e.g., `instagram.com/adpolicehq`), UAE news outlets (`gulfnews.com`), and App Store listings while still catching unverified impersonator handles and spoofed domains. |
| **Multi-Stage Cascade** | Fast ML filter (<35ms) at DNS & Browser Extension layers; deeper **RDAP domain-age + Mobile Safari DOM Payment/Cloaking Inspector** on suspicious candidates | Balances speed (instant pre-click badges & DNS resolution) with depth (catching card/CVV/OTP/Emirates ID forms and mobile-only cloaking). |
| **Mobile Protection** | **Private DNS Shield (`dnslib`) + Telegram Share-to-Check Bot** | Desktop extensions cannot inspect native iOS/Android Google Maps apps. Private DNS intercepts malicious domains **across every mobile app** with zero battery drain, while Telegram gives zero-install verification on any phone. |
| **Storage & Stack** | **FastAPI + SQLite (WAL mode) + Leaflet/OpenStreetMap** | Single-command local deployment (`./run.sh`), zero paid API keys, zero external DB servers, concurrent reads/writes across Patrol, Bot, DNS, and Dashboard. |
| **Privacy-by-Design** | **Automatic PII URL Redaction** + **Zero DNS Browsing Logs** | Strips Emirates IDs (`784-...`), UAE phone numbers (`+971`/`05...`), emails, and long auth tokens before saving any URL; DNS resolver inspects domains only and stores strictly anonymous aggregate counters. |

### Trade-Offs & What We Left Out (Honest MVP Scope)
* **Training Data:** For rapid, reproducible hackathon training without scraping instability, the MVP ML model was trained on a balanced 3,840-URL corpus combining official UAE/global domains with synthetic UAE-tailored phishing patterns (impersonation, homoglyphs, cloud hosting abuse, Maps hijacks). In production, we would continuously retrain on live verified feeds (**PhishTank, OpenPhish, URLhaus, Tranco**) with adversarial hard negatives.
* **Proactive Patrol Discovery:** To guarantee a deterministic, CAPTCHA-free live demo without hitting Google rate limits, `patrol/patrol_worker.py` runs a curated Abu Dhabi Maps/Search target sweep alongside optional live **Certificate Transparency (`CertStream`)** listening (`--certstream 15`). In production, this integrates with licensed Google Places/SERP monitoring APIs and continuous CT log consumers.
* **Visual Brand Clone Embeddings:** To keep setup lightweight (avoiding 2GB+ PyTorch downloads), the MVP relies on HTML DOM payment-form & urgency-lure analysis plus dual-persona anti-cloaking rather than headless screenshot CLIP embeddings.
* **Safe Synthetic Simulation:** Live demos use an isolated, clearly watermarked local mock scam page (`/demo-scam`, `adpolice-fines-pay.test`) rather than live third-party phishing sites for legal and campus-network safety.

### What We Would Build Next (With More Time)
1. **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) Production Gateway** with signed TLS certificates and Anycast edge deployment for one-tap iOS `.mobileconfig` and Android Private DNS onboarding.
2. **Multimodal Visual Brand Clone Detector** using headless Playwright mobile screenshots + quantized OpenCLIP embeddings to catch image-only phishing pages with zero text.
3. **Graph Infrastructure Clustering** linking scam domains by shared ASN, favicon hash, TLS issuer, and exfiltration webhooks to uncover entire fraud rings from a single report.
4. **Screenshot OCR in the Telegram Bot** so citizens can forward screenshots of SMS or Maps ads directly without copying URLs.

---

## 3. How to Build & Run

### Prerequisites
* **Python 3.9+**
* **Git**
* *(Optional)* A free Telegram Bot Token from `@BotFather` for the mobile Share-to-Check bot.
* *(Optional)* Google Chrome for loading the Pre-Click Browser Extension.

### Quick Start (1 Command)
```bash
git clone https://github.com/TiferniniDev/scamshield-ai.git
cd scamshield-ai

# Optional: enable the Telegram bot by copying .env.example to .env and adding TELEGRAM_BOT_TOKEN
cp .env.example .env

# Make launcher executable and start all services
chmod +x run.sh
./run.sh
```

`./run.sh` automatically:
1. Creates a local Python virtual environment (`venv`) and installs `requirements.txt`.
2. Trains the local ML model (`ml/scam_model.joblib`) if not already present.
3. Runs an initial proactive Abu Dhabi patrol sweep (`patrol/patrol_worker.py`).
4. Launches:
   * **ScamShield Command Center Dashboard:** http://127.0.0.1:8000
   * **Mobile DNS Block Warning Page Preview:** http://127.0.0.1:8000/blocked
   * **Safe Synthetic Demo Scam Page:** http://127.0.0.1:8000/demo-scam
   * **Mobile DNS Shield Server:** UDP port `1053` *(local non-root default)*
   * **Citizen Telegram Bot:** long-polling *(if `TELEGRAM_BOT_TOKEN` is set in `.env`)*

### Optional Component Tests
```bash
# 1. Re-train ML model and output evaluation metrics (ml/metrics.json)
./venv/bin/python -m ml.train_model

# 2. Run built-in Mobile DNS Shield self-test (proves Police list + Zero-Day auto-block + Safe pass)
./venv/bin/python -m dns_shield.dns_server --test

# 3. Run Proactive Patrol with 15s live Certificate Transparency (CertStream) listening
./venv/bin/python -m patrol.patrol_worker --certstream 15
```

### Loading the Pre-Click Chrome Extension (Google Search & Maps)
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder inside this repository.
4. Ensure `./run.sh` is running on `http://127.0.0.1:8000`, then search on **Google Search** or **Google Maps** to see live `🟢 Safe` / `🟡 Suspicious` / `🔴 FRAUD` badges before clicking.

### Live Real-Phone Mobile DNS Demo (Zero Domain / Zero Hosting)
1. Connect your laptop and test phone to the same personal mobile hotspot.
2. Find your laptop's hotspot IP (e.g., `172.20.10.2`) and run the DNS server on standard port `53`:
   ```bash
   sudo ./venv/bin/python -m dns_shield.dns_server --port 53 --block-ip <YOUR_LAPTOP_IP>
   ```
3. On the test phone's Wi-Fi settings, set **DNS → Manual** to `<YOUR_LAPTOP_IP>`.
4. Opening any blocked domain on the phone (from Google Maps, Safari, Chrome, or SMS) is immediately intercepted by ScamShield DNS!

---

## 4. Repository Structure
```text
scamshield-ai/
├── backend/
│   ├── main.py                # FastAPI core API, Dashboard routes & Takedown Dossier endpoint
│   ├── database.py            # SQLite (WAL) shared Threat DB, DNS Blocklist & Privacy counters
│   └── inspector.py           # RDAP domain age + Mobile Safari DOM payment & cloaking scanner
├── ml/
│   ├── uae_brands.json        # 22 official UAE entities (domains + verified social handles)
│   ├── features.py            # 24 lexical/homoglyph/brand features + UAE PDPL PII URL redactor
│   ├── train_model.py         # Local RF+GB ensemble trainer & latency/accuracy evaluator
│   └── predictor.py           # Bilingual (EN/AR) fast local predictor
├── patrol/
│   └── patrol_worker.py       # #1 Proactive Abu Dhabi Maps, Mobile Search & CertStream patrol
├── dns_shield/
│   ├── dns_server.py          # #2 Lightweight Mobile Private DNS Shield + zero-day auto-blocker
│   └── block_page.html        # Bilingual (EN/AR) mobile warning screen
├── bot/
│   └── telegram_bot.py        # #3 Citizen "Share-to-Check" Telegram Bot
├── extension/                 # #4 Manifest V3 Pre-Click Chrome Extension for Search & Maps
├── dashboard/
│   └── index.html             # Live Command Center (Abu Dhabi Map, Triage Queue, DNS Controls)
├── demo_scam_site/
│   └── index.html             # Safe, watermarked mock UAE traffic-fine scam page for testing
├── docs/
│   ├── TECHNICAL_AND_PRIVACY_DESIGN.md
│   └── PPT_SLIDE_DECK_SCRIPT.md
├── run.sh                     # One-command full-stack launcher
├── requirements.txt
└── .env.example
```

---

## 5. Documentation
* **Architecture, Model Choices & Privacy Design:** [docs/TECHNICAL_AND_PRIVACY_DESIGN.md](docs/TECHNICAL_AND_PRIVACY_DESIGN.md)
* **Presentation Deck & 3-Minute Live Demo Script:** [docs/PPT_SLIDE_DECK_SCRIPT.md](docs/PPT_SLIDE_DECK_SCRIPT.md)
