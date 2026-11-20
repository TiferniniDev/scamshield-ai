# ScamShield AI — Technical Architecture, Model Choices & Privacy Design

## 1. System Architecture

ScamShield AI is designed as a **closed-loop, multi-channel anti-fraud platform** built around a shared local AI scoring core and an event-synchronized SQLite (WAL-mode) threat store.

### High-Level Component Flow
1. **Discovery Layer (Proactive + Crowd-Powered):**
   * **Pillar #1 — Proactive Patrol (`patrol/patrol_worker.py`):** Sweeps Abu Dhabi Google Maps business listings, Mobile Google Search ads/results, and live public SSL Certificate Transparency (`CertStream`) logs to catch brand impersonation *before* victims click.
   * **Pillar #3 — Citizen Mobile Bot (`bot/telegram_bot.py`):** Allows any iOS or Android user to share suspicious URLs from Google Maps, Search, WhatsApp, or SMS for a 3-second bilingual (Arabic + English) verdict and 1-tap threat escalation.
   * **Pillar #4 — Pre-Click Browser Guard (`extension/`):** Manifest V3 Chrome Extension that badges links directly on Google Search & Google Maps before click and intercepts clicks on confirmed fraud links.
2. **Core AI & Inspection Engine (`ml/` + `backend/inspector.py`):**
   * **Stage 1 — Fast Local ML + Context-Aware Brand Engine (<35ms):** Runs synchronously on every DNS lookup, browser badge check, patrol target, and bot query.
   * **Stage 2 — Domain Trust (RDAP):** Queries public RDAP (`rdap.org`) with strict 2.5s timeout to flag newly minted domains (<30 days old).
   * **Stage 3 — Mobile Sandbox DOM & Anti-Cloaking Inspector:** Fetches target pages using a Mobile Safari iPhone user-agent + Google UAE referrer (`https://www.google.ae/`), inspecting `<form>` inputs for unverified card/CVV/OTP/Emirates ID harvesting, suspicious external webhooks (e.g., Telegram exfiltration), Arabic/English urgency lures, and dual-persona bot-vs-mobile cloaking.
3. **Action & Enforcement Layer:**
   * **Command Center Dashboard (`dashboard/index.html`):** Real-time Abu Dhabi OpenStreetMap visualization of flagged Maps pins, unified triage queue across all pillars, 1-click **"Approve & Block on DNS Shield"**, and machine-readable JSON Takedown Dossier export (`SCAMSHIELD-TAKEDOWN-V1`).
   * **Pillar #2 — Mobile Private DNS Shield (`dns_shield/dns_server.py`):** Intercepts malicious domains across *all* mobile apps (native Google Maps, Search, Safari, Chrome, SMS) and serves a bilingual warning page (`dns_shield/block_page.html`).

---

## 2. Model Choices & Engineering Decisions

### Why a Local Soft-Voting Ensemble (RandomForest + GradientBoosting)?
* **Speed at the Edge:** DNS resolvers and pre-click browser badges cannot wait 2–4 seconds for a remote LLM call. Our 24-feature `scikit-learn` ensemble (`RandomForestClassifier` + `GradientBoostingClassifier`, soft voting) achieves **~32ms average latency per URL** on standard laptop CPU.
* **Data Sovereignty:** 100% local open-weights inference means zero citizen-submitted URLs or investigative queries ever leave local/UAE infrastructure to third-party cloud LLM APIs.
* **Explainability:** Every prediction produces deterministic, bilingual human-readable reasons (EN + AR) tied to exact triggered indicators (impersonated UAE entity, Punycode/homoglyph substitution, free cloud hosting abuse, domain age, payment form harvest).

### Feature Engineering (24 Features in `ml/features.py`)
* **Structural & Entropy Features:** URL length, host length, path length, subdomain depth, dot/hyphen/digit counts, digit ratio, special character count, Shannon entropy of hostname (catches DGA/random scam hosts).
* **Deception & Evasion Signals:** Raw IP host detection, `@` credential obfuscation, double-slash path redirects, Punycode (`xn--`), Unicode Cyrillic/Greek & leetspeak homoglyph normalization (`0`→`o`, `1`→`l`, `5`→`s`, `rn`→`m`).
* **Hosting & TLD Risk:** High-abuse TLDs (`.xyz`, `.top`, `.click`, `.vip`, `.site`, etc.), free cloud hosts abused for zero-day phishing (`pages.dev`, `vercel.app`, `firebaseapp.com`), URL shorteners, and `.gov.ae` / `.abudhabi` verification.
* **UAE Localization:** Context-aware matching against **22 official UAE entities** (`ml/uae_brands.json`) including English + Arabizi lure tokens (`mokhalafat`, `shurta`, `tasdeed`, `hawiyati`, `salik`, `darb`, `tamm`, `uaepass`).

### Context-Aware False-Positive Reduction (Real-World QA Finding)
During live testing on Google Search, naive keyword matching flagged verified official social accounts (e.g., `instagram.com/adpolicehq`) because `"adpolice"` appeared in the URL path of a non-`.gov.ae` domain. We solved this with a **3-tier context verifier**:
1. **Verified Official UAE Domains & Official Social Handles:** Exact match against `official_domains` and `official_handles` on major social platforms (`instagram.com`, `x.com`, `facebook.com`, etc.) → **🟢 SAFE (2/100)**.
2. **Trusted News, App Stores & Knowledge Platforms:** Articles on `gulfnews.com`, `khaleejtimes.com`, `apps.apple.com`, `play.google.com`, and `wikipedia.org` referencing UAE entities never trigger domain-impersonation alarms.
3. **Unverified Impersonator Social Profiles:** Non-official social handles combining a UAE brand + financial lure words (e.g., `instagram.com/adpolice_fines_pay`) are downgraded to **🟡 SUSPICIOUS** with clear guidance to verify the official badge, while spoofed external domains remain **🔴 FRAUD**.

---

## 3. Privacy-by-Design Architecture (UAE PDPL Aligned)

Privacy is built directly into the data flow—not added as an afterthought:

| Threat Surface | Privacy Risk in Typical Tools | ScamShield AI Privacy Guarantee |
| :--- | :--- | :--- |
| **Citizen URL Submissions (#3 Bot & Manual Scan)** | Shared URLs often contain Emirates IDs, phone numbers, email addresses, or private auth/session tokens in query strings. | **`redact_url_pii()`** runs *before* storage, automatically replacing Emirates IDs (`784-XXXX-XXXXXXX-X`), UAE phone numbers (`+971`/`05...`), emails, and sensitive query parameters (`token`, `eid`, `phone`, `card`, `otp`) with `[REDACTED]`. |
| **Mobile Private DNS Shield (#2)** | Logging DNS queries exposes citizens' private medical, banking, and personal browsing history. | **Domain-Only Inspection + Zero Browsing Logs:** The DNS resolver never sees full URL paths, cookies, or form inputs; safe queries increment only an anonymous aggregate integer counter (`dns_queries_allowed`) with **zero client IP or benign domain logging**. |
| **Browser Pre-Click Extension (#4)** | Sending every visited page or Google search query leaks browsing intent. | **Zero Search-Query Leakage:** The extension strips Google search queries, inspects only external target link domains via the local service worker, and **never** writes safe links to the backend database. |
| **Proactive Patrol (#1)** | Invasive user-device monitoring. | **100% Public Infrastructure Only:** Patrol inspects purely public Maps business links, Search listings, and public SSL Certificate Transparency logs—never touching citizen devices or GPS. |
| **AI Model Inference** | Sending citizen reports to foreign third-party LLM APIs violates data sovereignty. | **100% Local On-Prem ML:** All model weights and feature extractors run locally with zero external AI API calls. |
| **ISP / Platform Takedown Sharing** | Sharing raw citizen complaints leaks reporter identities. | **Structured `SCAMSHIELD-TAKEDOWN-V1` JSON** includes an explicit `privacy_compliance` attestation certifying zero reporter identity and PII redaction prior to export. |
